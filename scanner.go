package ctwatch

import (
	"container/list"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
	"strings"

	"github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/x509"
)

// Clients wishing to implement their own Matchers should implement this interface:
type Matcher interface {
	// CertificateMatches is called by the scanner for each X509 Certificate found in the log.
	// The implementation should return |true| if the passed Certificate is interesting, and |false| otherwise.
	CertificateMatches(*x509.Certificate) bool

	// PrecertificateMatches is called by the scanner for each CT Precertificate found in the log.
	// The implementation should return |true| if the passed Precertificate is interesting, and |false| otherwise.
	PrecertificateMatches(*ct.Precertificate) bool
}

// MatchAll is a Matcher which will match every possible Certificate and Precertificate.
type MatchAll struct{}

func (m MatchAll) CertificateMatches(_ *x509.Certificate) bool {
	return true
}

func (m MatchAll) PrecertificateMatches(_ *ct.Precertificate) bool {
	return true
}

type DomainMatcher struct {
	domains			[]string
	domainSuffixes		[]string
}

func NewDomainMatcher (domains []string) DomainMatcher {
	m := DomainMatcher{}
	for _, domain := range domains {
		m.domains = append(m.domains, strings.ToLower(domain))
		m.domainSuffixes = append(m.domainSuffixes, "." + strings.ToLower(domain))
	}
	return m
}

func (m DomainMatcher) dnsNameMatches (dnsName string) bool {
	dnsNameLower := strings.ToLower(dnsName)
	for _, domain := range m.domains {
		if dnsNameLower == domain {
			return true
		}
	}
	for _, domainSuffix := range m.domainSuffixes {
		if strings.HasSuffix(dnsNameLower, domainSuffix) {
			return true
		}
	}
	return false
}

func (m DomainMatcher) CertificateMatches(c *x509.Certificate) bool {
	if m.dnsNameMatches(c.Subject.CommonName) {
		return true
	}
	for _, dnsName := range c.DNSNames {
		if m.dnsNameMatches(dnsName) {
			return true
		}
	}
	return false
}

func (m DomainMatcher) PrecertificateMatches(pc *ct.Precertificate) bool {
	return m.CertificateMatches(&pc.TBSCertificate)
}


// ScannerOptions holds configuration options for the Scanner
type ScannerOptions struct {
	// Custom matcher for x509 Certificates, functor will be called for each
	// Certificate found during scanning.
	Matcher Matcher

	// Number of entries to request in one batch from the Log
	BatchSize int

	// Number of concurrent matchers to run
	NumWorkers int

	// Number of concurrent fethers to run
	ParallelFetch int

	// Don't print any status messages to stdout
	Quiet bool
}

// Creates a new ScannerOptions struct with sensible defaults
func DefaultScannerOptions() *ScannerOptions {
	return &ScannerOptions{
		Matcher:       &MatchAll{},
		BatchSize:     1000,
		NumWorkers:    1,
		ParallelFetch: 1,
		Quiet:         false,
	}
}

// Scanner is a tool to scan all the entries in a CT Log.
type Scanner struct {
	// Client used to talk to the CT log instance
	logClient			*client.LogClient

	// Configuration options for this Scanner instance
	opts				ScannerOptions

	// Size of tree at end of scan
	latestTreeSize			int64

	// Stats
	certsProcessed			int64
	unparsableEntries		int64
	entriesWithNonFatalErrors	int64
}

// matcherJob represents the context for an individual matcher job.
type matcherJob struct {
	// The log entry returned by the log server
	entry ct.LogEntry
	// The index of the entry containing the LeafInput in the log
	index int64
}

// fetchRange represents a range of certs to fetch from a CT log
type fetchRange struct {
	start int64
	end   int64
}

// Takes the error returned by either x509.ParseCertificate() or
// x509.ParseTBSCertificate() and determines if it's non-fatal or otherwise.
// In the case of non-fatal errors, the error will be logged,
// entriesWithNonFatalErrors will be incremented, and the return value will be
// nil.
// Fatal errors will be logged, unparsableEntires will be incremented, and the
// fatal error itself will be returned.
// When |err| is nil, this method does nothing.
func (s *Scanner) handleParseEntryError(err error, entryType ct.LogEntryType, index int64) error {
	if err == nil {
		// No error to handle
		return nil
	}
	switch err.(type) {
	case x509.NonFatalErrors:
		s.entriesWithNonFatalErrors++
		// We'll make a note, but continue.
		s.Warn(fmt.Sprintf("Non-fatal error in %+v at index %d: %s", entryType, index, err.Error()))
	default:
		s.unparsableEntries++
		s.Warn(fmt.Sprintf("Failed to parse in %+v at index %d : %s", entryType, index, err.Error()))
		return err
	}
	return nil
}

// Processes the given |entry| in the specified log.
func (s *Scanner) processEntry(entry ct.LogEntry, foundCert func(*ct.LogEntry)) {
	atomic.AddInt64(&s.certsProcessed, 1)
	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err := x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry)
		if err = s.handleParseEntryError(err, entry.Leaf.TimestampedEntry.EntryType, entry.Index); err != nil {
			// We hit an unparseable entry, already logged inside handleParseEntryError()
			return
		}
		if s.opts.Matcher.CertificateMatches(cert) {
			entry.X509Cert = cert
			foundCert(&entry)
		}
	case ct.PrecertLogEntryType:
		c, err := x509.ParseTBSCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
		if err = s.handleParseEntryError(err, entry.Leaf.TimestampedEntry.EntryType, entry.Index); err != nil {
			// We hit an unparseable entry, already logged inside handleParseEntryError()
			return
		}
		precert := &ct.Precertificate{
			Raw:            entry.Chain[0],
			TBSCertificate: *c,
			IssuerKeyHash:  entry.Leaf.TimestampedEntry.PrecertEntry.IssuerKeyHash,
		}
		if s.opts.Matcher.PrecertificateMatches(precert) {
			entry.Precert = precert
			foundCert(&entry)
		}
	}
}

// Worker function to match certs.
// Accepts MatcherJobs over the |entries| channel, and processes them.
// Returns true over the |done| channel when the |entries| channel is closed.
func (s *Scanner) matcherJob(id int, entries <-chan matcherJob, foundCert func(*ct.LogEntry), wg *sync.WaitGroup) {
	for e := range entries {
		s.processEntry(e.entry, foundCert)
	}
	s.Log(fmt.Sprintf("Matcher %d finished", id))
	wg.Done()
}

// Worker function for fetcher jobs.
// Accepts cert ranges to fetch over the |ranges| channel, and if the fetch is
// successful sends the individual LeafInputs out (as MatcherJobs) into the
// |entries| channel for the matchers to chew on.
// Will retry failed attempts to retrieve ranges indefinitely.
// Sends true over the |done| channel when the |ranges| channel is closed.
func (s *Scanner) fetcherJob(id int, ranges <-chan fetchRange, entries chan<- matcherJob, wg *sync.WaitGroup) {
	for r := range ranges {
		success := false
		// TODO(alcutter): give up after a while:
		for !success {
			s.Log(fmt.Sprintf("Fetching entries %d to %d", r.start, r.end))
			logEntries, err := s.logClient.GetEntries(r.start, r.end)
			if err != nil {
				s.Warn(fmt.Sprintf("Problem fetching from log: %s", err.Error()))
				continue
			}
			for _, logEntry := range logEntries {
				logEntry.Index = r.start
				entries <- matcherJob{logEntry, r.start}
				r.start++
			}
			if r.start > r.end {
				// Only complete if we actually got all the leaves we were
				// expecting -- Logs MAY return fewer than the number of
				// leaves requested.
				success = true
			}
		}
	}
	s.Log(fmt.Sprintf("Fetcher %d finished", id))
	wg.Done()
}

// Returns the smaller of |a| and |b|
func min(a int64, b int64) int64 {
	if a < b {
		return a
	} else {
		return b
	}
}

// Returns the larger of |a| and |b|
func max(a int64, b int64) int64 {
	if a > b {
		return a
	} else {
		return b
	}
}

// Pretty prints the passed in number of |seconds| into a more human readable
// string.
func humanTime(seconds int) string {
	nanos := time.Duration(seconds) * time.Second
	hours := int(nanos / (time.Hour))
	nanos %= time.Hour
	minutes := int(nanos / time.Minute)
	nanos %= time.Minute
	seconds = int(nanos / time.Second)
	s := ""
	if hours > 0 {
		s += fmt.Sprintf("%d hours ", hours)
	}
	if minutes > 0 {
		s += fmt.Sprintf("%d minutes ", minutes)
	}
	if seconds > 0 {
		s += fmt.Sprintf("%d seconds ", seconds)
	}
	return s
}

func (s Scanner) Log(msg string) {
	if !s.opts.Quiet {
		log.Print(msg)
	}
}

func (s Scanner) Warn(msg string) {
	log.Print(msg)
}

func (s *Scanner) TreeSize() (int64, error) {
	latestSth, err := s.logClient.GetSTH()
	if err != nil {
		return 0, err
	}
	return int64(latestSth.TreeSize), nil
}

func (s *Scanner) Scan(startIndex int64, endIndex int64, foundCert func(*ct.LogEntry)) error {
	s.Log("Starting up...\n")

	s.certsProcessed = 0
	s.unparsableEntries = 0
	s.entriesWithNonFatalErrors = 0
	ticker := time.NewTicker(time.Second)
	startTime := time.Now()
	fetches := make(chan fetchRange, 1000)
	jobs := make(chan matcherJob, 100000)
	go func() {
		for range ticker.C {
			throughput := float64(s.certsProcessed) / time.Since(startTime).Seconds()
			remainingCerts := int64(endIndex) - int64(startIndex) - s.certsProcessed
			remainingSeconds := int(float64(remainingCerts) / throughput)
			remainingString := humanTime(remainingSeconds)
			s.Log(fmt.Sprintf("Processed: %d certs (to index %d). Throughput: %3.2f ETA: %s\n", s.certsProcessed,
				startIndex+int64(s.certsProcessed), throughput, remainingString))
		}
	}()

	var ranges list.List
	for start := startIndex; start < int64(endIndex); {
		end := min(start+int64(s.opts.BatchSize), int64(endIndex)) - 1
		ranges.PushBack(fetchRange{start, end})
		start = end + 1
	}
	var fetcherWG sync.WaitGroup
	var matcherWG sync.WaitGroup
	// Start matcher workers
	for w := 0; w < s.opts.NumWorkers; w++ {
		matcherWG.Add(1)
		go s.matcherJob(w, jobs, foundCert, &matcherWG)
	}
	// Start fetcher workers
	for w := 0; w < s.opts.ParallelFetch; w++ {
		fetcherWG.Add(1)
		go s.fetcherJob(w, fetches, jobs, &fetcherWG)
	}
	for r := ranges.Front(); r != nil; r = r.Next() {
		fetches <- r.Value.(fetchRange)
	}
	close(fetches)
	fetcherWG.Wait()
	close(jobs)
	matcherWG.Wait()
	s.Log(fmt.Sprintf("Completed %d certs in %s", s.certsProcessed, humanTime(int(time.Since(startTime).Seconds()))))
	s.Log(fmt.Sprintf("%d unparsable entries, %d non-fatal errors", s.unparsableEntries, s.entriesWithNonFatalErrors))

	return nil
}

// Creates a new Scanner instance using |client| to talk to the log, and taking
// configuration options from |opts|.
func NewScanner(client *client.LogClient, opts ScannerOptions) *Scanner {
	var scanner Scanner
	scanner.logClient = client
	// Set a default match-everything regex if none was provided:
	if opts.Matcher == nil {
		opts.Matcher = &MatchAll{}
	}
	scanner.opts = opts
	return &scanner
}
