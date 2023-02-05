# NAME

**certspotter** - Certificate Transparency Log Monitor

# SYNOPSIS

**certspotter** [**-verbose**] [**-start\_at\_end**] [**-watchlist** _file_] `...`

# DESCRIPTION

**Cert Spotter** is a Certificate Transparency log monitor from SSLMate that
alerts you when a SSL/TLS certificate is issued for one of your domains. Cert
Spotter is easier than other open source CT monitors, since it does not require
a database. It's also more robust, since it uses a special certificate parser
that ensures it won't miss certificates.

Cert Spotter is also available as a hosted service by SSLMate,
<https://sslmate.com/certspotter>.

You can use Cert Spotter to detect:

 * Certificates issued to attackers who have compromised your DNS and
   are redirecting your visitors to their malicious site.
 * Certificates issued to attackers who have taken over an abandoned
   sub-domain in order to serve malware under your name.
 * Certificates issued to attackers who have compromised a certificate
   authority and want to impersonate your site.
 * Certificates issued in violation of your corporate policy
   or outside of your centralized certificate procurement process.

# OPTIONS

**-all_time**
:   Scan certs from all time, not just those logged since the previous run of
    Cert Spotter.

**-batch_size** _int_
:   Max number of entries to request at per call to get-entries. This is
    advanced option. Defaults to 1000.

**-logs** _string_
:   Filename or HTTPS URL of a JSON file containing logs to monitor, in the
    format documented at <https://www.certificate-transparency.org/known-logs>.
    Defaults to <https://loglist.certspotter.org/monitor.json>, which includes
    the union of active logs recognized by Chrome and Apple.

**-no\_save**
:   Do not save a copy of matching certificates.

**-num\_workers** _int_
:   Number of concurrent matchers. Default 2.

**-script** _string_
:   Script to execute when a matching certificate is found. See
    **certspotter-script**(8) for information about the interface to scripts.

**-start\_at\_end**
:   Start monitoring logs from the end rather than the beginning.

    **WARNING**: monitoring from the beginning guarantees detection of all
    certificates, but requires downloading hundreds of millions of
    certificates, which takes days.

**-state\_dir** _string_
:   Directory for storing state. Defaults to `~/.certspotter`.

**-verbose**
:   Be verbose.

**-version**
:   Print version and exit.

**-watchlist** _string_
:   File containing identifiers to watch. Use `-` for stdin.
    Defaults to `~/.certspotter/watchlist`.

# NOTES

## Method of operation

Every time you run Cert Spotter, it scans all browser-recognized
Certificate Transparency logs for certificates matching domains on
your watch list. When Cert Spotter detects a matching certificate, it
writes a report to standard out.

Cert Spotter also saves a copy of matching certificates in
`~/.certspotter/certs` (unless you specify the **-no\_save** option).

When Cert Spotter has previously monitored a log, it scans the log
from the previous position, to avoid downloading the same log entry
more than once. (To override this behavior and scan all logs from the
beginning, specify the **-all\_time** option.)

When Cert Spotter has not previously monitored a log, it can either start
monitoring the log from the beginning, or seek to the end of the log and
start monitoring from there. Monitoring from the beginning guarantees
detection of all certificates, but requires downloading hundreds of
millions of certificates, which takes days. The default behavior is to
monitor from the beginning. To start monitoring new logs from the end,
specify the **-start\_at\_end** option.

You can add and remove domains on your watchlist at any time. However,
the certspotter command only notifies you of certificates that were
logged since adding a domain to the watchlist, unless you specify the
**-all\_time** option, which requires scanning the entirety of every log
and takes many days to complete with a fast Internet connection.
To examine preexisting certificates, it's better to use the Cert
Spotter service <https://sslmate.com/certspotter>, the Cert Spotter
API <https://sslmate.com/certspotter/api>, or a CT search engine such
as <https://crt.sh>.

## Coverage

Any certificate that is logged to a Certificate Transparency log trusted by
Chromium will be detected by Cert Spotter. All certificates issued after April
30, 2018 must be logged to such a log to be trusted by Chromium.

Generally, certificate authorities will automatically submit certificates
to logs so that they will work in Chromium.  In addition, certificates
that are discovered during Internet-wide scans are submitted to Certificate
Transparency logs.

## Bygone certificates

Cert Spotter can also notify users of bygone SSL certificates, which are SSL
certificates that outlived their prior domain owner's registration into the
next owners registration. To detect these certificates add a **valid\_at**
argument to each domain in the watchlist followed by the date the domain was
registered in the following format YYYY-MM-DD. For example:

```
example.com valid_at:2014-05-02
```

## Security considerations

Cert Spotter assumes an adversarial model in which an attacker produces a
certificate that is accepted by at least some clients but goes undetected
because of an encoding error that prevents CT monitors from understanding it.
To defend against this attack, Cert Spotter uses a special certificate parser
that keeps the certificate unparsed except for the identifiers.  If one of the
identifiers matches a domain on your watchlist, you will be notified, even if
other parts of the certificate are unparsable.

Cert Spotter takes special precautions to ensure identifiers are parsed
correctly, and implements defenses against identifier-based attacks.  For
instance, if a DNS identifier contains a null byte, Cert Spotter interprets it
as two identifiers: the complete identifier, and the identifier formed by
truncating at the first null byte.  For example, a certificate for
*example.org\0.example.com* will alert the owners of both *example.org* and
*example.com*. This defends against null prefix attacks
<http://www.thoughtcrime.org/papers/null-prefix-attacks.pdf>.

SSLMate continuously monitors CT logs to make sure every certificate's
identifiers can be successfully parsed, and will release updates to Cert
Spotter as necessary to fix parsing failures.

Cert Spotter understands wildcard and redacted DNS names, and will alert you if
a wildcard or redacted certificate might match an identifier on your watchlist.
For example, a watchlist entry for *sub.example.com* would match certificates for
*\*.example.com* or *?.example.com*.

Cert Spotter is not just a log monitor, but also a log auditor which checks
that the log is obeying its append-only property. A future release of Cert
Spotter will support gossiping with other log monitors to ensure the log is
presenting a single view.

# EXIT STATUS

certspotter exits 0 on success, 1 on any error.

# ENVIRONMENT

**CERTSPOTTER\_STATE\_DIR**
:   Directory for storing state. Overridden by **-state\_dir**. Defaults to
    `~/.certspotter`.

**CERTSPOTTER\_CONFIG\_DIR**
:   Directory from which any configuration, such as the watchlist, is read.
    Defaults to `~/.certspotter`.

# SEE ALSO

**certspotter-script**(8)

# COPYRIGHT

Copyright (c) 2016-2022 Opsmate, Inc.

# BUGS

Report bugs to <https://github.com/SSLmate/certspotter>.
