# NAME

**certspotter** - Certificate Transparency Log Monitor

# SYNOPSIS

**certspotter** [`-start_at_end`] [`-watchlist` *FILENAME*] [`-email` *ADDRESS*] `...`

# DESCRIPTION

**Cert Spotter** is a Certificate Transparency log monitor from SSLMate that
alerts you when a SSL/TLS certificate is issued for one of your domains.
Cert Spotter is easier to use than other open source CT monitors, since it does not require
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

-batch_size *NUMBER*

:   Maximum number of entries to request per call to get-entries.
    You should not generally need to change this. Defaults to 1000.

-email *ADDRESS*

:   Email address to contact when a matching certificate is discovered.
    You can specify this option more than once to email multiple addresses.
    Your system must have a working sendmail(1) command.

-logs *ADDRESS*

:   Filename or HTTPS URL of a v2 or v3 JSON log list containing logs to monitor.
    The schema for this file can be found at <https://www.gstatic.com/ct/log_list/v3/log_list_schema.json>.
    Defaults to <https://loglist.certspotter.org/monitor.json>, which includes
    the union of active logs recognized by Chrome and Apple.  certspotter periodically
    reloads the log list in case it has changed.

-no_save

:   Do not save a copy of matching certificates.

-script *COMMAND*

:   Command to execute when a matching certificate is found. See
    certspotter-script(8) for information about the interface to scripts.

-start_at_end

:   Start monitoring logs from the end rather than the beginning.

    **WARNING**: monitoring from the beginning guarantees detection of all
    certificates, but requires downloading hundreds of millions of
    certificates, which takes days.

-state_dir *PATH*

:   Directory for storing state. Defaults to `$CERTSPOTTER_STATE_DIR`, which is
    "~/.certspotter" by default.

-stdout

:   Write matching certificates to stdout.

-verbose

:   Be verbose.

-version

:   Print version and exit.

-watchlist *PATH*

:   File containing DNS names to monitor, one per line.  To monitor an entire
    domain namespace (including the domain itself and all sub-domains) prefix
    the domain name with a dot (e.g. ".example.com").  To monitor a single DNS
    name only, do not prefix the name with a dot.
    
    Defaults to `$CERTSPOTTER_CONFIG_DIR/watchlist`, which is
    "~/.certspotter/watchlist" by default.
    Specify `-` to read the watch list from stdin.
    
    certspotter reads the watch list only when starting up, so you must restart
    certspotter if you change it.

# OPERATION

certspotter continuously monitors all browser-recognized Certificate
Transparency logs looking for certificates which are valid for any domain
on your watch list. When certspotter detects a matching certificate, it
emails you (if `-email` is specified), executes a script (if `-script`
is specified), and/or writes a report to standard out (if `-stdout`
is specified).

certspotter also saves a copy of matching certificates in
`$CERTSPOTTER_STATE_DIR/certs` ("~/.certspotter/certs" by default)
unless you specify the `-no_save` option.

When certspotter has not previously monitored a log, it can either start
monitoring the log from the beginning, or seek to the end of the log and
start monitoring from there. Monitoring from the beginning guarantees
detection of all certificates, but requires downloading hundreds of
millions of certificates, which takes days. The default behavior is to
monitor from the beginning. To start monitoring new logs from the end,
specify the `-start_at_end` option.

If certspotter has previously monitored a log, it resumes monitoring
the log from the previous position.  This means that if you add
a domain to your watch list, certspotter will not detect any certificates
that were logged prior to the addition.  To detect such certificates,
you must delete `$CERTSPOTTER_STATE_DIR/logs`, which will cause certspotter
to restart monitoring from the very beginning of each log (provided
`-start_at_end` is not specified).  This will cause certspotter to download
hundreds of millions of certificates, which takes days.  To find preexisting
certificates, it's faster to use the Cert Spotter service
<https://sslmate.com/certspotter>, SSLMate's Certificate Transparency Search
API <https://sslmate.com/ct_search_api>, or a CT search engine such as
<https://crt.sh>.

# EXIT STATUS

certspotter exits 0 when it receives `SIGTERM` or `SIGINT`,
and non-zero when a serious error occurs.

# ENVIRONMENT

`CERTSPOTTER_STATE_DIR`

:   Directory for storing state. Overridden by `-state_dir`. Defaults to
    `~/.certspotter`.

`CERTSPOTTER_CONFIG_DIR`

:   Directory from which any configuration, such as the watch list, is read.
    Defaults to `~/.certspotter`.

`HTTPS_PROXY`

:   URL of proxy server for making HTTPS requests.  `http://`, `https://`, and
    `socks5://` URLs are supported.  By default, no proxy server is used.

# SEE ALSO

certspotter-script(8)

# COPYRIGHT

Copyright (c) 2016-2023 Opsmate, Inc.

# BUGS

Report bugs to <https://github.com/SSLMate/certspotter>.