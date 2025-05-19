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

-email *ADDRESS*

:   Email address to contact when a matching certificate is discovered, or
    an error occurs.  You can specify this option more than once to email
    multiple addresses.  Your system must have a working sendmail(1) command.

    Regardless of the `-email` option, certspotter also emails any address listed
    in `$CERTSPOTTER_CONFIG_DIR/email_recipients` file
    (`~/.certspotter/email_recipients` by default).  (One address per line,
    blank lines are ignored.)  This file is read only at startup, so you
    must restart certspotter if you change it.

-healthcheck *INTERVAL*

:   Perform a health check at the given interval (default: "24h") as described
    below.  *INTERVAL* must be a decimal number followed by "h" for hours or
    "m" for minutes.

-logs *ADDRESS*

:   Filename or HTTPS URL of a v2 or v3 JSON log list containing logs to monitor.
    The schema for this file can be found at <https://www.gstatic.com/ct/log_list/v3/log_list_schema.json>.
    Defaults to <https://loglist.certspotter.org/monitor.json>, which includes
    the union of active logs recognized by Chrome and Apple.  certspotter periodically
    reloads the log list in case it has changed.

-no\_save

:   Do not save a copy of matching certificates. Note that enabling this option
    will cause you to receive duplicate notifications, since certspotter will
    have no way of knowing if you've been previously notified about a certificate.

-script *COMMAND*

:   Command to execute when a matching certificate is found or an error occurs. See
    certspotter-script(8) for information about the interface to scripts.

    Regardless of the `-script` option, certspotter also executes any executable
    file in the `$CERTSPOTTER_CONFIG_DIR/hooks.d` directory
    (`~/.certspotter/hooks.d` by default).

-start\_at\_end

:   Start monitoring logs from the end rather than the beginning.

    **WARNING**: monitoring from the beginning guarantees detection of all
    certificates, but requires downloading hundreds of millions of
    certificates, which takes days.

-state\_dir *PATH*

:   Directory for storing state. Defaults to `$CERTSPOTTER_STATE_DIR`, which is
    "~/.certspotter" by default.

-stdout

:   Write matching certificates and errors to stdout.

-verbose

:   Print detailed information about certspotter's operation (such as errors contacting logs) to stderr.

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

# NOTIFICATIONS

When certspotter detects a certificate matching your watchlist, or encounters
an error that is preventing it from discovering certificates, it notifies you
as follows:

* Emails any address specified by the `-email` command line flag.

* Emails any address listed in the `$CERTSPOTTER_CONFIG_DIR/email_recipients`
  file (`~/.certspotter/email_recipients` by default).  (One address per line,
  blank lines are ignored.)  This file is read only at startup, so you
  must restart certspotter if you change it.

* Executes the script specified by the `-script` command line flag.

* Executes every executable file in the `$CERTSPOTTER_CONFIG_DIR/hooks.d`
 directory (`~/.certspotter/hooks.d` by default).

* Writes the notification to standard out if the `-stdout` flag was specified.

Sending email requires a working sendmail(1) command.  For details about
the script interface, see certspotter-script(8).

# OPERATION

certspotter continuously monitors all browser-recognized Certificate
Transparency logs looking for certificates (including precertificates)
which are valid for any domain on your watch list. When certspotter
detects a matching certificate, it emails you, executes a script, and/or
writes a report to standard out, as described above.

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

# ERROR HANDLING

When certspotter encounters a problem with the local system (e.g. failure
to write a file or execute a script), it prints a message to stderr and
exits with a non-zero status.

When certspotter encounters a problem monitoring a log, it prints a message
to stderr if `-verbose` is specified and continues running.  It will try monitoring the log again later;
most log errors are transient.

Every 24 hours (unless overridden by `-healthcheck`), certspotter performs the
following health checks:

 * Ensure that the log list has been successfully retrieved at least once
   since the previous health check.
 * Ensure that every log has been successfully contacted at least once
   since the previous health check.
 * Ensure that certspotter is not falling behind monitoring any logs.

If any health check fails, certspotter notifies you by email, script, and/or
standard out, as described above.

Health check failures should be rare, and you should take them seriously because it means
certspotter might not detect all certificates.  It might also be an indication
of CT log misbehavior.  Enable the `-verbose` flag and consult stderr for details, and if
you need help, file an issue at <https://github.com/SSLMate/certspotter>.

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

`EMAIL`

:   Email address from which to send emails. If not set, certspotter lets sendmail pick
    the address.

`HTTPS_PROXY`

:   URL of proxy server for making HTTPS requests.  `http://`, `https://`, and
    `socks5://` URLs are supported.  By default, no proxy server is used.

`SENDMAIL_PATH`

:   Path to the sendmail binary used for sending emails. Defaults to `/usr/sbin/sendmail`.

# DIRECTORIES

Config directory

: Stores configuration, such as the watch list. The location is: (1) the `CERTSPOTTER_CONFIG_DIR` environment variable, if set, or (2) the default location `~/.certspotter`. certspotter does not write to this directory.

State directory

: Stores state, such as the position of each log and a store of discovered certificates. The location is: (1) the `-state_dir` command line flag, if provided, (2) the `CERTSPOTTER_STATE_DIR` environment variable, if set, or (3) the default location `~/.certspotter`.  certspotter creates this directory if necessary.

Cache directory

: Stores cached data. The location is `$XDG_CACHE_HOME/certspotter` (which on Linux is `~/.cache/certspotter` by default).  You can delete this directory without without impacting functionality, but certspotter may need to perform additional computation or network requests.

# SEE ALSO

certspotter-script(8)

# COPYRIGHT

Copyright (c) 2016-2025 Opsmate, Inc.

# BUGS

Report bugs to <https://github.com/SSLMate/certspotter>.
