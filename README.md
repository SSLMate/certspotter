# Cert Spotter - Certificate Transparency Monitor

**Cert Spotter** is a Certificate Transparency log monitor from SSLMate that
alerts you when an SSL/TLS certificate is issued for one of your domains.
Cert Spotter is easier to use than other open source CT monitors, since it does not require
a database. It's also more robust, since it uses a special certificate parser
that ensures it won't miss certificates.

Cert Spotter is also available as a hosted service by SSLMate that
requires zero setup and provides an easy web dashboard to centrally
manage your certificates.  Visit <https://sslmate.com/certspotter>
to sign up.

You can use Cert Spotter to detect:

 * Certificates issued to attackers who have compromised your DNS and
   are redirecting your visitors to their malicious site.
 * Certificates issued to attackers who have taken over an abandoned
   sub-domain in order to serve malware under your name.
 * Certificates issued to attackers who have compromised a certificate
   authority and want to impersonate your site.
 * Certificates issued in violation of your corporate policy
   or outside of your centralized certificate procurement process.

## Quickstart

The following instructions require you to have [Go version 1.21 or higher](https://go.dev/dl/) installed.

1. Install the certspotter command using the `go` command:

   ```
   go install software.sslmate.com/src/certspotter/cmd/certspotter@latest
   ```

2. Create a watch list file `$HOME/.certspotter/watchlist` containing the DNS names you want to monitor,
   one per line.  To monitor an entire domain tree (including the domain itself
   and all sub-domains) prefix the domain name with a dot (e.g. `.example.com`).
   To monitor a single DNS name only, do not prefix the name with a dot.

3. Place one or more email addresses in the `$HOME/.certspotter/email_recipients`
   file (one per line), and/or place one or more executable scripts in the
   `$HOME/.certspotter/hooks.d` directory.  certspotter will email the listed
   addresses (requires your system to have a working sendmail command) and
   execute the provided scripts when it detects a certificate for a domain on
   your watch list.

4. Configure your system to run `certspotter` as a daemon.  You may want to specify
   the `-start_at_end` command line option to tell certspotter to start monitoring
   new logs at the end instead of the beginning.  This saves significant bandwidth, but
   you won't be notified about certificates which were logged before you started
   using certspotter.

## Documentation

* Command line options and operational details: [certspotter(8) man page](man/certspotter.md)
* The script interface: [certspotter-script(8) man page](man/certspotter-script.md)
* Authorizing known certificates: [certspotter-authorize(8) man page](man/certspotter-authorize.md)
* [Change Log](CHANGELOG.md)

## Authorizing Known Certificates to Prevent False Alarms

You can use the **certspotter-authorize** command to tell certspotter
about legitimate certificates issued by your certificate authority.
certspotter won't notify you when it discovers an authorized certificate
(or its corresponding precertificate) in Certificate Transparency logs.

To install certspotter-authorize, run:

```
go install software.sslmate.com/src/certspotter/cmd/certspotter-authorize@latest
```

To authorize a certificate, run:

```
certspotter-authorize /path/to/cert.pem
```

For more details, see the [certspotter-authorize(8) man page](man/certspotter-authorize.md).

## What certificates are detected by Cert Spotter?

In the default configuration, any certificate that is logged to a
Certificate Transparency log listed as Qualified, Usable, or ReadOnly
in the Google Chrome or Apple log lists will be detected by Cert Spotter.
By default, Chrome, Safari, Firefox, and Edge only accept certificates that are
logged to at least one such log (Firefox and Edge use the Chrome log list), so any
certificate that works in these browsers will be detected by Cert Spotter.

Cert Spotter monitors both traditional RFC6962 logs and modern static-ct-api logs.

## Security

Cert Spotter assumes an adversarial model in which an attacker produces
a certificate that is accepted by at least some clients but goes
undetected because of an encoding error that prevents CT monitors from
understanding it.  To defend against this attack, Cert Spotter uses a
special certificate parser that keeps the certificate unparsed except
for the identifiers.  If one of the identifiers matches a domain on your
watchlist, you will be notified, even if other parts of the certificate
are unparsable.

Cert Spotter takes special precautions to ensure identifiers are parsed
correctly, and implements defenses against identifier-based attacks.
For instance, if a DNS identifier contains a null byte, Cert Spotter
interprets it as two identifiers: the complete identifier, and the
identifier formed by truncating at the first null byte.  For example, a
certificate for `example.org\0.example.com` will alert the owners of both
`example.org` and `example.com`.  This defends against [null prefix attacks](
http://www.thoughtcrime.org/papers/null-prefix-attacks.pdf).

SSLMate continuously monitors CT logs to make sure every certificate's
identifiers can be successfully parsed, and will release updates to
Cert Spotter as necessary to fix parsing failures.

Cert Spotter understands wildcard DNS names, and will alert
you if a wildcard certificate might match an identifier on
your watchlist.  For example, a watchlist entry for `sub.example.com` would
match certificates for `*.example.com`.

Cert Spotter is not just a log monitor, but also a log auditor which
checks that the log is obeying its append-only property.  A future
release of Cert Spotter will support gossiping with other log monitors
to ensure the log is presenting a single view.

## Testing

Every day at around 12:05 UTC, a certificate is issued and logged to CT
for the DNS name `DAY-OF-WEEK.test.certspotter.org`. You can add one
or more of these DNS names (or `.test.certspotter.org`) to your watch
list to get confirmation that Cert Spotter is working.

| DNS Name                         | Issuer        | Key Type |
| -------------------------------- | ------------- | -------- |
| `monday.test.certspotter.org`    | Sectigo       | RSA      |
| `tuesday.test.certspotter.org`   | Let's Encrypt | ECDSA    |
| `wednesday.test.certspotter.org` | Google        | RSA      |
| `thursday.test.certspotter.org`  | Sectigo       | ECDSA    |
| `friday.test.certspotter.org`    | Let's Encrypt | RSA      |
| `saturday.test.certspotter.org`  | Google        | ECDSA    |
| `sunday.test.certspotter.org`    | Let's Encrypt | ECDSA    |

## Copyright

Copyright © 2016-2026 Opsmate, Inc.

Licensed under the [Mozilla Public License Version 2.0](LICENSE).
