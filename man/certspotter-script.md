# NAME

**certspotter-script** - Certificate Transparency Log Monitor (hook script)

# DESCRIPTION

**certspotter-script** is *any* program that is called using **certspotter(8)**'s
*-script* argument. **certspotter** executes this program when it needs to notify
you about an event, such as detecting a certificate for a domain on your watch list.

# ENVIRONMENT

## Event information

The following environment variables are set for all types of events:

`EVENT`

:   One of the following values, indicating the type of event:

      * `discovered_cert` - certspotter has discovered a certificate for a
      domain on your watch list.

      * `malformed_cert` - certspotter can't determine if a certificate
      matches your watch list because the certificate or the log entry
      is malformed.

      * `error` - a problem is preventing certspotter from monitoring all
      logs.

    Additional event types may be defined in the future, so your script should
    be able to handle unknown values.

`SUMMARY`

:   A short human-readable string describing the event.


## Discovered certificate information

The following environment variables are set for `discovered_cert` events:

`WATCH_ITEM`

:    The item from your watch list which matches this certificate.
     (If more than one item matches, the first one is used.)

`LOG_URI`

:    The URI of the log containing the certificate.

`ENTRY_INDEX`

:    The index of the log entry containing the certificate.

`TBS_SHA256`

:    The hex-encoded SHA-256 digest of the TBSCertificate, as defined in RFC 6962 Section 3.2.
     Certificates and their corresponding precertificates have the same `TBS_SHA256` value.

`CERT_SHA256`

:    The hex-encoded SHA-256 digest (sometimes called fingerprint) of the certificate.
     The digest is computed over the ASN.1 DER encoding. 

`PUBKEY_SHA256`

:    The hex-encoded SHA-256 digest of the certificate's Subject Public Key Info.

`CERT_FILENAME`

:    Path to a file containing the PEM-encoded certificate chain.  Not set if `-no_save` was used.

`JSON_FILENAME`

:    Path to a JSON file containing additional information about the certificate.  See below for the format of the JSON file.
     Not set if `-no_save` was used.

`TEXT_FILENAME`

:    Path to a text file containing information about the certificate.  This file contains the same text that
     certspotter uses in emails.  You should not attempt to parse this file because its format may change in the future.
     Not set if `-no_save` was used.

`NOT_BEFORE`, `NOT_BEFORE_UNIXTIME`, `NOT_BEFORE_RFC3339`

:    The not before time of the certificate, in a human-readable format, seconds since the UNIX epoch, and RFC3339, respectively.  These variables may be unset if there was a parse error, in which case `VALIDITY_PARSE_ERROR` is set.

`NOT_AFTER`, `NOT_AFTER_UNIXTIME`, `NOT_AFTER_RFC3339`

:    The not after (expiration) time of the certificate, in a human-readable format, seconds since the UNIX epoch, and RFC3339, respectively.  These variables may be unset if there was a parse error, in which case `VALIDITY_PARSE_ERROR` is set.

`VALIDITY_PARSE_ERROR`

:    Error parsing not before and not after, if any.  If this variable is set, then the `NOT_BEFORE` and `NOT_AFTER` family of variables are unset.

`SUBJECT_DN`

:    The distinguished name of the certificate's subject.  This variable may be unset if there was a parse error, in which case `SUBJECT_PARSE_ERROR` is set.

`SUBJECT_PARSE_ERROR`

:    Error parsing the subject, if any.  If this variable is set, then `SUBJECT_DN` is unset.

`ISSUER_DN`

:    The distinguished name of the certificate's issuer.  This variable may be unset if there was a parse error, in which case `ISSUER_PARSE_ERROR` is set.

`ISSUER_PARSE_ERROR`

:    Error parsing the issuer, if any.  If this variable is set, then `ISSUER_DN` is unset.

`SERIAL`

:    The hex-encoded serial number of the certificate.  Prefixed with a minus (-) sign if negative.  This variable may be unset if there was a parse error, in which case `SERIAL_PARSE_ERROR` is set.

`SERIAL_PARSE_ERROR`

:    Error parsing the serial number, if any.  If this variable is set, then `SERIAL` is unset.

## Malformed certificate information

The following environment variables are set for `malformed_cert` events:

`LOG_URI`

:    The URI of the log containing the malformed certificate.

`ENTRY_INDEX`

:    The index of the log entry containing the malformed certificate.

`LEAF_HASH`

:    The base64-encoded Merkle hash of the leaf containing the malformed certificate.

`PARSE_ERROR`

:    A human-readable string describing why the certificate is malformed.

`ENTRY_FILENAME`

:    Path to a file containing the JSON log entry.  The file contains a JSON object with two fields, `leaf_input` and `extra_data`, as described in RFC 6962 Section 4.6.

`TEXT_FILENAME`

:    Path to a text file containing a description of the malformed certificate.  This file contains the same text that certspotter uses in emails.

## Error information

The following environment variables are set for `error` events:

`TEXT_FILENAME`

:    Path to a text file containing a description of the error.  This file contains the same text that certspotter uses in emails.

# JSON FILE FORMAT

Unless `-no_save` is used, certspotter saves a JSON file for every discovered certificate
under `$CERTSPOTTER_STATE_DIR`, and puts the path to the file in `$JSON_FILENAME`.  Your
script can read the JSON file, such as with the jq(1) command, to get additional information
about the certificate which isn't appropriate for environment variables.

The JSON file contains an object with the following fields:

`tbs_sha256`

:    A string containing the hex-encoded SHA-256 digest of the TBSCertificate, as defined in RFC 6962 Section 3.2.
     Certificates and their corresponding precertificates have the same `tbs_sha256` value.

`pubkey_sha256`

:    A string containing the hex-encoded SHA-256 digest of the certificate's Subject Public Key Info.

`dns_names`

:    An array of strings containing the DNS names for which the
     certificate is valid, taken from both the DNS subject alternative names
     (SANs) and the subject common name (CN). Internationalized domain names
     are encoded in Punycode.

`ip_addresses`

:    An array of strings containing the IP addresses for which the certificate is valid,
     taken from both the IP subject alternative names (SANs) and the subject common name (CN).

`not_before`

:    A string containing the not before time of the certificate in RFC3339 format.
     Null if there was an error parsing the certificate's validity.

`not_after`

:    A string containing the not after (expiration) time of the certificate in RFC3339 format.
     Null if there was an error parsing the certificate's validity.

Additional fields will be added in the future based on user feedback. Please open
an issue at <https://github.com/SSLMate/certspotter> if you have a use case for another field.

# EXAMPLES

Example environment variables for a `discovered_cert` event:

```
CERT_FILENAME=/home/andrew/.certspotter/certs/3c/3cdc83b3932c194fcdf17aa2bf1abc34e8438b293c3d5c70693e175b38ff128a.pem
CERT_SHA256=3cdc83b3932c194fcdf17aa2bf1abc34e8438b293c3d5c70693e175b38ff128a
ENTRY_INDEX=6464843
EVENT=discovered_cert
ISSUER_DN=C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA
JSON_FILENAME=/usr2/andrew/.certspotter/certs/3c/3cdc83b3932c194fcdf17aa2bf1abc34e8438b293c3d5c70693e175b38ff128a.v1.json
LOG_URI=https://ct.cloudflare.com/logs/nimbus2024/
NOT_AFTER='2024-01-26 03:47:26 +0000 UTC'
NOT_AFTER_RFC3339=2024-01-26T03:47:26Z
NOT_AFTER_UNIXTIME=1706240846
NOT_BEFORE='2023-01-31 03:47:26 +0000 UTC'
NOT_BEFORE_RFC3339=2023-01-31T03:47:26Z
NOT_BEFORE_UNIXTIME=1675136846
PUBKEY_SHA256=33ac1d9b9e56005ccac045eac2398b3e9dd6b3f5b66ae6260f2d478c7c0d82c8
SERIAL=c170fbf3bf27481e5c351a4db6f2dc5f
SUBJECT_DN=CN=sslmate.com
SUMMARY='certificate discovered for .sslmate.com'
TBS_SHA256=2388ee81c6f45cffc73e68a35fa8921e839e20acc9a98e8e6dcaea07cbfbdef8
TEXT_FILENAME=/usr2/andrew/.certspotter/certs/3c/3cdc83b3932c194fcdf17aa2bf1abc34e8438b293c3d5c70693e175b38ff128a.txt
WATCH_ITEM=.sslmate.com
```

Example JSON file for a discovered certificate:

```
{
  "dns_names": [
    "sslmate.com",
    "www.sslmate.com"
  ],
  "ip_addresses": [],
  "not_after": "2024-01-26T03:47:26Z",
  "not_before": "2023-01-31T03:47:26Z",
  "pubkey_sha256": "33ac1d9b9e56005ccac045eac2398b3e9dd6b3f5b66ae6260f2d478c7c0d82c8",
  "tbs_sha256": "2388ee81c6f45cffc73e68a35fa8921e839e20acc9a98e8e6dcaea07cbfbdef8"
}
```

# SEE ALSO

certspotter(8)

# COPYRIGHT

Copyright (c) 2016-2023 Opsmate, Inc.

# BUGS

Report bugs to <https://github.com/SSLMate/certspotter>.
