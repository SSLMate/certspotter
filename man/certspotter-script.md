# NAME

**certspotter-script** - Certificate Transparency Log Monitor (hook script)

# SYNOPSIS

**certspotter-script**

# DESCRIPTION

**certspotter-script** is *any* program that is called from **certspotter**'s
*-script* argument. **certspotter** executes this script when a file from the
CT log matches against the watchlist.

# ENVIRONMENT

The script will have the following variables defined in its environment:

## Log entry information

**CERT\_FILENAME**
:    The path of the saved certificate on the local filesystem, if one exists.

**CERT\_TYPE**
:    The certificate's type (*cert* or *precert*).

**FINGERPRINT**
:    The certificate's fingerprint.

**LOG\_URI**
:    The URI of the log the certificate was found on.

**ENTRY\_INDEX**
:    The entry's index in the log.

**CERT\_PARSEABLE**
:    Whether the certificate could be parsed.

## Identifiers

**DNS\_NAMES**
:    A comma-separated list of the certificate's dnsNames.

**IP\_ADDRESSES**
:    A comma-separated list of the certificate's IP addresses.

## Certificate information

**PUBKEY\_HASH**
:    The certificate public key's hash.

**SERIAL**
:    The certificate's serial.

**NOT\_BEFORE**, **NOT\_AFTER**
:    The certificate's validity information, as a string.

**NOT\_BEFORE\_UNIXTIME**, **NOT\_AFTER\_UNIXTIME**
:    The certificate's validity information, as UNIX time.

**SUBJECT\_DN**
:    The certificate's subject distinguished name (DN).

**ISSUER\_DN**
:    the certificate issuer distinguished name (DN).

## Errors

**PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract information about
    the certificate. In this case, **CERT\_PARSEABLE** will also be set to "no"
    and information such as **PUBKEY\_HASH**, **SERIAL**, as well as validity
    and subject, will not be present.

**SERIAL\_PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract the certificate's
    serial. Emitted instead of **SERIAL**.

**IDENTIFIERS\_PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract the certificate's
    identifiers. Emitted instead of **DNS\_NAMES**, **IP\_ADDRESSES**.

**VALIDITY\_PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract the certificate's
    validity information. Emitted instead of **NOT\_BEFORE**, **NOT\_AFTER**.

**SUBJECT\_PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract the certificate's
    subject information. Emitted instead of **SUBJECT\_DN**.

**ISSUER\_PARSE\_ERROR**
:   Set to the error that occurred when attempting to extract the certificate's
    issuer information. Emitted instead of **ISSUER\_DN**.

# SEE ALSO

**certspotter**(8), **x509**(1)

# COPYRIGHT

Copyright (c) 2016-2022 Opsmate, Inc.

# BUGS

Report bugs to <https://github.com/SSLmate/certspotter>.
