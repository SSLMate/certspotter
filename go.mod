module software.sslmate.com/src/certspotter

go 1.25.0

require (
	golang.org/x/crypto v0.52.0
	golang.org/x/net v0.55.0
	golang.org/x/sync v0.20.0
	golang.org/x/time v0.15.0
)

require golang.org/x/text v0.37.0 // indirect

retract v0.19.0 // Contains serious bugs.
