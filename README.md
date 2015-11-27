# h2scan

Scan a list of sites to see which support HTTPS, SPDY/3.1 and
HTTP/2. Outputs a CSV containing information about which protocols are
supported. 

# Usage

To get information about a single site

    $ echo "http2.cloudflare.com" | ./h2scan
    http2.cloudflare.com,t,t,t,t,t,t,t,t,h2 spdy/3.1 http/1.1

h2scan will read lines from an input file and perform multiple tests
concurrently for bulk testing.

# Options

`-workers` sets the number of worker routines performing the
testing. Defaults to 10.

`fields` causes h2scan to output a header line in the CSV containing
field names.

`log` gives the name of a file to which log information will be
written. If given the file is overwritten.
