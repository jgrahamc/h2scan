package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/amahi/spdy"
	"golang.org/x/net/http2"
	"io/ioutil"
	"jgcrypto/tls"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// in returns true is s is one of the strings in list
func in(list []string, s string) bool {
	for _, t := range list {
		if s == t {
			return true
		}
	}

	return false
}

// tri captures a tri-state. The value of yesno is true only is ran is
// true
type tri struct {
	ran   bool
	yesno bool
}

func (t tri) String() string {
	switch {
	case !t.ran:
		return "-"
	case t.yesno:
		return "t"
	case !t.yesno:
		return "f"
	}

	// Should not be reached ever

	return "!"
}

// site is a web site identified by its DNS name along with the state
// of various tests performed on the site. The states are only filled
// in if test() is called on the site.
type site struct {
	name string        // DNS name of the web site

	resolves       tri // Whether the name resolves
	port443Open    tri // Whether port 443 is open via TCP
	tlsWorks       tri // Whether a TLS connection works
	httpsWorks     tri // Whether an HTTPS request works using HTTP/1.1
	spdyAnnounced  tri // Whether spdy/3.1 is announced using NPN
	http2Announced tri // Whether h2 is announced using NPN
	spdyWorks      tri // Whether a SPDY/3.1 request works
	http2Works     tri // Whether an HTTP/2 request works
	
	npn            []string // List of protocols advertised by server using NPN
}

// test tests a site to see if it supports various protocols
func (s *site) test(l *os.File) {

	// Check the name resolves, give up if it does not

	s.resolves.ran = true
	_, err := net.LookupHost(s.name)
	if err != nil {
		s.logf(l, "Error resolving name: %s", err)
		s.resolves.yesno = false
		return
	}
	s.resolves.yesno = true

	// See if port 443 is open, give up if it is not

	hostPort := net.JoinHostPort(s.name, "443")
	
	s.port443Open.ran = true
	c, err := net.DialTimeout("tcp", hostPort, 2 * time.Second)
	if err != nil {
		s.logf(l, "TCP dial to port 443 failed: %s", err)
		s.port443Open.yesno = false
		return
	}
	c.Close()
	s.port443Open.yesno = true

	// See if TLS works and if SPDY/3.1 or HTTP/2 offered. Give up if
	// TLS does not work. If the name doesn't work try adding www.  to
	// se if it's a TLS certificate error.

	s.tlsWorks.ran = true
	config := &tls.Config{}
	config.ServerName = s.name
	tc, err := tls.Dial("tcp", hostPort, config)
	if err != nil {
		s.name = "www." + s.name
		config.ServerName = s.name
		hostPort = net.JoinHostPort(s.name, "443")
		tc, err = tls.Dial("tcp", hostPort, config)
		if err != nil {
			s.logf(l, "Error performing TLS connection: %s", err)
			s.tlsWorks.yesno = false
			return
		}
	}
	s.tlsWorks.yesno = true

	// Retrieve the list of NPN offered protocols and check for
	// spdy/3.1 and h2
	
	cs := tc.ConnectionState()
	s.npn = cs.OfferedProtocols
	s.spdyAnnounced.ran = true
	s.spdyAnnounced.yesno = in(cs.OfferedProtocols, "spdy/3.1")
	s.http2Announced.ran = true
	s.http2Announced.yesno = in(cs.OfferedProtocols, "h2")
	tc.Close()

	// See if HTTPS works by performing GET /

	s.httpsWorks.ran = true
	resp, err := http.Get("https://" + s.name)
	if err != nil {
		s.logf(l, "HTTP request failed: %s", err)
		return
	}
	if resp != nil && resp.Body != nil {
		_, _ = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}
	s.httpsWorks.yesno = err == nil

	// See if SPDY works by doing GET / over SPDY

	if s.spdyAnnounced.yesno {
		s.spdyWorks.ran = true
		conf := &tls.Config{}
		conf.NextProtos = []string{"spdy/3.1"}
		spdyC, err := tls.Dial("tcp", hostPort, conf)
		if err == nil {
			defer spdyC.Close()
			cs = spdyC.ConnectionState()
			if cs.NegotiatedProtocol != "spdy/3.1" {
				s.logf(l, "NegotiatedProtocol not spdy/3.1: %s",
					cs.NegotiatedProtocol)
			} else {
				sc, err := spdy.NewClientConn(spdyC)
				if err == nil {
					defer sc.Close()
					req, _ := http.NewRequest("GET", "https://"+s.name, nil)
					resp, err := sc.Do(req)
					if err != nil {
						s.logf(l, "Failed to do SPDY request: %s", err)
					}
					s.spdyWorks.yesno = err == nil
					if resp != nil && resp.Body != nil {
						_, _ = ioutil.ReadAll(resp.Body)
						resp.Body.Close()
					}
				} else {
					s.logf(l, "Failed create SPDY client connection: %s", err)
				}
			}
		} else {
			s.logf(l, "Failed to dial port 443 for SPDY: %s", err)
		}
	}

	// See if HTTP/2 works by doing GET / using HTTP/2

	if s.http2Announced.yesno {
		s.http2Works.ran = true
		conf := &tls.Config{}
		conf.NextProtos = []string{"h2"}
		h2C, err := tls.Dial("tcp", hostPort, conf)
		if err == nil {
			defer h2C.Close()
			cs = h2C.ConnectionState()
			if cs.NegotiatedProtocol != "h2" {
				s.logf(l, "NegotiatedProtocol not h2: %s",
					cs.NegotiatedProtocol)
			} else {
				h2t := &http2.Transport{}
				h2c, err := h2t.NewClientConn(h2C)
				if err == nil {
					req, _ := http.NewRequest("GET", "https://"+s.name, nil)
					resp, err := h2c.RoundTrip(req)
					if err != nil {
						s.logf(l, "HTTP/2 RoundTrip failed: %s", err)
					}
					s.http2Works.yesno = err == nil
					if resp != nil && resp.Body != nil {
						_, _ = ioutil.ReadAll(resp.Body)
						resp.Body.Close()
					}
				} else {
					s.logf(l, "Failed create HTTP/2 client connection: %s", err)
				}
				h2t.CloseIdleConnections()
			}
		} else {
			s.logf(l, "Failed to dial port 443 for HTTP/2: %s", err)
		}
	}
}

// logf writes to the log file prefixing with the name of the site
// being logged
func (s *site) logf(f *os.File, format string, a ...interface{}) {
	if f != nil {
		fmt.Fprintf(f, fmt.Sprintf(s.name + ": " + format + "\n", a...))
	}
}

// fields returns the list of fields that String() will return for a
// site
func (s *site) fields() string {
	return "name,resolves,port443Open,tlsWorks,httpsWorks,spdyAnnounced,http2Announced,spdyWorks,http2Works,npn"
}

func (s *site) String() string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
		s.name, s.resolves, s.port443Open, s.tlsWorks, s.httpsWorks,
		s.spdyAnnounced, s.http2Announced, s.spdyWorks, s.http2Works,
		strings.Join(s.npn, " "))
}

var wg sync.WaitGroup

func worker(work, result chan *site, l *os.File) {
	for s := range work {
		s.test(l)
		result <- s
	}
	wg.Done()
}

func writer(result chan *site, stop chan struct{}, fields bool) {
	first := true
	for s := range result {
		if fields && first {
			fmt.Printf("%s\n", s.fields())
			first = false
		}
		
		fmt.Printf("%s\n", s)
	}
	close(stop)
}

func main() {

	// The SPDY library is chatty so discard its log statements
	
	spdy.SetLog(ioutil.Discard)

	fields := flag.Bool("fields", false,
		"If set outputs a header line containing field names")
	workers := flag.Int("workers", 10, "Number of concurrent workers")
	log := flag.String("log", "", "File to write log information to")
	flag.Parse()

	if *workers < 1 {
		fmt.Printf("-workers must be a positive number\n")
		return
	}

	var l *os.File
	var err error
	if *log != "" {
		if l, err = os.Create(*log); err != nil {
			fmt.Printf("Failed to create log file %s: %s\n", *log, err)
			return
		}
		defer l.Close()
	}
	
	work := make(chan *site)
	result := make(chan *site)
	stop := make(chan struct{})

	go writer(result, stop, *fields)

	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(work, result, l)
	}

	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		work <- &site{name: scan.Text()}
	}

	close(work)
	wg.Wait()
	close(result)
	<-stop

	if scan.Err() != nil {
		fmt.Printf("Error reading input: %s\n", scan.Err())
		return
	}
}
