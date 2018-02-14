// +build windows

package main

/*
 * procattr_windows.go
 * Return a procattr hiding windows
 * By J. Stuart McMurray
 * Created 20180212
 * Last Modified 20180212
 */

import (
	"os/exec"
	"syscall"
)

/* setProcAttr modifies c to hide windows */
func setProcAttr(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
