// +build !windows

package main

/*
 * procattr_nonwindows.go
 * Return a nil, to be compatible with windows
 * By J. Stuart McMurray
 * Created 20180212
 * Last Modified 20180212
 */

import "os/exec"

/* setProcAttr does nothing */
func setProcAttr(*exec.Cmd) {}
