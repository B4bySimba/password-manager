//go:build linux

package prompt

import "syscall"

// Linux exposes terminal attributes through the TCGETS/TCSETS ioctls.
const (
	ioctlReadTermios  = syscall.TCGETS
	ioctlWriteTermios = syscall.TCSETS
)
