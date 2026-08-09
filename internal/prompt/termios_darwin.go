//go:build darwin

package prompt

import "syscall"

// The BSDs, macOS included, name the same ioctls differently.
const (
	ioctlReadTermios  = syscall.TIOCGETA
	ioctlWriteTermios = syscall.TIOCSETA
)
