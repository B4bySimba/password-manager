//go:build !linux && !darwin

package prompt

import (
	"fmt"
	"os"
)

// On platforms whose terminal handling is not implemented here, refuse rather than read
// a password with echo on. Printing a master password to the screen because a build tag
// did not match is exactly the kind of silent downgrade this project avoids elsewhere.
func readNoEcho(uintptr) ([]byte, error) {
	return nil, fmt.Errorf("prompt: no-echo input is not implemented on this platform; set %s instead", EnvPassword)
}

func isTerminal(fd uintptr) bool { return fd == os.Stdin.Fd() }
