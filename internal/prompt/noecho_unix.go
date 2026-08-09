//go:build linux || darwin

package prompt

import (
	"fmt"
	"syscall"
	"unsafe"
)

// readNoEcho reads a line from fd with terminal echo disabled.
//
// Echo is a property of the *terminal driver*, not of the program: the kernel is what
// prints your keystrokes back, before the process ever sees them. So hiding a password
// means asking the driver to stop, which is an ioctl on the tty — there is no way to do
// it from inside the program's own I/O.
//
// The dangerous part is restoring it. If the process dies between disabling echo and
// restoring it, the user is left with an invisible shell. Hence the deferred restore,
// and the signal handling in the caller.
func readNoEcho(fd uintptr) ([]byte, error) {
	var before syscall.Termios
	if err := ioctl(fd, ioctlReadTermios, &before); err != nil {
		return nil, fmt.Errorf("prompt: read terminal attributes: %w", err)
	}

	after := before
	after.Lflag &^= syscall.ECHO
	// Keep ECHONL so the newline the user types still moves the cursor down; without it
	// the next output overwrites the prompt line.
	after.Lflag |= syscall.ECHONL

	if err := ioctl(fd, ioctlWriteTermios, &after); err != nil {
		return nil, fmt.Errorf("prompt: disable echo: %w", err)
	}
	defer func() { _ = ioctl(fd, ioctlWriteTermios, &before) }()

	return readLine(fd)
}

// readLine reads one byte at a time. Buffering would be faster and would also read past
// the newline into whatever comes next on the pipe, which for a password prompt means
// swallowing the user's next command.
func readLine(fd uintptr) ([]byte, error) {
	var (
		out [1]byte
		buf []byte
	)
	for {
		n, err := syscall.Read(int(fd), out[:])
		if err != nil {
			return nil, fmt.Errorf("prompt: read: %w", err)
		}
		if n == 0 {
			break // EOF
		}
		switch out[0] {
		case '\n', '\r':
			return buf, nil
		case 0x7f, 0x08: // backspace, in case the terminal is not in canonical mode
			if len(buf) > 0 {
				buf[len(buf)-1] = 0
				buf = buf[:len(buf)-1]
			}
		case 0x03: // Ctrl-C
			return nil, ErrInterrupted
		default:
			buf = append(buf, out[0])
		}
	}
	return buf, nil
}

func ioctl(fd uintptr, req uintptr, t *syscall.Termios) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// isTerminal reports whether fd is a tty, by asking for its attributes: if the ioctl
// succeeds it is a terminal, if it returns ENOTTY it is a pipe or a file.
func isTerminal(fd uintptr) bool {
	var t syscall.Termios
	return ioctl(fd, ioctlReadTermios, &t) == nil
}
