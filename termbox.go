// +build !windows

package termbox

import "unicode/utf8"

import "bytes"
import "syscall"
import "unsafe"
import "strings"
import "strconv"
import "os"
import "io"

// private API

const (
	t_enter_ca = iota
	t_exit_ca
	t_show_cursor
	t_hide_cursor
	t_clear_screen
	t_sgr0
	t_underline
	t_bold
	t_blink
	t_reverse
	t_enter_keypad
	t_exit_keypad
	t_enter_mouse
	t_exit_mouse
	t_max_funcs
)

const (
	coord_invalid = -2
	attr_invalid  = Attribute(0xFFFFFF)
)

type input_event struct {
	data []byte
	err  error
}

var (
	// term specific sequences
	keys  []string
	funcs []string

	// termbox inner state
	orig_tios       syscall_Termios
	back_buffer     cellbuf
	front_buffer    cellbuf
	termw           int
	termh           int
	input_mode      = InputEsc
	out             *os.File
	in              int
	lastfg          = attr_invalid
	lastbg          = attr_invalid
	lastx           = coord_invalid
	lasty           = coord_invalid
	cursor_x        = cursor_hidden
	cursor_y        = cursor_hidden
	foreground      = ColorDefault
	background      = ColorDefault
	inbuf           = make([]byte, 0, 64)
	outbuf          bytes.Buffer
	sigwinch        = make(chan os.Signal, 1)
	sigio           = make(chan os.Signal, 1)
	quit            = make(chan int)
	input_comm      = make(chan input_event)
	intbuf          = make([]byte, 0, 16)
	extended_colors = false
)

func write_cursor(x, y int) {
	outbuf.WriteString("\033[")
	outbuf.Write(strconv.AppendUint(intbuf, uint64(y+1), 10))
	outbuf.WriteString(";")
	outbuf.Write(strconv.AppendUint(intbuf, uint64(x+1), 10))
	outbuf.WriteString("H")
}

func write_sgr_fg(a Attribute) {
	if extended_colors {
		outbuf.WriteString("\033[38;5;")
	} else {
		outbuf.WriteString("\033[3")
	}
	outbuf.Write(strconv.AppendUint(intbuf, uint64(a), 10))
	outbuf.WriteString("m")
}

func write_sgr_bg(a Attribute) {
	if extended_colors {
		outbuf.WriteString("\033[48;5;")
	} else {
		outbuf.WriteString("\033[4")
	}
	outbuf.Write(strconv.AppendUint(intbuf, uint64(a), 10))
	outbuf.WriteString("m")
}

func write_sgr(fg, bg Attribute) {
	if extended_colors {
		outbuf.WriteString("\033[38;5;")
	} else {
		outbuf.WriteString("\033[3")
	}
	outbuf.Write(strconv.AppendUint(intbuf, uint64(fg), 10))
	if extended_colors {
		outbuf.WriteString(";48;5;")
	} else {
		outbuf.WriteString(";4")
	}
	outbuf.Write(strconv.AppendUint(intbuf, uint64(bg), 10))
	outbuf.WriteString("m")
}

type winsize struct {
	rows    uint16
	cols    uint16
	xpixels uint16
	ypixels uint16
}

func get_term_size(fd uintptr) (int, int) {
	var sz winsize
	_, _, _ = syscall.Syscall(syscall.SYS_IOCTL,
		fd, uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&sz)))
	return int(sz.cols), int(sz.rows)
}

func send_attr(fg, bg Attribute) {
	if fg != lastfg || bg != lastbg {
		outbuf.WriteString(funcs[t_sgr0])
		fgcol := fg & 0xFF
		bgcol := bg & 0xFF
		if fgcol != ColorDefault {
			if bgcol != ColorDefault {
				write_sgr(fgcol, bgcol)
			} else {
				write_sgr_fg(fgcol)
			}
		} else if bgcol != ColorDefault {
			write_sgr_bg(bgcol)
		}

		if fg&AttrBold != 0 {
			outbuf.WriteString(funcs[t_bold])
		}
		if bg&AttrBold != 0 {
			outbuf.WriteString(funcs[t_blink])
		}
		if fg&AttrUnderline != 0 {
			outbuf.WriteString(funcs[t_underline])
		}
		if fg&AttrReverse|bg&AttrReverse != 0 {
			outbuf.WriteString(funcs[t_reverse])
		}

		lastfg, lastbg = fg, bg
	}
}

func send_char(x, y int, ch rune) {
	var buf [8]byte
	n := utf8.EncodeRune(buf[:], ch)
	if x-1 != lastx || y != lasty {
		write_cursor(x, y)
	}
	lastx, lasty = x, y
	outbuf.Write(buf[:n])
}

func flush() error {
	_, err := io.Copy(out, &outbuf)
	outbuf.Reset()
	if err != nil {
		return err
	}
	return nil
}

func send_clear() error {
	send_attr(foreground, background)
	outbuf.WriteString(funcs[t_clear_screen])
	if !is_cursor_hidden(cursor_x, cursor_y) {
		write_cursor(cursor_x, cursor_y)
	}

	// we need to invalidate cursor position too and these two vars are
	// used only for simple cursor positioning optimization, cursor
	// actually may be in the correct place, but we simply discard
	// optimization once and it gives us simple solution for the case when
	// cursor moved
	lastx = coord_invalid
	lasty = coord_invalid

	return flush()
}

func update_size_maybe() error {
	w, h := get_term_size(out.Fd())
	if w != termw || h != termh {
		termw, termh = w, h
		back_buffer.resize(termw, termh)
		front_buffer.resize(termw, termh)
		front_buffer.clear()
		return send_clear()
	}
	return nil
}

func tcsetattr(fd uintptr, termios *syscall_Termios) error {
	r, _, e := syscall.Syscall(syscall.SYS_IOCTL,
		fd, uintptr(syscall_TCSETS), uintptr(unsafe.Pointer(termios)))
	if r != 0 {
		return os.NewSyscallError("SYS_IOCTL", e)
	}
	return nil
}

func tcgetattr(fd uintptr, termios *syscall_Termios) error {
	r, _, e := syscall.Syscall(syscall.SYS_IOCTL,
		fd, uintptr(syscall_TCGETS), uintptr(unsafe.Pointer(termios)))
	if r != 0 {
		return os.NewSyscallError("SYS_IOCTL", e)
	}
	return nil
}

func parse_escape_sequence(event *Event, buf []byte) (int, bool) {
	bufstr := string(buf)
	// mouse
	mode := 0
	x := 0
	y := 0
	consumed := 0
	mouse := false
	if len(bufstr) >= 9 && strings.HasPrefix(bufstr, "\033[<") {
		// SGR format : http://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-Extended-coordinates
		consumed = 3
		event.MouseBtnState = MouseBtnUp
		v := 0
		idx := 0
		for _, c := range bufstr[3:] {
			consumed++
			switch c {
			case 'm':
				y = v - 1
				break
			case 'M':
				event.MouseBtnState = MouseBtnDown
				y = v - 1
				break
			case ';':
				if idx == 0 {
					mode = v
					idx++
				} else {
					x = v - 1
				}
				v = 0
			default:
				v = v*10 + int(c) - 48
			}
		}
		mouse = true
	} else if len(bufstr) >= 6 && strings.HasPrefix(bufstr, "\033[M") {
		// X10 format : http://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-X10-compatbility-mode
		mode = int(buf[3]) - 32
		x = int(buf[4]) - 1 - 32
		y = int(buf[5]) - 1 - 32
		if x < 0 {
			x += 255
		}
		if y < 0 {
			y += 255
		}
		mouse = true
		consumed = 6
	}
	if mouse {
		wheel := mode&64 == 64
		event.DragOn = mode&32 == 32
		switch mode & 3 {
		case 0: // left
			if wheel {
				event.Key = MouseScrollUp
			} else {
				event.Key = MouseLeft
			}
		case 1: // middle
			if wheel {
				event.Key = MouseScrollDown
			} else {
				event.Key = MouseMiddle
			}
		case 2: // right
			event.Key = MouseRight
		case 3: // other unhandled
			return consumed, false
		}
		event.Type = EventMouse // KeyEvent by default
		event.MouseX = x
		event.MouseY = y
		return consumed, true
	}

	for i, key := range keys {
		if strings.HasPrefix(bufstr, key) {
			event.Ch = 0
			event.Key = Key(0xFFFF - i)
			return len(key), true
		}
		if parseMetaKey(bufstr, key, event) {
			event.Key = Key(0xFFFF - i)
			return len(key) + 2, true
		}
		if key[1] == 79 { // 'O'
			// For some crazy reason xterm sends LeftArrow as [27,79,68]
			// but Shift+LeftArrow as [27,91,49,59,50,68]
			// the extra [59, 50] was expected but not the [79] -> [91,49]
			// Basically seems to be sent in SS3 format in the first case
			// but in CSI format in the second !
			// http://invisible-island.net/xterm/ctlseqs/ctlseqs.html#h2-PC-Style-Function-Keys
			k2 := []byte{key[0]}
			k2 = append(k2, 91, 49) // '[', '1'
			k2 = append(k2, key[2:]...)
			if parseMetaKey(bufstr, string(k2), event) {
				event.Key = Key(0xFFFF - i)
				return len(k2) + 2, true
			}
		}
	}
	return 0, true
}

// function key modifiers which are parameters appended before the
// final character of the control sequence.
func parseMetaKey(bufstr, key string, event *Event) bool {
	kl := len(key)
	if len(bufstr) < kl+2 {
		return false
	}
	if !strings.HasPrefix(bufstr, key[:kl-2]) {
		return false
	}
	if bufstr[kl-1] != ';' {
		return false
	}
	if bufstr[kl] < 50 || bufstr[kl] > 57 { // 2 to 9 ASCII
		return false
	}
	if bufstr[kl+1] != key[kl-1] {
		return false
	}

	event.Ch = 0
	event.Meta = KeyMeta(bufstr[kl] - 48)
	return true
}

func extract_event(event *Event) bool {
	if len(inbuf) == 0 {
		return false
	}
	if inbuf[0] == '\033' {
		// possible escape sequence
		n, ok := parse_escape_sequence(event, inbuf)
		if n != 0 {
			copy(inbuf, inbuf[n:])
			inbuf = inbuf[:len(inbuf)-n]
			return ok
		}
	}

	if len(inbuf) > 1 {
		if inbuf[0] == 27 {
			event.Mod = ModAlt
		}
		inbuf = inbuf[1:]
	}
	k := Key(inbuf[0])

	// scpecial key (esc, del, ctrl combination ...)
	if k < KeySpace || k == KeyBackspace2 {
		event.Key = Key(inbuf[0])
		event.Ch = 0
		copy(inbuf, inbuf[1:])
		inbuf = inbuf[:len(inbuf)-1]
		return true
	}
	// rune
	if r, n := utf8.DecodeRune(inbuf); r != utf8.RuneError {
		event.Ch = r
		event.Key = 0
		copy(inbuf, inbuf[n:])
		inbuf = inbuf[:len(inbuf)-n]
		return true
	}
	return false
}

func fcntl(fd int, cmd int, arg int) (val int, err error) {
	r, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), uintptr(cmd),
		uintptr(arg))
	val = int(r)
	if e != 0 {
		err = e
	}
	return
}
