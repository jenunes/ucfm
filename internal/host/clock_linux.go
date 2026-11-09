//go:build linux

package host

import "golang.org/x/sys/unix"

// Linux adjtimex constants (include/uapi/linux/timex.h).
const (
	staUnsync = 0x0040 // STA_UNSYNC: clock not synchronized
	timeError = 5      // TIME_ERROR: clock not synchronized
)

// clockSynced asks the kernel whether NTP/chrony/timesyncd keeps the clock
// synchronized. nil means unknown.
func clockSynced() *bool {
	if Root != "/" {
		return fakeClock()
	}
	var tx unix.Timex
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return nil
	}
	ok := state != timeError && tx.Status&staUnsync == 0
	return &ok
}
