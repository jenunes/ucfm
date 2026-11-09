//go:build !linux

package host

func clockSynced() *bool {
	if Root != "/" {
		return fakeClock()
	}
	return nil
}
