//go:build linux

package traffic

import "syscall"

// These cumulative CPU seconds cover the whole gateway process, including
// diagnostics. A measurement window uses differences between two snapshots.
func processCPU() map[string]any {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return map[string]any{"cpu_measurement_available": false}
	}
	user := float64(usage.Utime.Sec) + float64(usage.Utime.Usec)/1e6
	system := float64(usage.Stime.Sec) + float64(usage.Stime.Usec)/1e6
	return map[string]any{"cpu_measurement_available": true, "cpu_user_seconds": user, "cpu_system_seconds": system, "cpu_total_seconds": user + system, "cpu_boundary": "cumulative CPU seconds for the entire process"}
}
