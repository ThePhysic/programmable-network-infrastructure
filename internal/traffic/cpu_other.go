//go:build !linux

package traffic

// Linux is the authoritative lab runtime. Other platforms remain buildable
// and explicitly report that the Linux CPU measurement is unavailable.
func processCPU() map[string]any { return map[string]any{"cpu_measurement_available": false} }
