//go:build unix

package transcode

import "syscall"

// lowPriority makes ffmpeg yield to everything else on the machine.
func lowPriority(pid int) { _ = syscall.Setpriority(syscall.PRIO_PROCESS, pid, 19) }
