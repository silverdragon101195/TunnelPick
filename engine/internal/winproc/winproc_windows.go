// Package winproc resolves a PID to a verifiable process identity on Windows.
package winproc

import (
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/silverdragon101195/TunnelPick/engine/internal/policy"
)

// Cache implements policy.Resolver. Every Lookup re-reads the process start time, so a
// recycled PID is never mistaken for the process that used to own it.
type Cache struct{}

const processCommandLineInformation = 60

func (Cache) Lookup(pid uint32) (policy.Proc, bool) {
	if pid == 0 {
		return policy.Proc{}, false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return policy.Proc{}, false
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return policy.Proc{}, false
	}
	p := policy.Proc{PID: pid, Created: uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)}

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		p.Path = windows.UTF16ToString(buf[:size])
	}

	var pbi windows.PROCESS_BASIC_INFORMATION
	var n uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &n); err == nil {
		p.Parent = uint32(pbi.InheritedFromUniqueProcessId)
	}

	p.Cmd = commandLine(h)
	return p, true
}

// commandLine reads the process command line; it returns "" when it cannot be read.
func commandLine(h windows.Handle) string {
	var need uint32
	// First call reports the required size (STATUS_INFO_LENGTH_MISMATCH is expected).
	windows.NtQueryInformationProcess(h, processCommandLineInformation, nil, 0, &need)
	if need == 0 || need > 1<<20 {
		return ""
	}
	buf := make([]byte, need)
	if err := windows.NtQueryInformationProcess(h, processCommandLineInformation,
		unsafe.Pointer(&buf[0]), need, &need); err != nil {
		return ""
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Length == 0 || us.Buffer == nil {
		return ""
	}
	chars := unsafe.Slice(us.Buffer, int(us.Length/2))
	return string(utf16.Decode(chars))
}
