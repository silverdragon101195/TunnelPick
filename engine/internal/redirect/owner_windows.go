package redirect

import (
	"net/netip"
	"syscall"
	"unsafe"
)

var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procGetTCPTable     = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetUDPTable     = iphlpapi.NewProc("GetExtendedUdpTable")
	tcpTableOwnerPIDAll = uintptr(5)
	udpTableOwnerPID    = uintptr(1)
)

const (
	afInet  = 2
	afInet6 = 23
)

// ownerPID returns the process that owns the socket a packet was sent from.
// The socket exists in the table before its first packet leaves, so this works
// while the packet is still held by the redirector.
func ownerPID(tcp bool, local netip.Addr, lport uint16, remote netip.Addr, rport uint16) (uint32, bool) {
	v6 := !local.Unmap().Is4()
	table := fetchTable(tcp, v6)
	if len(table) < 4 {
		return 0, false
	}
	count := int(*(*uint32)(unsafe.Pointer(&table[0])))
	body := table[4:]

	var rowSize int
	switch {
	case tcp && !v6:
		rowSize = 24
	case tcp && v6:
		rowSize = 56
	case !tcp && !v6:
		rowSize = 12
	default:
		rowSize = 28
	}
	if len(body) < count*rowSize {
		count = len(body) / rowSize
	}

	var fallback uint32
	for i := 0; i < count; i++ {
		row := body[i*rowSize : (i+1)*rowSize]
		var rl, rr netip.Addr
		var rlp, rrp uint16
		var pid uint32
		switch {
		case tcp && !v6:
			rl = addr4(row[4:8])
			rlp = port(row[8:12])
			rr = addr4(row[12:16])
			rrp = port(row[16:20])
			pid = le32(row[20:24])
		case tcp && v6:
			rl = addr6(row[0:16])
			rlp = port(row[20:24])
			rr = addr6(row[24:40])
			rrp = port(row[44:48])
			pid = le32(row[52:56])
		case !tcp && !v6:
			rl = addr4(row[0:4])
			rlp = port(row[4:8])
			pid = le32(row[8:12])
		default:
			rl = addr6(row[0:16])
			rlp = port(row[20:24])
			pid = le32(row[24:28])
		}
		if rlp != lport {
			continue
		}
		if !rl.IsUnspecified() && rl != local.Unmap() && rl != local {
			continue
		}
		if tcp {
			if rr == remote.Unmap() || rr == remote {
				if rrp == rport {
					return pid, true
				}
			}
			fallback = pid
			continue
		}
		return pid, true
	}
	if fallback != 0 {
		return fallback, true
	}
	return 0, false
}

func fetchTable(tcp, v6 bool) []byte {
	af := uintptr(afInet)
	if v6 {
		af = afInet6
	}
	proc, class := procGetUDPTable, udpTableOwnerPID
	if tcp {
		proc, class = procGetTCPTable, tcpTableOwnerPIDAll
	}
	size := uint32(32 * 1024)
	for attempt := 0; attempt < 5; attempt++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, af, class, 0)
		switch r {
		case 0:
			return buf[:size]
		case 122: // ERROR_INSUFFICIENT_BUFFER: size now holds the required length
			size += 4096
		default:
			return nil
		}
	}
	return nil
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// port decodes a DWORD holding a network-order port in its low 16 bits.
func port(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}) }

func addr6(b []byte) netip.Addr {
	var a [16]byte
	copy(a[:], b)
	return netip.AddrFrom16(a)
}
