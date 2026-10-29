package redirect

import (
	"encoding/binary"
	"net/netip"
)

const (
	protoTCP = 6
	protoUDP = 17

	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// packet is a parsed view over a raw IP packet; the slice is not copied.
type packet struct {
	raw      []byte
	v6       bool
	proto    byte
	src, dst netip.Addr
	sport    uint16
	dport    uint16
	l4       int // offset of the TCP/UDP header
	payload  int // offset of the TCP/UDP payload
	frag     bool
}

// parse understands IPv4 and IPv6 packets carrying TCP or UDP with no extension headers.
func parse(b []byte) (packet, bool) {
	p := packet{raw: b}
	if len(b) < 20 {
		return p, false
	}
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 {
			return p, false
		}
		p.proto = b[9]
		p.src = netip.AddrFrom4([4]byte(b[12:16]))
		p.dst = netip.AddrFrom4([4]byte(b[16:20]))
		p.l4 = ihl
		p.frag = binary.BigEndian.Uint16(b[6:8])&0x3fff != 0
	case 6:
		if len(b) < 48 {
			return p, false
		}
		p.v6 = true
		p.proto = b[6]
		p.src = netip.AddrFrom16([16]byte(b[8:24]))
		p.dst = netip.AddrFrom16([16]byte(b[24:40]))
		p.l4 = 40
	default:
		return p, false
	}
	switch p.proto {
	case protoTCP:
		if len(b) < p.l4+20 {
			return p, false
		}
		p.payload = p.l4 + int(b[p.l4+12]>>4)*4
	case protoUDP:
		p.payload = p.l4 + 8
	default:
		return p, false
	}
	if p.payload > len(b) {
		return p, false
	}
	p.sport = binary.BigEndian.Uint16(b[p.l4:])
	p.dport = binary.BigEndian.Uint16(b[p.l4+2:])
	return p, true
}

func (p *packet) tcpFlags() byte { return p.raw[p.l4+13] }

func (p *packet) setSrc(a netip.Addr, port uint16) {
	p.src, p.sport = a, port
	putAddr(p.raw, p.v6, 12, 8, a)
	binary.BigEndian.PutUint16(p.raw[p.l4:], port)
}

func (p *packet) setDst(a netip.Addr, port uint16) {
	p.dst, p.dport = a, port
	putAddr(p.raw, p.v6, 16, 24, a)
	binary.BigEndian.PutUint16(p.raw[p.l4+2:], port)
}

func putAddr(b []byte, v6 bool, off4, off6 int, a netip.Addr) {
	if v6 {
		x := a.As16()
		copy(b[off6:off6+16], x[:])
		return
	}
	x := a.As4()
	copy(b[off4:off4+4], x[:])
}

// buildUDP4 assembles an IPv4/UDP datagram. Checksums are left zero for the caller to fill in.
func buildUDP4(src, dst netip.AddrPort, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(total))
	binary.BigEndian.PutUint16(b[6:], 0x4000) // DF
	b[8] = 64
	b[9] = protoUDP
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:], src.Port())
	binary.BigEndian.PutUint16(b[22:], dst.Port())
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

// buildRST4 answers a TCP segment with RST|ACK so the sender fails immediately.
func buildRST4(in *packet) []byte {
	b := make([]byte, 40)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 40)
	binary.BigEndian.PutUint16(b[6:], 0x4000)
	b[8] = 64
	b[9] = protoTCP
	s, d := in.dst.As4(), in.src.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:], in.dport)
	binary.BigEndian.PutUint16(b[22:], in.sport)
	// TCP header: seq at 24, ack at 28, data offset at 32, flags at 33.
	b[32] = 5 << 4
	if in.tcpFlags()&tcpACK != 0 {
		// Reply to a segment that carries an ACK: RST takes the sequence number it expects next.
		binary.BigEndian.PutUint32(b[24:], binary.BigEndian.Uint32(in.raw[in.l4+8:]))
		b[33] = tcpRST
		return b
	}
	seq := binary.BigEndian.Uint32(in.raw[in.l4+4:])
	segLen := uint32(len(in.raw) - in.payload)
	if in.tcpFlags()&(tcpSYN|tcpFIN) != 0 {
		segLen++
	}
	binary.BigEndian.PutUint32(b[28:], seq+segLen)
	b[33] = tcpRST | tcpACK
	return b
}
