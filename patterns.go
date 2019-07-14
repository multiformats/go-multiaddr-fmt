package mafmt

import (
	"strings"

	ma "github.com/multiformats/go-multiaddr"
	madns "github.com/multiformats/go-multiaddr-dns"
)

// Define a dns4 format multiaddr
var DNS4 = Base(madns.P_DNS4)

// Define a dns6 format multiaddr
var DNS6 = Base(madns.P_DNS6)

// Define a dnsaddr, dns4 or dns6 format multiaddr
var DNS = Or(
	Base(madns.P_DNSADDR),
	DNS4,
	DNS6,
)

// Define IP as either ipv4 or ipv6
var IP = Or(Base(ma.P_IP4), Base(ma.P_IP6))

// Define TCP as 'tcp' on top of either ipv4 or ipv6, or dns equivalents.
var TCP = Or(
	And(DNS, Base(ma.P_TCP)),
	And(IP, Base(ma.P_TCP)),
)

// Define UDP as 'udp' on top of either ipv4 or ipv6, or dns equivalents.
var UDP = Or(
	And(DNS, Base(ma.P_UDP)),
	And(IP, Base(ma.P_UDP)),
)

// Define UTP as 'utp' on top of udp (on top of ipv4 or ipv6).
var UTP = And(UDP, Base(ma.P_UTP))

// Define QUIC as 'quic' on top of udp (on top of ipv4 or ipv6)
var QUIC = And(UDP, Base(ma.P_QUIC))

// Define garlic32 (i2p hashed) as it self
var GARLIC32 = Base(ma.P_GARLIC32)

// Define garlic64 (i2p destination) as it self
var GARLIC64 = Base(ma.P_GARLIC64)

// Define garlic (i2p destination or hashed) as any of garlic32 or garlic64
var GARLIC = Or(GARLIC64, GARLIC32)

// Define sam3 as tcp or udp and sam3
// Sam3 have a special case, he can't be used to connect to other peers but his
// instance allow to listen and connect garlic
var SAM3 = And(Or(TCP, UDP), Base(ma.P_SAM3))

// Define unreliable transport as udp or sam3
var Unreliable = Or(UDP)

// Now define a Reliable transport as either tcp or utp or quic or garlic
var Reliable = Or(TCP, UTP, QUIC, GARLIC)

// IPFS can run over any reliable underlying transport protocol
var IPFS = And(Reliable, Base(ma.P_IPFS))

// Define http over TCP or DNS or http over DNS format multiaddr
var HTTP = Or(
	And(TCP, Base(ma.P_HTTP)),
	And(IP, Base(ma.P_HTTP)),
	And(DNS, Base(ma.P_HTTP)),
)

// Define https over TCP or DNS or https over DNS format multiaddr
var HTTPS = Or(
	And(TCP, Base(ma.P_HTTPS)),
	And(IP, Base(ma.P_HTTPS)),
	And(DNS, Base(ma.P_HTTPS)),
)

// Define p2p-webrtc-direct over HTTP or p2p-webrtc-direct over HTTPS format multiaddr
var WebRTCDirect = Or(
	And(HTTP, Base(ma.P_P2P_WEBRTC_DIRECT)),
	And(HTTPS, Base(ma.P_P2P_WEBRTC_DIRECT)))

const (
	or  = iota
	and = iota
)

func And(ps ...Pattern) Pattern {
	return &pattern{
		Op:   and,
		Args: ps,
	}
}

func Or(ps ...Pattern) Pattern {
	return &pattern{
		Op:   or,
		Args: ps,
	}
}

type Pattern interface {
	Matches(ma.Multiaddr) bool
	partialMatch([]ma.Protocol) (bool, []ma.Protocol)
	String() string
}

type pattern struct {
	Args []Pattern
	Op   int
}

func (ptrn *pattern) Matches(a ma.Multiaddr) bool {
	ok, rem := ptrn.partialMatch(a.Protocols())
	return ok && len(rem) == 0
}

func (ptrn *pattern) partialMatch(pcs []ma.Protocol) (bool, []ma.Protocol) {
	switch ptrn.Op {
	case or:
		for _, a := range ptrn.Args {
			ok, rem := a.partialMatch(pcs)
			if ok {
				return true, rem
			}
		}
		return false, nil
	case and:
		if len(pcs) < len(ptrn.Args) {
			return false, nil
		}

		for i := 0; i < len(ptrn.Args); i++ {
			ok, rem := ptrn.Args[i].partialMatch(pcs)
			if !ok {
				return false, nil
			}

			pcs = rem
		}

		return true, pcs
	default:
		panic("unrecognized pattern operand")
	}
}

func (ptrn *pattern) String() string {
	var sub []string
	for _, a := range ptrn.Args {
		sub = append(sub, a.String())
	}

	switch ptrn.Op {
	case and:
		return strings.Join(sub, "/")
	case or:
		return "{" + strings.Join(sub, "|") + "}"
	default:
		panic("unrecognized pattern op!")
	}
}

type Base int

func (p Base) Matches(a ma.Multiaddr) bool {
	pcs := a.Protocols()
	return pcs[0].Code == int(p) && len(pcs) == 1
}

func (p Base) partialMatch(pcs []ma.Protocol) (bool, []ma.Protocol) {
	if len(pcs) == 0 {
		return false, nil
	}
	if pcs[0].Code == int(p) {
		return true, pcs[1:]
	}
	return false, nil
}

func (p Base) String() string {
	return ma.ProtocolWithCode(int(p)).Name
}
