/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The ICMP helper API of iphlpapi.dll sends echo requests without a raw socket, so it works for any user and is
// not affected by the restrictions Windows puts on raw sockets.
var (
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procIcmpCreateFile  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = modiphlpapi.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = modiphlpapi.NewProc("IcmpSendEcho2Ex")
	procIcmp6SendEcho2  = modiphlpapi.NewProc("Icmp6SendEcho2")

	// Go's clock on Windows advances in timer ticks of up to 15.6 ms, too coarse for round trips, which over a
	// nearby peer take a few milliseconds. The performance counter has sub-microsecond resolution.
	modkernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = modkernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modkernel32.NewProc("QueryPerformanceFrequency")
)

// performanceCounter returns a reading of the performance counter and its frequency. Both calls cannot fail on
// Windows XP and later.
func performanceCounter() (counter, frequency int64) {
	procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&counter)))
	procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&frequency)))
	return
}

// elapsedSince converts the counter difference to a duration, without overflowing for any plausible interval.
func elapsedSince(start int64) time.Duration {
	now, frequency := performanceCounter()
	if frequency <= 0 || now < start {
		return 0
	}
	ticks := now - start
	return time.Duration(ticks/frequency)*time.Second + time.Duration(ticks%frequency)*time.Second/time.Duration(frequency)
}

// IP_STATUS values from ipexport.h that mean the request left the machine and no answer came back. The other
// IP_STATUS values describe local failures, so a probe that ends in one of them was not sent.
const (
	ipSuccess                   = 0
	ipDestNetUnreachable        = 11002
	ipDestHostUnreachable       = 11003
	ipDestProtUnreachable       = 11004
	ipDestPortUnreachable       = 11005
	ipPacketTooBig              = 11009
	ipReqTimedOut               = 11010
	ipTTLExpiredTransit         = 11013
	ipTTLExpiredReassem         = 11014
	ipSourceQuench              = 11016
	ipStatusFirst, ipStatusLast = 11000, 11050
)

func icmpStatusIsLoss(status uint32) bool {
	switch status {
	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable, ipDestPortUnreachable,
		ipPacketTooBig, ipReqTimedOut, ipTTLExpiredTransit, ipTTLExpiredReassem, ipSourceQuench:
		return true
	}
	return false
}

// errProbeLost means that the echo request was sent and no answer arrived in time.
var errProbeLost = errors.New("no reply")

// icmpStatusError is an IP_STATUS that is not a loss, reported as an error.
type icmpStatusError uint32

func (e icmpStatusError) Error() string {
	return "ICMP status " + strconv.FormatUint(uint64(e), 10)
}

// icmpEchoReply is ICMP_ECHO_REPLY from ipexport.h. Its Data and Options.OptionsData members are pointers, which
// uintptr reproduces, so that the layout is 28 bytes on x86 and 40 bytes on amd64 and arm64, like the native
// structure in each process. (ICMP_ECHO_REPLY32 is only for 64-bit code that serves 32-bit callers.)
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// ICMPV6_ECHO_REPLY has no pointers, so it is read from the buffer at fixed offsets instead of through a Go
// structure. Its IPV6_ADDRESS_EX member is packed to 26 bytes in the Windows SDK (an echo to ::1 puts the
// address at offset 6), while mingw-w64's header pads it to 28 bytes; either way the following ULONG Status is
// aligned to offset 28, and RoundTripTime follows. The layout does not depend on the architecture.
const (
	icmpv6EchoReplySize          = 36
	icmpv6EchoReplyStatusOffset  = 28
	icmpv6EchoReplyRoundTripTime = 32
)

// The payload of the echo request: 32 bytes, as Windows' own ping sends.
var icmpRequestData = []byte("WireGuard connection quality....")

// The reply buffer must hold the reply structure, a copy of the request data, 8 bytes for an ICMP error message
// and an IO_STATUS_BLOCK; this has room to spare on every architecture.
const icmpReplyBufferSize = 128 + 32 + 64

type icmpHandle struct {
	handle windows.Handle
	ipv6   bool
}

func openICMP(ipv6 bool) (*icmpHandle, error) {
	proc := procIcmpCreateFile
	if ipv6 {
		proc = procIcmp6CreateFile
	}
	if err := proc.Find(); err != nil {
		return nil, err
	}
	r1, _, e1 := proc.Call()
	if windows.Handle(r1) == windows.InvalidHandle {
		return nil, errnoOr(e1, windows.ERROR_INVALID_HANDLE)
	}
	return &icmpHandle{handle: windows.Handle(r1), ipv6: ipv6}, nil
}

func (h *icmpHandle) close() {
	if h != nil && h.handle != windows.InvalidHandle {
		procIcmpCloseHandle.Call(uintptr(h.handle))
		h.handle = windows.InvalidHandle
	}
}

func errnoOr(e error, fallback error) error {
	if errno, ok := e.(syscall.Errno); ok && errno != 0 {
		return errno
	}
	return fallback
}

// echo sends one echo request from source to target and waits up to timeout for the answer. It returns the
// round-trip time; errProbeLost when the request was sent but not answered; any other error means that nothing
// was sent. The time is measured here with the performance counter rather than taken from the reply, which
// counts in whole milliseconds.
func (h *icmpHandle) echo(source, target netip.Addr, timeout time.Duration) (time.Duration, error) {
	if source.Is4() != target.Is4() || source.Is4() == h.ipv6 {
		return 0, errors.New("address family does not match")
	}
	var reply [icmpReplyBufferSize]byte
	data := icmpRequestData
	timeoutMillis := uintptr(timeout / time.Millisecond)
	var r1 uintptr
	var e1 error
	start, _ := performanceCounter()
	if h.ipv6 {
		src := sockaddrInet6(source)
		dst := sockaddrInet6(target)
		r1, _, e1 = procIcmp6SendEcho2.Call(uintptr(h.handle), 0, 0, 0,
			uintptr(unsafe.Pointer(&src)), uintptr(unsafe.Pointer(&dst)),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), timeoutMillis)
	} else {
		// IPAddr is the address in network byte order, as it lies in memory.
		src4, dst4 := source.As4(), target.As4()
		r1, _, e1 = procIcmpSendEcho2Ex.Call(uintptr(h.handle), 0, 0, 0,
			uintptr(binary.LittleEndian.Uint32(src4[:])), uintptr(binary.LittleEndian.Uint32(dst4[:])),
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
			uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), timeoutMillis)
	}
	elapsed := elapsedSince(start)
	if r1 == 0 {
		errno, _ := e1.(syscall.Errno)
		if uint32(errno) >= ipStatusFirst && uint32(errno) <= ipStatusLast {
			if icmpStatusIsLoss(uint32(errno)) {
				return 0, errProbeLost
			}
			return 0, icmpStatusError(errno)
		}
		return 0, errnoOr(e1, windows.ERROR_GEN_FAILURE)
	}
	var status uint32
	if h.ipv6 {
		status = binary.LittleEndian.Uint32(reply[icmpv6EchoReplyStatusOffset:])
	} else {
		status = (*icmpEchoReply)(unsafe.Pointer(&reply[0])).Status
	}
	switch {
	case status == ipSuccess:
		return elapsed, nil
	case icmpStatusIsLoss(status):
		return 0, errProbeLost
	}
	return 0, icmpStatusError(status)
}

func sockaddrInet6(addr netip.Addr) windows.RawSockaddrInet6 {
	return windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: addr.As16()}
}

// Compile-time checks that the reply buffer can hold the replies on this architecture.
var (
	_ = [icmpReplyBufferSize - int(unsafe.Sizeof(icmpEchoReply{})) - 32 - 8 - 16]byte{}
	_ = [icmpReplyBufferSize - icmpv6EchoReplySize - 32 - 8 - 16]byte{}
)
