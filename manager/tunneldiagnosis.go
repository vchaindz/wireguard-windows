/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// DiagnosisOutcome is how a step of testing a tunnel ended.
type DiagnosisOutcome int

const (
	DiagnosisPassed DiagnosisOutcome = iota
	DiagnosisFailed
	DiagnosisSkipped
)

// The steps of testing a tunnel, in the order they run. The identifiers are stable, so that the UI can word
// each step in the user's language; the details are facts, such as addresses and times, not sentences.
const (
	DiagnosisEndpointResolves = "endpoint-resolves"
	DiagnosisHandshake        = "handshake-recent"
	DiagnosisPing             = "tunnel-ping"
	DiagnosisDNS              = "tunnel-dns"
	DiagnosisEndpointRoute    = "endpoint-route"
)

// DiagnosisStep is the result of one step of testing a tunnel.
type DiagnosisStep struct {
	ID      string
	Outcome DiagnosisOutcome
	Detail  string
}

const (
	// Each network operation has a short timeout of its own, so that a whole test takes seconds even when nothing
	// answers.
	diagnosisResolveTimeout = 3 * time.Second
	diagnosisDNSTimeout     = 2 * time.Second
	// A handshake is retried every 5 seconds (REKEY_TIMEOUT), so waiting a little longer sees the first retry.
	diagnosisHandshakeWait = 6 * time.Second
	diagnosisHandshakePoll = 250 * time.Millisecond
	diagnosisPingCount     = 3
	// At most this many host names and DNS servers are tried, so that a long configuration cannot make a test run
	// for minutes.
	diagnosisMostHosts   = 4
	diagnosisMostServers = 3
	// diagnosisMinInterval is how long after a test ends another one of the same tunnel may start.
	diagnosisMinInterval = 5 * time.Second
)

// diagnosisEnv is what the steps need from the system. The manager's implementation talks to the driver and the
// network; tests use a fake one.
type diagnosisEnv interface {
	// resolve looks a host name up with the system's resolver.
	resolve(ctx context.Context, host string) ([]netip.Addr, error)
	// lastHandshakes returns when each peer last completed a handshake, zero for none.
	lastHandshakes() ([]time.Time, error)
	// echo sends one echo request through the tunnel. errProbeLost means it was sent and not answered.
	echo(target netip.Addr, timeout time.Duration) (time.Duration, error)
	// dnsQuery sends one query from the tunnel's address to a DNS server and waits for its answer.
	dnsQuery(server netip.Addr, timeout time.Duration) (time.Duration, error)
	// path describes how the tunnel reaches its peers.
	path() (TunnelPath, error)
	now() time.Time
	sleep(d time.Duration)
}

// millis writes a duration in milliseconds with one decimal, as the details give times.
func millis(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d)/float64(time.Millisecond))
}

// runDiagnosis runs the steps of testing a tunnel in order and returns their results. progress, if set, is
// called with the results so far after each step. target is the address to ping, invalid for none, and
// pingAllowed is false when policy forbids sending pings.
func runDiagnosis(config *conf.Config, target netip.Addr, pingAllowed bool, env diagnosisEnv, progress func([]DiagnosisStep)) []DiagnosisStep {
	var steps []DiagnosisStep
	add := func(step DiagnosisStep) {
		steps = append(steps, step)
		if progress != nil {
			progress(append([]DiagnosisStep(nil), steps...))
		}
	}
	if !pingAllowed {
		target = netip.Addr{}
	}
	add(diagnoseResolve(config, env))
	add(diagnoseHandshake(target, env))
	add(diagnosePing(target, pingAllowed, env))
	add(diagnoseDNS(config, env))
	add(diagnoseRoute(env))
	return steps
}

// diagnoseResolve looks up the host names of the peers' endpoints. Endpoints given as addresses need no lookup.
func diagnoseResolve(config *conf.Config, env diagnosisEnv) DiagnosisStep {
	step := DiagnosisStep{ID: DiagnosisEndpointResolves}
	var hosts, details []string
	seen := make(map[string]bool)
	for i := range config.Peers {
		host := config.Peers[i].Endpoint.Host
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		step.Outcome, step.Detail = DiagnosisSkipped, "no host names"
		return step
	}
	if len(hosts) > diagnosisMostHosts {
		hosts = hosts[:diagnosisMostHosts]
	}
	for _, host := range hosts {
		ctx, cancel := context.WithTimeout(context.Background(), diagnosisResolveTimeout)
		start := env.now()
		addrs, err := env.resolve(ctx, host)
		elapsed := env.now().Sub(start)
		cancel()
		if err == nil && len(addrs) == 0 {
			err = errors.New("no addresses")
		}
		if err != nil {
			step.Outcome = DiagnosisFailed
			if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
				details = append(details, fmt.Sprintf("%s: no answer in %v", host, diagnosisResolveTimeout))
			} else {
				details = append(details, fmt.Sprintf("%s: %v", host, err))
			}
			continue
		}
		parts := make([]string, len(addrs))
		for i := range addrs {
			parts[i] = addrs[i].Unmap().String()
		}
		details = append(details, fmt.Sprintf("%s: %s in %s", host, strings.Join(parts, " "), millis(elapsed)))
	}
	step.Detail = strings.Join(details, "; ")
	return step
}

// newestHandshake is the most recent handshake of any peer, or zero.
func newestHandshake(handshakes []time.Time) time.Time {
	var newest time.Time
	for _, handshake := range handshakes {
		if handshake.After(newest) {
			newest = handshake
		}
	}
	return newest
}

// diagnoseHandshake checks that a peer completed a handshake recently. A tunnel that sent nothing for a while has
// no fresh handshake without anything being wrong, so if there is a target, one echo is sent through the tunnel,
// which makes the driver start a handshake, and the step waits a little for it.
func diagnoseHandshake(target netip.Addr, env diagnosisEnv) DiagnosisStep {
	step := DiagnosisStep{ID: DiagnosisHandshake}
	handshakes, err := env.lastHandshakes()
	if err != nil {
		step.Outcome, step.Detail = DiagnosisFailed, err.Error()
		return step
	}
	if len(handshakes) == 0 {
		step.Outcome, step.Detail = DiagnosisFailed, "no peers"
		return step
	}
	now := env.now()
	newest := newestHandshake(handshakes)
	if !newest.IsZero() && now.Sub(newest) < healthHandshakeFresh {
		step.Detail = fmt.Sprintf("latest %s, %d s ago", newest.UTC().Format(time.RFC3339), int(now.Sub(newest)/time.Second))
		return step
	}
	if target.IsValid() {
		start := env.now()
		env.echo(target, probeTimeout)
		for env.now().Sub(start) < diagnosisHandshakeWait {
			handshakes, err = env.lastHandshakes()
			if err != nil {
				break
			}
			if fresh := newestHandshake(handshakes); fresh.After(newest) {
				step.Detail = fmt.Sprintf("completed %s after sending to %v, %s", fresh.UTC().Format(time.RFC3339), target, millis(env.now().Sub(start)))
				return step
			}
			env.sleep(diagnosisHandshakePoll)
		}
	}
	step.Outcome = DiagnosisFailed
	switch {
	case newest.IsZero() && target.IsValid():
		step.Detail = fmt.Sprintf("never; none within %v after sending to %v", diagnosisHandshakeWait, target)
	case newest.IsZero():
		step.Detail = "never"
	case target.IsValid():
		step.Detail = fmt.Sprintf("latest %s, %d s ago; none within %v after sending to %v", newest.UTC().Format(time.RFC3339), int(now.Sub(newest)/time.Second), diagnosisHandshakeWait, target)
	default:
		step.Detail = fmt.Sprintf("latest %s, %d s ago", newest.UTC().Format(time.RFC3339), int(now.Sub(newest)/time.Second))
	}
	return step
}

// diagnosePing sends a few echo requests through the tunnel to the address that connection quality is measured
// with.
func diagnosePing(target netip.Addr, allowed bool, env diagnosisEnv) DiagnosisStep {
	step := DiagnosisStep{ID: DiagnosisPing}
	if !allowed {
		step.Outcome, step.Detail = DiagnosisSkipped, "disabled by policy"
		return step
	}
	if !target.IsValid() {
		step.Outcome, step.Detail = DiagnosisSkipped, "no address to ping"
		return step
	}
	answered, sent := 0, 0
	var total time.Duration
	var failure error
	for i := 0; i < diagnosisPingCount; i++ {
		rtt, err := env.echo(target, probeTimeout)
		switch err {
		case nil:
			sent++
			answered++
			total += rtt
		case errProbeLost:
			sent++
		default:
			failure = err
		}
		if failure != nil {
			break
		}
	}
	switch {
	case failure != nil && sent == 0:
		step.Outcome, step.Detail = DiagnosisFailed, fmt.Sprintf("%v: %v", target, failure)
	case answered == 0:
		step.Outcome, step.Detail = DiagnosisFailed, fmt.Sprintf("%v: %d sent, 0 answered within %v each", target, sent, probeTimeout)
	default:
		step.Detail = fmt.Sprintf("%v: %d sent, %d answered, average %s", target, sent, answered, millis(total/time.Duration(answered)))
	}
	return step
}

// diagnoseDNS asks each of the tunnel's DNS servers a question, from the tunnel's own address so that the
// question and its answer go through the tunnel. It passes if any server answers, and the details list each.
func diagnoseDNS(config *conf.Config, env diagnosisEnv) DiagnosisStep {
	step := DiagnosisStep{ID: DiagnosisDNS}
	var servers []netip.Addr
	for _, server := range config.Interface.DNS {
		if server.IsValid() && len(servers) < diagnosisMostServers {
			servers = append(servers, server.Unmap())
		}
	}
	if len(servers) == 0 {
		step.Outcome, step.Detail = DiagnosisSkipped, "no DNS servers"
		return step
	}
	var details []string
	answered := false
	for _, server := range servers {
		elapsed, err := env.dnsQuery(server, diagnosisDNSTimeout)
		switch {
		case err == nil:
			answered = true
			details = append(details, fmt.Sprintf("%v: answered in %s", server, millis(elapsed)))
		case errors.Is(err, os.ErrDeadlineExceeded):
			details = append(details, fmt.Sprintf("%v: no answer in %v", server, diagnosisDNSTimeout))
		default:
			details = append(details, fmt.Sprintf("%v: %v", server, err))
		}
	}
	if !answered {
		step.Outcome = DiagnosisFailed
	}
	step.Detail = strings.Join(details, "; ")
	return step
}

// interfaceKindKey names an interface kind in the details.
func interfaceKindKey(kind InterfaceKind) string {
	switch kind {
	case InterfaceKindEthernet:
		return "ethernet"
	case InterfaceKindWiFi:
		return "wifi"
	case InterfaceKindMobile:
		return "mobile"
	}
	return "other"
}

// diagnoseRoute checks that each endpoint in use can be reached by a route outside the tunnel. Without one, the
// packets to the peer could only go into the tunnel itself, which is a routing loop, and the driver drops them.
func diagnoseRoute(env diagnosisEnv) DiagnosisStep {
	step := DiagnosisStep{ID: DiagnosisEndpointRoute}
	path, err := env.path()
	if err != nil {
		step.Outcome, step.Detail = DiagnosisFailed, err.Error()
		return step
	}
	var details []string
	for i := range path.Peers {
		peer := &path.Peers[i]
		if !peer.Address.IsValid() {
			continue
		}
		var detail string
		if peer.NoRoute {
			step.Outcome = DiagnosisFailed
			detail = fmt.Sprintf("%v: no route outside the tunnel", peer.Address)
		} else {
			detail = fmt.Sprintf("%v: via %s (%s, MTU %d)", peer.Address, peer.Carrier, interfaceKindKey(peer.CarrierKind), peer.CarrierMTU)
		}
		if peer.CoveredByTunnel {
			detail += ", tunnel routes cover it"
		}
		details = append(details, detail)
	}
	if len(details) == 0 {
		step.Outcome, step.Detail = DiagnosisSkipped, "no endpoint in use"
		return step
	}
	step.Detail = strings.Join(details, "; ")
	return step
}

// DNS over UDP, as much as a single question needs. It is written out here rather than taken from a package, as
// one question with a fixed name is all there is to it.

const (
	dnsTypeNS   = 2
	dnsClassIN  = 1
	dnsHeader   = 12
	dnsFlagRD   = 0x0100
	dnsFlagQR   = 0x8000
	dnsRcodeMax = 0x000f
)

// dnsQuestion builds a query for the name servers of the root zone, which every recursive server can answer from
// its cache and which names nothing about the user.
func dnsQuestion(id uint16) []byte {
	query := make([]byte, dnsHeader, dnsHeader+5)
	binary.BigEndian.PutUint16(query[0:], id)
	binary.BigEndian.PutUint16(query[2:], dnsFlagRD)
	binary.BigEndian.PutUint16(query[4:], 1) // one question
	query = append(query, 0)                 // the root name
	query = binary.BigEndian.AppendUint16(query, dnsTypeNS)
	query = binary.BigEndian.AppendUint16(query, dnsClassIN)
	return query
}

// errDNSMismatch is a datagram that is not the answer to our question; it is ignored.
var errDNSMismatch = errors.New("not the answer")

// dnsAnswerError checks a datagram for being the answer to the question with the given identifier. A server that
// answers with an error code has still answered, but cannot resolve, which is reported.
func dnsAnswerError(answer []byte, id uint16) error {
	if len(answer) < dnsHeader || binary.BigEndian.Uint16(answer[0:]) != id {
		return errDNSMismatch
	}
	flags := binary.BigEndian.Uint16(answer[2:])
	if flags&dnsFlagQR == 0 {
		return errDNSMismatch
	}
	if rcode := flags & dnsRcodeMax; rcode != 0 {
		return fmt.Errorf("answered with error code %d", rcode)
	}
	return nil
}

// systemDiagnosisEnv runs the steps against the real tunnel.
type systemDiagnosisEnv struct {
	tunnelName string
	luid       winipcfg.LUID
}

func (env *systemDiagnosisEnv) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (env *systemDiagnosisEnv) lastHandshakes() ([]time.Time, error) {
	peers, _, err := readDriverPeers(env.tunnelName)
	if err != nil {
		return nil, err
	}
	handshakes := make([]time.Time, len(peers))
	for i := range peers {
		if peers[i].handshake != 0 {
			// LastHandshake is a FILETIME: 100ns units since 1601.
			handshakes[i] = time.Unix(0, int64((peers[i].handshake-116444736000000000)*100))
		}
	}
	return handshakes, nil
}

func (env *systemDiagnosisEnv) echo(target netip.Addr, timeout time.Duration) (time.Duration, error) {
	source, err := tunnelSourceAddress(env.luid, !target.Is4())
	if err != nil {
		return 0, err
	}
	handle, err := openICMP(!target.Is4())
	if err != nil {
		return 0, err
	}
	defer handle.close()
	return handle.echo(source, target, timeout)
}

func (env *systemDiagnosisEnv) dnsQuery(server netip.Addr, timeout time.Duration) (time.Duration, error) {
	source, err := tunnelSourceAddress(env.luid, !server.Is4())
	if err != nil {
		return 0, err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0)))
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	var idBytes [2]byte
	rand.Read(idBytes[:])
	id := binary.BigEndian.Uint16(idBytes[:])
	start := time.Now()
	conn.SetDeadline(start.Add(timeout))
	if _, err := conn.WriteToUDPAddrPort(dnsQuestion(id), netip.AddrPortFrom(server, 53)); err != nil {
		return 0, err
	}
	var answer [1500]byte
	for {
		n, from, err := conn.ReadFromUDPAddrPort(answer[:])
		if err != nil {
			return 0, err
		}
		if from.Addr().Unmap() != server || from.Port() != 53 {
			continue
		}
		if err := dnsAnswerError(answer[:n], id); err != errDNSMismatch {
			return time.Since(start), err
		}
	}
}

func (env *systemDiagnosisEnv) path() (TunnelPath, error) {
	return tunnelPath(env.tunnelName)
}

func (env *systemDiagnosisEnv) now() time.Time { return time.Now() }

func (env *systemDiagnosisEnv) sleep(d time.Duration) { time.Sleep(d) }

// A diagnosisRun is the latest test of one tunnel: running, or its result.
type diagnosisRun struct {
	running  bool
	finished time.Time
	steps    []DiagnosisStep
	err      string
}

var (
	diagnosisLock sync.Mutex
	diagnosisRuns = make(map[string]*diagnosisRun)
)

var (
	errDiagnosisRunning = errors.New("This tunnel is already being tested")
	errDiagnosisTooSoon = errors.New("This tunnel was tested a moment ago; please wait a few seconds")
	errNotStarted       = errors.New("The tunnel is not active")
	errNoDiagnosis      = errors.New("This tunnel has not been tested")
)

// claimDiagnosis records that a test of the tunnel starts, unless one is running or ended too recently.
func claimDiagnosis(tunnelName string, now time.Time) (*diagnosisRun, error) {
	diagnosisLock.Lock()
	defer diagnosisLock.Unlock()
	if run := diagnosisRuns[tunnelName]; run != nil {
		if run.running {
			return nil, errDiagnosisRunning
		}
		if since := now.Sub(run.finished); since >= 0 && since < diagnosisMinInterval {
			return nil, errDiagnosisTooSoon
		}
	}
	run := &diagnosisRun{running: true}
	diagnosisRuns[tunnelName] = run
	return run, nil
}

// startDiagnosis begins testing a started tunnel in the background. Every target comes from the stored
// configuration and settings of the tunnel; nothing the client sends but the name is used.
func startDiagnosis(tunnelName string) error {
	if !conf.NameExists(tunnelName) {
		return os.ErrNotExist
	}
	if !tunnelStarted(tunnelName) {
		return errNotStarted
	}
	run, err := claimDiagnosis(tunnelName, time.Now())
	if err != nil {
		return err
	}
	go func() {
		steps, err := diagnoseTunnel(tunnelName, func(steps []DiagnosisStep) {
			diagnosisLock.Lock()
			run.steps = steps
			diagnosisLock.Unlock()
		})
		diagnosisLock.Lock()
		run.running, run.finished, run.steps = false, time.Now(), steps
		if err != nil {
			run.err = err.Error()
		}
		diagnosisLock.Unlock()
	}()
	return nil
}

// diagnoseTunnel tests a started tunnel and logs the outcome of each step.
func diagnoseTunnel(tunnelName string, progress func([]DiagnosisStep)) ([]DiagnosisStep, error) {
	config, err := conf.LoadFromName(tunnelName)
	if err != nil {
		return nil, err
	}
	_, luid, err := readDriverPeers(tunnelName)
	if err != nil {
		return nil, err
	}
	allowed := probingAllowed()
	target := probeTarget(config, loadTunnelSettings(tunnelName).ProbeTarget)
	log.Printf("[%s] Testing the tunnel", tunnelName)
	steps := runDiagnosis(config, target, allowed, &systemDiagnosisEnv{tunnelName, luid}, progress)
	for _, step := range steps {
		switch step.Outcome {
		case DiagnosisPassed:
			log.Printf("[%s] Test %s passed: %s", tunnelName, step.ID, step.Detail)
		case DiagnosisFailed:
			log.Printf("[%s] Warning: test %s failed: %s", tunnelName, step.ID, step.Detail)
		case DiagnosisSkipped:
			log.Printf("[%s] Test %s skipped: %s", tunnelName, step.ID, step.Detail)
		}
	}
	return steps, nil
}

// diagnosisResult returns the steps of the latest test of a tunnel that have finished, and whether it still runs.
func diagnosisResult(tunnelName string) (steps []DiagnosisStep, running bool, err error) {
	diagnosisLock.Lock()
	defer diagnosisLock.Unlock()
	run := diagnosisRuns[tunnelName]
	if run == nil {
		return nil, false, errNoDiagnosis
	}
	if run.err != "" {
		err = errors.New(run.err)
	}
	return append([]DiagnosisStep(nil), run.steps...), run.running, err
}
