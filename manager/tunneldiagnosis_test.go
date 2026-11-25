/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
)

// fakeDiagnosisEnv answers the steps from fields, with a clock that only sleeping and echoes advance.
type fakeDiagnosisEnv struct {
	clock      time.Time
	resolved   map[string][]netip.Addr
	handshakes []time.Time
	// handshakeAfterEcho, if set, is given to the first peer once an echo was sent.
	handshakeAfterEcho bool
	echoes             []error
	echoed             int
	dnsAnswers         map[netip.Addr]error
	tunnelPath         TunnelPath
	pathErr            error
	calls              []string
}

func (env *fakeDiagnosisEnv) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	env.calls = append(env.calls, "resolve "+host)
	addrs, ok := env.resolved[host]
	if !ok {
		return nil, errors.New("host not found")
	}
	return addrs, nil
}

func (env *fakeDiagnosisEnv) lastHandshakes() ([]time.Time, error) {
	return env.handshakes, nil
}

func (env *fakeDiagnosisEnv) echo(target netip.Addr, timeout time.Duration) (time.Duration, error) {
	env.calls = append(env.calls, "echo "+target.String())
	env.clock = env.clock.Add(20 * time.Millisecond)
	if env.handshakeAfterEcho && len(env.handshakes) > 0 {
		env.handshakes[0] = env.clock.Add(time.Second)
		env.handshakeAfterEcho = false
	}
	var err error
	if env.echoed < len(env.echoes) {
		err = env.echoes[env.echoed]
	}
	env.echoed++
	if err != nil {
		env.clock = env.clock.Add(timeout)
		return 0, err
	}
	return 20 * time.Millisecond, nil
}

func (env *fakeDiagnosisEnv) dnsQuery(server netip.Addr, timeout time.Duration) (time.Duration, error) {
	env.calls = append(env.calls, "dns "+server.String())
	if err, ok := env.dnsAnswers[server]; ok {
		return 12 * time.Millisecond, err
	}
	return 0, os.ErrDeadlineExceeded
}

func (env *fakeDiagnosisEnv) path() (TunnelPath, error) {
	env.calls = append(env.calls, "path")
	return env.tunnelPath, env.pathErr
}

func (env *fakeDiagnosisEnv) now() time.Time { return env.clock }

func (env *fakeDiagnosisEnv) sleep(d time.Duration) { env.clock = env.clock.Add(d) }

func diagnosisTestConfig() *conf.Config {
	config := &conf.Config{Name: "office"}
	config.Interface.DNS = []netip.Addr{netip.MustParseAddr("10.8.0.1"), netip.MustParseAddr("10.8.0.2")}
	config.Peers = []conf.Peer{
		{PublicKey: conf.Key{1}, Endpoint: conf.Endpoint{Host: "vpn.example.com", Port: 51820}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}},
		{PublicKey: conf.Key{2}, Endpoint: conf.Endpoint{Host: "198.51.100.7", Port: 51820}},
	}
	return config
}

func healthyDiagnosisEnv(now time.Time) *fakeDiagnosisEnv {
	return &fakeDiagnosisEnv{
		clock:      now,
		resolved:   map[string][]netip.Addr{"vpn.example.com": {netip.MustParseAddr("192.0.2.10")}},
		handshakes: []time.Time{now.Add(-42 * time.Second), {}},
		dnsAnswers: map[netip.Addr]error{netip.MustParseAddr("10.8.0.1"): nil},
		tunnelPath: TunnelPath{Peers: []PeerPath{{Peer: 0, Address: netip.MustParseAddrPort("192.0.2.10:51820"), Carrier: "Wi-Fi", CarrierKind: InterfaceKindWiFi, CarrierMTU: 1500}}},
	}
}

func outcomes(steps []DiagnosisStep) string {
	var parts []string
	for _, step := range steps {
		parts = append(parts, step.ID+"="+[]string{"pass", "fail", "skip"}[step.Outcome])
	}
	return strings.Join(parts, " ")
}

func TestDiagnosisSequence(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	target := netip.MustParseAddr("10.8.0.1")
	env := healthyDiagnosisEnv(now)
	var progress []int
	steps := runDiagnosis(diagnosisTestConfig(), target, true, env, func(steps []DiagnosisStep) { progress = append(progress, len(steps)) })
	if got, want := outcomes(steps), "endpoint-resolves=pass handshake-recent=pass tunnel-ping=pass tunnel-dns=pass endpoint-route=pass"; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if len(progress) != 5 || progress[0] != 1 || progress[4] != 5 {
		t.Errorf("progress: %v", progress)
	}
	// The literal endpoint is not looked up; the ping comes after the handshake check, which needed no echo.
	if got, want := strings.Join(env.calls, ", "), "resolve vpn.example.com, echo 10.8.0.1, echo 10.8.0.1, echo 10.8.0.1, dns 10.8.0.1, dns 10.8.0.2, path"; got != want {
		t.Errorf("calls: %s\nwant %s", got, want)
	}
	if steps[0].Detail != "vpn.example.com: 192.0.2.10 in 0.0 ms" {
		t.Errorf("resolve detail: %q", steps[0].Detail)
	}
	if steps[1].Detail != "latest 2026-03-10T11:59:18Z, 42 s ago" {
		t.Errorf("handshake detail: %q", steps[1].Detail)
	}
	if steps[2].Detail != "10.8.0.1: 3 sent, 3 answered, average 20.0 ms" {
		t.Errorf("ping detail: %q", steps[2].Detail)
	}
	// One of two DNS servers answering is enough, and the one that did not is named.
	if steps[3].Detail != "10.8.0.1: answered in 12.0 ms; 10.8.0.2: no answer in 2s" {
		t.Errorf("DNS detail: %q", steps[3].Detail)
	}
	if steps[4].Detail != "192.0.2.10:51820: via Wi-Fi (wifi, MTU 1500)" {
		t.Errorf("route detail: %q", steps[4].Detail)
	}
}

func TestDiagnosisFailures(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	target := netip.MustParseAddr("10.8.0.1")

	// Nothing answers: the name does not resolve, the handshake is old and does not renew, pings are lost, DNS
	// is silent, and the only route to the endpoint goes through the tunnel.
	env := healthyDiagnosisEnv(now)
	env.resolved = nil
	env.handshakes = []time.Time{now.Add(-10 * time.Minute), {}}
	env.echoes = []error{errProbeLost, errProbeLost, errProbeLost, errProbeLost}
	env.dnsAnswers = nil
	env.tunnelPath.Peers[0] = PeerPath{Address: netip.MustParseAddrPort("192.0.2.10:51820"), NoRoute: true, CoveredByTunnel: true}
	steps := runDiagnosis(diagnosisTestConfig(), target, true, env, nil)
	if got, want := outcomes(steps), "endpoint-resolves=fail handshake-recent=fail tunnel-ping=fail tunnel-dns=fail endpoint-route=fail"; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	if !strings.Contains(steps[1].Detail, "none within 6s after sending to 10.8.0.1") {
		t.Errorf("handshake detail: %q", steps[1].Detail)
	}
	if env.clock.Sub(now) < diagnosisHandshakeWait {
		t.Errorf("waited %v for a handshake", env.clock.Sub(now))
	}
	if steps[2].Detail != "10.8.0.1: 3 sent, 0 answered within 900ms each" {
		t.Errorf("ping detail: %q", steps[2].Detail)
	}
	if steps[4].Detail != "192.0.2.10:51820: no route outside the tunnel, tunnel routes cover it" {
		t.Errorf("route detail: %q", steps[4].Detail)
	}

	// A tunnel that was idle gets its handshake once the echo makes the driver start one.
	env = healthyDiagnosisEnv(now)
	env.handshakes = []time.Time{now.Add(-10 * time.Minute), {}}
	env.handshakeAfterEcho = true
	steps = runDiagnosis(diagnosisTestConfig(), target, true, env, nil)
	if steps[1].Outcome != DiagnosisPassed || !strings.HasPrefix(steps[1].Detail, "completed ") {
		t.Errorf("triggered handshake: %+v", steps[1])
	}

	// An echo that cannot be sent at all is a failure with its reason, after one try.
	env = healthyDiagnosisEnv(now)
	env.echoes = []error{errNoTunnelAddress}
	steps = runDiagnosis(diagnosisTestConfig(), target, true, env, nil)
	if steps[2].Outcome != DiagnosisFailed || steps[2].Detail != "10.8.0.1: the tunnel has no address of this family" || env.echoed != 1 {
		t.Errorf("unsendable echo: %+v after %d echoes", steps[2], env.echoed)
	}

	// Some answers are enough.
	env = healthyDiagnosisEnv(now)
	env.echoes = []error{errProbeLost, nil, errProbeLost}
	if steps = runDiagnosis(diagnosisTestConfig(), target, true, env, nil); steps[2].Outcome != DiagnosisPassed {
		t.Errorf("partly answered: %+v", steps[2])
	}

	// A server that answers with an error has answered, but cannot resolve.
	env = healthyDiagnosisEnv(now)
	env.dnsAnswers = map[netip.Addr]error{netip.MustParseAddr("10.8.0.1"): errors.New("answered with error code 2")}
	if steps = runDiagnosis(diagnosisTestConfig(), target, true, env, nil); steps[3].Outcome != DiagnosisFailed {
		t.Errorf("DNS error code: %+v", steps[3])
	}
}

func TestDiagnosisSkips(t *testing.T) {
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	config := &conf.Config{Name: "literal"}
	config.Peers = []conf.Peer{{PublicKey: conf.Key{1}, Endpoint: conf.Endpoint{Host: "198.51.100.7", Port: 51820}}}
	env := healthyDiagnosisEnv(now)
	env.tunnelPath = TunnelPath{}
	steps := runDiagnosis(config, netip.Addr{}, true, env, nil)
	if got, want := outcomes(steps), "endpoint-resolves=skip handshake-recent=pass tunnel-ping=skip tunnel-dns=skip endpoint-route=skip"; got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
	for _, call := range env.calls {
		if !strings.HasPrefix(call, "path") {
			t.Errorf("unexpected call %q", call)
		}
	}

	// Policy that forbids pings also keeps the handshake check from sending one.
	env = healthyDiagnosisEnv(now)
	env.handshakes = []time.Time{{}, {}}
	steps = runDiagnosis(diagnosisTestConfig(), netip.MustParseAddr("10.8.0.1"), false, env, nil)
	if steps[1].Outcome != DiagnosisFailed || steps[1].Detail != "never" || steps[2].Outcome != DiagnosisSkipped || steps[2].Detail != "disabled by policy" {
		t.Errorf("forbidden pings: %+v %+v", steps[1], steps[2])
	}
	for _, call := range env.calls {
		if strings.HasPrefix(call, "echo") {
			t.Errorf("an echo was sent although policy forbids it")
		}
	}
}

func TestDiagnosisClaims(t *testing.T) {
	const name = "diagnosis-claim-test"
	t.Cleanup(func() {
		diagnosisLock.Lock()
		delete(diagnosisRuns, name)
		diagnosisLock.Unlock()
	})
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	run, err := claimDiagnosis(name, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claimDiagnosis(name, now.Add(time.Minute)); err != errDiagnosisRunning {
		t.Errorf("second test while one runs: %v", err)
	}
	diagnosisLock.Lock()
	run.running, run.finished = false, now.Add(10*time.Second)
	diagnosisLock.Unlock()
	if _, err := claimDiagnosis(name, now.Add(12*time.Second)); err != errDiagnosisTooSoon {
		t.Errorf("test right after the last: %v", err)
	}
	if _, err := claimDiagnosis(name, now.Add(10*time.Second+diagnosisMinInterval)); err != nil {
		t.Errorf("test after waiting: %v", err)
	}
}

func TestDNSQuestion(t *testing.T) {
	query := dnsQuestion(0xbeef)
	want := []byte{0xbe, 0xef, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if string(query) != string(want) {
		t.Fatalf("query % x", query)
	}
	answer := append([]byte(nil), query...)
	answer[2] |= 0x80
	if err := dnsAnswerError(answer, 0xbeef); err != nil {
		t.Errorf("answer: %v", err)
	}
	if err := dnsAnswerError(answer, 0xbeee); err != errDNSMismatch {
		t.Errorf("other identifier: %v", err)
	}
	if err := dnsAnswerError(query, 0xbeef); err != errDNSMismatch {
		t.Errorf("a query taken for an answer: %v", err)
	}
	answer[3] |= 2
	if err := dnsAnswerError(answer, 0xbeef); err == nil || err == errDNSMismatch {
		t.Errorf("error code: %v", err)
	}
	if err := dnsAnswerError(answer[:5], 0xbeef); err != errDNSMismatch {
		t.Errorf("short datagram: %v", err)
	}
}
