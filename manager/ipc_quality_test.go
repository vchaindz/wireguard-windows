/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package manager

import (
	"bytes"
	"encoding/gob"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// connectTestClient serves a ManagerService over in-memory pipes and points the IPC client at it, so that the
// order of what client and server encode is checked end to end.
func connectTestClient(t *testing.T, service *ManagerService) {
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()
	done := make(chan struct{})
	go func() {
		service.ServeConn(serverReader, serverWriter)
		close(done)
	}()
	rpcMutex.Lock()
	rpcEncoder, rpcDecoder = gob.NewEncoder(clientWriter), gob.NewDecoder(clientReader)
	rpcMutex.Unlock()
	t.Cleanup(func() {
		clientWriter.Close()
		serverWriter.Close()
		<-done
	})
}

func TestIPCQualityMethods(t *testing.T) {
	service := &ManagerService{}
	connectTestClient(t, service)

	const name = "ipc-quality-test"
	trackedTunnelsLock.Lock()
	history := newSampleHistory()
	trackedTunnelsSamples[name] = history
	for s := 0; s < 130; s++ {
		history.add(TunnelSample{Time: sec(s), RxBytes: uint64(s), Health: TunnelHealthConnected, Probed: s%2 == 0, ProbesSent: 1, LatencyMicros: 5000})
	}
	trackedTunnelsLock.Unlock()
	t.Cleanup(func() {
		trackedTunnelsLock.Lock()
		delete(trackedTunnelsSamples, name)
		trackedTunnelsLock.Unlock()
	})

	tunnel := &Tunnel{name}
	samples, err := tunnel.Samples(SampleResolutionSecond, sec(120))
	if err != nil || len(samples) != 9 || samples[0].RxBytes != 121 || !samples[0].Time.Equal(sec(121)) {
		t.Fatalf("seconds: got %d samples, %v", len(samples), err)
	}
	minutes, err := tunnel.Samples(SampleResolutionMinute, time.Time{})
	if err != nil || len(minutes) != 2 || minutes[1].RxBytes != 119 || minutes[1].ProbesSent != 30 {
		t.Fatalf("minutes: got %+v, %v", minutes, err)
	}
	if _, err := tunnel.Samples(SampleResolution(9), time.Time{}); err == nil {
		t.Fatal("unknown resolution accepted")
	}
	none, err := (&Tunnel{"not-started"}).Samples(SampleResolutionSecond, time.Time{})
	if err != nil || len(none) != 0 {
		t.Fatalf("tunnel that is not started: got %d samples, %v", len(none), err)
	}

	// The service has no elevated token, as for the limited-operator UI.
	if err := tunnel.SetSettings(TunnelSettings{Probe: true}); err == nil || err.Error() != windows.ERROR_ACCESS_DENIED.Error() {
		t.Fatalf("limited operator set settings: got %v", err)
	}
	if _, _, err := (&Tunnel{`..\x`}).Settings(); err == nil {
		t.Fatal("settings of an invalid name returned")
	}

	if err := IPCClientWatch(true); err != nil {
		t.Fatal(err)
	}
	// A request after the hint makes sure the server has handled it.
	tunnel.Samples(SampleResolutionSecond, time.Now())
	if interval, _ := sampleInterval(); interval != healthSampleIntervalWatched {
		t.Fatalf("interval %v while watching", interval)
	}
}

func TestIPCWatchEndsWithConnection(t *testing.T) {
	clientReader, serverWriter := io.Pipe()
	serverReader, clientWriter := io.Pipe()
	done := make(chan struct{})
	go func() {
		(&ManagerService{}).ServeConn(serverReader, serverWriter)
		close(done)
	}()
	encoder := gob.NewEncoder(clientWriter)
	encoder.Encode(WatchMethodType)
	encoder.Encode(true)
	encoder.Encode(GlobalStateMethodType)
	var state TunnelState
	gob.NewDecoder(clientReader).Decode(&state)
	if interval, _ := sampleInterval(); interval != healthSampleIntervalWatched {
		t.Fatalf("interval %v while watching", interval)
	}
	clientWriter.Close()
	<-done
	if interval, _ := sampleInterval(); interval != healthSampleIntervalIdle {
		t.Fatalf("interval %v after the connection ended", interval)
	}
}

func TestIPCHistoryMethods(t *testing.T) {
	if !historyAllowed() {
		t.Skip("connection history is disabled by policy on this computer")
	}
	root := historyTestRoot(t)
	const name = "ipc-history-test"
	if err := os.WriteFile(filepath.Join(root, "Configurations", name+".conf.dpapi"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var recorder historyRecorder
	clock := newHistoryClock("2026-03-10T12:00:00Z")
	clock.observe(&recorder, 0, 0, TunnelHealthConnected)
	clock.step(5 * time.Second)
	clock.observe(&recorder, 1000, 2000, TunnelHealthConnected)
	clock.step(5 * time.Second)
	recorder.stop(clock.wall, clock.mono)
	clock.step(time.Minute)
	clock.observe(&recorder, 0, 0, TunnelHealthConnected)
	tunnelHistoriesLock.Lock()
	tunnelHistories[name] = &recorder
	tunnelHistoriesLock.Unlock()
	withTunnelMetrics(name, func(r *metricsRecorder) {
		r.metrics.LastActiveEnd, r.metrics.LastActiveDuration = clock.wall, time.Minute
	})
	t.Cleanup(func() {
		tunnelHistoriesLock.Lock()
		delete(tunnelHistories, name)
		tunnelHistoriesLock.Unlock()
		trackedTunnelsLock.Lock()
		delete(trackedTunnelsMetrics, name)
		trackedTunnelsLock.Unlock()
	})

	// The limited-operator UI reads history but cannot clear it.
	connectTestClient(t, &ManagerService{})
	tunnel := &Tunnel{name}
	history, enabled, err := tunnel.History()
	if err != nil || !enabled || len(history.Sessions) != 2 || len(history.Days) != 1 {
		t.Fatalf("history: %+v, %v, %v", history, enabled, err)
	}
	if s := history.Sessions[0]; s.RxBytes != 1000 || s.TxBytes != 2000 || s.ActiveSeconds != 10 || s.EndedBy != SessionDeactivated || s.Endpoint != "vpn.example.com:51820" || !s.Start.Equal(newHistoryClock("2026-03-10T12:00:00Z").wall) {
		t.Errorf("first session: %+v", s)
	}
	if history.Sessions[1].EndedBy != SessionInProgress {
		t.Errorf("current session: %+v", history.Sessions[1])
	}
	if _, _, err := (&Tunnel{"not-a-tunnel"}).History(); err == nil {
		t.Error("history of a tunnel that does not exist returned")
	}
	if _, _, err := (&Tunnel{`..\x`}).History(); err == nil {
		t.Error("history of an invalid name returned")
	}
	if err := tunnel.ClearHistory(); err == nil || err.Error() != windows.ERROR_ACCESS_DENIED.Error() {
		t.Fatalf("limited operator clear: got %v", err)
	}

	// An administrator clears it, and when the tunnel was last active goes with it.
	connectTestClient(t, &ManagerService{elevatedToken: windows.Token(1)})
	if err := (&Tunnel{"not-a-tunnel"}).ClearHistory(); err == nil {
		t.Error("history of a tunnel that does not exist cleared")
	}
	if err := tunnel.ClearHistory(); err != nil {
		t.Fatal(err)
	}
	history, enabled, err = tunnel.History()
	if err != nil || !enabled || len(history.Sessions) != 1 || history.Sessions[0].ActiveSeconds != 0 || len(history.Days) != 0 {
		t.Fatalf("after clearing: %+v, %v, %v", history, enabled, err)
	}
	if metrics := trackedTunnelMetrics(name); !metrics.LastActiveEnd.IsZero() {
		t.Errorf("last active kept after clearing: %v", metrics.LastActiveEnd)
	}
}

func TestIPCPathAndDiagnosis(t *testing.T) {
	root := historyTestRoot(t)
	const name = "ipc-diagnosis-test"
	if err := os.WriteFile(filepath.Join(root, "Configurations", name+".conf.dpapi"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		diagnosisLock.Lock()
		delete(diagnosisRuns, name)
		diagnosisLock.Unlock()
	})
	// Both are open to the limited-operator UI.
	connectTestClient(t, &ManagerService{})
	tunnel := &Tunnel{name}

	// A tunnel that is not started has an empty path and cannot be tested.
	path, err := tunnel.Path()
	if err != nil || len(path.Peers) != 0 || path.TunnelMTU != 0 {
		t.Fatalf("path of a stopped tunnel: %+v, %v", path, err)
	}
	if _, err := (&Tunnel{"not-a-tunnel"}).Path(); err == nil {
		t.Error("path of a tunnel that does not exist returned")
	}
	if _, err := (&Tunnel{`..\x`}).Path(); err == nil {
		t.Error("path of an invalid name returned")
	}
	if _, err := tunnel.Diagnose(); err == nil || err.Error() != errNotStarted.Error() {
		t.Errorf("test of a stopped tunnel: %v", err)
	}
	if _, err := (&Tunnel{"not-a-tunnel"}).Diagnose(); err == nil {
		t.Error("a tunnel that does not exist was tested")
	}
	if _, _, err := tunnel.diagnosis(); err == nil || err.Error() != errNoDiagnosis.Error() {
		t.Errorf("result before any test: %v", err)
	}

	// The result of a test travels with its steps in order, and says whether the test still runs.
	diagnosisLock.Lock()
	diagnosisRuns[name] = &diagnosisRun{running: true, steps: []DiagnosisStep{
		{ID: DiagnosisEndpointResolves, Outcome: DiagnosisSkipped, Detail: "no host names"},
		{ID: DiagnosisHandshake, Outcome: DiagnosisFailed, Detail: "never"},
	}}
	diagnosisLock.Unlock()
	trackedTunnelsLock.Lock()
	tunnelHealthMonitors[name] = &tunnelHealthMonitor{}
	trackedTunnelsLock.Unlock()
	t.Cleanup(func() {
		trackedTunnelsLock.Lock()
		delete(tunnelHealthMonitors, name)
		trackedTunnelsLock.Unlock()
	})
	steps, running, err := tunnel.diagnosis()
	if err != nil || !running || len(steps) != 2 || steps[1].ID != DiagnosisHandshake || steps[1].Outcome != DiagnosisFailed || steps[1].Detail != "never" {
		t.Fatalf("result: %+v, %v, %v", steps, running, err)
	}
	if _, err := tunnel.Diagnose(); err == nil || err.Error() != errDiagnosisRunning.Error() {
		t.Errorf("a second test while one runs: %v", err)
	}
}

func TestIPCPathRoundTrip(t *testing.T) {
	// The path is encoded by gob, which must carry the endpoint addresses.
	want := TunnelPath{TunnelMTU: 1420, RoutesAllTraffic: true, Peers: []PeerPath{
		{Peer: 1, Endpoint: "vpn.example.com:51820", Address: netip.MustParseAddrPort("[2001:db8::7]:51820"), Carrier: "Wi-Fi", CarrierKind: InterfaceKindWiFi, CarrierMTU: 1500, CoveredByTunnel: true},
		{Peer: 2, Endpoint: "gone.example.com:51820", NoRoute: true},
	}}
	var buffer bytes.Buffer
	if err := gob.NewEncoder(&buffer).Encode(want); err != nil {
		t.Fatal(err)
	}
	var got TunnelPath
	if err := gob.NewDecoder(&buffer).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TunnelMTU != want.TunnelMTU || !got.RoutesAllTraffic || len(got.Peers) != 2 || got.Peers[0] != want.Peers[0] || got.Peers[1] != want.Peers[1] {
		t.Errorf("got %+v", got)
	}
}
