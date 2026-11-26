/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"

	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/l18n"
	"golang.zx2c4.com/wireguard/windows/manager"
	"golang.zx2c4.com/wireguard/windows/ringlogger"
	"golang.zx2c4.com/wireguard/windows/version"
)

// A diagnostics file is one text file about one tunnel that a person can send to whoever helps them, with what is
// known about the tunnel and the log lines about it. It is written in fixed English words, like the history export,
// so that whoever reads it can, whatever the language of the computer it came from. It never holds private or
// preshared keys, and the addresses in it are replaced by placeholders unless the person chooses to include them.

// diagnosticsInput is everything a diagnostics file is made of, gathered on the UI thread.
type diagnosticsInput struct {
	now                                     time.Time
	appVersion, driverVersion, osName, arch string
	entry                                   tunnelEntry
	samples                                 tunnelSamples
	diagnosis                               *tunnelDiagnosis
	logLines                                []ringlogger.FollowLine
}

// shortKey is the beginning of a public key, enough to tell keys apart and to find the peer on the server.
func shortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8] + "…"
}

func healthKey(health manager.TunnelHealth) string {
	switch health {
	case manager.TunnelHealthUnverified:
		return "unverified"
	case manager.TunnelHealthConnected:
		return "connected"
	case manager.TunnelHealthNoConnection:
		return "no_connection"
	case manager.TunnelHealthWaitingForPeer:
		return "waiting_for_peer"
	case manager.TunnelHealthNoConnectionNetworkBlocked:
		return "network_cut_off"
	}
	return "unknown"
}

func stateKey(state manager.TunnelState) string {
	switch state {
	case manager.TunnelStarted:
		return "active"
	case manager.TunnelStopped:
		return "inactive"
	case manager.TunnelStarting:
		return "activating"
	case manager.TunnelStopping:
		return "deactivating"
	}
	return "unknown"
}

func timelineStateKey(state timelineState) string {
	switch state {
	case timelineConnected:
		return "connected"
	case timelineUnverified:
		return "unverified"
	case timelineWaiting:
		return "waiting_for_peer"
	case timelineNoConnection:
		return "no_connection"
	case timelineCutOff:
		return "network_cut_off"
	}
	return "no_data"
}

func outcomeKey(outcome manager.DiagnosisOutcome) string {
	switch outcome {
	case manager.DiagnosisPassed:
		return "passed"
	case manager.DiagnosisFailed:
		return "failed"
	}
	return "skipped"
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}

// endpointHost is the host of an endpoint written as host:port, without brackets.
func endpointHost(endpoint string) string {
	if i := strings.LastIndexByte(endpoint, ':'); i > 0 {
		endpoint = endpoint[:i]
	}
	return strings.TrimSuffix(strings.TrimPrefix(endpoint, "["), "]")
}

// summarizeSamples writes what a series of samples shows without listing them: their span, the time spent in each
// state, and the events and probes in it.
func summarizeSamples(w io.Writer, title string, samples []manager.TunnelSample, maxGap time.Duration) {
	if len(samples) == 0 {
		fmt.Fprintf(w, "%s: none\n", title)
		return
	}
	first, last := samples[0].Time, samples[len(samples)-1].Time
	fmt.Fprintf(w, "%s: %d from %s to %s\n", title, len(samples), stamp(first), stamp(last))
	var durations [timelineStateCount]time.Duration
	for _, segment := range healthSegments(samples, first, last.Add(time.Nanosecond), maxGap) {
		durations[segment.state] += segment.end.Sub(segment.start)
	}
	var parts []string
	for state := timelineState(0); state < timelineStateCount; state++ {
		if durations[state] > 0 {
			parts = append(parts, fmt.Sprintf("%s %s", timelineStateKey(state), durations[state].Round(time.Second)))
		}
	}
	fmt.Fprintf(w, "  time by state: %s\n", strings.Join(parts, ", "))
	var handshakes, sent, lost, conflict, unstable int
	for i := range samples {
		handshakes += int(samples[i].Handshakes)
		if samples[i].Probed {
			sent += int(samples[i].ProbesSent)
			lost += int(samples[i].ProbesLost)
		}
		if samples[i].ConflictSuspected {
			conflict++
		}
		if samples[i].Unstable {
			unstable++
		}
	}
	reconnects := 0
	for _, bucket := range timelineBuckets(samples, first, last.Sub(first)+time.Nanosecond, 1, maxGap) {
		reconnects += bucket.reconnects
	}
	fmt.Fprintf(w, "  handshakes: %d, reconnects: %d, samples with key conflict warning: %d, samples with unstable warning: %d\n", handshakes, reconnects, conflict, unstable)
	if sent > 0 {
		fmt.Fprintf(w, "  probes: %d sent, %d lost\n", sent, lost)
	}
	if rx, tx := counterGrowth(samples); rx+tx > 0 {
		fmt.Fprintf(w, "  traffic: %d bytes received, %d bytes sent\n", rx, tx)
	}
}

// counterGrowth adds up how much the byte counters grew over samples, starting afresh where they went backwards.
func counterGrowth(samples []manager.TunnelSample) (rx, tx uint64) {
	for i := 1; i < len(samples); i++ {
		if samples[i].RxBytes >= samples[i-1].RxBytes && samples[i].TxBytes >= samples[i-1].TxBytes {
			rx += samples[i].RxBytes - samples[i-1].RxBytes
			tx += samples[i].TxBytes - samples[i-1].TxBytes
		}
	}
	return
}

// collectDiagnostics writes the diagnostics file of a tunnel, before any address is replaced, and returns it with
// the host names it holds, which are to be hidden like addresses. Keys are written shortened from the start; the
// interface's own key is not written at all, since showing even its public half would mean reading the private one.
func collectDiagnostics(in *diagnosticsInput) (text string, hosts []string) {
	var b strings.Builder
	entry := &in.entry
	name := entry.tunnel.Name
	addHost := func(host string) {
		if host == "" {
			return
		}
		if _, err := netip.ParseAddr(host); err == nil {
			return
		}
		hosts = append(hosts, host)
	}

	fmt.Fprintf(&b, "WireGuard diagnostics\n")
	fmt.Fprintf(&b, "Written: %s\n", stamp(in.now))
	fmt.Fprintf(&b, "App version: %s\nDriver version: %s\nOperating system: %s\nArchitecture: %s\n", in.appVersion, in.driverVersion, in.osName, in.arch)

	fmt.Fprintf(&b, "\n[Tunnel]\n")
	fmt.Fprintf(&b, "Name: %s\nState: %s\n", name, stateKey(entry.state))
	if entry.state == manager.TunnelStarted {
		fmt.Fprintf(&b, "Health: %s\nKey conflict suspected: %v\nUnstable: %v\n", healthKey(entry.health), entry.conflictSuspected, entry.unstable)
	}

	m := &entry.metrics
	fmt.Fprintf(&b, "\n[Metrics]\n")
	fmt.Fprintf(&b, "Active since: %s\nConnected since: %s\n", stamp(m.ActiveSince), stamp(m.ConnectedSince))
	fmt.Fprintf(&b, "Last active end: %s\nLast active duration: %s\n", stamp(m.LastActiveEnd), m.LastActiveDuration.Round(time.Second))
	fmt.Fprintf(&b, "Connection failures: %d\nReconnects: %d\n", m.ConnectionFailures, m.Reconnects)
	fmt.Fprintf(&b, "Interface errors: %d in, %d out\nDropped packets: %d in, %d out\n", m.InErrors, m.OutErrors, m.InDiscards, m.OutDiscards)

	if entry.settingsLoaded {
		s := &entry.settings
		fmt.Fprintf(&b, "\n[Settings]\n")
		fmt.Fprintf(&b, "Measure connection quality: %v (allowed by policy: %v)\n", s.Probe, entry.probingAllowed)
		target := s.ProbeTarget
		if target == "" {
			target = "automatic"
		}
		fmt.Fprintf(&b, "Address to measure: %s\nFavorite: %v\nColor: %s\n", target, s.Favorite, s.Color)
	}

	if c := entry.config; c != nil {
		fmt.Fprintf(&b, "\n[Configuration]\n")
		fmt.Fprintf(&b, "Addresses: %s\n", joinStrings(c.Interface.Addresses))
		if c.Interface.ListenPort > 0 {
			fmt.Fprintf(&b, "Listen port: %d\n", c.Interface.ListenPort)
		}
		if c.Interface.MTU > 0 {
			fmt.Fprintf(&b, "MTU: %d\n", c.Interface.MTU)
		}
		fmt.Fprintf(&b, "DNS servers: %s\n", joinStrings(c.Interface.DNS))
		if len(c.Interface.DNSSearch) > 0 {
			fmt.Fprintf(&b, "DNS search domains: %s\n", strings.Join(c.Interface.DNSSearch, ", "))
			for _, domain := range c.Interface.DNSSearch {
				addHost(domain)
			}
		}
		fmt.Fprintf(&b, "Table off: %v\nRoutes all traffic: %v\n", c.Interface.TableOff, c.RoutesAllTraffic())
		for i := range c.Peers {
			peer := &c.Peers[i]
			fmt.Fprintf(&b, "Peer %d:\n", i+1)
			fmt.Fprintf(&b, "  Public key: %s\n", shortKey(peer.PublicKey.String()))
			fmt.Fprintf(&b, "  Allowed IPs: %s\n", joinStrings(peer.AllowedIPs))
			if !peer.Endpoint.IsEmpty() {
				fmt.Fprintf(&b, "  Endpoint: %s\n", peer.Endpoint.String())
				addHost(peer.Endpoint.Host)
			}
			if peer.PersistentKeepalive > 0 {
				fmt.Fprintf(&b, "  Persistent keepalive: %d\n", peer.PersistentKeepalive)
			}
			if !peer.LastHandshakeTime.IsEmpty() {
				fmt.Fprintf(&b, "  Latest handshake: %s\n", stamp(time.Unix(0, int64(peer.LastHandshakeTime))))
			}
			if peer.RxBytes+peer.TxBytes > 0 {
				fmt.Fprintf(&b, "  Transfer: %d bytes received, %d bytes sent\n", peer.RxBytes, peer.TxBytes)
			}
		}
	}

	if entry.pathLoaded {
		p := &entry.path
		fmt.Fprintf(&b, "\n[Path]\n")
		fmt.Fprintf(&b, "Tunnel MTU: %d\nRoutes all traffic: %v\n", p.TunnelMTU, p.RoutesAllTraffic)
		for i := range p.Peers {
			peer := &p.Peers[i]
			fmt.Fprintf(&b, "Peer %d:\n  Endpoint: %s\n", peer.Peer+1, peer.Endpoint)
			addHost(endpointHost(peer.Endpoint))
			if peer.Address.IsValid() {
				family := "IPv4"
				if peer.IPv6() {
					family = "IPv6"
				}
				fmt.Fprintf(&b, "  Address in use: %s (%s)\n", peer.Address, family)
			}
			if peer.NoRoute {
				fmt.Fprintf(&b, "  Carried by: no route outside the tunnel\n")
			} else {
				fmt.Fprintf(&b, "  Carried by: %s (%s), MTU %d\n", peer.Carrier, interfaceKindKey(peer.CarrierKind), peer.CarrierMTU)
			}
			fmt.Fprintf(&b, "  Tunnel routes cover endpoint: %v\n", peer.CoveredByTunnel)
		}
	}

	if d := in.diagnosis; d != nil && !d.running {
		fmt.Fprintf(&b, "\n[Last test]\n")
		fmt.Fprintf(&b, "Finished: %s\n", stamp(d.finished))
		if len(d.err) > 0 {
			fmt.Fprintf(&b, "Error: %s\n", d.err)
		}
		for _, step := range d.steps {
			fmt.Fprintf(&b, "%s: %s: %s\n", step.ID, outcomeKey(step.Outcome), step.Detail)
		}
	}

	fmt.Fprintf(&b, "\n[Samples]\n")
	summarizeSamples(&b, "Per second", in.samples.seconds, 16*time.Second)
	summarizeSamples(&b, "Per minute", in.samples.minutes, 3*time.Minute)
	if quality := summarizeQuality(in.samples.seconds); quality.hasData {
		fmt.Fprintf(&b, "Last minute: %d probes sent, %d lost, latency %s, jitter %s\n", quality.sent, quality.lost, quality.latency.Round(time.Microsecond*100), quality.jitter.Round(time.Microsecond*100))
	}

	if entry.historyLoaded {
		h := &entry.history
		fmt.Fprintf(&b, "\n[History]\n")
		if !entry.historyEnabled {
			fmt.Fprintf(&b, "Disabled by policy\n")
		} else {
			fmt.Fprintf(&b, "Sessions: %d\n", len(h.Sessions))
			for _, days := range []int{1, 7, 30} {
				totals := usageOfLastDays(h.Days, in.now, days)
				fmt.Fprintf(&b, "Last %d days: %d bytes received, %d bytes sent, active %s, connected %s\n", days, totals.rx, totals.tx, totals.active, totals.connected)
			}
			const sessionsListed = 10
			first := max(len(h.Sessions)-sessionsListed, 0)
			if first > 0 {
				fmt.Fprintf(&b, "Latest %d sessions:\n", sessionsListed)
			}
			for _, session := range h.Sessions[first:] {
				fmt.Fprintf(&b, "  %s to %s, active %ds, connected %ds, %d bytes received, %d bytes sent, %d failures, %d reconnects, endpoint %s, %s\n",
					stamp(session.Start), stamp(session.End), session.ActiveSeconds, session.ConnectedSeconds, session.RxBytes, session.TxBytes,
					session.ConnectionFailures, session.Reconnects, session.Endpoint, sessionEndKey(session.EndedBy))
				addHost(endpointHost(session.Endpoint))
			}
		}
	}

	fmt.Fprintf(&b, "\n[Log]\n")
	for _, line := range in.logLines {
		parsed := ringlogger.ParseLine(line.Line)
		if parsed.Tunnel == name || parsed.Tunnel == "" && parsed.Source == "MGR" {
			fmt.Fprintf(&b, "%s: %s\n", line.Stamp.Format("2006-01-02 15:04:05.000"), line.Line)
		}
	}
	return b.String(), hosts
}

func joinStrings[T interface{ String() string }](items []T) string {
	if len(items) == 0 {
		return "-"
	}
	parts := make([]string, len(items))
	for i := range items {
		parts[i] = items[i].String()
	}
	return strings.Join(parts, ", ")
}

// interfaceKindKey names an interface kind in the file.
func interfaceKindKey(kind manager.InterfaceKind) string {
	switch kind {
	case manager.InterfaceKindEthernet:
		return "ethernet"
	case manager.InterfaceKindWiFi:
		return "wifi"
	case manager.InterfaceKindMobile:
		return "mobile"
	}
	return "other"
}

var (
	// A WireGuard key in base64: 43 characters of which the last carries only some bits, and the padding.
	keyPattern = regexp.MustCompile(`[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=`)
	// Candidates for addresses; each is checked by parsing it, so that times and version numbers are left alone.
	ipv4Pattern = regexp.MustCompile(`[0-9]{1,3}(?:\.[0-9]{1,3}){3}`)
	ipv6Pattern = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.[0-9]{1,3}){0,3}(?:%[0-9A-Za-z]+)?`)
)

// shortenKeys shortens every key in the text to its beginning. Log lines may hold keys that the file does not
// write itself, and this keeps them as short in those as elsewhere.
func shortenKeys(text string) string {
	return keyPattern.ReplaceAllStringFunc(text, shortKey)
}

// isHostChar reports whether a byte can be part of a host name, so that a match inside a longer name is not taken
// for the name.
func isHostChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// redactDiagnostics replaces every IP address in the text, and every one of the host names, by a placeholder. The
// same address or name always gets the same placeholder, so that the file still shows which lines are about the
// same peer. Keys are shortened as well.
func redactDiagnostics(text string, hosts []string) string {
	text = shortenKeys(text)
	placeholders := make(map[string]string)
	placeholder := func(kind, key string) string {
		if p, ok := placeholders[kind+key]; ok {
			return p
		}
		count := 1
		for k := range placeholders {
			if strings.HasPrefix(k, kind) {
				count++
			}
		}
		p := "<" + kind + "-" + strconv.Itoa(count) + ">"
		placeholders[kind+key] = p
		return p
	}

	// Longer names first, so that a name is not hidden partly by a shorter one that ends it.
	sorted := append([]string(nil), hosts...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, host := range sorted {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" {
			continue
		}
		var out strings.Builder
		lower := strings.ToLower(text)
		for i := 0; ; {
			found := strings.Index(lower[i:], host)
			if found < 0 {
				out.WriteString(text[i:])
				break
			}
			start, end := i+found, i+found+len(host)
			before := start > 0 && (isHostChar(text[start-1]) || text[start-1] == '.')
			after := end < len(text) && (isHostChar(text[end]) || text[end] == '.' && end+1 < len(text) && isHostChar(text[end+1]))
			out.WriteString(text[i:start])
			if before || after {
				out.WriteString(text[start:end])
			} else {
				out.WriteString(placeholder("host", host))
			}
			i = end
		}
		text = out.String()
	}

	replaceAddresses := func(text string, pattern *regexp.Regexp, boundary func(c byte) bool) string {
		var out strings.Builder
		last := 0
		for _, match := range pattern.FindAllStringIndex(text, -1) {
			start, end := match[0], match[1]
			if start > 0 && boundary(text[start-1]) || end < len(text) && boundary(text[end]) {
				continue
			}
			// An address at the end of a clause, as in "fd00::1: no answer", takes the colon after it along.
			for end-start > 2 && (text[end-1] == ':' && text[end-2] != ':' || text[end-1] == '.') {
				end--
			}
			addr, err := netip.ParseAddr(text[start:end])
			if err != nil {
				continue
			}
			out.WriteString(text[last:start])
			out.WriteString(placeholder("address", addr.Unmap().WithZone("").String()))
			last = end
		}
		out.WriteString(text[last:])
		return out.String()
	}
	text = replaceAddresses(text, ipv6Pattern, func(c byte) bool {
		return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' || c == ':'
	})
	text = replaceAddresses(text, ipv4Pattern, func(c byte) bool { return c >= '0' && c <= '9' || c == '.' })
	return text
}

// diagnosticsText gathers the diagnostics file of a tunnel from what the window holds and from the log, and hides
// the addresses in it unless they are to be included.
func (model *appModel) diagnosticsText(entry *tunnelEntry, includeAddresses bool, now time.Time) string {
	in := diagnosticsInput{
		now:           now,
		appVersion:    version.Number,
		driverVersion: driver.Version(),
		osName:        version.OsName(),
		arch:          version.Arch(),
		entry:         *entry,
		samples:       model.samples[entry.tunnel.Name],
		diagnosis:     model.diagnoses[entry.tunnel.Name],
	}
	if ringlogger.Global != nil {
		in.logLines, _ = ringlogger.Global.FollowFromCursor(ringlogger.CursorAll)
	}
	text, hosts := collectDiagnostics(&in)
	if includeAddresses {
		return shortenKeys(text)
	}
	return redactDiagnostics(text, hosts)
}

// saveDiagnostics asks whether addresses are to be included and where to save, and writes the diagnostics file of
// a tunnel there.
func (model *appModel) saveDiagnostics(owner walk.Form, name string) {
	if model.entry(name) == nil {
		return
	}
	includeAddresses, ok := runDiagnosticsDialog(owner)
	if !ok {
		return
	}
	dlg := walk.FileDialog{
		Filter:   l18n.Sprintf("Text Files (*.txt)|*.txt|All Files (*.*)|*.*"),
		FilePath: fmt.Sprintf("wireguard-diagnostics-%s-%s.txt", name, time.Now().Format("2006-01-02T150405")),
		Title:    l18n.Sprintf("Save diagnostics to file"),
	}
	if ok, _ := dlg.ShowSave(owner); !ok {
		return
	}
	if dlg.FilterIndex == 1 && !strings.HasSuffix(strings.ToLower(dlg.FilePath), ".txt") {
		dlg.FilePath += ".txt"
	}
	// The entry is looked up again, as the model may have reloaded while the dialogs were open.
	entry := model.entry(name)
	if entry == nil {
		return
	}
	text := model.diagnosticsText(entry, includeAddresses, time.Now())
	writeFileWithOverwriteHandling(owner, dlg.FilePath, func(file *os.File) error {
		_, err := io.WriteString(file, strings.ReplaceAll(text, "\n", "\r\n"))
		return err
	})
}

// runDiagnosticsDialog explains what a diagnostics file holds and asks whether it may include addresses. It
// reports the choice, and whether the person went on.
func runDiagnosticsDialog(owner walk.Form) (includeAddresses, ok bool) {
	var disposables walk.Disposables
	defer disposables.Treat()

	dlg, err := walk.NewDialog(owner)
	if showError(err, owner) {
		return false, false
	}
	disposables.Add(dlg)
	dlg.SetTitle(l18n.Sprintf("Save diagnostics"))
	if owner != nil {
		dlg.SetIcon(owner.Icon())
	}
	layout := walk.NewGridLayout()
	layout.SetSpacing(8)
	layout.SetMargins(walk.Margins{14, 14, 14, 14})
	dlg.SetLayout(layout)
	dlg.SetMinMaxSize(walk.Size{440, 0}, walk.Size{0, 0})

	explanation, err := walk.NewTextLabel(dlg)
	if showError(err, owner) {
		return false, false
	}
	layout.SetRange(explanation, walk.Rectangle{0, 0, 2, 1})
	explanation.SetText(l18n.Sprintf("The file describes this tunnel for whoever helps you: versions, state, measurements, the last test, recent history and the log lines about it. It never contains private or preshared keys, and public keys are shortened. Addresses and host names are replaced by placeholders unless you include them."))

	checkBox, err := walk.NewCheckBox(dlg)
	if showError(err, owner) {
		return false, false
	}
	layout.SetRange(checkBox, walk.Rectangle{0, 1, 1, 1})
	// The text of a check box cannot be given a color, so it is shown by a label next to the box instead.
	checkText := l18n.Sprintf("&Include addresses")
	checkBox.Accessibility().SetName(strings.Replace(checkText, "&", "", 1))
	checkBox.SetMinMaxSize(walk.Size{Width: 16}, walk.Size{Width: 16})
	checkLabel, err := walk.NewTextLabel(dlg)
	if showError(err, owner) {
		return false, false
	}
	layout.SetRange(checkLabel, walk.Rectangle{1, 1, 1, 1})
	checkLabel.SetText(strings.Replace(checkText, "&", "", 1))
	checkLabel.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			checkBox.SetChecked(!checkBox.Checked())
		}
	})

	buttons, err := walk.NewComposite(dlg)
	if showError(err, owner) {
		return false, false
	}
	layout.SetRange(buttons, walk.Rectangle{0, 2, 2, 1})
	buttons.SetLayout(walk.NewHBoxLayout())
	buttons.Layout().SetMargins(walk.Margins{})
	walk.NewHSpacer(buttons)
	saveButton, err := walk.NewPushButton(buttons)
	if showError(err, owner) {
		return false, false
	}
	saveButton.SetText(l18n.Sprintf("Save…"))
	cancelButton, err := walk.NewPushButton(buttons)
	if showError(err, owner) {
		return false, false
	}
	cancelButton.SetText(l18n.Sprintf("Cancel"))

	saveButton.Clicked().Attach(func() {
		ok, includeAddresses = true, checkBox.Checked()
		dlg.Accept()
	})
	cancelButton.Clicked().Attach(dlg.Cancel)
	dlg.SetDefaultButton(saveButton)
	dlg.SetCancelButton(cancelButton)

	restyle := func() {
		styleDialog(dlg)
		buttons.SetBackground(themeBrush(theme.backdrop))
		styleLabels(theme.text, explanation, checkLabel)
		styleButtons(saveButton, cancelButton, checkBox)
	}
	restyle()
	defer watchTheme(restyle)()

	dlg.Starting().Attach(func() {
		saveButton.SetFocus()
	})
	disposables.Spare()
	defer dlg.Dispose()
	dlg.Run()
	return includeAddresses, ok
}
