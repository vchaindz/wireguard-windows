# Roadmap: a client that looks finished and explains the connection

This is a plan for the next rounds of work on the status-first UI (branch `ui-status-first`). It
describes what to build, in which order, how each piece fits the existing architecture, and what
can go wrong. Nothing in it is implemented yet.

## 1. Where the client stands

What exists after the last round:

- A dark, status-first window and tray popup, custom-drawn (`ui/scene.go`, `ui/canvasview.go`,
  `ui/screens.go`, `ui/traypopup.go`), operable by keyboard.
- A connection check in the manager with health states, duplicate-key and instability warnings
  (`manager/tunnelhealth.go`), and routes held back until a peer answers (`tunnel/peerwait.go`).
- Per-tunnel metrics kept in the manager's memory (`manager/tunnelmetrics.go`): active and
  connected time, last active, failures, reconnects, interface errors and drops.
- Live rates and a 60-second graph, computed in the UI while the window is open (`ui/traffic.go`).
- Log lines with level and tunnel tag (`ringlogger/parse.go`).

What a user of a polished VPN client would still miss falls into three groups: **knowing how good
the connection is** (latency, loss, history), **a UI that feels finished** (state-telling tray
icon, motion, themes, readable numbers), and **not having to think about it** (auto-connect,
actionable notifications, quick sharing).

## 2. Principles

These decide the design questions below, so they come first.

1. **The manager measures, the UI shows.** The UI process talks only to the manager and never to
   drivers or the config store. Anything that must keep running while the window is closed, or
   needs privileges, lives in the manager and reaches the UI over the existing gob IPC.
2. **Nothing is sent that the user did not ask for.** Passive data (counters, handshakes) is free.
   Active probing (pings) is opt-in per tunnel and visible in the UI.
3. **What is stored is treated like configuration.** Connection history says when and where a
   machine was online. It goes under the same restricted directory as the configs, is never sent
   anywhere, has a size limit, and can be cleared and switched off.
4. **Admin policy wins.** Every new behaviour that an organisation may not want (probing, history,
   auto-connect) gets a registry switch read with `conf.AdminBool`, documented in
   `docs/adminregistry.md`, like `ApplyRoutesImmediately`.
5. **No new dependencies.** `go.mod` pins a small set and the toolkit is a fork. Charts, QR codes
   and animation are written in the repo, small and tested.
6. **Every screen is rendered in tests.** `go test ./ui` with `WG_UI_RENDER_DIR` already draws all
   screens to PNG. Each new visual gets a case there, because the real window cannot be opened
   from a test binary.

## 3. What the platform gives and does not give

| Wanted | Available from | Note |
|---|---|---|
| Bytes in/out, last handshake, endpoint per peer | WireGuardNT (`driver.Adapter.Configuration`) | Already used. |
| Interface errors, drops, MTU, link state | IP Helper (`winipcfg`, `MibIfRow2`) | Already used for errors. |
| Latency, jitter, packet loss | Not provided | Must be measured by pinging through the tunnel. |
| Per-peer errors, retransmits | Not provided | WireGuard has none; do not fake them. |
| Which physical adapter carries the tunnel | IP Helper route lookup for the endpoint address | New, read-only. |
| Network changes (Wi-Fi joined, cable unplugged) | `winipcfg.RegisterInterfaceChangeCallback`, already used by the tunnel service | The manager would register its own. |
| Network identity (which Wi-Fi) | Network List Manager / WLAN API | New API surface; needed only for auto-connect. |
| Notifications with buttons | WinRT toasts, need an app identity and COM activation | Large; balloons have no buttons. See phase 5. |

## 4. Foundations (built once, used by several phases)

### 4.1 A telemetry recorder in the manager

Today `tunnelHealthMonitor.run` samples every 5 s and feeds the health evaluator and the metrics
recorder. Extend that one loop, do not add a second:

- Sample every second while at least one UI has asked for live data, every 5 s otherwise. The UI
  sends a "watching" hint over IPC when its window becomes visible and withdraws it when hidden.
- Each sample becomes a fixed-size record: time, rx bytes, tx bytes, handshake age, health, and,
  if probing is on, latency and loss.
- Records go into a ring per tunnel in memory (last hour at 1 s, last day at 1 min by
  down-sampling: sum bytes, keep worst health, average and maximum latency).

This moves rate calculation from the UI to the manager. The UI's `trafficHistory` then only holds
what it was sent, and the graph is filled the moment the window opens instead of building up.

### 4.2 A history store

A small append-only file per tunnel under `conf.RootDirectory()` in a new `History` directory with
the same ACL as `Configurations`:

- **Sessions:** one record when a tunnel stops: start, end, bytes in and out, failures,
  reconnects, endpoint. Fixed size, capped (for example the last 500 sessions per tunnel).
- **Usage:** one record per tunnel per day: bytes in and out, active seconds, connected seconds.
- Written by the manager only; read through IPC. Written on stop and once a minute while active,
  so a crash loses at most a minute.
- Format: versioned binary records with a header, so later versions can extend it. No database.
- Deleted with the tunnel. A "Clear history" action per tunnel and a policy
  `DisableConnectionHistory`.

`TunnelMetrics` is then seeded from this store when the manager starts, which fixes the current
limitation that "last active" is forgotten on restart.

### 4.3 IPC additions

Three methods, following the pattern of `HealthMethodType`/`MetricsMethodType` in
`manager/ipc_client.go` and `ipc_server.go`:

- `Samples(tunnel, resolution, since)` → a slice of sample records.
- `History(tunnel)` → sessions and daily usage.
- `Watch(on)` → the "window is visible" hint from 4.1.

Samples are pulled by the UI once a second while visible (it already polls), not pushed, so no new
notification type is needed.

### 4.4 Animation in the drawing layer

`canvasView` repaints only when told. Add a per-view clock:

- `scene.animate(id, target)` returns a value eased towards `target` over about 150 ms and asks
  for another frame while it is moving. The view runs a 16 ms timer only while something moves.
- Used for switches sliding, hover fading, the ring pulsing while activating, graph bars growing,
  and a cross-fade between screens.
- Honours the Windows "show animations" setting (`SPI_GETCLIENTAREAANIMATION`).
- Partial redraw already limits the cost to what changed.

### 4.5 A chart primitive

Replace the bar-only `trafficGraph` with one function that draws a series as bars or as a filled
line, with an optional second series, a time axis with a few labels, a scale label, and a hover
read-out (the value and time under the mouse). Lines are polylines split into runs of at most 16
points, as the scene's shapes allow.

## 5. Phases

Each phase is shippable on its own. Effort is relative: S is about a day of work as done so far,
M two to three, L more.

### Phase 1 — Connection quality (M)

*Why first: it is the insight people ask for, and the foundations it needs serve everything else.*

- Build 4.1, 4.3 and 4.5.
- **Latency and loss:** the manager sends one ICMP echo per second through the tunnel while
  probing is on, using `IcmpSendEcho2Ex` with the tunnel's address as source so the reply must
  come through it. Target: by default the peer's first allowed address that is a single host, or
  the tunnel's DNS server; configurable per tunnel. Results: round-trip time, jitter (mean
  deviation), loss over the last minute.
- **Opt-in:** a "Measure connection quality" switch on the details screen, off by default,
  remembered per tunnel in the history directory (not in the config file, which stays plain
  wg-quick). Policy `DisableConnectionProbing`.
- **UI:** a quality tile on the status screen ("24 ms · 0 % loss"), a latency graph under the
  traffic graph, and time ranges 1 min / 1 h / 24 h on both.
- **Quality in the health state:** high loss or latency becomes an "unstable" reason, with its own
  wording, instead of only the handshake heuristic.

Risks: a target that does not answer pings looks like 100 % loss, so "no reply from target" must
be told apart from loss after replies were seen. ICMP from LocalSystem through a kill-switch
tunnel must not be blocked by the WFP rules in `tunnel/firewall`; verify with a full-tunnel config.

Verify: unit tests for the down-sampling and the loss/jitter arithmetic with synthetic series;
renders with sample data; on a real tunnel, compare against `ping` in a terminal.

### Phase 2 — History and usage (M)

- Build 4.2; seed `TunnelMetrics` from it.
- **Details screen:** "Usage" card (today, 7 days, 30 days, with a small bar per day), "Sessions"
  list (start, duration, data, how it ended), and an uptime figure (connected time over active
  time).
- **Status screen:** inactive rows keep "last active …" across restarts.
- **Export:** "Save history" as CSV next to "Save log".

Risks: clock changes and sleep. Record durations from a monotonic clock and wall time only for
display; close a session on suspend and open a new one on resume, so a night of sleep is not
counted as connected time.

Verify: unit tests for the store (append, cap, version, truncated file, clock going backwards);
manual check across a manager restart and a sleep/resume.

### Phase 3 — Visual finish (M)

- Build 4.4.
- **Tray icon by state:** draw the icon with the scene rasterizer at the needed sizes instead of
  overlaying a system icon: logo with a green, amber or red mark, and a grey logo when off.
  Tooltip: state, connected time, current rates. Replaces `iconWithOverlayForState`.
- **Light theme:** turn the colour constants in `ui/theme.go` into a palette struct with a dark and
  a light instance, chosen from the Windows app-mode setting and switched live on
  `WM_SETTINGCHANGE`. The accent stays green; optional: follow the Windows accent colour.
- **Numbers:** "218 MB", "43 s ago", "1.2 MB/s" in the new screens. `conf.Bytes.String()` and
  `HandshakeTime.String()` are used by `wg` output too, so add UI-side formatters and leave those.
- **Tunnel identity:** a colour chosen per tunnel (stored with the per-tunnel settings from phase
  1), shown as the row mark and in the graph; favourites sorted first; a filter field when there
  are more than about eight tunnels.
- **First run:** a welcome state with three clear starts: import a file, paste a configuration,
  add an empty tunnel.
- **Dialogs:** move the edit dialog into the window as a screen with the custom header, so the
  last native light-era surface is gone. The syntax editor stays the RichEdit control, hosted in
  the screen the way the log table is.

Risks: per-monitor DPI for the generated tray icon; high-contrast mode must fall back to system
colours (the syntax editor already inverts for it; the custom views need an explicit palette).

Verify: renders for both themes for every screen; a contrast test that checks every text/ground
pair in both palettes against 4.5:1.

### Phase 4 — Explain the path (S–M)

- **Path card:** resolved endpoint address, IPv4 or IPv6, the physical interface that carries the
  tunnel (name, Wi-Fi or Ethernet), tunnel MTU and the MTU of the underlying route, and whether
  the tunnel takes all traffic. Read in the manager via `winipcfg`.
- **Events timeline:** a strip on the details screen with handshakes, losses, endpoint changes,
  network changes and state changes over the selected time range, drawn from the samples and from
  log lines of that tunnel. This makes "unstable" and "key used elsewhere" visible as a pattern.
- **Test this tunnel:** a button that runs checks in order and shows each result: endpoint name
  resolves; peer answers a handshake; ping through the tunnel; DNS answers through the tunnel;
  for full tunnels, the public address differs from before. Each failing step names the likely
  cause. Runs in the manager; the public-address check contacts an outside service, so it is
  off unless the user ticks it for that run.
- **Diagnostics bundle:** one file with version, tunnel states, metrics, recent samples and the
  log, with keys and endpoints redacted unless the user opts to include endpoints.

### Phase 5 — Less to think about (L)

*Last because it changes when tunnels start without the user acting, which touches the manager's
security model. Read `docs/attacksurface.md` before starting.*

- **Auto-connect rules per tunnel:** connect when on a network that is not marked trusted;
  disconnect on trusted networks; connect at sign-in. Trusted networks are identified by the
  Network List Manager's network identity, not by Wi-Fi name alone, because names can be spoofed.
  Rules are evaluated in the manager on interface-change notifications, are editable by
  administrators only, and are stored beside the config with the same ACL. Policy
  `DisableAutoConnect`.
- **Notifications with actions:** "Connection lost — Reconnect / Deactivate". This needs WinRT
  toasts, which need an application identity registered by the installer and a COM activator.
  It is the most platform-heavy item here; evaluate it separately, and keep balloons if the cost
  is not worth it.
- **Global hotkey** to toggle the last tunnel (`RegisterHotKey` in the UI process), off by default.
- **QR code:** show a tunnel's configuration as a QR code for a phone. Needs a small encoder
  written in the repo. Showing it reveals the private key, so it sits behind the same admin check
  as export, with a warning.
- **Compact mode:** a small always-on-top window with state, rates and quality.

## 6. Order and dependencies

```
Phase 1 (quality) ──► Phase 2 (history) ──► Phase 4 (path, timeline, test)
        │
        └─ foundations 4.1, 4.3, 4.5 used by 2 and 4
Phase 3 (visual finish) can run in parallel with 2 after 1; it needs only 4.4
Phase 5 (automation) after everything else, as its own reviewed change
```

Recommended sequence: 1, 3, 2, 4, 5. Phase 3 early because it is what "looks way nicer" and has
no dependency on stored data; phase 2 next because history makes phase 4's timeline worth having.

## 7. Deliberately not planned

- **Throughput tests** (speed tests against a server): need infrastructure and send a lot of data.
- **Per-application traffic:** would need a kernel callout or ETW tracing; out of scale.
- **Server-side statistics:** the client cannot know them.
- **Cloud sync or accounts:** against the nature of the tool.
- **Screen-reader support (UI Automation)** for the custom-drawn views: important, but its own
  project; until then the keyboard works and the log, editor and update screens stay native.

## 8. Decisions to make before starting

1. **Probing default:** off per tunnel (planned) or on while the window is open?
2. **History default:** on with a clear switch (planned) or off until enabled?
3. **Light theme:** follow Windows automatically (planned) or a manual switch as well?
4. **Upstream:** is this fork meant to stay a fork? If parts should go upstream, the health check,
   routing hold-back and log levels are candidates; the custom-drawn UI is unlikely to be accepted
   and should then be kept separable.
