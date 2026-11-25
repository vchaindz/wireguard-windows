# Network Configuration Quirks

As part of setting up a WireGuard tunnel, the tunnel service also sets up various network configuration parameters that are in one way or another related to the original configuration.

### Routing

The tunnel service takes all the allowed IPs from each peer, deduplicates them, and adds them to the routes for the WireGuard interface. The service then monitors which interface on the system has a default route (a route with a `/0` CIDR) that is not the WireGuard interface itself, and, if no MTU has been specified in the configuration, it sets the MTU of the WireGuard interface to be 80 less than the MTU of that default route interface. WireGuardNT also monitors the routing table and determines the outgoing route that does not loopback to itself, and then sends each packet using `IP_PKTINFO`/`IPV6_PKTINFO`. It keeps track of the incoming interface and source address for received packets, and always replies to the sender in that way.

### Firewall Considerations for `/0` Allowed IPs

If an interface has only one peer, and that peer contains an Allowed IP in `/0`, then WireGuard enables a so-called "kill-switch", which adds firewall rules to do the following:

- Packets from the tunnel service itself are permitted, so that WireGuard packets can flow successfully.
- If the configuration specifies DNS servers, then packets sent to port `53` are only permitted if they are to one of those DNS servers. This is to prevent Windows' [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29), so that DNS queries only go to the DNS server specified, rather than multiple DNS servers.
- Loopback packets are permitted, and packets actually going through the WireGuard tunnel are permitted.
- DHCP for IPv4 and IPv6 and NDP for IPv6 are permitted.
- All other packets are blocked.

This prevents traffic from leaking outside the tunnel.

If you'd like to use a default route _without_ having these restrictive kill-switch semantics, one may use the routes `0.0.0.0/1` and `128.0.0.0/1` in place of `0.0.0.0/0`, as well as `::/1` and `8000::/1` in place of `::/0`. This achieves nearly the same thing, but does not activate the above firewalling semantics. (The UI's editor has a checkbox that toggles this.)  And users without the need for a `/0` route at all do not have to worry about this, and instead fall back to ordinary Windows routing and DNS behavior.

### Considerations for non-`/0` Allowed IPs

When the above conditions do not apply, routing and DNS information is handed to Windows in the typical way for Windows to manage. This includes its [ordinary multihomed DNS resolution behavior](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197552%28v%3Dws.10%29) as well as its ordinary routing table resolution. Users may make use of the normal Windows firewalling and network configuration capabilities to firewall this as needed. One firewall rule is added, however, which allows the tunnel service to send and receive WireGuard packets.

### Network List Manager

Windows assigns a unique GUID to each new WireGuard adapter. The application takes pains to make this GUID deterministic, so that firewall policy (such as "public" vs "private" network categorization) can be consistently applied to the tunnel's network. This determinism is based on the configuration of the tunnel. Therefore, if the WireGuard configuration changes, so too will the unique GUID. Technical details are described in [a mailing list post](https://lists.zx2c4.com/pipermail/wireguard/2019-June/004259.html).

### Adapter Lifetime

WireGuard's network adapter is created dynamically when a tunnel is started and destroyed when a tunnel is stopped. This means that additional filters, address families, or protocols should be bound to the adapter programmatically, possibly through use of dangerous script execution in the configuration file or by way of automatic NDIS layer binding.

### Connection Check

A tunnel's service is "active" as soon as its adapter is up, whether or not a peer ever answers, because WireGuard itself is connectionless. The manager service therefore samples each active tunnel's per-peer counters from the driver every 5 seconds and reports one of:

- **Active (connected)** &ndash; at least one peer completed a handshake within the last 180 seconds.
- **Active, but no connection** &ndash; packets have been sent for 20 seconds or more without any peer completing a handshake. This is also shown in the tunnel list and as a tray notification, and stays until a handshake succeeds.
- **Active (connection not verified yet)** &ndash; there is no recent handshake, but nothing has been sent for long enough to tell. A tunnel without `PersistentKeepalive` only handshakes when there is traffic, so an idle tunnel cannot be told apart from a broken one.

When a peer does not answer, the report also says what that means for the rest of the network: either the tunnel's routes have not been applied yet (see below), or the tunnel takes over all traffic with a `/0` allowed IP, or its two `/1` halves, and the machine is cut off until the peer answers or the tunnel is deactivated.

### Waiting for a Peer Before Routing

On activation, the tunnel service brings the adapter up but holds back routes, addresses, DNS servers, and firewall rules until a peer completes a handshake. Since nothing is routed into the tunnel yet, it starts the handshake itself by briefly turning persistent keepalive on for every peer that has an endpoint, repeating this every 95 seconds, and restores the configured value once a peer answers. A tunnel to a peer that no longer exists therefore stays up without touching the rest of the network, and reports that its peer does not answer.

This applies only to activation. Once a peer has answered, routes and firewall rules stay in place even if the connection is lost later, so that traffic meant for the tunnel never leaves by another path. It also means that the kill-switch does not cover the time between activation and the first handshake. The `ApplyRoutesImmediately` registry key described in [`adminregistry.md`](adminregistry.md) restores the original order. Tunnels without any peer endpoint are always configured at once.

The same samples are used to warn when another device appears to be using the same private key. In that situation the server answers whichever device spoke last, the other one hears nothing and renews its session after about 15 seconds, and the two keep displacing each other, which breaks long-lived connections on both. The warning is raised when sessions are renewed less than 60 seconds apart three times within five minutes, where the normal interval is two minutes. A single such early renewal is reported as an unstable connection, since it means that the session was lost once and recovered. This is a heuristic: a very lossy path can cause the same pattern, and two devices that are never busy at the same time will not trigger it. The certain test is on the server, where the peer's endpoint in `wg show` alternates between two addresses. The remedy is a separate key pair, and tunnel address, for each device.

### Connection Quality

WireGuard itself reports no latency or loss, so the manager service can measure them by sending ICMP echo requests ("pings") through the tunnel. This is off by default and is switched on per tunnel; the setting is kept by the manager in `Data\Settings`, not in the configuration file. While it is on, one echo request is sent with every sample of the connection check: once per second while a WireGuard window is open, and once every five seconds otherwise. Each request waits up to 900 milliseconds for its answer. The request is sent from the tunnel interface's own address, so Windows sends it only through the tunnel and the answer can only come back that way; until the tunnel has an address (for example while it waits for a peer before routing), nothing is sent.

The address to ping can be set per tunnel. Otherwise it is the tunnel's first DNS server, and failing that the first allowed IP of a peer that is a single host (`/32` or `/128`), which is usually the peer's own tunnel address. A tunnel that has neither, such as one that only routes networks, has nothing to measure until an address is set. The target must answer pings: one that is reachable but ignores them looks like complete loss.

The manager keeps the last hour of samples (five hours at the slower rate) and a day of one-minute summaries in memory, and forgets them when the tunnel stops. The `DisableConnectionProbing` registry key described in [`adminregistry.md`](adminregistry.md) switches measuring off for all tunnels.

### Connection History

The manager service keeps a history of each tunnel, which the details screen shows as its usage and its sessions, and which can be saved as a CSV file from there. It is kept by the manager, not by the UI, so that it is recorded whether or not a window is open.

- **What is stored:** for each period of the tunnel being active (a *session*), its start and end, how long it was active and how long connected, the data received and sent, the number of connection failures and reconnects, the endpoint of the first peer as configured, and how it ended: deactivated, the WireGuard service stopped, or the computer went to sleep. For each calendar day, the data received and sent and the active and connected time. Nothing about the traffic itself is recorded, and nothing is sent anywhere.
- **Where:** one file per tunnel, `History\<tunnel>.json`, under `C:\Program Files\WireGuard\Data`, next to `Configurations`. The directory inherits the data directory's ACL (SYSTEM and Administrators only), and each file is written like a configuration file: to a temporary file owned by SYSTEM that only SYSTEM can read, then renamed into place. The UI reads the history through the manager; members of the Network Configuration Operators group see it in the limited-operator UI, but only administrators can clear it.
- **Limits:** the most recent 500 sessions and 400 days per tunnel. The file is versioned JSON of at most 512 KiB; with every field at its largest it stays under about 330 KB. A file that is larger, damaged, or of another version is ignored and replaced.
- **When it is written:** when a session ends, and once a minute while a tunnel is active, so that a crash of the manager loses at most a minute. A session that is still open when the manager starts again is closed as ended by the service stopping, at the time it was last written.
- **Time:** durations are measured with a monotonic clock, so that changing the time of the computer does not change them; the wall-clock times are only for display and for telling days apart. If samples stop for more than 30 seconds, as when the computer sleeps, the session is closed at the last sample before the gap and a new one starts after it, so sleep never counts as active or connected time. A session that crosses midnight counts towards both days.
- **Clearing:** the "Clear history" button on the details screen (administrators only) deletes a tunnel's file, along with the "last active" shown in the tunnel list. History is kept when a tunnel is edited, as editing replaces it under the same name, and is removed when the manager starts and finds that its tunnel no longer exists. To clear the history of all tunnels at once, stop the manager and delete the `History` directory.

The `DisableConnectionHistory` registry key described in [`adminregistry.md`](adminregistry.md) switches recording off for all tunnels.
