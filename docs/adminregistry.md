# Registry Keys for Admins

These are advanced configuration knobs that admins can set to do unusual things
that are not recommended. There is no UI to enable these, and no such thing is
planned. These registry keys may also be removed at some point in the future.
The uninstaller will clean up the entirety of `HKLM\Software\WireGuard`. Use
at your own risk, and please make sure you know what you're doing.

#### `HKLM\Software\WireGuard\LimitedOperatorUI`

When this key is set to `DWORD(1)`, the UI will be launched on desktops of
users belonging to the Network Configuration Operators builtin group
(S-1-5-32-556), with the following limitations for members of that group:

  - Configurations are stripped of all public, private, and pre-shared keys;
  - No version update popup notifications are shown, and updates are not permitted, though a tab still indicates the availability;
  - Adding, removing, editing, importing, or exporting configurations is forbidden; and
  - Quitting the manager is forbidden.

However, basic functionality such as starting and stopping tunnels remains intact.

```
> reg add HKLM\Software\WireGuard /v LimitedOperatorUI /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\DangerousScriptExecution`

When this key is set to `DWORD(1)`, the tunnel service will execute the commands
specified in the `PreUp`, `PostUp`, `PreDown`, and `PostDown` options of a
tunnel configuration. Note that this execution is done as the Local System user,
which runs with the highest permissions on the operating system, and is therefore
a real target of malware. Therefore, you should enable this option only with the
utmost trepidation. Rather than use `%i`, WireGuard for Windows instead sets the
environment variable `WIREGUARD_TUNNEL_NAME` to the name of the tunnel when
executing these scripts.

```
> reg add HKLM\Software\WireGuard /v DangerousScriptExecution /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\ApplyRoutesImmediately`

By default, the tunnel service brings the adapter up and then waits for a peer
to complete a handshake before it applies routes, addresses, DNS servers, and
firewall rules, so that activating a tunnel whose peer is gone does not take
the machine off the network. Until then, traffic uses the ordinary network,
which means the kill-switch of a `/0` tunnel only takes effect once the peer
has answered. When this key is set to `DWORD(1)`, everything is applied at
once, before any peer has answered, as in the official client.

```
> reg add HKLM\Software\WireGuard /v ApplyRoutesImmediately /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\DisableConnectionProbing`

Measuring a tunnel's connection quality is off by default and can be switched
on per tunnel by an administrator. While it is on, the manager service sends
one ICMP echo request ("ping") through the tunnel with every sample: once per
second while a WireGuard window is open, and once every five seconds
otherwise. When this key is set to `DWORD(1)`, no tunnel sends these probes,
whatever its settings say, and the UI shows the measurement as disabled by
policy. The change applies to running tunnels within a few seconds.

```
> reg add HKLM\Software\WireGuard /v DisableConnectionProbing /t REG_DWORD /d 1 /f
```

#### `HKLM\Software\WireGuard\DisableConnectionHistory`

By default, the manager service keeps a history of each tunnel: when it was
active, for how long, how much data it moved, and how much of each day it was
in use. The history is described in [`netquirk.md`](netquirk.md#connection-history).
When this key is set to `DWORD(1)`, nothing is recorded or written any more,
existing history is no longer shown, and the UI says that history is disabled by
policy. Files that already exist are left in place; delete the `History`
directory to remove them. The change applies to running tunnels within a few
seconds.

```
> reg add HKLM\Software\WireGuard /v DisableConnectionHistory /t REG_DWORD /d 1 /f
```
