# Attack Surface

_This is an evolving document, describing currently known attack surface, a few mitigations, and several open questions. This is a work in progress. We document our current understanding with the intent of improving both our understanding and our security posture over time._

WireGuard for Windows consists of four components: a kernel driver, and three separate interacting userspace parts.

### WireGuardNT

WireGuardNT is a kernel driver. It exposes:

  - A miniport driver to the ndis stack, meaning any process on the system that can access the network stack in a reasonable way can send and receive packets, hitting those related ndis handlers.
  - A UDP port parsing WireGuard packets.
  - There are also various ndis OID calls, accessible to certain users, which hit further code.
  - A PNP and Close notifier added to the NDIS device file.
  - IOCTLs are added to the NDIS device file, and those IOCTLs are restricted to `O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NWNRNX;;;HI)`. The IOCTL allows userspace to get and set configuration, adapter state, and read log messages from a ring buffer.

### Tunnel Service

The tunnel service is a userspace service running as Local System, responsible for creating WireGuardNT adapters and configuring them. It exposes:

  - A global mutex is used for WireGuardNT interface creation, with the same DACL as the pipe, but first CreatePrivateNamespace is called with a "Local System" SID.
  - After some initial setup, it uses `AdjustTokenPrivileges` to remove all privileges, except for `SeLoadDriverPrivilege`, so that it can remove the interface when shutting down. This latter point is rather unfortunate, as `SeLoadDriverPrivilege` can be used for all sorts of interesting escalation. Future work includes forking an additional process or the like so that we can drop this from the main tunnel process.

### Manager Service

The manager service is a userspace service running as Local System, responsible for starting and stopping tunnel services, and ensuring a UI program with certain handles is available to Administrators. It exposes:

  - Extensive IPC using unnamed pipes, inherited by the UI process.
  - A readable `CreateFileMapping` handle to a binary ringlog shared by all services, inherited by the UI process.
  - It listens for service changes in tunnel services according to the string prefix "WireGuardTunnel$".
  - It manages DPAPI-encrypted configuration files in `C:\Program Files\WireGuard\Data`, which is created with `O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`, and makes some effort to enforce good configuration filenames.
  - The actual DPAPI-encrypted configuration files are created with `O:SYG:SYD:PAI(A;;FA;;;SY)(A;;SD;;;BA)`.
  - It keeps two more per-tunnel files next to the configurations: settings (`Data\Settings\<name>.json`: connection probing, probe target, colour, favourite) and connection history (`Data\History\<name>.json`: sessions with their start, end and endpoint, and daily traffic totals). Both directories inherit the DACL of `Data`, and the files are written like configuration files, with `O:SYG:SYD:PAI(A;;FA;;;SY)(A;;SD;;;BA)`, to a temporary file that is renamed into place. They are plain JSON, not DPAPI-encrypted, and contain no keys. File names are checked with the tunnel name rules, files that are not regular or have another suffix are ignored, and reads are capped at 4 KiB for settings and 512 KiB for history, so a planted file costs a bounded read and a JSON parse. History is not kept when `HKLM\Software\WireGuard\DisableConnectionHistory` is set.
  - While a tunnel has connection probing switched on, the manager sends ICMP echo requests (`IcmpSendEcho2Ex`, `Icmp6SendEcho2`) from the tunnel's address to a target, and parses the replies. The target is either chosen from the tunnel's configuration or an IP address set by an administrator; host names are not accepted. Probing is off by default and is refused when `HKLM\Software\WireGuard\DisableConnectionProbing` is set.
  - A tunnel test can be requested over IPC. It resolves the host names of the configured endpoints with the system resolver, reads handshake times from the driver, sends one ICMP echo (subject to the same policy), sends one fixed DNS question over UDP from the tunnel's address to each configured DNS server and parses the answer header, and looks up the route to the endpoint. All addresses come from the stored configuration or the administrator-set probe target, never from the request, and only one test per tunnel runs at a time, with a pause between runs.
  - The IPC methods that write (changing settings, clearing history) require the elevated token. The ones that read (samples, settings, history, path, test results), starting a tunnel test, and telling the manager that a window is watching (which raises the sampling rate from every 5 seconds to every second) are also open to the limited-operator UI. Read methods only answer for tunnels whose configuration file exists, so that made-up names do not grow the manager's memory. Limited operators can thus see endpoint addresses, traffic volumes and connection times of all tunnels, and can cause the lookups and packets of a tunnel test.
  - It uses `WTSEnumerateSessions` and `WTSSESSION_NOTIFICATION` to walk through each available session. It then uses `WTSQueryUserToken` to get the token belonging to each session and then determines whether or not it is an administrator token. To determine that, it calls `CheckTokenMembership(CreateWellKnownSid(WinBuiltinAdministratorsSid))` on a duplicated impersonation token, as well as and calling `GetTokenInformation(TokenElevation)` on it. If either of these are false, then it fetched the linked token using `GetTokenInformation(TokenLinkedToken)` and queries the same. Only then does it spawn the UI process as that the elevated user token, passing it three unnamed pipe handles for IPC and the log mapping handle, as described above.
  - In the event that the administrator has set `HKLM\Software\WireGuard\LimitedOperatorUI` to 1, sessions are started for users that are a member of group S-1-5-32-556 (determined sing `CheckTokenMembership(CreateWellKnownSid(WinBuiltinNetworkConfigurationOperatorsSid))` on it and its linked token), with a more limited IPC interface, in which these non-admin users are denied private keys and tunnel editing rights. (This means users can potentially DoS the IPC server by draining notifications too slowly, or exhausting memory of the manager by spawning too many watcher go routines, or by sending garbage data that Go's `gob` decoder isn't expecting.)

### UI

The UI is a process running for each user who is in the Administrators group (per the above), running with the elevated high integrity linked token. It exposes:

  - Since the UI process is executed with an elevated token, it runs at high integrity and should be immune to various shatter attacks, modulo the great variety of clever bypasses in the latest Windows release.
  - It uses `AdjustTokenPrivileges` to remove all privileges.
  - It writes two kinds of files to a place the user picks in a save dialog, with the user's own rights: a CSV of a tunnel's history, and a diagnostics text file (state, path, test results, recent log lines). Private and preshared keys are never written to the diagnostics file, public keys are shortened, and addresses and host names are replaced unless the user chooses to include them.
  - It renders highlighted config files to a msftedit.dll control, which typically is capable of all sorts of OLE and RTF nastiness that we make some attempt to avoid.

### Updates

A server hosts the result of `b2sum -l 256 *.msi > list && signify -S -e -s release.sec -m list && upload ./list.sec`, with the private key stored on an HSM. The MSIs in that list are only the latest ones available, and filenames fit the form `wireguard-${arch}-${version}.msi`. The updater, running as part of the manager service, downloads this list over TLS and verifies the signify Ed25519 signature of it. If it validates, then it finds the first MSI in it for its architecture that has a greater version. It then downloads this MSI from a predefined URL to a randomly generated (256-bits) file name inside `C:\Windows\Temp` with permissions of `O:SYD:PAI(A;;FA;;;SY)(A;;FR;;;BA)`, scheduled to be cleaned up at next boot via `MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT)`, and verifies the BLAKE2b-256 signature. If it validates, then it executes the installer with `msiexec.exe /qb!- /i`, using the elevated token linked to the IPC UI session that requested the update. Because `msiexec` requires exclusive access to the file, the file handle is closed in between the completion of downloading and the commencement of `msiexec`. Hopefully the permissions of `C:\Windows\Temp` are good enough that an attacker can't replace the MSI from beneath us.
