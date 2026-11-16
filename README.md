# Network — Native Windows Telemetry & Route Inspector

<img width="1040" height="660" alt="Screenshot 2026-11-17 072645" src="https://github.com/user-attachments/assets/2190015b-0cff-48ed-8b99-f62cfe931bed" />

**Network** (`ip.cpp`) is a single-file, zero-dependency, hardware-accelerated network telemetry and route inspection utility for Windows 10 and Windows 11. Written in pure C++ using native Win32, Direct2D, DirectWrite, IP Helper (`iphlpapi`), and SSPI/Schannel APIs, it compiles into a standalone executable of **~150 KB** with a minimal memory footprint and zero external runtime requirements.

Unlike conventional network monitors that only display raw socket tables or adapter counters, **Network** correlates kernel TCP state tables, local loopback proxy handshakes, Layer-3 TUN routing tables, and in-memory OS DNS caches to provide real-time visibility into **how each process actually exits your machine**—whether directly over a physical NIC, through a local `SOCKS5`/`HTTP` proxy port, or inside a virtual `TUN` tunnel.

---

## Key Features

### 1. Dual-Stack Public Endpoint Telemetry
* **Direct Route Probing**: Queries `ipinfo.io` (IPv4) and `v6.ipinfo.io` (IPv6) over the operating system's default physical/system route to resolve your public IPv4/IPv6 addresses, geographic location, timezone, and ASN/ISP organization.
* **Privacy Masking**: One-click `Show` / `Hide` toggle on the dashboard masks public IPv4 and IPv6 addresses for safe screen sharing and screenshots.
* **Smart Caching & Rate-Limit Protection**: Automatically caches endpoint metadata for 5 minutes and only triggers background re-probing when a route topology change is detected (e.g., TUN adapter state change or System Proxy toggle) or when manually refreshed.

### 2. Autonomous Local Proxy Discovery & Tunnel Verification
* **Non-Intrusive Protocol Fingerprinting**: Automatically inspects active local loopback (`127.0.0.1`) listening ports owned by non-system processes—intelligently bypassing privileged system ports (`<1024`), known database/debugger ports, and idle Windows ephemeral IPC ranges (`49152–65535`)—to identify active `SOCKS5` and `HTTP CONNECT` proxy servers via fast, per-PID cached non-blocking handshakes, even when Windows System Proxy settings are disabled.
* **Native TLS-over-Proxy Probing**: Establishes raw TCP tunnels through discovered local `SOCKS5` or `HTTP` proxy ports and performs a full native **Win32 SSPI/Schannel TLS handshake** directly over the tunneled socket to determine the true external exit IP, ASN, and geolocation of each local proxy instance.
* **True End-to-End RTT Measurement**: Measures round-trip latency (`ms`) immediately upon completion of the remote TLS handshake over the proxy tunnel.

### 3. Loopback Socket Stitching & Process Attribution
* **Full Chain-of-Custody Mapping**: When an application connects to a local proxy on `127.0.0.1`, standard tools only show `App.exe -> 127.0.0.1:Port`. **Network** cross-references the client PID's loopback connection with the owning proxy server PID's remote outbound sockets, stitching the full path:
  `ClientProcess.exe (#PID) -> via SOCKS5 :Port (ProxyCore.exe) -> RemoteDomain (RemoteIP:Port)`.

### 4. Layer-3 TUN Virtual Adapter & Route Takeover Detection
* **Routing Table Inspection**: Uses `GetBestInterface` against global anycast roots (`1.1.1.1` / `8.8.8.8`) alongside `GetAdaptersAddresses` and `GetIfTable2` to distinguish between a passive virtual adapter (`TUN Up`) and an active full-system route takeover (`Global TUN Route`).
* **Bypass Identification**: Detects processes binding directly to the physical LAN interface IP to bypass an active TUN route, labeling each socket accurately as `TUNNELED` vs. `DIRECT`.

### 5. Zero-Wire DNS Cache Resolution & Async PTR Engine
* **Instant Domain Mapping**: Reads the Windows internal DNS resolver cache in-memory (`DnsGetCacheDataTable` + `DnsQuery_W` with `DNS_QUERY_NO_WIRE_QUERY`) to map remote IPv4 addresses back to their queried domain names with zero network overhead.
* **Asynchronous Reverse DNS**: Queues unmapped public IPs to a background worker thread performing non-blocking `GetNameInfoW` PTR lookups without stalling the UI render loop.

### 6. Hardware-Accelerated Glassmorphic UI
* **Modern Borderless Window**: Integrates with the Windows 11 Desktop Window Manager (`DWMWA_SYSTEMBACKDROP_TYPE`, `DWMWA_WINDOW_CORNER_PREFERENCE`, `DWMWA_USE_IMMERSIVE_DARK_MODE`) for native Mica/Acrylic dark glass aesthetics and Per-Monitor V2 High-DPI scaling (`WM_DPICHANGED`).
* **Direct2D & DirectWrite Engine**: Renders anti-aliased cubic Bezier throughput charts, custom scroll views, and sub-pixel grayscale typography (`Segoe UI Variable Display` & `Cascadia Mono`) at 60 FPS with near-zero CPU utilization.

---

## Interface Overview

The application is organized into three primary views accessible from the left navigation rail:

### Dashboard
* **Realtime Throughput**: Real-time download/upload throughput (`B/s`, `KB/s`, `MB/s`, `GB/s`) with a 60-second dual-series cubic Bezier history graph.
* **Public Endpoint**: System route public IPv4/IPv6, geolocation, ASN/ISP, RTT badge, privacy mask toggle (`Show`/`Hide`), and manual `Refresh` trigger.
* **Proxy Outbound**: Scrollable list of all auto-detected local `SOCKS5` and `HTTP` proxy ports, displaying each port's owning process, system proxy status (`[Sys]`), external exit IPv4/IPv6, geolocation, and true tunnel latency.
* **Live Activity Stream**: Chronological real-time feed of newly established outbound process connections (click to jump directly to the full Connections log).
* **Compact Status Cards**: At-a-glance telemetry cards for **Virtual TUN** status, **Proxy Ports** summary, session/total **Session Traffic**, and primary **Local Network** (IPv4 / IPv6 / Default Gateway).

### Connections
Includes four filterable sub-views and a `Clear Log` action:
1. **Live Event Log (Time)**: Chronological stream (up to 2,000 events) recording every new outbound connection with timestamp, route badge (`PROXY`, `TUN`, `DIRECT`), process name & PID, proxy hop details, and resolved remote target.
2. **Active Sockets**: Real-time snapshot of all currently `ESTABLISHED` outbound TCP connections.
3. **Proxied / TUN Log**: Filtered event stream showing only connections routed through local proxies or TUN interfaces.
4. **Verified Ports**: Lists local listening ports owned by non-OS processes, highlighting verified `SOCKS5` and `HTTP` proxy servers alongside their active client counts and external exit IPs.

### Interfaces
* Displays all active and inactive network adapters (`[TUN]`, `[UP]`, `[DOWN]`), friendly names, hardware descriptions, IPv4/IPv6 addresses, default gateways, link speeds (`Mbps`), and cumulative `Rx` / `Tx` byte counters.

---

## Building from Source

The entire application is self-contained in `ip.cpp` and links exclusively against standard Windows SDK libraries via `#pragma comment(lib, ...)` directives.

### Prerequisites
* **OS**: Windows 10 (1809+) or Windows 11
* **Compiler**: Microsoft Visual C++ (MSVC / Visual Studio 2019 or 2022) or Clang-CL with the Windows 10/11 SDK installed.

### Compile via Developer Command Prompt (MSVC)
Open the **x64 Native Tools Command Prompt for VS** and run:

```bat
cl /O2 /EHsc /utf-8 /W4 ip.cpp /link /SUBSYSTEM:WINDOWS
```

### Optional Application Icon
If you wish to embed a custom `.ico` file (`IDI_APP_ICON` = `101`), create an `app.rc` file:
```rc
101 ICON "app.ico"
```
Compile and link with the resource file:
```bat
rc app.rc
cl /O2 /EHsc /utf-8 /W4 ip.cpp app.res /link /SUBSYSTEM:WINDOWS
```

---

## Privacy & Security Transparency

### External Network Requests
To resolve public exit IP addresses, ASN, and geolocation metadata, **Network** makes HTTPS `GET` requests exclusively to:
* `https://ipinfo.io/json` (IPv4 endpoint detection)
* `https://v6.ipinfo.io/json` (IPv6 endpoint detection)

No other external servers are contacted, and no user telemetry, analytics, or connection logs ever leave your machine. You can pause all background polling at any time using the **Pause / Resume** button in the bottom-right corner.

### Note on Low-Level OS APIs & Heuristic Scanners
Because **Network** is a standalone native binary that inspects system-wide routing and socket tables without requiring a kernel driver, it uses legitimate Windows diagnostic APIs including:
* `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`) & `CreateToolhelp32Snapshot` to map sockets to process names.
* `DnsGetCacheDataTable` (`dnsapi.dll`) to read the local DNS resolver cache without generating outbound DNS queries.
* Non-intrusive `127.0.0.1` loopback socket handshakes (`ShouldProbeLocalPort` + `ProbeLocalPortProtocol`) and direct `Schannel` TLS contexts (`InitializeSecurityContextW` / `EncryptMessage` / `DecryptMessage`) to verify local proxy tunnels independently of WinINet global settings.

If you compile an unsigned binary from source or download an unsigned release, some heuristic antivirus engines may flag these diagnostic API combinations. Building directly from `ip.cpp` using the single-line `cl` command above guarantees a 100% verifiable binary.

---

## License

Released under the [Apache License 2.0](LICENSE).
