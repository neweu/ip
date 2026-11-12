<div align="center">

# Network — Native Telemetry

**A zero-dependency, single-file C++ native network telemetry, proxy tunnel analyzer, and socket attribution engine.**

![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Win32%20x64-0078D6.svg)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen.svg)
![Rendering](https://img.shields.io/badge/UI-Direct2D%20%2B%20DWM-purple.svg)
![License](https://img.shields.io/badge/License-MIT-orange.svg)

</div>

---

## Overview

**Network** is a lightweight, hardware-accelerated native desktop utility designed for real-time network traffic visualization, local proxy discovery, Layer-3 TUN route analysis, and per-process socket attribution.

Engineered entirely within a single C++ source file (`ip.cpp`) using pure operating system APIs and the C++ Standard Library, it requires **zero external libraries, zero runtime frameworks, and zero configuration files**. It compiles into a standalone executable of approximately **150 KB** with instant cold-start performance and sub-millisecond UI rendering.

---

## Key Features

### 1. Dual-Stack Public Endpoint Telemetry
* **Direct Route Probing:** Queries `https://ipinfo.io/json` and `https://v6.ipinfo.io/json` over the native operating system routing stack to resolve public IPv4/IPv6 addresses, geolocation, timezone, ASN, ISP organization, and round-trip latency.
* **Privacy Masking:** Built-in one-click privacy toggle (`Hide` / `Show`) that masks public IPv4 and IPv6 segments directly in the rendering pipeline for safe screen sharing and screenshots.
* **Smart Caching & Rate-Limit Protection:** Caches verified endpoint metadata with a 5-minute TTL and only triggers network re-validation when route topology changes or when manually refreshed.

### 2. Autonomous Local Proxy Discovery & Tunnel Verification
* **Protocol Fingerprinting:** Automatically scans active local loopback (`127.0.0.1`) listening ports owned by non-system processes and performs fast, non-blocking protocol handshakes to identify active **SOCKS5** and **HTTP CONNECT** proxy servers—even if system-wide proxy settings are disabled.
* **Native TLS-over-Proxy Probing:** Implements a custom TLS client state machine directly over raw sockets using the native `Schannel` (SSPI) security provider (`AcquireCredentialsHandleW`, `InitializeSecurityContextW`, `EncryptMessage`, `DecryptMessage`) with automatic certificate chain validation (`SCH_CRED_AUTO_CRED_VALIDATION`).
* **True End-to-End RTT Measurement:** Tunnels encrypted HTTPS requests through each discovered local proxy port to `ipinfo.io` to determine the true external exit IPv4/IPv6, geolocation, and real remote handshake latency for up to 6 concurrent local proxy instances.

### 3. Loopback Socket Stitching & Process Attribution
* **Full Chain-of-Custody Mapping:** Standard network monitors show proxied application traffic terminating at `127.0.0.1:Port`. **Network** correlates the client socket (`Client PID -> 127.0.0.1:Port`) with the listening proxy process (`Proxy PID`) and inspects the proxy process's active external sockets (`Proxy PID -> Remote IP:Port`).
* **Multi-Node Awareness:** Accurately attributes local application flows to their corresponding local proxy protocol, port, owning process, and active remote upstream endpoints.

### 4. Layer-3 TUN Virtual Adapter & Route Takeover Detection
* **Routing Table Inspection:** Evaluates active network interfaces and queries the kernel routing table (`GetBestInterface`) against public anycast routing targets (`1.1.1.1` and `8.8.8.8`) to detect active Layer-3 virtual tunnel (`TUN`) adapters.
* **Bypass Identification:** Distinguishes between processes routed through the virtual TUN interface (`TUNNELED`) and proxy core processes binding directly to the physical LAN interface (`DIRECT`) to prevent routing loops.

### 5. Zero-Wire DNS Cache Resolution & Async PTR Engine
* **Instant Domain Mapping:** Dynamically inspects the local resolver cache table (`DnsGetCacheDataTable` combined with `DNS_QUERY_NO_WIRE_QUERY`) to map raw remote IPv4 addresses back to their original queried domain names with zero network packet overhead.
* **Asynchronous Reverse DNS:** Uncached remote IP addresses are dispatched to a background worker thread (`GetNameInfoW`) for non-blocking reverse `PTR` resolution.

### 6. Hardware-Accelerated Glassmorphic UI
* **Modern Borderless Window:** Integrates with the Desktop Window Manager (`DWM`) to provide native dark mode, rounded window geometry, system backdrop materials, and custom hit-testing (`WM_NCHITTEST` / `WM_NCCALCSIZE`) for seamless resizing and snapping.
* **Direct2D & DirectWrite Engine:** Renders real-time cubic Bezier throughput charts with linear gradient fills and custom symmetric grayscale text rendering parameters (`DWRITE_RENDERING_MODE_NATURAL_SYMMETRIC`) for crisp typography on translucent surfaces.

---

## Architecture

The application is architected around a lock-minimized, multi-threaded pipeline to ensure the UI thread remains completely non-blocking at high refresh rates:

~~~text
+-------------------------------------------------------------------------+
|                        Main UI Thread (Win32 + D2D1)                    |
|  - Borderless DWM Glass Frame & Custom Hit-Testing                      |
|  - 60+ FPS Direct2D Rendering & Cubic Bezier Bandwidth Charts           |
|  - Read-Only State Rendering (Zero I/O or Thread Creation in WM_PAINT)  |
+------------------------------------+------------------------------------+
                                     |
                      Microsecond CriticalSection Swap
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+-----------------+       +---------------------+       +-----------------+
| Telemetry       |       | Endpoint Probe      |       | Reverse DNS     |
| Worker Thread   |       | Worker Thread       |       | Worker Thread   |
+-----------------+       +---------------------+       +-----------------+
| - GetIfTable2   |       | - Local Port Probe  |       | - Async PTR     |
| - AdaptersInfo  |       |   (SOCKS5 / HTTP)   |       |   GetNameInfoW  |
| - Extended TCP  |       | - Direct OS HTTPS   |       | - Updates       |
|   Table & PIDs  |       |   (WinINet)         |       |   dnsCacheMap   |
| - DNS Cache     |       | - Proxy Tunnel TLS  |       +-----------------+
|   Inspection    |       |   (Winsock+Schannel)|
+-----------------+       | - Queries ipinfo.io |
                          +---------------------+
~~~

---

## Interface Overview

The user interface is organized into three primary telemetry views:

1. **Dashboard**
   * **Network Speed:** Real-time download/upload throughput with a 60-second dual-series cubic Bezier history graph.
   * **Network Detection:** System route public IPv4/IPv6, geolocation, ASN/ISP, RTT badge, privacy mask toggle, and manual refresh trigger.
   * **Proxy Outbound:** Scrollable list of all auto-detected local `SOCKS5` and `HTTP` proxy ports, displaying each port's owning process, system proxy status (`[Sys]`), external exit IPv4/IPv6, geolocation, and true tunnel latency.
   * **Live Activity Stream:** Chronological real-time feed of newly established outbound process connections.
   * **Compact Status Cards:** At-a-glance cards for **TUN** status, **Proxy Ports** summary, session/total **Traffic Usage**, and primary **Intranet IP** / Gateway.

2. **Connections**
   * **Live Event Log (Time):** Timestamped history of up to 2,000 recent outbound connection events.
   * **Active Sockets:** Real-time list of all established external and proxied TCP connections with process name, PID, route badge (`PROXY`, `TUN`, `DIRECT`), and resolved target domain/IP.
   * **Proxied / TUN Log:** Filtered stream isolating traffic routed through local proxies or virtual TUN interfaces.
   * **Verified Ports:** Detailed view of all active non-system listening ports and verified local proxy servers, including active loopback client counts.

3. **Interfaces**
   * Comprehensive list of active physical and virtual network adapters, displaying operational status (`[UP]`, `[DOWN]`, `[TUN]`), interface description, IPv4, IPv6, Default Gateway, link speed (Mbps), and cumulative Rx/Tx byte counters.

---

## Building from Source

### Prerequisites
* **Architecture:** x64
* **Compiler:** C++17 compatible native compiler (`cl.exe`) with the standard platform SDK headers and libraries (`d2d1.lib`, `dwrite.lib`, `iphlpapi.lib`, `ws2_32.lib`, `wininet.lib`, `dnsapi.lib`, `secur32.lib`, `dwmapi.lib`, `user32.lib`, `gdi32.lib`).

### Single-Command Compilation
Open the **x64 Native Tools Command Prompt** and run:

~~~cmd
cl /O2 /EHsc /utf-8 /W4 ip.cpp /link /SUBSYSTEM:WINDOWS
~~~

### Optional: Embedding an Application Icon
The source code automatically looks for an icon resource with ID `101` (`IDI_APP_ICON`). To embed a custom `.ico` file:

1. Create a file named `resource.rc` in the same directory:

~~~rc
101 ICON "app.ico"
~~~

2. Compile the resource and link it with `ip.cpp`:

~~~cmd
rc resource.rc
cl /O2 /EHsc /utf-8 /W4 ip.cpp resource.res /link /SUBSYSTEM:WINDOWS
~~~

---

## Privacy & Security Transparency

### External Network Requests
This utility does **not** collect, store, or transmit any telemetry, analytics, or personal data to any developer-controlled servers.
* The **only** external network requests made by this software are HTTPS `GET` requests to:
  * `https://ipinfo.io/json`
  * `https://v6.ipinfo.io/json`
* These requests are performed strictly to resolve your current public IPv4/IPv6 address, ASN, and geolocation for display in the local UI.
* Clicking the **Pause** button halts background interface polling, and public IP checks are cached locally to minimize external requests.

### Note on Low-Level OS APIs & Heuristic Scanners
Because this tool performs deep local network introspection without external drivers, it utilizes several advanced operating system APIs:
* `GetExtendedTcpTable` & `CreateToolhelp32Snapshot` — to correlate active TCP sockets with their owning process IDs (`PID`) and executable names.
* `DnsGetCacheDataTable` & `DnsQuery_W` (`DNS_QUERY_NO_WIRE_QUERY`) — to resolve IP addresses in the UI using the local DNS cache without generating external DNS traffic.
* Localhost (`127.0.0.1`) socket probing — to automatically detect whether local listening ports speak `SOCKS5` or `HTTP` proxy protocols.
* Direct `Schannel` (`secur32.lib`) SSPI calls — to perform native TLS handshakes over raw proxy sockets.

All source code is contained within a single, human-readable file (`ip.cpp`) and can be audited and compiled directly from source in seconds.

---

## Attribution

* Public IP address, ASN, and geolocation data are powered by **[IPinfo](https://ipinfo.io)**.

---

## License

This project is licensed under the **MIT License**.

~~~text
MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
~~~