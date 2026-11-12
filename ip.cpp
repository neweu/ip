#define UNICODE
#define _UNICODE
#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windowsx.h>
#include <wininet.h>
#include <windns.h>
#include <security.h>
#include <schannel.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <d2d1.h>
#include <dwrite.h>
#include <dwmapi.h>

#include <vector>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "d2d1.lib")
#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#define IDI_APP_ICON          101
#define WM_USER_IP_UPDATED    (WM_USER + 101)
#define WM_USER_STATS_UPDATED (WM_USER + 102)

typedef struct _DNS_CACHE_ENTRY {
 struct _DNS_CACHE_ENTRY* pNext;
 PWSTR pszName;
 WORD wType;
 WORD wDataLength;
 DWORD dwFlags;
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;
typedef BOOL(WINAPI* PFN_DnsGetCacheDataTable)(PDNS_CACHE_ENTRY* ppEntry);

static inline D2D1_COLOR_F HexColor(UINT32 h, float a = 1.0f) {
 return D2D1::ColorF((h >> 16 & 0xFF) / 255.0f, (h >> 8 & 0xFF) / 255.0f, (h & 0xFF) / 255.0f, a);
}
static inline D2D1_RECT_F RF(float l, float t, float r, float b) { return D2D1::RectF(l, t, r, b); }

template <class T>
static inline void SafeRelease(T** ppT) {
 if (*ppT) { (*ppT)->Release(); *ppT = nullptr; }
}

struct DarkGlassPalette {
 D2D1_COLOR_F bg            = HexColor(0x08080A, 0.74f);
 D2D1_COLOR_F navBg         = HexColor(0x0E0E12, 0.84f);
 D2D1_COLOR_F cardBg        = HexColor(0x1A1A20, 0.62f);
 D2D1_COLOR_F cardInnerBg   = HexColor(0x0F0F13, 0.58f);
 D2D1_COLOR_F cardBorder    = HexColor(0xFFFFFF, 0.11f);
 D2D1_COLOR_F cardTopGlow   = HexColor(0xFFFFFF, 0.18f);
 D2D1_COLOR_F logoBg        = HexColor(0x23232B, 0.95f);
 D2D1_COLOR_F logoBorder    = HexColor(0xFFFFFF, 0.24f);
 D2D1_COLOR_F pillBg        = HexColor(0x282832, 0.85f);
 D2D1_COLOR_F textWhite     = HexColor(0xFFFFFF, 1.00f);
 D2D1_COLOR_F textBright    = HexColor(0xE6E6EC, 0.95f);
 D2D1_COLOR_F textMuted     = HexColor(0x9494A0, 0.90f);
 D2D1_COLOR_F accentGreen   = HexColor(0x7EE787, 1.00f);
 D2D1_COLOR_F chartLineMain = HexColor(0xFFFFFF, 0.95f);
 D2D1_COLOR_F chartLineSub  = HexColor(0x8A8A98, 0.85f);
} g_pal;

enum LocalProxyProto { PROXY_PROTO_UNKNOWN = -1, PROXY_PROTO_NONE = 0, PROXY_PROTO_SOCKS5 = 1, PROXY_PROTO_HTTP = 2 };
enum FlowRouteType   { FLOW_DIRECT = 0, FLOW_LOCALPROXY = 1, FLOW_TUN = 2, FLOW_LISTEN = 3 };

struct ListenPortInfo { u_short port; DWORD pid; std::wstring procName; int activeClients; LocalProxyProto verifiedProto; };
struct VerifiedPortCacheEntry { DWORD pid; LocalProxyProto proto; ULONGLONG lastProbeTick; };
struct EndpointIpResult { std::wstring ipv4 = L"Detecting...", ipv6 = L"Detecting...", location = L"Probing ipinfo.io...", orgLine = L"--"; int latencyMs = -1; };
struct ProxyIpCacheEntry { DWORD pid; LocalProxyProto proto; EndpointIpResult outbound; ULONGLONG lastFetchTick; };
struct VerifiedProxyInstance { u_short port; DWORD pid; LocalProxyProto proto; std::wstring procName; bool isSysProxy; EndpointIpResult outbound; };
struct FlowItem { FlowRouteType routeType; std::wstring badgeText, procName; DWORD pid; std::wstring viaText, targetDisplay, stateText; };
struct LogEventItem { std::wstring timeStr; FlowRouteType routeType; std::wstring badgeText, procName; DWORD pid; std::wstring viaText; DWORD remoteIpNet; u_short remotePortHost; std::wstring customTarget; };
struct AdapterItem { NET_IFINDEX ifIndex; std::wstring name, desc, ipv4, ipv6, mac, gateway, dns; ULONG64 linkSpeedMbps, inBytes, outBytes; bool isUp, isTun; };

struct AppState {
 HWND hwnd = nullptr;
 volatile LONG isShuttingDown = 0;

 ID2D1Factory* pD2DFactory = nullptr;
 ID2D1HwndRenderTarget* pRT = nullptr;
 IDWriteFactory* pDWriteFactory = nullptr;

 IDWriteTextFormat *tfLogo = nullptr, *tfTitle = nullptr, *tfNav = nullptr, *tfCardTitle = nullptr;
 IDWriteTextFormat *tfHeroIp = nullptr, *tfHeroSubV6 = nullptr, *tfSpeedVal = nullptr;
 IDWriteTextFormat *tfSecValue = nullptr, *tfBody = nullptr, *tfSmall = nullptr, *tfTiny = nullptr, *tfMono = nullptr;

 float dpiScale = 1.0f, width = 1040.0f, height = 660.0f;
 bool isPaused = false, maskPublicIp = false;
 int currentTab = 0, connFilter = 0;
 float scrollY = 0.0f, proxyCardScrollY = 0.0f, dashLogScrollY = 0.0f, mouseX = -1.0f, mouseY = -1.0f;
 D2D1_RECT_F rcEyeBtn = { 0 }, rcRefreshIpBtn = { 0 }, rcProxyCardArea = { 0 }, rcFlowsPreviewCard = { 0 }, rcClearLogBtn = { 0 };

 std::vector<float> downHistory, upHistory;
 ULONG64 lastInBytes = 0, lastOutBytes = 0, sessionInBytes = 0, sessionOutBytes = 0, totalSysInBytes = 0, totalSysOutBytes = 0;
 ULONGLONG lastTick = 0;
 double curDownSpeed = 0.0, curUpSpeed = 0.0;

 bool tunActive = false, tunTakeoverRoute = false;
 std::wstring tunAdapterName = L"Disabled", tunAdapterIp = L"--";
 bool sysProxyEnabled = false;
 std::wstring sysProxyServer = L"Disabled";
 int cntProxiedFlows = 0, cntTunFlows = 0, cntDirectFlows = 0;

 std::vector<ListenPortInfo> unknownListenPorts;
 std::unordered_map<u_short, VerifiedPortCacheEntry> portCache;
 std::unordered_map<u_short, ProxyIpCacheEntry> proxyIpCache;
 ULONGLONG lastSysIpFetchTick = 0;

 bool isCheckingIp = false, pendingIpRecheck = false, forceIpRefresh = false;
 bool isUpdatingStats = false;
 EndpointIpResult sysRoute;
 std::vector<VerifiedProxyInstance> verifiedProxies;

 std::unordered_map<DWORD, std::wstring> dnsCacheMap;
 std::unordered_set<std::wstring> queriedDnsNames;
 ULONGLONG lastDnsFullFlushTick = 0;
 std::unordered_set<DWORD> pendingPtrIps;
 bool ptrWorkerBusy = false;

 std::unordered_set<std::wstring> seenConnKeys;
 std::deque<LogEventItem> eventLog;

 bool prevTunActive = false, prevSysProxyEnabled = false, firstRunDone = false;
 std::wstring prevSysProxyServer = L"";
 std::wstring windowsDirPrefix;
 HMODULE hDnsDll = nullptr;
 PFN_DnsGetCacheDataTable pfnDnsGetCacheDataTable = nullptr;

 AdapterItem primaryAdapter;
 std::vector<AdapterItem> adapters;
 std::vector<FlowItem> flows;
 CRITICAL_SECTION dataLock;

 AppState() {
  InitializeCriticalSection(&dataLock);
  downHistory.assign(60, 0.0f);
  upHistory.assign(60, 0.0f);
  primaryAdapter = { 0, L"No Active Adapter", L"", L"0.0.0.0", L"Unavailable", L"--", L"--", L"--", 0, 0, 0, false, false };
  wchar_t winDir[MAX_PATH] = { 0 };
  if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0) {
   windowsDirPrefix = winDir;
   for (auto& c : windowsDirPrefix) c = towlower(c);
  }
  hDnsDll = LoadLibraryW(L"dnsapi.dll");
  if (hDnsDll) pfnDnsGetCacheDataTable = (PFN_DnsGetCacheDataTable)GetProcAddress(hDnsDll, "DnsGetCacheDataTable");
 }

 ~AppState() {
  if (hDnsDll) FreeLibrary(hDnsDll);
  DeleteCriticalSection(&dataLock);
 }
} g_app;

static void TriggerPublicIpCheck(bool forceRefresh);

static std::wstring Utf8ToWide(const std::string& s) {
 if (s.empty()) return L"";
 int sz = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
 std::wstring res(sz, 0);
 MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &res[0], sz);
 return res;
}

static std::wstring ExtractJsonStr(const std::wstring& j, const std::wstring& k) {
 std::wstring pat = L"\"" + k + L"\"";
 size_t p = j.find(pat);
 if (p == std::wstring::npos || (p = j.find(L':', p + pat.length())) == std::wstring::npos) return L"";
 size_t s = j.find(L'"', p + 1);
 if (s == std::wstring::npos) return L"";
 size_t e = s + 1;
 while (e < j.size()) {
  if (j[e] == L'"' && j[e - 1] != L'\\') break;
  e++;
 }
 return (e >= j.size()) ? L"" : j.substr(s + 1, e - s - 1);
}

static std::wstring MaskIpString(const std::wstring& ip) {
 if (ip.empty() || ip == L"Detecting..." || ip == L"Unavailable" || ip == L"Failed" || ip == L"No Proxy Active") return ip;
 size_t d = ip.find(L'.');
 if (d != std::wstring::npos) return ip.substr(0, d) + L".***.***.***";
 size_t c = ip.find(L':');
 return (c != std::wstring::npos) ? (ip.substr(0, c) + L":****:****:****:****") : L"***.***.***.***";
}

static std::wstring FormatBytes(double b, bool spd) {
 const wchar_t* u[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
 int i = 0;
 while (b >= 1024.0 && i < 4) { b /= 1024.0; i++; }
 wchar_t buf[64];
 swprintf(buf, 64, (i == 0) ? L"%.0f %s%s" : L"%.2f %s%s", b, u[i], spd ? L"/s" : L"");
 return buf;
}

static std::wstring IpToStr(DWORD ip) {
 unsigned char* b = (unsigned char*)&ip;
 wchar_t buf[32];
 swprintf(buf, 32, L"%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
 return buf;
}

static std::wstring GetCurrentTimeStr() {
 SYSTEMTIME st; GetLocalTime(&st);
 wchar_t buf[32]; swprintf(buf, 32, L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
 return buf;
}

static void RefreshWindowsDnsCacheTable() {
 if (!g_app.pfnDnsGetCacheDataTable) return;
 PDNS_CACHE_ENTRY pEntry = nullptr;
 if (!g_app.pfnDnsGetCacheDataTable(&pEntry) || !pEntry) return;

 ULONGLONG nowTick = GetTickCount64();
 std::unordered_set<std::wstring> knownNames;
 EnterCriticalSection(&g_app.dataLock);
 if (nowTick - g_app.lastDnsFullFlushTick > 60000) {
  g_app.queriedDnsNames.clear();
  g_app.lastDnsFullFlushTick = nowTick;
 }
 knownNames = g_app.queriedDnsNames;
 LeaveCriticalSection(&g_app.dataLock);

 std::unordered_map<DWORD, std::wstring> newMap;
 std::vector<std::wstring> newlyQueried;
 PDNS_CACHE_ENTRY c = pEntry;
 int cnt = 0;
 while (c) {
  PDNS_CACHE_ENTRY next = c->pNext;
  if (cnt < 250 && c->pszName && c->wType == DNS_TYPE_A) {
   std::wstring domainName = c->pszName;
   if (knownNames.find(domainName) == knownNames.end()) {
    knownNames.insert(domainName);
    newlyQueried.push_back(domainName);
    PDNS_RECORDW pRec = nullptr;
    if (DnsQuery_W(c->pszName, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, nullptr, (PDNS_RECORD*)&pRec, nullptr) == 0 && pRec) {
     for (PDNS_RECORDW r = pRec; r; r = r->pNext)
      if (r->wType == DNS_TYPE_A) newMap[r->Data.A.IpAddress] = domainName;
     DnsRecordListFree((PDNS_RECORD)pRec, DnsFreeRecordList);
    }
    cnt++;
   }
  }
  if (c->pszName) LocalFree(c->pszName);
  LocalFree(c);
  c = next;
 }
 if (!newMap.empty() || !newlyQueried.empty()) {
  EnterCriticalSection(&g_app.dataLock);
  for (const auto& name : newlyQueried) g_app.queriedDnsNames.insert(name);
  for (const auto& kv : newMap) g_app.dnsCacheMap[kv.first] = kv.second;
  LeaveCriticalSection(&g_app.dataLock);
 }
}

static DWORD WINAPI ReverseDnsWorkerThread(LPVOID) {
 while (InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) == 0) {
  DWORD ip = 0;
  EnterCriticalSection(&g_app.dataLock);
  if (!g_app.pendingPtrIps.empty()) {
   auto it = g_app.pendingPtrIps.begin();
   ip = *it; g_app.pendingPtrIps.erase(it);
  } else {
   g_app.ptrWorkerBusy = false;
   LeaveCriticalSection(&g_app.dataLock);
   break;
  }
  LeaveCriticalSection(&g_app.dataLock);

  sockaddr_in sa = { AF_INET, 0, {}, {} }; sa.sin_addr.s_addr = ip;
  wchar_t host[NI_MAXHOST] = { 0 };
  std::wstring dom = (GetNameInfoW((const SOCKADDR*)&sa, sizeof(sa), host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD) == 0) ? host : L"";

  EnterCriticalSection(&g_app.dataLock);
  if (g_app.dnsCacheMap.find(ip) == g_app.dnsCacheMap.end()) g_app.dnsCacheMap[ip] = dom;
  LeaveCriticalSection(&g_app.dataLock);

  if (g_app.hwnd && !dom.empty()) InvalidateRect(g_app.hwnd, nullptr, FALSE);
 }
 return 0;
}

static std::wstring FormatIpAndDomain(DWORD ipNet, u_short portHost, bool allowQueuePtr) {
 std::wstring ipStr = IpToStr(ipNet), dom;
 wchar_t pBuf[16]; swprintf(pBuf, 16, L":%u", portHost);
 bool startW = false;
 EnterCriticalSection(&g_app.dataLock);
 auto it = g_app.dnsCacheMap.find(ipNet);
 if (it != g_app.dnsCacheMap.end()) {
  dom = it->second;
 } else if (allowQueuePtr && ipNet != 0 && ipNet != htonl(INADDR_LOOPBACK) && (ipNet & 0xFF) != 10 && g_app.pendingPtrIps.size() < 35) {
  g_app.pendingPtrIps.insert(ipNet);
  if (!g_app.ptrWorkerBusy && InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) == 0) {
   g_app.ptrWorkerBusy = true;
   startW = true;
  }
 }
 LeaveCriticalSection(&g_app.dataLock);
 if (startW) {
  HANDLE h = CreateThread(nullptr, 0, ReverseDnsWorkerThread, nullptr, 0, nullptr);
  if (h) CloseHandle(h);
 }
 return (!dom.empty() && dom != ipStr) ? (dom + L" (" + ipStr + pBuf + L")") : (ipStr + pBuf);
}

static SOCKET ConnectLoopbackFast(u_short port, int timeoutMs) {
 SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
 if (s == INVALID_SOCKET) return INVALID_SOCKET;
 u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
 sockaddr_in addr = { AF_INET, htons(port), {}, {} }; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
 connect(s, (sockaddr*)&addr, sizeof(addr));
 fd_set wfds; FD_ZERO(&wfds); FD_SET(s, &wfds);
 timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
 if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) { closesocket(s); return INVALID_SOCKET; }
 int soErr = 0; int errLen = sizeof(soErr);
 if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&soErr, &errLen) != 0 || soErr != 0) {
  closesocket(s); return INVALID_SOCKET;
 }
 nb = 0; ioctlsocket(s, FIONBIO, &nb);
 DWORD to = 2500;
 setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
 setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
 return s;
}

static LocalProxyProto ProbeLocalPortProtocol(u_short port) {
 SOCKET s = ConnectLoopbackFast(port, 45);
 if (s != INVALID_SOCKET) {
  DWORD to = 65;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
  const unsigned char g[3] = { 0x05, 0x01, 0x00 }; unsigned char r[2] = { 0 };
  if (send(s, (const char*)g, 3, 0) == 3 && recv(s, (char*)r, 2, 0) == 2 && r[0] == 0x05 && r[1] == 0x00) {
   closesocket(s); return PROXY_PROTO_SOCKS5;
  }
  closesocket(s);
 }
 s = ConnectLoopbackFast(port, 45);
 if (s != INVALID_SOCKET) {
  DWORD to = 65;
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to));
  setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&to, sizeof(to));
  const char* p = "HEAD http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  char b[16] = { 0 };
  if (send(s, p, (int)strlen(p), 0) > 0 && recv(s, b, 12, 0) >= 5 && strncmp(b, "HTTP/", 5) == 0) {
   closesocket(s); return PROXY_PROTO_HTTP;
  }
  closesocket(s);
 }
 return PROXY_PROTO_NONE;
}

static bool IsHttpJsonResponseComplete(const std::string& raw) {
 size_t hdrEnd = raw.find("\r\n\r\n");
 if (hdrEnd == std::string::npos) return false;
 size_t bodyStart = hdrEnd + 4;
 if (bodyStart >= raw.size()) return false;

 size_t clPos = raw.find("Content-Length:");
 if (clPos == std::string::npos || clPos > hdrEnd) clPos = raw.find("content-length:");
 if (clPos != std::string::npos && clPos < hdrEnd) {
  int cl = atoi(raw.c_str() + clPos + 15);
  if (cl > 0) return (raw.size() - bodyStart) >= (size_t)cl;
 }

 size_t firstBrace = raw.find('{', bodyStart);
 if (firstBrace == std::string::npos) return false;
 int depth = 0; bool inStr = false, esc = false;
 for (size_t i = firstBrace; i < raw.size(); i++) {
  char c = raw[i];
  if (esc) { esc = false; continue; }
  if (c == '\\' && inStr) { esc = true; continue; }
  if (c == '"') { inStr = !inStr; continue; }
  if (!inStr) {
   if (c == '{') depth++;
   else if (c == '}') {
    depth--;
    if (depth == 0) return true;
   }
  }
 }
 return false;
}

static std::string PerformSchannelHttpsGet(SOCKET sock, const wchar_t* hostW, const char* hostA, const char* pathA, ULONGLONG t0, int* outMs) {
 SCHANNEL_CRED cred = { 0 };
 cred.dwVersion = SCHANNEL_CRED_VERSION;
 cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_AUTO_CRED_VALIDATION;

 CredHandle hCred; TimeStamp ts;
 if (AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W, SECPKG_CRED_OUTBOUND, nullptr, &cred, nullptr, nullptr, &hCred, &ts) != SEC_E_OK) return "";
 CtxtHandle hCtx = { 0 }; bool hasCtx = false; std::vector<char> inBuf;
 DWORD flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

 SECURITY_STATUS st = SEC_I_CONTINUE_NEEDED;
 while (st == SEC_I_CONTINUE_NEEDED || st == SEC_E_INCOMPLETE_MESSAGE) {
  SecBuffer inB[2] = { { (ULONG)inBuf.size(), SECBUFFER_TOKEN, inBuf.empty() ? nullptr : inBuf.data() }, { 0, SECBUFFER_EMPTY, nullptr } };
  SecBuffer outB[1] = { { 0, SECBUFFER_TOKEN, nullptr } };
  SecBufferDesc inD = { SECBUFFER_VERSION, 2, inB }, outD = { SECBUFFER_VERSION, 1, outB };
  DWORD outF = 0;
  st = InitializeSecurityContextW(&hCred, hasCtx ? &hCtx : nullptr, (SEC_WCHAR*)hostW, flags, 0, SECURITY_NATIVE_DREP,
                                  hasCtx ? &inD : nullptr, 0, hasCtx ? nullptr : &hCtx, &outD, &outF, &ts);
  hasCtx = true;
  if (outB[0].cbBuffer > 0 && outB[0].pvBuffer) { send(sock, (const char*)outB[0].pvBuffer, outB[0].cbBuffer, 0); FreeContextBuffer(outB[0].pvBuffer); }
  if (st == SEC_E_INCOMPLETE_MESSAGE) {
   char tmp[2048]; int r = recv(sock, tmp, sizeof(tmp), 0); if (r <= 0) break;
   inBuf.insert(inBuf.end(), tmp, tmp + r); continue;
  }
  if (inB[1].BufferType == SECBUFFER_EXTRA && inB[1].cbBuffer > 0) {
   size_t ex = inB[1].cbBuffer; memmove(inBuf.data(), inBuf.data() + (inBuf.size() - ex), ex); inBuf.resize(ex);
  } else inBuf.clear();
  if (st == SEC_I_CONTINUE_NEEDED && inBuf.empty()) {
   char tmp[2048]; int r = recv(sock, tmp, sizeof(tmp), 0); if (r <= 0) break;
   inBuf.insert(inBuf.end(), tmp, tmp + r);
  }
 }
 if (st != SEC_E_OK) { if (hasCtx) DeleteSecurityContext(&hCtx); FreeCredentialsHandle(&hCred); return ""; }

 // Measure true end-to-end RTT right after remote TLS handshake completes
 if (outMs && t0 > 0) *outMs = (int)(GetTickCount64() - t0);

 SecPkgContext_StreamSizes sz = { 0 };
 QueryContextAttributesW(&hCtx, SECPKG_ATTR_STREAM_SIZES, &sz);
 char req[512];
 int reqLen = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Network/1.0\r\nAccept: application/json\r\nConnection: close\r\n\r\n", pathA, hostA);
 std::vector<char> sBuf(sz.cbHeader + reqLen + sz.cbTrailer);
 memcpy(sBuf.data() + sz.cbHeader, req, reqLen);
 SecBuffer eB[4] = { { sz.cbHeader, SECBUFFER_STREAM_HEADER, sBuf.data() }, { (ULONG)reqLen, SECBUFFER_DATA, sBuf.data() + sz.cbHeader },
                     { sz.cbTrailer, SECBUFFER_STREAM_TRAILER, sBuf.data() + sz.cbHeader + reqLen }, { 0, SECBUFFER_EMPTY, nullptr } };
 SecBufferDesc eD = { SECBUFFER_VERSION, 4, eB };
 if (EncryptMessage(&hCtx, 0, &eD, 0) == SEC_E_OK) send(sock, sBuf.data(), eB[0].cbBuffer + eB[1].cbBuffer + eB[2].cbBuffer, 0);

 std::string dec;
 while (dec.size() < 32768) {
  if (inBuf.empty()) { char tmp[2048]; int r = recv(sock, tmp, sizeof(tmp), 0); if (r <= 0) break; inBuf.insert(inBuf.end(), tmp, tmp + r); }
  SecBuffer dB[4] = { { (ULONG)inBuf.size(), SECBUFFER_DATA, inBuf.data() }, {}, {}, {} };
  SecBufferDesc dD = { SECBUFFER_VERSION, 4, dB };
  SECURITY_STATUS ds = DecryptMessage(&hCtx, &dD, 0, nullptr);
  if (ds == SEC_E_INCOMPLETE_MESSAGE) { char tmp[2048]; int r = recv(sock, tmp, sizeof(tmp), 0); if (r <= 0) break; inBuf.insert(inBuf.end(), tmp, tmp + r); continue; }
  if (ds != SEC_E_OK && ds != SEC_I_CONTEXT_EXPIRED) break;
  size_t exLen = 0; char* exPtr = nullptr;
  for (int i = 1; i < 4; i++) {
   if (dB[i].BufferType == SECBUFFER_DATA && dB[i].cbBuffer > 0) dec.append((const char*)dB[i].pvBuffer, dB[i].cbBuffer);
   else if (dB[i].BufferType == SECBUFFER_EXTRA && dB[i].cbBuffer > 0) { exLen = dB[i].cbBuffer; exPtr = (char*)dB[i].pvBuffer; }
  }
  if (exLen > 0 && exPtr) { memmove(inBuf.data(), exPtr, exLen); inBuf.resize(exLen); } else inBuf.clear();
  if (ds == SEC_I_CONTEXT_EXPIRED || IsHttpJsonResponseComplete(dec)) break;
 }
 DeleteSecurityContext(&hCtx); FreeCredentialsHandle(&hCred);
 size_t hdrEnd = dec.find("\r\n\r\n");
 size_t searchPos = (hdrEnd != std::string::npos) ? (hdrEnd + 4) : 0;
 size_t bPos = dec.find('{', searchPos);
 return (bPos != std::string::npos) ? dec.substr(bPos) : "";
}

static std::string FetchHttpsViaLocalProxy(u_short port, LocalProxyProto proto, const wchar_t* hostW, const char* hostA, int* outMs) {
 ULONGLONG t0 = GetTickCount64();
 SOCKET s = ConnectLoopbackFast(port, 900);
 if (s == INVALID_SOCKET) return "";
 if (proto == PROXY_PROTO_SOCKS5) {
  const unsigned char g[3] = { 0x05, 0x01, 0x00 }; unsigned char gr[2] = { 0 };
  if (send(s, (const char*)g, 3, 0) != 3 || recv(s, (char*)gr, 2, 0) != 2 || gr[0] != 0x05 || gr[1] != 0x00) { closesocket(s); return ""; }
  size_t hLen = strlen(hostA);
  std::vector<unsigned char> req(7 + hLen);
  req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03; req[4] = (unsigned char)hLen;
  memcpy(&req[5], hostA, hLen); req[5 + hLen] = (443 >> 8) & 0xFF; req[6 + hLen] = 443 & 0xFF;
  unsigned char cr[4] = { 0 };
  if (send(s, (const char*)req.data(), (int)req.size(), 0) != (int)req.size() || recv(s, (char*)cr, 4, 0) != 4 || cr[0] != 0x05 || cr[1] != 0x00) { closesocket(s); return ""; }
  int dr = 2 + (cr[3] == 0x01 ? 4 : (cr[3] == 0x04 ? 16 : 0));
  if (cr[3] == 0x03) { unsigned char dl = 0; recv(s, (char*)&dl, 1, 0); dr += dl; }
  char dm[64]; while (dr > 0) { int r = recv(s, dm, (std::min)(dr, 64), 0); if (r <= 0) break; dr -= r; }
 } else if (proto == PROXY_PROTO_HTTP) {
  char cReq[256]; int len = snprintf(cReq, sizeof(cReq), "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", hostA, hostA);
  if (send(s, cReq, len, 0) != len) { closesocket(s); return ""; }
  std::string hdr; char ch = 0;
  while (hdr.size() < 1024 && recv(s, &ch, 1, 0) == 1) { hdr.push_back(ch); if (hdr.size() >= 4 && hdr.substr(hdr.size() - 4) == "\r\n\r\n") break; }
  if (hdr.find(" 200 ") == std::string::npos) { closesocket(s); return ""; }
 } else { closesocket(s); return ""; }

 std::string body = PerformSchannelHttpsGet(s, hostW, hostA, "/json", t0, outMs);
 closesocket(s);
 return body;
}

static std::string HttpGetDirectOS(const wchar_t* url, int* outMs, DWORD timeoutMs) {
 HINTERNET hInet = InternetOpenW(L"Network/1.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
 if (!hInet) return "";
 InternetSetOptionW(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
 InternetSetOptionW(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
 InternetSetOptionW(hInet, INTERNET_OPTION_SEND_TIMEOUT, &timeoutMs, sizeof(timeoutMs));
 ULONGLONG t0 = GetTickCount64();
 HINTERNET hUrl = InternetOpenUrlW(hInet, url, nullptr, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
 if (!hUrl) { InternetCloseHandle(hInet); if (outMs) *outMs = -1; return ""; }
 if (outMs) *outMs = (int)(GetTickCount64() - t0);
 std::string res; char buf[1024]; DWORD read = 0;
 while (InternetReadFile(hUrl, buf, sizeof(buf), &read) && read > 0) { res.append(buf, read); if (res.size() > 16384) break; }
 InternetCloseHandle(hUrl); InternetCloseHandle(hInet);
 return res;
}

static void ParseIpinfoJson(const std::wstring& json, EndpointIpResult& out) {
 std::wstring city = ExtractJsonStr(json, L"city"), reg = ExtractJsonStr(json, L"region");
 std::wstring ctry = ExtractJsonStr(json, L"country"), tz = ExtractJsonStr(json, L"timezone");
 std::wstring loc = ctry;
 if (!reg.empty())  loc += (loc.empty() ? L"" : L" \u00B7 ") + reg;
 if (!city.empty()) loc += (loc.empty() ? L"" : L" \u00B7 ") + city;
 if (!tz.empty()) loc += L" (" + tz + L")";
 out.location = loc.empty() ? L"Unknown Location" : loc;
 std::wstring org = ExtractJsonStr(json, L"org");
 if (!org.empty()) {
  size_t sp = org.find(L' ');
  out.orgLine = (sp != std::wstring::npos && org.substr(0, 2) == L"AS") ? (org.substr(0, sp) + L" \u00B7 " + org.substr(sp + 1)) : org;
 } else out.orgLine = L"Unknown ISP";
}

static EndpointIpResult ProbeDualStackIpinfo(bool viaProxy, u_short port = 0, LocalProxyProto proto = PROXY_PROTO_NONE) {
 EndpointIpResult res; int v4Ms = -1, v6Ms = -1;
 std::wstring j4 = Utf8ToWide(viaProxy ? FetchHttpsViaLocalProxy(port, proto, L"ipinfo.io", "ipinfo.io", &v4Ms)
                                       : HttpGetDirectOS(L"https://ipinfo.io/json", &v4Ms, 3000));
 std::wstring ip4 = ExtractJsonStr(j4, L"ip");
 if (!ip4.empty()) { res.ipv4 = ip4; res.latencyMs = v4Ms; ParseIpinfoJson(j4, res); }
 else { res.ipv4 = L"Unavailable"; res.location = viaProxy ? L"Proxy Probe Failed" : L"Connection Failed"; res.orgLine = L"--"; }

 std::wstring j6 = Utf8ToWide(viaProxy ? FetchHttpsViaLocalProxy(port, proto, L"v6.ipinfo.io", "v6.ipinfo.io", &v6Ms)
                                       : HttpGetDirectOS(L"https://v6.ipinfo.io/json", &v6Ms, 2000));
 std::wstring ip6 = ExtractJsonStr(j6, L"ip");
 if (!ip6.empty() && ip6.find(L':') != std::wstring::npos) {
  res.ipv6 = ip6;
  if (res.ipv4 == L"Unavailable") { res.latencyMs = v6Ms; ParseIpinfoJson(j6, res); }
 } else res.ipv6 = L"Unavailable";
 return res;
}

static u_short ParsePortFromProxyStr(const std::wstring& s) {
 size_t c = s.rfind(L':');
 if (c != std::wstring::npos) { int p = _wtoi(s.substr(c + 1).c_str()); if (p > 0 && p < 65536) return (u_short)p; }
 return 0;
}

static DWORD WINAPI PublicIpWorkerThread(LPVOID) {
 while (InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) == 0) {
  EnterCriticalSection(&g_app.dataLock);
  bool forceRefresh = g_app.forceIpRefresh;
  g_app.forceIpRefresh = false;
  g_app.pendingIpRecheck = false;
  bool sysProxyOn = g_app.sysProxyEnabled;
  std::wstring sysProxyStr = g_app.sysProxyServer;
  std::vector<ListenPortInfo> listenList = g_app.unknownListenPorts;
  auto portCacheCopy = g_app.portCache;
  auto proxyIpCacheCopy = g_app.proxyIpCache;
  EndpointIpResult sysRes = g_app.sysRoute;
  ULONGLONG lastSysTick = g_app.lastSysIpFetchTick;
  LeaveCriticalSection(&g_app.dataLock);

  ULONGLONG nowTick = GetTickCount64();

  // Only query system route IP if forced, expired (>5 min), or never succeeded
  bool needSysIp = forceRefresh || lastSysTick == 0 || (nowTick - lastSysTick > 300000) ||
                   sysRes.ipv4 == L"Detecting..." || sysRes.ipv4 == L"Unavailable";
  if (needSysIp) {
   sysRes = ProbeDualStackIpinfo(false);
   lastSysTick = GetTickCount64();
  }

  // Probe unknown local listening ports on 127.0.0.1 (zero external API traffic)
  int newProbes = 0;
  for (auto& item : listenList) {
   auto it = portCacheCopy.find(item.port);
   if (it != portCacheCopy.end() && it->second.pid == item.pid) {
    bool isVerifiedProxy = (it->second.proto == PROXY_PROTO_SOCKS5 || it->second.proto == PROXY_PROTO_HTTP);
    if (isVerifiedProxy || (nowTick - it->second.lastProbeTick) < 60000) {
     item.verifiedProto = it->second.proto;
     continue;
    }
   }
   if (newProbes < 30) {
    item.verifiedProto = ProbeLocalPortProtocol(item.port);
    portCacheCopy[item.port] = { item.pid, item.verifiedProto, nowTick };
    newProbes++;
   }
  }

  u_short sysPort = sysProxyOn ? ParsePortFromProxyStr(sysProxyStr) : 0;
  std::vector<VerifiedProxyInstance> activeList;
  std::unordered_set<u_short> addedPorts;

  auto resolveProxyOutbound = [&](u_short port, DWORD pid, LocalProxyProto proto) -> EndpointIpResult {
   auto it = proxyIpCacheCopy.find(port);
   if (!forceRefresh && it != proxyIpCacheCopy.end() && it->second.pid == pid && it->second.proto == proto &&
       (nowTick - it->second.lastFetchTick) < 300000 &&
       it->second.outbound.ipv4 != L"Unavailable" && it->second.outbound.ipv4 != L"Detecting...") {
    return it->second.outbound;
   }
   EndpointIpResult out = ProbeDualStackIpinfo(true, port, proto);
   proxyIpCacheCopy[port] = { pid, proto, out, GetTickCount64() };
   return out;
  };

  if (sysPort > 0) {
   LocalProxyProto p = ProbeLocalPortProtocol(sysPort);
   if (p == PROXY_PROTO_NONE) p = PROXY_PROTO_HTTP;
   std::wstring pName = L"System Proxy"; DWORD pPid = 0;
   for (const auto& l : listenList) if (l.port == sysPort) { pName = l.procName; pPid = l.pid; break; }
   VerifiedProxyInstance inst = { sysPort, pPid, p, pName, true, resolveProxyOutbound(sysPort, pPid, p) };
   activeList.push_back(inst);
   addedPorts.insert(sysPort);
  }

  for (const auto& item : listenList) {
   if ((item.verifiedProto == PROXY_PROTO_SOCKS5 || item.verifiedProto == PROXY_PROTO_HTTP) &&
       addedPorts.find(item.port) == addedPorts.end()) {
    VerifiedProxyInstance inst = { item.port, item.pid, item.verifiedProto, item.procName, false, {} };
    if (activeList.size() < 6) inst.outbound = resolveProxyOutbound(item.port, item.pid, item.verifiedProto);
    activeList.push_back(inst);
    addedPorts.insert(item.port);
   }
  }

  EnterCriticalSection(&g_app.dataLock);
  g_app.portCache = portCacheCopy;
  g_app.proxyIpCache = proxyIpCacheCopy;
  g_app.sysRoute = sysRes;
  g_app.lastSysIpFetchTick = lastSysTick;
  g_app.verifiedProxies = activeList;
  bool loopAgain = g_app.pendingIpRecheck;
  if (!loopAgain) g_app.isCheckingIp = false;
  LeaveCriticalSection(&g_app.dataLock);

  if (g_app.hwnd) PostMessageW(g_app.hwnd, WM_USER_IP_UPDATED, 0, 0);
  if (!loopAgain) break;
 }
 return 0;
}

static void TriggerPublicIpCheck(bool forceRefresh) {
 if (InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) != 0) return;
 EnterCriticalSection(&g_app.dataLock);
 if (forceRefresh) {
  g_app.forceIpRefresh = true;
  g_app.sysRoute.ipv4 = L"Detecting...";
  g_app.sysRoute.ipv6 = L"Detecting...";
  g_app.sysRoute.location = L"Probing system route...";
 }
 if (g_app.isCheckingIp) {
  g_app.pendingIpRecheck = true;
  LeaveCriticalSection(&g_app.dataLock);
  return;
 }
 g_app.isCheckingIp = true;
 LeaveCriticalSection(&g_app.dataLock);

 if (g_app.hwnd && forceRefresh) InvalidateRect(g_app.hwnd, nullptr, FALSE);
 HANDLE h = CreateThread(nullptr, 0, PublicIpWorkerThread, nullptr, 0, nullptr);
 if (h) CloseHandle(h);
}

static void QuerySystemProxyStatus(bool& outEnabled, std::wstring& outServer) {
 outEnabled = false; outServer = L"Disabled";
 INTERNET_PER_CONN_OPTION_LISTW list;
 INTERNET_PER_CONN_OPTIONW opt[2] = { { INTERNET_PER_CONN_FLAGS, {} }, { INTERNET_PER_CONN_PROXY_SERVER, {} } };
 DWORD sz = sizeof(list);
 list = { sizeof(list), nullptr, 2, 0, opt };
 if (InternetQueryOptionW(nullptr, INTERNET_OPTION_PER_CONNECTION_OPTION, &list, &sz)) {
  bool on = (opt[0].Value.dwValue & PROXY_TYPE_PROXY) != 0;
  if (on && opt[1].Value.pszValue && opt[1].Value.pszValue[0] != L'\0') {
   outEnabled = true; outServer = opt[1].Value.pszValue;
  }
  if (opt[1].Value.pszValue) GlobalFree(opt[1].Value.pszValue);
 }
}

static bool IsLayer3TunInterface(PIP_ADAPTER_ADDRESSES c, bool isBest) {
 if (c->IfType == IF_TYPE_SOFTWARE_LOOPBACK) return false;
 if (c->PhysicalAddressLength == 0 && (c->IfType == IF_TYPE_PROP_VIRTUAL || c->IfType == IF_TYPE_TUNNEL || c->IfType == 53)) return true;
 return isBest && (c->IfType == IF_TYPE_PROP_VIRTUAL || c->IfType == IF_TYPE_TUNNEL || c->IfType == 53);
}

static bool IsWindowsOsBuiltinProcess(DWORD pid) {
 if (pid <= 4) return true;
 if (g_app.windowsDirPrefix.empty()) return false;
 HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
 if (!h) return true;
 wchar_t buf[MAX_PATH] = { 0 }; DWORD sz = MAX_PATH; bool isWin = false;
 if (QueryFullProcessImageNameW(h, 0, buf, &sz)) {
  std::wstring p = buf; for (auto& c : p) c = towlower(c);
  if (p.find(g_app.windowsDirPrefix) == 0) isWin = true;
 }
 CloseHandle(h);
 return isWin;
}

static void PerformBackgroundStatsUpdate() {
 EnterCriticalSection(&g_app.dataLock);
 bool paused = g_app.isPaused;
 LeaveCriticalSection(&g_app.dataLock);
 if (paused) return;

 bool sysProxyOn = false;
 std::wstring sysProxyStr = L"Disabled";
 QuerySystemProxyStatus(sysProxyOn, sysProxyStr);
 RefreshWindowsDnsCacheTable();

 DWORD bestIf1 = 0, bestIf2 = 0;
 GetBestInterface(0x01010101, &bestIf1);
 GetBestInterface(0x08080808, &bestIf2);

 bool locTunActive = false, locTunTakeover = false;
 std::wstring locTunName = L"Disabled", locTunIp = L"--";
 AdapterItem locPriAdapter = { 0, L"No Active Adapter", L"", L"0.0.0.0", L"Unavailable", L"--", L"--", L"--", 0, 0, 0, false, false };
 std::vector<AdapterItem> locAdapters;
 ULONG64 sumIn = 0, sumOut = 0;
 bool hasIfTable = false;

 PMIB_IF_TABLE2 pIfTable = nullptr;
 if (GetIfTable2(&pIfTable) == NO_ERROR && pIfTable) {
  hasIfTable = true;
  for (ULONG i = 0; i < pIfTable->NumEntries; i++) {
   const MIB_IF_ROW2& r = pIfTable->Table[i];
   if (r.OperStatus == IfOperStatusUp && r.Type != IF_TYPE_SOFTWARE_LOOPBACK &&
       r.Type != IF_TYPE_TUNNEL && !r.InterfaceAndOperStatusFlags.FilterInterface) {
    sumIn += r.InOctets; sumOut += r.OutOctets;
   }
  }

  ULONG outLen = 32768; std::vector<BYTE> aBuf(outLen);
  auto pAddr = (PIP_ADAPTER_ADDRESSES)aBuf.data();
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, pAddr, &outLen) == ERROR_BUFFER_OVERFLOW) {
   aBuf.resize(outLen); pAddr = (PIP_ADAPTER_ADDRESSES)aBuf.data();
  }

  std::unordered_map<NET_IFINDEX, AdapterItem> aMap;
  if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, pAddr, &outLen) == NO_ERROR) {
   for (auto c = pAddr; c; c = c->Next) {
    if (c->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
    bool isBest = (c->IfIndex == bestIf1 || c->IfIndex == bestIf2);
    AdapterItem item = { c->IfIndex, c->FriendlyName ? c->FriendlyName : L"Adapter",
     c->Description ? c->Description : L"", L"--", L"Unavailable", L"", L"--", L"--",
     c->ReceiveLinkSpeed / 1000000ULL, 0, 0, (c->OperStatus == IfOperStatusUp), IsLayer3TunInterface(c, isBest) };
    if (c->PhysicalAddressLength > 0) {
     wchar_t mBuf[64] = { 0 };
     for (ULONG m = 0; m < c->PhysicalAddressLength; m++) {
      wchar_t pt[8]; swprintf(pt, 8, m == 0 ? L"%02X" : L":%02X", c->PhysicalAddress[m]); wcscat_s(mBuf, pt);
     }
     item.mac = mBuf;
    } else item.mac = L"L3 TUN (No MAC)";

    for (auto ua = c->FirstUnicastAddress; ua; ua = ua->Next) {
     if (ua->Address.lpSockaddr->sa_family == AF_INET && item.ipv4 == L"--")
      item.ipv4 = IpToStr(((sockaddr_in*)ua->Address.lpSockaddr)->sin_addr.S_un.S_addr);
     else if (ua->Address.lpSockaddr->sa_family == AF_INET6 && item.ipv6 == L"Unavailable") {
      wchar_t v6[64] = { 0 };
      if (InetNtopW(AF_INET6, &((sockaddr_in6*)ua->Address.lpSockaddr)->sin6_addr, v6, 64)) item.ipv6 = v6;
     }
    }
    for (auto gw = c->FirstGatewayAddress; gw; gw = gw->Next)
     if (gw->Address.lpSockaddr->sa_family == AF_INET) { item.gateway = IpToStr(((sockaddr_in*)gw->Address.lpSockaddr)->sin_addr.S_un.S_addr); break; }
    for (auto dn = c->FirstDnsServerAddress; dn; dn = dn->Next)
     if (dn->Address.lpSockaddr->sa_family == AF_INET) { item.dns = IpToStr(((sockaddr_in*)dn->Address.lpSockaddr)->sin_addr.S_un.S_addr); break; }

    if (item.isUp && item.isTun && (!locTunActive || isBest)) {
     locTunActive = true; locTunTakeover = isBest;
     locTunName = item.name; locTunIp = item.ipv4;
    }
    aMap[c->IfIndex] = item;
   }
  }
  for (ULONG i = 0; i < pIfTable->NumEntries; i++) {
   const MIB_IF_ROW2& r = pIfTable->Table[i];
   auto it = aMap.find(r.InterfaceIndex);
   if (it != aMap.end()) { it->second.inBytes = r.InOctets; it->second.outBytes = r.OutOctets; }
  }
  bool foundPri = false;
  for (auto& kv : aMap) {
   locAdapters.push_back(kv.second);
   if (!foundPri && kv.second.isUp && !kv.second.isTun && kv.second.gateway != L"--") { locPriAdapter = kv.second; foundPri = true; }
  }
  if (!foundPri) for (auto& kv : aMap) if (kv.second.isUp && !kv.second.isTun && kv.second.ipv4 != L"--") { locPriAdapter = kv.second; break; }
  FreeMibTable(pIfTable);
 }

 std::unordered_map<DWORD, std::wstring> pidMap;
 HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
 if (hSnap != INVALID_HANDLE_VALUE) {
  PROCESSENTRY32W pe = { sizeof(pe) };
  if (Process32FirstW(hSnap, &pe)) do { pidMap[pe.th32ProcessID] = pe.szExeFile; } while (Process32NextW(hSnap, &pe));
  CloseHandle(hSnap);
 }

 EnterCriticalSection(&g_app.dataLock);
 auto cacheCopy = g_app.portCache;
 auto verifiedListCopy = g_app.verifiedProxies;
 auto seenConnKeysCopy = g_app.seenConnKeys;
 LeaveCriticalSection(&g_app.dataLock);

 std::unordered_map<u_short, VerifiedProxyInstance> verifiedByPort;
 for (const auto& vp : verifiedListCopy) verifiedByPort[vp.port] = vp;

 DWORD selfPid = GetCurrentProcessId(), loNet = htonl(INADDR_LOOPBACK), tcpSize = 0;
 GetExtendedTcpTable(nullptr, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
 std::vector<MIB_TCPROW_OWNER_PID> tcpRows;
 if (tcpSize > 0) {
  std::vector<BYTE> tcpBuf(tcpSize);
  if (GetExtendedTcpTable(tcpBuf.data(), &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
   auto pTbl = (PMIB_TCPTABLE_OWNER_PID)tcpBuf.data();
   tcpRows.assign(pTbl->table, pTbl->table + pTbl->dwNumEntries);
  }
 }

 std::unordered_map<u_short, int> loClients;
 std::unordered_map<u_short, ListenPortInfo> listenMap;
 std::unordered_map<DWORD, std::vector<std::pair<DWORD, u_short>>> pidRemotes;
 std::unordered_set<DWORD> physBypassPids;

 IN_ADDR priAddr = { 0 };
 DWORD priLanNet = (InetPtonW(AF_INET, locPriAdapter.ipv4.c_str(), &priAddr) == 1) ? priAddr.S_un.S_addr : 0;

 for (const auto& r : tcpRows) {
  u_short rp = ntohs((u_short)r.dwRemotePort);
  if (r.dwState == MIB_TCP_STATE_ESTAB) {
   if (r.dwLocalAddr == loNet && r.dwRemoteAddr == loNet) loClients[rp]++;
   else if (r.dwRemoteAddr != loNet && r.dwRemoteAddr != 0) {
    auto& vec = pidRemotes[r.dwOwningPid];
    bool exists = false;
    for (const auto& pr : vec) if (pr.first == r.dwRemoteAddr && pr.second == rp) { exists = true; break; }
    if (!exists) vec.push_back({ r.dwRemoteAddr, rp });
    if (locTunActive && r.dwLocalAddr == priLanNet && priLanNet != 0) physBypassPids.insert(r.dwOwningPid);
   }
  }
 }

 std::vector<ListenPortInfo> newListen;
 for (const auto& r : tcpRows) {
  if (r.dwState == MIB_TCP_STATE_LISTEN && (r.dwLocalAddr == loNet || r.dwLocalAddr == 0) && r.dwOwningPid > 4 && r.dwOwningPid != selfPid) {
   u_short lp = ntohs((u_short)r.dwLocalPort);
   if (listenMap.find(lp) != listenMap.end()) continue;
   int cli = loClients[lp];
   auto cit = cacheCopy.find(lp);
   bool cachedKnown = (cit != cacheCopy.end() && cit->second.pid == r.dwOwningPid);
   if (cli > 0 || cachedKnown || !IsWindowsOsBuiltinProcess(r.dwOwningPid)) {
    auto pit = pidMap.find(r.dwOwningPid);
    std::wstring pname = (pit != pidMap.end()) ? pit->second : L"Unknown";
    LocalProxyProto vp = cachedKnown ? cit->second.proto : PROXY_PROTO_UNKNOWN;
    ListenPortInfo info = { lp, r.dwOwningPid, pname, cli, vp };
    listenMap[lp] = info;
    newListen.push_back(info);
   }
  }
 }

 std::sort(newListen.begin(), newListen.end(), [](const ListenPortInfo& a, const ListenPortInfo& b) {
  return (a.activeClients != b.activeClients) ? (a.activeClients > b.activeClients) : (a.port < b.port);
 });

 bool hasUnverified = false;
 for (const auto& item : newListen) if (item.verifiedProto == PROXY_PROTO_UNKNOWN) { hasUnverified = true; break; }

 std::vector<FlowItem> locFlows;
 std::vector<LogEventItem> newLogEvents;
 int locCntProxied = 0, locCntTun = 0, locCntDirect = 0;
 std::unordered_set<std::wstring> currentConnKeys;

 for (const auto& r : tcpRows) {
  if (r.dwOwningPid == selfPid || r.dwState != MIB_TCP_STATE_ESTAB) continue;
  u_short lp = ntohs((u_short)r.dwLocalPort), rp = ntohs((u_short)r.dwRemotePort);
  auto pit = pidMap.find(r.dwOwningPid);
  std::wstring cProc = (pit != pidMap.end()) ? pit->second : L"System";

  wchar_t keyBuf[128];
  swprintf(keyBuf, 128, L"%lu_%lu:%u_%lu:%u", r.dwOwningPid, r.dwLocalAddr, lp, r.dwRemoteAddr, rp);
  std::wstring connKey = keyBuf;
  currentConnKeys.insert(connKey);
  bool isNewConn = (seenConnKeysCopy.find(connKey) == seenConnKeysCopy.end());

  if (r.dwLocalAddr == loNet && r.dwRemoteAddr == loNet) {
   auto lit = listenMap.find(rp);
   if (lit != listenMap.end() && lit->second.pid != r.dwOwningPid) {
    const auto& pInfo = lit->second;
    FlowItem f = { FLOW_LOCALPROXY, L"PROXY", cProc, r.dwOwningPid, L"", L"", L"PROXIED" };
    const wchar_t* pStr = (pInfo.verifiedProto == PROXY_PROTO_SOCKS5) ? L"SOCKS5" : (pInfo.verifiedProto == PROXY_PROTO_HTTP ? L"HTTP" : L"LOCAL");
    wchar_t vBuf[128]; swprintf(vBuf, 128, L"via %s :%u (%s)", pStr, pInfo.port, pInfo.procName.c_str());
    f.viaText = vBuf;

    DWORD tgtIp = 0; u_short tgtPort = 0; std::wstring customTgt;
    auto oit = pidRemotes.find(pInfo.pid);
    if (oit != pidRemotes.end() && !oit->second.empty()) {
     tgtIp = oit->second.back().first;
     tgtPort = oit->second.back().second;
     std::wstring formatted = FormatIpAndDomain(tgtIp, tgtPort, true);
     if (oit->second.size() > 1) {
      customTgt = formatted + L" (+" + std::to_wstring(oit->second.size() - 1) + L" nodes)";
      f.targetDisplay = L"-> " + customTgt;
     } else {
      f.targetDisplay = L"-> " + formatted;
     }
    } else {
     auto vpit = verifiedByPort.find(pInfo.port);
     if (vpit != verifiedByPort.end() && vpit->second.outbound.ipv4 != L"Unavailable")
      customTgt = L"Exit: " + vpit->second.outbound.ipv4 + L" (" + vpit->second.outbound.location + L")";
     else customTgt = L"127.0.0.1:" + std::to_wstring(pInfo.port) + L" [Tunnel]";
     f.targetDisplay = L"-> " + customTgt;
    }
    locFlows.push_back(f);
    locCntProxied++;
    if (isNewConn) newLogEvents.push_back({ GetCurrentTimeStr(), FLOW_LOCALPROXY, L"PROXY", cProc, r.dwOwningPid, f.viaText, tgtIp, tgtPort, customTgt });
   }
   continue;
  }
  if (r.dwRemoteAddr != loNet && r.dwRemoteAddr != 0) {
   FlowItem f = { FLOW_DIRECT, L"DIRECT", cProc, r.dwOwningPid, L"", L"-> " + FormatIpAndDomain(r.dwRemoteAddr, rp, true), L"ESTABLISHED" };
   std::wstring lIp = IpToStr(r.dwLocalAddr);
   if (locTunActive && (lIp == locTunIp || (locTunTakeover && physBypassPids.find(r.dwOwningPid) == physBypassPids.end()))) {
    f.routeType = FLOW_TUN; f.badgeText = L"TUN"; f.viaText = L"via TUN (" + locTunName + L")"; f.stateText = L"TUNNELED";
    locCntTun++;
   } else {
    f.viaText = L"DIRECT (" + lIp + L")";
    locCntDirect++;
   }
   locFlows.push_back(f);
   if (isNewConn) newLogEvents.push_back({ GetCurrentTimeStr(), f.routeType, f.badgeText, cProc, r.dwOwningPid, f.viaText, r.dwRemoteAddr, rp, L"" });
  }
 }

 for (const auto& lp : newListen) {
  FlowItem f = { FLOW_LISTEN, L"LISTEN", lp.procName, lp.pid, L"Listen 127.0.0.1:" + std::to_wstring(lp.port), L"", L"LISTEN" };
  if (lp.verifiedProto == PROXY_PROTO_SOCKS5 || lp.verifiedProto == PROXY_PROTO_HTTP) {
   f.badgeText = (lp.verifiedProto == PROXY_PROTO_SOCKS5) ? L"SOCKS5" : L"HTTP";
   auto vpit = verifiedByPort.find(lp.port);
   f.targetDisplay = (vpit != verifiedByPort.end()) ? (L"Exit: " + vpit->second.outbound.ipv4 + L"  [" + vpit->second.outbound.location + L"]")
                                                    : (L"Verified Proxy Server (Clients: " + std::to_wstring(lp.activeClients) + L")");
   f.stateText = L"ACTIVE";
  } else f.targetDisplay = L"Non-Proxy Listening Port (Clients: " + std::to_wstring(lp.activeClients) + L")";
  locFlows.push_back(f);
 }

 // Commit all telemetry updates under lock in < 0.1 ms
 bool routeTopologyChanged = false;
 EnterCriticalSection(&g_app.dataLock);
 g_app.sysProxyEnabled = sysProxyOn;
 g_app.sysProxyServer  = sysProxyStr;

 if (hasIfTable) {
  ULONGLONG now = GetTickCount64();
  if (g_app.lastTick != 0 && now > g_app.lastTick) {
   double dt = (now - g_app.lastTick) / 1000.0;
   ULONG64 dIn = (sumIn >= g_app.lastInBytes) ? (sumIn - g_app.lastInBytes) : 0;
   ULONG64 dOut = (sumOut >= g_app.lastOutBytes) ? (sumOut - g_app.lastOutBytes) : 0;
   g_app.curDownSpeed = dIn / dt; g_app.curUpSpeed = dOut / dt;
   g_app.sessionInBytes += dIn; g_app.sessionOutBytes += dOut;
   g_app.downHistory.erase(g_app.downHistory.begin()); g_app.downHistory.push_back((float)g_app.curDownSpeed);
   g_app.upHistory.erase(g_app.upHistory.begin());     g_app.upHistory.push_back((float)g_app.curUpSpeed);
  }
  g_app.lastInBytes = g_app.totalSysInBytes = sumIn;
  g_app.lastOutBytes = g_app.totalSysOutBytes = sumOut;
  g_app.lastTick = now;

  g_app.tunActive = locTunActive;
  g_app.tunTakeoverRoute = locTunTakeover;
  g_app.tunAdapterName = locTunName;
  g_app.tunAdapterIp = locTunIp;
  g_app.primaryAdapter = locPriAdapter;
  g_app.adapters = std::move(locAdapters);
 }

 g_app.unknownListenPorts = std::move(newListen);
 g_app.flows = std::move(locFlows);
 g_app.cntProxiedFlows = locCntProxied;
 g_app.cntTunFlows = locCntTun;
 g_app.cntDirectFlows = locCntDirect;
 g_app.seenConnKeys = std::move(currentConnKeys);

 for (const auto& ev : newLogEvents) {
  g_app.eventLog.push_front(ev);
  if (g_app.eventLog.size() > 2000) g_app.eventLog.pop_back();
 }

 if (!g_app.firstRunDone) {
  g_app.firstRunDone = true;
  g_app.prevTunActive = g_app.tunActive;
  g_app.prevSysProxyEnabled = g_app.sysProxyEnabled;
  g_app.prevSysProxyServer = g_app.sysProxyServer;
 } else if (g_app.tunActive != g_app.prevTunActive ||
            g_app.sysProxyEnabled != g_app.prevSysProxyEnabled ||
            g_app.sysProxyServer != g_app.prevSysProxyServer) {
  g_app.prevTunActive = g_app.tunActive;
  g_app.prevSysProxyEnabled = g_app.sysProxyEnabled;
  g_app.prevSysProxyServer = g_app.sysProxyServer;
  routeTopologyChanged = true;
 }
 LeaveCriticalSection(&g_app.dataLock);

 if (routeTopologyChanged) TriggerPublicIpCheck(true);
 else if (hasUnverified)   TriggerPublicIpCheck(false);
}

static DWORD WINAPI StatsWorkerThread(LPVOID) {
 PerformBackgroundStatsUpdate();
 EnterCriticalSection(&g_app.dataLock);
 g_app.isUpdatingStats = false;
 LeaveCriticalSection(&g_app.dataLock);
 if (g_app.hwnd && InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) == 0)
  PostMessageW(g_app.hwnd, WM_USER_STATS_UPDATED, 0, 0);
 return 0;
}

static void TriggerStatsUpdate() {
 if (InterlockedCompareExchange(&g_app.isShuttingDown, 0, 0) != 0) return;
 EnterCriticalSection(&g_app.dataLock);
 if (g_app.isUpdatingStats) { LeaveCriticalSection(&g_app.dataLock); return; }
 g_app.isUpdatingStats = true;
 LeaveCriticalSection(&g_app.dataLock);
 HANDLE h = CreateThread(nullptr, 0, StatsWorkerThread, nullptr, 0, nullptr);
 if (h) CloseHandle(h);
}

static void MakeFont(const wchar_t* family, DWRITE_FONT_WEIGHT weight, float size, IDWriteTextFormat** ppOut) {
 g_app.pDWriteFactory->CreateTextFormat(family, nullptr, weight, DWRITE_FONT_STYLE_NORMAL, DWRITE_FONT_STRETCH_NORMAL, size, L"en-us", ppOut);
}

static void CreateD2DRenderTarget(HWND hwnd) {
 if (g_app.pRT || !g_app.pD2DFactory) return;
 UINT dpi = GetDpiForWindow(hwnd);
 if (dpi == 0) dpi = 96;
 g_app.dpiScale = dpi / 96.0f;

 RECT rc; GetClientRect(hwnd, &rc);
 UINT pxW = (std::max)(1L, rc.right - rc.left);
 UINT pxH = (std::max)(1L, rc.bottom - rc.top);
 g_app.width  = pxW / g_app.dpiScale;
 g_app.height = pxH / g_app.dpiScale;

 D2D1_RENDER_TARGET_PROPERTIES rtProps = D2D1::RenderTargetProperties(
  D2D1_RENDER_TARGET_TYPE_DEFAULT,
  D2D1::PixelFormat(DXGI_FORMAT_B8G8R8A8_UNORM, D2D1_ALPHA_MODE_PREMULTIPLIED),
  (float)dpi, (float)dpi);

 g_app.pD2DFactory->CreateHwndRenderTarget(rtProps,
  D2D1::HwndRenderTargetProperties(hwnd, D2D1::SizeU(pxW, pxH)), &g_app.pRT);

 if (g_app.pRT && g_app.pDWriteFactory) {
  g_app.pRT->SetTextAntialiasMode(D2D1_TEXT_ANTIALIAS_MODE_GRAYSCALE);
  g_app.pRT->SetAntialiasMode(D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);

  IDWriteRenderingParams *pDef = nullptr, *pCust = nullptr;
  if (SUCCEEDED(g_app.pDWriteFactory->CreateRenderingParams(&pDef)) && pDef) {
   if (SUCCEEDED(g_app.pDWriteFactory->CreateCustomRenderingParams(
       1.8f, 1.4f, 1.0f, pDef->GetPixelGeometry(),
       DWRITE_RENDERING_MODE_NATURAL_SYMMETRIC, &pCust)) && pCust) {
    g_app.pRT->SetTextRenderingParams(pCust);
    pCust->Release();
   }
   pDef->Release();
  }
 }
}

static void InitD2D(HWND hwnd) {
 D2D1CreateFactory(D2D1_FACTORY_TYPE_SINGLE_THREADED, &g_app.pD2DFactory);
 DWriteCreateFactory(DWRITE_FACTORY_TYPE_SHARED, __uuidof(IDWriteFactory), (IUnknown**)&g_app.pDWriteFactory);

 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_EXTRA_BOLD, 23.5f, &g_app.tfHeroIp);
 MakeFont(L"Cascadia Mono",             DWRITE_FONT_WEIGHT_SEMI_BOLD,  10.0f, &g_app.tfHeroSubV6);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_EXTRA_BOLD, 18.0f, &g_app.tfLogo);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_BOLD,       16.0f, &g_app.tfTitle);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_BOLD,       16.5f, &g_app.tfSpeedVal);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_BOLD,       13.5f, &g_app.tfSecValue);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_BOLD,       12.0f, &g_app.tfNav);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_BOLD,       11.8f, &g_app.tfCardTitle);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_SEMI_BOLD,  11.5f, &g_app.tfBody);
 MakeFont(L"Segoe UI Variable Display", DWRITE_FONT_WEIGHT_SEMI_BOLD,  10.5f, &g_app.tfSmall);
 MakeFont(L"Cascadia Mono",             DWRITE_FONT_WEIGHT_SEMI_BOLD,   9.2f, &g_app.tfTiny);
 MakeFont(L"Cascadia Mono",             DWRITE_FONT_WEIGHT_SEMI_BOLD,  11.0f, &g_app.tfMono);

 CreateD2DRenderTarget(hwnd);
}

static void CleanupD2D() {
 SafeRelease(&g_app.tfLogo); SafeRelease(&g_app.tfTitle); SafeRelease(&g_app.tfNav); SafeRelease(&g_app.tfCardTitle);
 SafeRelease(&g_app.tfHeroIp); SafeRelease(&g_app.tfHeroSubV6); SafeRelease(&g_app.tfSpeedVal);
 SafeRelease(&g_app.tfSecValue); SafeRelease(&g_app.tfBody); SafeRelease(&g_app.tfSmall); SafeRelease(&g_app.tfTiny); SafeRelease(&g_app.tfMono);
 SafeRelease(&g_app.pRT);
 SafeRelease(&g_app.pDWriteFactory);
 SafeRelease(&g_app.pD2DFactory);
}

static inline bool PtInRectF(float x, float y, D2D1_RECT_F r) { return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom; }
static inline void FillRR(ID2D1RenderTarget* rt, ID2D1SolidColorBrush* br, D2D1_RECT_F r, float rad, D2D1_COLOR_F col) {
 br->SetColor(col); rt->FillRoundedRectangle(D2D1::RoundedRect(r, rad, rad), br);
}
static inline void DrawRR(ID2D1RenderTarget* rt, ID2D1SolidColorBrush* br, D2D1_RECT_F r, float rad, D2D1_COLOR_F col, float st = 1.0f) {
 br->SetColor(col); rt->DrawRoundedRectangle(D2D1::RoundedRect(r, rad, rad), br, st);
}
static void DrawTxt(ID2D1RenderTarget* rt, ID2D1SolidColorBrush* br, IDWriteTextFormat* tf, const std::wstring& txt, D2D1_RECT_F r, D2D1_COLOR_F col,
                    DWRITE_TEXT_ALIGNMENT al = DWRITE_TEXT_ALIGNMENT_LEADING) {
 tf->SetTextAlignment(al); tf->SetParagraphAlignment(DWRITE_PARAGRAPH_ALIGNMENT_CENTER);
 br->SetColor(col); rt->DrawText(txt.c_str(), (UINT32)txt.length(), tf, r, br, D2D1_DRAW_TEXT_OPTIONS_CLIP);
}

static void DrawSmoothChart(ID2D1RenderTarget* rt, D2D1_RECT_F cRect, const std::vector<float>& data, float maxV, D2D1_COLOR_F col) {
 if (data.size() < 2 || maxV <= 0.0f) return;
 float w = cRect.right - cRect.left, h = cRect.bottom - cRect.top; int n = (int)data.size();
 std::vector<D2D1_POINT_2F> pts(n);
 for (int i = 0; i < n; i++) pts[i] = D2D1::Point2F(cRect.left + (w * i) / (n - 1), cRect.bottom - (std::min)(1.0f, data[i] / maxV) * (h - 6.0f));
 ID2D1PathGeometry *pArea = nullptr, *pLine = nullptr;
 g_app.pD2DFactory->CreatePathGeometry(&pArea); g_app.pD2DFactory->CreatePathGeometry(&pLine);
 if (pArea && pLine) {
  ID2D1GeometrySink* s = nullptr;
  if (SUCCEEDED(pArea->Open(&s))) {
   s->BeginFigure(D2D1::Point2F(cRect.left, cRect.bottom), D2D1_FIGURE_BEGIN_FILLED); s->AddLine(pts[0]);
   for (int i = 0; i < n - 1; i++) { float mx = (pts[i].x + pts[i + 1].x) * 0.5f; s->AddBezier(D2D1::BezierSegment(D2D1::Point2F(mx, pts[i].y), D2D1::Point2F(mx, pts[i + 1].y), pts[i + 1])); }
   s->AddLine(D2D1::Point2F(cRect.right, cRect.bottom)); s->EndFigure(D2D1_FIGURE_END_CLOSED); s->Close(); s->Release();
  }
  if (SUCCEEDED(pLine->Open(&s))) {
   s->BeginFigure(pts[0], D2D1_FIGURE_BEGIN_HOLLOW);
   for (int i = 0; i < n - 1; i++) { float mx = (pts[i].x + pts[i + 1].x) * 0.5f; s->AddBezier(D2D1::BezierSegment(D2D1::Point2F(mx, pts[i].y), D2D1::Point2F(mx, pts[i + 1].y), pts[i + 1])); }
   s->EndFigure(D2D1_FIGURE_END_OPEN); s->Close(); s->Release();
  }
  D2D1_GRADIENT_STOP stp[2] = { { 0.0f, D2D1::ColorF(col.r, col.g, col.b, 0.25f) }, { 1.0f, D2D1::ColorF(col.r, col.g, col.b, 0.0f) } };
  ID2D1GradientStopCollection* pStp = nullptr; ID2D1LinearGradientBrush* pGrad = nullptr;
  rt->CreateGradientStopCollection(stp, 2, &pStp);
  if (pStp) {
   rt->CreateLinearGradientBrush(D2D1::LinearGradientBrushProperties(D2D1::Point2F(cRect.left, cRect.top), D2D1::Point2F(cRect.left, cRect.bottom)), pStp, &pGrad);
   if (pGrad) { rt->FillGeometry(pArea, pGrad); pGrad->Release(); } pStp->Release();
  }
  ID2D1SolidColorBrush* pLb = nullptr; rt->CreateSolidColorBrush(col, &pLb);
  if (pLb) { rt->DrawGeometry(pLine, pLb, 2.0f); pLb->Release(); }
 }
 if (pArea) pArea->Release(); if (pLine) pLine->Release();
}

static void DrawGlassCard(ID2D1RenderTarget* rt, ID2D1SolidColorBrush* br, D2D1_RECT_F r, const std::wstring& title, const std::wstring& glyph) {
 FillRR(rt, br, r, 14.0f, g_pal.cardBg);
 DrawRR(rt, br, r, 14.0f, g_pal.cardBorder, 1.0f);
 br->SetColor(g_pal.cardTopGlow);
 rt->DrawLine(D2D1::Point2F(r.left + 14.0f, r.top + 0.5f), D2D1::Point2F(r.right - 14.0f, r.top + 0.5f), br, 1.0f);

 D2D1_RECT_F ib = RF(r.left + 14, r.top + 11, r.left + 34, r.top + 31);
 FillRR(rt, br, ib, 6.0f, g_pal.pillBg);
 DrawRR(rt, br, ib, 6.0f, g_pal.cardBorder, 1.0f);
 DrawTxt(rt, br, g_app.tfSmall, glyph, ib, g_pal.textWhite, DWRITE_TEXT_ALIGNMENT_CENTER);
 DrawTxt(rt, br, g_app.tfCardTitle, title, RF(r.left + 42, r.top + 11, r.right - 14, r.top + 31), g_pal.textMuted);
}

static void DrawCompactStatCard(ID2D1RenderTarget* rt, ID2D1SolidColorBrush* br, D2D1_RECT_F r, const std::wstring& title, const std::wstring& glyph,
                                const std::wstring& mainVal, D2D1_COLOR_F mainCol, const std::wstring& midVal, const std::wstring& botVal) {
 DrawGlassCard(rt, br, r, title, glyph);
 DrawTxt(rt, br, g_app.tfSecValue, mainVal, RF(r.left + 14, r.top + 40, r.right - 14, r.top + 66), mainCol);
 DrawTxt(rt, br, g_app.tfTiny, midVal, RF(r.left + 14, r.top + 68, r.right - 14, r.top + 86), g_pal.textBright);
 DrawTxt(rt, br, g_app.tfSmall, botVal, RF(r.left + 14, r.bottom - 28, r.right - 14, r.bottom - 10), g_pal.textMuted);
}

static void RenderUI() {
 if (!g_app.pRT) CreateD2DRenderTarget(g_app.hwnd);
 if (!g_app.pRT) return;

 ID2D1RenderTarget* rt = g_app.pRT;
 rt->BeginDraw();
 rt->Clear(g_pal.bg);
 ID2D1SolidColorBrush* br = nullptr;
 rt->CreateSolidColorBrush(g_pal.textWhite, &br);
 if (!br) { rt->EndDraw(); return; }

 EnterCriticalSection(&g_app.dataLock);

 float W = g_app.width, H = g_app.height, navW = 186.0f;
 br->SetColor(g_pal.navBg); rt->FillRectangle(RF(0, 0, navW, H), br);
 br->SetColor(g_pal.cardBorder); rt->DrawLine(D2D1::Point2F(navW, 0), D2D1::Point2F(navW, H), br, 1.0f);

 D2D1_RECT_F logoRect = RF(16, 18, 48, 50);
 FillRR(rt, br, logoRect, 10.0f, g_pal.logoBg);
 DrawRR(rt, br, logoRect, 10.0f, g_pal.logoBorder, 1.2f);
 DrawTxt(rt, br, g_app.tfLogo, L"N", logoRect, g_pal.textWhite, DWRITE_TEXT_ALIGNMENT_CENTER);
 DrawTxt(rt, br, g_app.tfTitle, L"Network", RF(58, 17, 178, 37), g_pal.textWhite);
 DrawTxt(rt, br, g_app.tfTiny, L"Native Telemetry", RF(58, 36, 178, 50), g_pal.textMuted);

 const wchar_t* navNames[] = { L"Dashboard", L"Connections", L"Interfaces" };
 const wchar_t* navIcons[] = { L"\u25C9", L"\u21C4", L"\u229E" };
 for (int i = 0; i < 3; i++) {
  D2D1_RECT_F ir = RF(12, 72.0f + i * 44.0f, navW - 12, 108.0f + i * 44.0f);
  bool sel = (g_app.currentTab == i);
  if (sel) { FillRR(rt, br, ir, 10.0f, g_pal.pillBg); DrawRR(rt, br, ir, 10.0f, g_pal.cardBorder, 1.0f); }
  else if (PtInRectF(g_app.mouseX, g_app.mouseY, ir)) FillRR(rt, br, ir, 10.0f, g_pal.cardBg);
  D2D1_COLOR_F fg = sel ? g_pal.textWhite : g_pal.textMuted;
  DrawTxt(rt, br, g_app.tfNav, navIcons[i], RF(ir.left + 14, ir.top, ir.left + 36, ir.bottom), fg, DWRITE_TEXT_ALIGNMENT_CENTER);
  DrawTxt(rt, br, g_app.tfNav, navNames[i], RF(ir.left + 42, ir.top, ir.right - 10, ir.bottom), fg);
 }

 float contentX = navW + 20.0f, contentW = W - contentX - 20.0f;
 DrawTxt(rt, br, g_app.tfTitle, navNames[g_app.currentTab], RF(contentX, 14, contentX + 120, 44), g_pal.textWhite);

 D2D1_RECT_F badgeRect = RF(contentX + 115, 18, contentX + 385, 40);
 FillRR(rt, br, badgeRect, 11.0f, g_pal.pillBg);
 DrawRR(rt, br, badgeRect, 11.0f, g_pal.cardBorder, 1.0f);
 std::wstring modeText = L"\u25CF ";
 if (g_app.isPaused) modeText += L"Paused";
 else if (g_app.tunActive && g_app.tunTakeoverRoute) modeText += L"Global TUN Route (" + g_app.tunAdapterName + L")";
 else if (g_app.tunActive) modeText += L"TUN Up (" + g_app.tunAdapterName + L")";
 else modeText += L"Direct Physical Route";
 DrawTxt(rt, br, g_app.tfSmall, modeText, badgeRect, g_pal.textBright, DWRITE_TEXT_ALIGNMENT_CENTER);

 const wchar_t* winBtns[] = { L"\u2014", L"\u25A1", L"\u2715" };
 for (int i = 0; i < 3; i++) {
  D2D1_RECT_F bRect = RF(W - 132.0f + i * 40.0f, 10.0f, W - 96.0f + i * 40.0f, 36.0f);
  bool hov = PtInRectF(g_app.mouseX, g_app.mouseY, bRect);
  if (hov) FillRR(rt, br, bRect, 7.0f, i == 2 ? HexColor(0xE81123) : g_pal.pillBg);
  DrawTxt(rt, br, g_app.tfBody, winBtns[i], bRect, hov ? g_pal.textWhite : g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_CENTER);
 }

 float topY = 54.0f, gap = 14.0f;
 if (g_app.currentTab == 0) {
  float col2W = (contentW - gap) * 0.5f, row1H = 196.0f;
  bool checking = g_app.isCheckingIp;
  const EndpointIpResult& sysRes = g_app.sysRoute;
  const auto& vProxies = g_app.verifiedProxies;

  D2D1_RECT_F speedCard = RF(contentX, topY, contentX + col2W, topY + row1H);
  DrawGlassCard(rt, br, speedCard, L"Network Speed", L"\u21C5");
  DrawTxt(rt, br, g_app.tfSpeedVal, L"\u2193 " + FormatBytes(g_app.curDownSpeed, true), RF(speedCard.left + 14, speedCard.top + 38, speedCard.left + 210, speedCard.top + 66), g_pal.textWhite);
  DrawTxt(rt, br, g_app.tfSpeedVal, L"\u2191 " + FormatBytes(g_app.curUpSpeed, true), RF(speedCard.right - 210, speedCard.top + 38, speedCard.right - 14, speedCard.top + 66), g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_TRAILING);

  float maxSpd = 10240.0f;
  for (float v : g_app.downHistory) if (v > maxSpd) maxSpd = v;
  for (float v : g_app.upHistory)   if (v > maxSpd) maxSpd = v;
  maxSpd *= 1.15f;
  D2D1_RECT_F cRect = RF(speedCard.left + 14, speedCard.top + 72, speedCard.right - 14, speedCard.bottom - 14);
  br->SetColor(g_pal.cardBorder);
  for (int g = 1; g <= 2; g++) { float gy = cRect.top + (cRect.bottom - cRect.top) * (g / 3.0f); rt->DrawLine(D2D1::Point2F(cRect.left, gy), D2D1::Point2F(cRect.right, gy), br, 1.0f); }
  DrawSmoothChart(rt, cRect, g_app.upHistory, maxSpd, g_pal.chartLineSub);
  DrawSmoothChart(rt, cRect, g_app.downHistory, maxSpd, g_pal.chartLineMain);

  D2D1_RECT_F netCard = RF(contentX + col2W + gap, topY, contentX + contentW, topY + row1H);
  DrawGlassCard(rt, br, netCard, L"Network Detection", L"IP");
  g_app.rcEyeBtn = RF(netCard.right - 126, netCard.top + 10, netCard.right - 72, netCard.top + 32);
  g_app.rcRefreshIpBtn = RF(netCard.right - 66, netCard.top + 10, netCard.right - 12, netCard.top + 32);
  FillRR(rt, br, g_app.rcEyeBtn, 6.0f, PtInRectF(g_app.mouseX, g_app.mouseY, g_app.rcEyeBtn) ? g_pal.pillBg : g_pal.cardInnerBg);
  DrawRR(rt, br, g_app.rcEyeBtn, 6.0f, g_pal.cardBorder);
  DrawTxt(rt, br, g_app.tfSmall, g_app.maskPublicIp ? L"Show" : L"Hide", g_app.rcEyeBtn, g_pal.textBright, DWRITE_TEXT_ALIGNMENT_CENTER);
  FillRR(rt, br, g_app.rcRefreshIpBtn, 6.0f, PtInRectF(g_app.mouseX, g_app.mouseY, g_app.rcRefreshIpBtn) ? g_pal.pillBg : g_pal.cardInnerBg);
  DrawRR(rt, br, g_app.rcRefreshIpBtn, 6.0f, g_pal.cardBorder);
  DrawTxt(rt, br, g_app.tfSmall, checking ? L"..." : L"Refresh", g_app.rcRefreshIpBtn, g_pal.textWhite, DWRITE_TEXT_ALIGNMENT_CENTER);

  DrawTxt(rt, br, g_app.tfBody, sysRes.location, RF(netCard.left + 16, netCard.top + 42, netCard.right - 88, netCard.top + 64), g_pal.textBright);
  if (sysRes.latencyMs > 0) {
   wchar_t pBuf[32]; swprintf(pBuf, 32, L"%d ms", sysRes.latencyMs);
   D2D1_RECT_F pb = RF(netCard.right - 80, netCard.top + 42, netCard.right - 14, netCard.top + 64);
   FillRR(rt, br, pb, 6.0f, g_pal.pillBg);
   DrawTxt(rt, br, g_app.tfSmall, pBuf, pb, g_pal.accentGreen, DWRITE_TEXT_ALIGNMENT_CENTER);
  }
  std::wstring sV4 = g_app.maskPublicIp ? MaskIpString(sysRes.ipv4) : sysRes.ipv4;
  std::wstring sV6 = g_app.maskPublicIp ? MaskIpString(sysRes.ipv6) : sysRes.ipv6;
  DrawTxt(rt, br, g_app.tfHeroIp, sV4, RF(netCard.left + 16, netCard.top + 70, netCard.right - 16, netCard.top + 110), g_pal.textWhite);
  DrawTxt(rt, br, g_app.tfHeroSubV6, L"IPv6: " + sV6, RF(netCard.left + 16, netCard.top + 112, netCard.right - 16, netCard.top + 132), g_pal.textMuted);
  DrawTxt(rt, br, g_app.tfSmall, sysRes.orgLine, RF(netCard.left + 16, netCard.top + 154, netCard.right - 16, netCard.top + 180), g_pal.textMuted);

  float row2Y = speedCard.bottom + gap, row2H = 166.0f;
  D2D1_RECT_F prxCard = RF(contentX, row2Y, contentX + col2W, row2Y + row2H);
  g_app.rcProxyCardArea = prxCard;
  wchar_t prxHeader[64];
  if (!vProxies.empty()) swprintf(prxHeader, 64, L"Proxy Outbound (%zu Active)", vProxies.size());
  else wcscpy_s(prxHeader, L"Proxy Outbound");
  DrawGlassCard(rt, br, prxCard, prxHeader, L"\u21C4");

  if (vProxies.empty()) {
   DrawTxt(rt, br, g_app.tfSecValue, checking ? L"Scanning Local Ports..." : L"No Local Proxy Active", RF(prxCard.left + 16, prxCard.top + 48, prxCard.right - 16, prxCard.top + 76), g_pal.textMuted);
   DrawTxt(rt, br, g_app.tfTiny, L"IPv6: Unavailable", RF(prxCard.left + 16, prxCard.top + 80, prxCard.right - 16, prxCard.top + 98), g_pal.textMuted);
   DrawTxt(rt, br, g_app.tfSmall, L"Auto-detects any unknown SOCKS5 / HTTP port", RF(prxCard.left + 16, prxCard.top + 124, prxCard.right - 16, prxCard.top + 148), g_pal.textMuted);
  } else {
   D2D1_RECT_F clipR = RF(prxCard.left + 10, prxCard.top + 38, prxCard.right - 10, prxCard.bottom - 8);
   rt->PushAxisAlignedClip(clipR, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
   float py = clipR.top - g_app.proxyCardScrollY;
   float itemBoxH = (vProxies.size() == 1) ? 112.0f : 54.0f;
   for (const auto& vp : vProxies) {
    D2D1_RECT_F sub = RF(clipR.left + 4, py, clipR.right - 4, py + itemBoxH);
    FillRR(rt, br, sub, 8.0f, g_pal.cardInnerBg); DrawRR(rt, br, sub, 8.0f, g_pal.cardBorder);
    wchar_t head[128];
    swprintf(head, 128, L"%s :%u (%s)%s", (vp.proto == PROXY_PROTO_SOCKS5 ? L"SOCKS5" : L"HTTP"), vp.port, vp.procName.c_str(), vp.isSysProxy ? L" [Sys]" : L"");
    DrawTxt(rt, br, g_app.tfSmall, head, RF(sub.left + 10, sub.top + 4, sub.right - 66, sub.top + 20), g_pal.textBright);
    if (vp.outbound.latencyMs > 0) {
     wchar_t msB[32]; swprintf(msB, 32, L"%d ms", vp.outbound.latencyMs);
     DrawTxt(rt, br, g_app.tfTiny, msB, RF(sub.right - 64, sub.top + 4, sub.right - 10, sub.top + 20), g_pal.accentGreen, DWRITE_TEXT_ALIGNMENT_TRAILING);
    }
    std::wstring pV4 = g_app.maskPublicIp ? MaskIpString(vp.outbound.ipv4) : vp.outbound.ipv4;
    std::wstring pV6 = g_app.maskPublicIp ? MaskIpString(vp.outbound.ipv6) : vp.outbound.ipv6;
    DrawTxt(rt, br, g_app.tfSecValue, pV4, RF(sub.left + 10, sub.top + 20, sub.left + 175, sub.top + 38), g_pal.textWhite);
    DrawTxt(rt, br, g_app.tfSmall, vp.outbound.location, RF(sub.left + 180, sub.top + 20, sub.right - 10, sub.top + 38), g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_TRAILING);
    DrawTxt(rt, br, g_app.tfTiny, L"IPv6: " + pV6, RF(sub.left + 10, sub.top + 38, sub.right - 10, sub.top + 52), g_pal.textMuted);
    if (vProxies.size() == 1) DrawTxt(rt, br, g_app.tfSmall, vp.outbound.orgLine, RF(sub.left + 10, sub.top + 80, sub.right - 10, sub.top + 102), g_pal.textMuted);
    py += itemBoxH + 6.0f;
   }
   rt->PopAxisAlignedClip();
  }

  D2D1_RECT_F flwCard = RF(contentX + col2W + gap, row2Y, contentX + contentW, row2Y + row2H);
  g_app.rcFlowsPreviewCard = flwCard;
  wchar_t logHeader[64];
  swprintf(logHeader, 64, L"Live Activity Stream (%zu Events)", g_app.eventLog.size());
  DrawGlassCard(rt, br, flwCard, logHeader, L"\u29C9");

  D2D1_RECT_F logClip = RF(flwCard.left + 10, flwCard.top + 38, flwCard.right - 10, flwCard.bottom - 8);
  rt->PushAxisAlignedClip(logClip, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
  float ly = logClip.top - g_app.dashLogScrollY;
  for (const auto& ev : g_app.eventLog) {
   if (ly > logClip.bottom) break;
   if (ly + 26.0f >= logClip.top) {
    D2D1_RECT_F pill = RF(logClip.left + 4, ly, logClip.right - 4, ly + 24.0f);
    FillRR(rt, br, pill, 6.0f, g_pal.cardInnerBg);
    std::wstring tgt = ev.customTarget.empty() ? FormatIpAndDomain(ev.remoteIpNet, ev.remotePortHost, false) : ev.customTarget;
    DrawTxt(rt, br, g_app.tfTiny, L"[" + ev.timeStr + L"] " + ev.procName, RF(pill.left + 8, pill.top, pill.left + 155, pill.bottom), g_pal.textWhite);
    DrawTxt(rt, br, g_app.tfTiny, tgt, RF(pill.left + 160, pill.top, pill.right - 8, pill.bottom), g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_TRAILING);
   }
   ly += 28.0f;
  }
  if (g_app.eventLog.empty()) {
   DrawTxt(rt, br, g_app.tfSmall, L"Waiting for new outbound process connections...", RF(flwCard.left + 16, flwCard.top + 70, flwCard.right - 16, flwCard.top + 100), g_pal.textMuted);
  }
  rt->PopAxisAlignedClip();

  float row3Y = row2Y + row2H + gap, row3H = (std::max)(122.0f, H - row3Y - 18.0f), col4W = (contentW - gap * 3.0f) / 4.0f;

  DrawCompactStatCard(rt, br, RF(contentX, row3Y, contentX + col4W, row3Y + row3H), L"TUN", L"T",
   g_app.tunActive ? L"Enabled" : L"Disabled", g_app.tunActive ? g_pal.accentGreen : g_pal.textMuted,
   g_app.tunActive ? (L"IF: " + g_app.tunAdapterName) : L"IF: None", g_app.tunActive ? g_app.tunAdapterIp : L"Inactive");

  std::wstring pMain = L"Disabled", pMid = L"0 Active";
  if (!vProxies.empty()) {
   wchar_t b[64];
   if (vProxies.size() == 1) swprintf(b, 64, L"%s :%u", (vProxies[0].proto == PROXY_PROTO_SOCKS5 ? L"SOCKS5" : L"HTTP"), vProxies[0].port);
   else swprintf(b, 64, L"%zu Active Ports", vProxies.size());
   pMain = b; pMid.clear();
   for (size_t i = 0; i < vProxies.size(); i++) {
    if (i > 0) pMid += L", ";
    pMid += std::wstring(vProxies[i].proto == PROXY_PROTO_SOCKS5 ? L"S5:" : L"HT:") + std::to_wstring(vProxies[i].port);
   }
  }
  float c2X = contentX + (col4W + gap) * 1;
  DrawCompactStatCard(rt, br, RF(c2X, row3Y, c2X + col4W, row3Y + row3H), L"Proxy Ports", L"P",
   pMain, vProxies.empty() ? g_pal.textMuted : g_pal.textWhite, pMid, g_app.sysProxyEnabled ? (L"Sys: " + g_app.sysProxyServer) : L"SysProxy: Off");

  float c3X = contentX + (col4W + gap) * 2;
  DrawCompactStatCard(rt, br, RF(c3X, row3Y, c3X + col4W, row3Y + row3H), L"Traffic Usage", L"\u2261",
   L"\u2193 " + FormatBytes((double)g_app.sessionInBytes, false), g_pal.textWhite,
   L"\u2191 " + FormatBytes((double)g_app.sessionOutBytes, false), L"Total: " + FormatBytes((double)g_app.totalSysInBytes, false));

  float c4X = contentX + (col4W + gap) * 3;
  DrawCompactStatCard(rt, br, RF(c4X, row3Y, contentX + contentW, row3Y + row3H), L"Intranet IP", L"L",
   g_app.primaryAdapter.ipv4, g_pal.textWhite, g_app.primaryAdapter.ipv6, L"GW: " + g_app.primaryAdapter.gateway);

} else if (g_app.currentTab == 1) {
  const wchar_t* filters[] = { L"Live Event Log (Time)", L"Active Sockets", L"Proxied / TUN Log", L"Verified Ports" };
  float fx = contentX;
  for (int i = 0; i < 4; i++) {
   D2D1_RECT_F fRect = RF(fx, topY, fx + 150.0f, topY + 30.0f);
   bool sel = (g_app.connFilter == i);
   FillRR(rt, br, fRect, 8.0f, sel ? g_pal.pillBg : g_pal.cardBg);
   DrawRR(rt, br, fRect, 8.0f, sel ? g_pal.cardTopGlow : g_pal.cardBorder);
   DrawTxt(rt, br, g_app.tfSmall, filters[i], fRect, sel ? g_pal.textWhite : g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_CENTER);
   fx += 160.0f;
  }

  g_app.rcClearLogBtn = RF(contentX + contentW - 95.0f, topY, contentX + contentW, topY + 30.0f);
  FillRR(rt, br, g_app.rcClearLogBtn, 8.0f, PtInRectF(g_app.mouseX, g_app.mouseY, g_app.rcClearLogBtn) ? g_pal.pillBg : g_pal.cardBg);
  DrawRR(rt, br, g_app.rcClearLogBtn, 8.0f, g_pal.cardBorder);
  DrawTxt(rt, br, g_app.tfSmall, L"Clear Log", g_app.rcClearLogBtn, g_pal.textBright, DWRITE_TEXT_ALIGNMENT_CENTER);

  D2D1_RECT_F listArea = RF(contentX, topY + 40.0f, contentX + contentW, H - 18.0f);
  rt->PushAxisAlignedClip(listArea, D2D1_ANTIALIAS_MODE_PER_PRIMITIVE);
  float itemH = 48.0f, curY = listArea.top - g_app.scrollY;

  if (g_app.connFilter == 0 || g_app.connFilter == 2) {
   for (const auto& ev : g_app.eventLog) {
    if (g_app.connFilter == 2 && ev.routeType != FLOW_LOCALPROXY && ev.routeType != FLOW_TUN) continue;
    if (curY + itemH >= listArea.top && curY <= listArea.bottom) {
     D2D1_RECT_F rowRect = RF(contentX, curY, contentX + contentW, curY + 42.0f);
     FillRR(rt, br, rowRect, 10.0f, g_pal.cardBg); DrawRR(rt, br, rowRect, 10.0f, g_pal.cardBorder);
     DrawTxt(rt, br, g_app.tfTiny, L"[" + ev.timeStr + L"]", RF(rowRect.left + 10, rowRect.top, rowRect.left + 72, rowRect.bottom), g_pal.textMuted);
     D2D1_RECT_F pBadge = RF(rowRect.left + 76, rowRect.top + 9, rowRect.left + 130, rowRect.bottom - 9);
     bool isPrx = (ev.routeType == FLOW_LOCALPROXY || ev.routeType == FLOW_TUN);
     FillRR(rt, br, pBadge, 5.0f, g_pal.pillBg);
     DrawTxt(rt, br, g_app.tfTiny, ev.badgeText, pBadge, isPrx ? g_pal.accentGreen : g_pal.textBright, DWRITE_TEXT_ALIGNMENT_CENTER);
     wchar_t procBuf[128]; swprintf(procBuf, 128, L"%s (#%lu)", ev.procName.c_str(), ev.pid);
     DrawTxt(rt, br, g_app.tfCardTitle, procBuf, RF(rowRect.left + 140, rowRect.top, rowRect.left + 305, rowRect.bottom), g_pal.textWhite);
     DrawTxt(rt, br, g_app.tfSmall, ev.viaText, RF(rowRect.left + 310, rowRect.top, rowRect.left + 510, rowRect.bottom), g_pal.textMuted);
     std::wstring tgt = L"-> " + (ev.customTarget.empty() ? FormatIpAndDomain(ev.remoteIpNet, ev.remotePortHost, false) : ev.customTarget);
     DrawTxt(rt, br, g_app.tfMono, tgt, RF(rowRect.left + 515, rowRect.top, rowRect.right - 14, rowRect.bottom), g_pal.textWhite);
    }
    curY += itemH;
   }
  } else {
   for (const auto& f : g_app.flows) {
    if (g_app.connFilter == 1 && f.routeType == FLOW_LISTEN) continue;
    if (g_app.connFilter == 3 && f.routeType != FLOW_LISTEN) continue;
    if (curY + itemH >= listArea.top && curY <= listArea.bottom) {
     D2D1_RECT_F rowRect = RF(contentX, curY, contentX + contentW, curY + 42.0f);
     FillRR(rt, br, rowRect, 10.0f, g_pal.cardBg); DrawRR(rt, br, rowRect, 10.0f, g_pal.cardBorder);
     D2D1_RECT_F pBadge = RF(rowRect.left + 10, rowRect.top + 9, rowRect.left + 68, rowRect.bottom - 9);
     bool isPrx = (f.routeType == FLOW_LOCALPROXY || f.routeType == FLOW_TUN || f.badgeText == L"SOCKS5" || f.badgeText == L"HTTP");
     FillRR(rt, br, pBadge, 5.0f, g_pal.pillBg);
     DrawTxt(rt, br, g_app.tfTiny, f.badgeText, pBadge, isPrx ? g_pal.accentGreen : g_pal.textBright, DWRITE_TEXT_ALIGNMENT_CENTER);
     wchar_t procBuf[128]; swprintf(procBuf, 128, L"%s (#%lu)", f.procName.c_str(), f.pid);
     DrawTxt(rt, br, g_app.tfCardTitle, procBuf, RF(rowRect.left + 78, rowRect.top, rowRect.left + 250, rowRect.bottom), g_pal.textWhite);
     DrawTxt(rt, br, g_app.tfSmall, f.viaText, RF(rowRect.left + 255, rowRect.top, rowRect.left + 465, rowRect.bottom), g_pal.textMuted);
     DrawTxt(rt, br, g_app.tfMono, f.targetDisplay, RF(rowRect.left + 470, rowRect.top, rowRect.right - 90, rowRect.bottom), g_pal.textWhite);
     DrawTxt(rt, br, g_app.tfSmall, f.stateText, RF(rowRect.right - 85, rowRect.top, rowRect.right - 12, rowRect.bottom), isPrx ? g_pal.accentGreen : g_pal.textMuted, DWRITE_TEXT_ALIGNMENT_TRAILING);
    }
    curY += itemH;
   }
  }
  rt->PopAxisAlignedClip();

 } else if (g_app.currentTab == 2) {
  float curY = topY;
  for (const auto& ad : g_app.adapters) {
   if (curY + 96.0f > H) break;
   D2D1_RECT_F card = RF(contentX, curY, contentX + contentW, curY + 88.0f);
   FillRR(rt, br, card, 14.0f, g_pal.cardBg); DrawRR(rt, br, card, 14.0f, g_pal.cardBorder);
   std::wstring badge = ad.isTun ? L"[TUN] " : (ad.isUp ? L"[UP] " : L"[DOWN] ");
   DrawTxt(rt, br, g_app.tfCardTitle, badge + ad.name + L"  -  " + ad.desc, RF(card.left + 18, card.top + 10, card.right - 18, card.top + 32), g_pal.textWhite);
   wchar_t infoLine[256];
   swprintf(infoLine, 256, L"IPv4: %s   |   IPv6: %s   |   GW: %s   |   Link: %llu Mbps", ad.ipv4.c_str(), ad.ipv6.c_str(), ad.gateway.c_str(), ad.linkSpeedMbps);
   DrawTxt(rt, br, g_app.tfSmall, infoLine, RF(card.left + 18, card.top + 34, card.right - 18, card.top + 56), g_pal.textMuted);
   std::wstring rxTx = L"Total Rx: " + FormatBytes((double)ad.inBytes, false) + L"     Total Tx: " + FormatBytes((double)ad.outBytes, false);
   DrawTxt(rt, br, g_app.tfSmall, rxTx, RF(card.left + 18, card.top + 58, card.right - 18, card.top + 80), g_pal.textBright);
   curY += 98.0f;
  }
 }

 D2D1_RECT_F fabRect = RF(W - 126.0f, H - 56.0f, W - 22.0f, H - 16.0f);
 FillRR(rt, br, fabRect, 12.0f, g_pal.logoBg);
 DrawRR(rt, br, fabRect, 12.0f, g_pal.logoBorder, 1.2f);
 DrawTxt(rt, br, g_app.tfCardTitle, g_app.isPaused ? L"Resume" : L"Pause", fabRect, g_pal.textWhite, DWRITE_TEXT_ALIGNMENT_CENTER);

 LeaveCriticalSection(&g_app.dataLock);

 br->Release();
 HRESULT hr = rt->EndDraw();
 if (hr == D2DERR_RECREATE_TARGET) {
  SafeRelease(&g_app.pRT);
 }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
 switch (msg) {
 case WM_CREATE: {
  g_app.hwnd = hwnd;
  BOOL dark = TRUE;
  DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
  DWORD cornerPref = 2;
  DwmSetWindowAttribute(hwnd, 33, &cornerPref, sizeof(cornerPref));
  DWORD backdrop = 3;
  DwmSetWindowAttribute(hwnd, 38, &backdrop, sizeof(backdrop));
  MARGINS margins = { -1, -1, -1, -1 };
  DwmExtendFrameIntoClientArea(hwnd, &margins);
  SetWindowPos(hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
  InitD2D(hwnd);
  TriggerStatsUpdate();
  TriggerPublicIpCheck(true);
  SetTimer(hwnd, 1, 1000, nullptr);
  return 0;
 }
 case WM_NCCALCSIZE:
  if (wParam == TRUE && IsZoomed(hwnd)) {
   NCCALCSIZE_PARAMS* p = (NCCALCSIZE_PARAMS*)lParam;
   int pad = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
   p->rgrc[0].left += pad; p->rgrc[0].top += pad;
   p->rgrc[0].right -= pad; p->rgrc[0].bottom -= pad;
  }
  return 0;
 case WM_DPICHANGED: {
  UINT dpi = HIWORD(wParam);
  g_app.dpiScale = dpi / 96.0f;
  if (g_app.pRT) g_app.pRT->SetDpi((float)dpi, (float)dpi);
  RECT* const prc = (RECT*)lParam;
  SetWindowPos(hwnd, nullptr, prc->left, prc->top, prc->right - prc->left, prc->bottom - prc->top, SWP_NOZORDER | SWP_NOACTIVATE);
  return 0;
 }
 case WM_USER_IP_UPDATED:
 case WM_USER_STATS_UPDATED:
  InvalidateRect(hwnd, nullptr, FALSE);
  return 0;
 case WM_TIMER:
  TriggerStatsUpdate();
  return 0;
 case WM_SIZE:
  if (g_app.pRT) {
   UINT w = LOWORD(lParam), h = HIWORD(lParam);
   if (w > 0 && h > 0) {
    g_app.pRT->Resize(D2D1::SizeU(w, h));
    g_app.width = w / g_app.dpiScale;
    g_app.height = h / g_app.dpiScale;
    InvalidateRect(hwnd, nullptr, FALSE);
   }
  }
  return 0;
 case WM_NCHITTEST: {
  POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
  ScreenToClient(hwnd, &pt);
  float mx = pt.x / g_app.dpiScale, my = pt.y / g_app.dpiScale, b = 6.0f;
  if (!IsZoomed(hwnd)) {
   if (my < b && mx < b) return HTTOPLEFT;
   if (my < b && mx > g_app.width - b) return HTTOPRIGHT;
   if (my > g_app.height - b && mx < b) return HTBOTTOMLEFT;
   if (my > g_app.height - b && mx > g_app.width - b) return HTBOTTOMRIGHT;
   if (mx < b) return HTLEFT;
   if (mx > g_app.width - b) return HTRIGHT;
   if (my < b) return HTTOP;
   if (my > g_app.height - b) return HTBOTTOM;
  }
  if (my < 46.0f && mx < g_app.width - 140.0f) return HTCAPTION;
  return HTCLIENT;
 }
 case WM_MOUSEMOVE:
  g_app.mouseX = GET_X_LPARAM(lParam) / g_app.dpiScale;
  g_app.mouseY = GET_Y_LPARAM(lParam) / g_app.dpiScale;
  InvalidateRect(hwnd, nullptr, FALSE);
  return 0;
 case WM_MOUSEWHEEL: {
  int delta = GET_WHEEL_DELTA_WPARAM(wParam);
  EnterCriticalSection(&g_app.dataLock);
  if (g_app.currentTab == 0 && PtInRectF(g_app.mouseX, g_app.mouseY, g_app.rcProxyCardArea)) {
   g_app.proxyCardScrollY -= (delta / 120.0f) * 30.0f;
   if (g_app.proxyCardScrollY < 0.0f) g_app.proxyCardScrollY = 0.0f;
   float maxS = (std::max)(0.0f, (float)g_app.verifiedProxies.size() * 60.0f - 110.0f);
   if (g_app.proxyCardScrollY > maxS) g_app.proxyCardScrollY = maxS;
   InvalidateRect(hwnd, nullptr, FALSE);
  } else if (g_app.currentTab == 0 && PtInRectF(g_app.mouseX, g_app.mouseY, g_app.rcFlowsPreviewCard)) {
   g_app.dashLogScrollY -= (delta / 120.0f) * 28.0f;
   if (g_app.dashLogScrollY < 0.0f) g_app.dashLogScrollY = 0.0f;
   float maxS = (std::max)(0.0f, (float)g_app.eventLog.size() * 28.0f - 112.0f);
   if (g_app.dashLogScrollY > maxS) g_app.dashLogScrollY = maxS;
   InvalidateRect(hwnd, nullptr, FALSE);
  } else if (g_app.currentTab == 1) {
   g_app.scrollY -= (delta / 120.0f) * 48.0f;
   if (g_app.scrollY < 0.0f) g_app.scrollY = 0.0f;
   size_t cnt = (g_app.connFilter == 0 || g_app.connFilter == 2) ? g_app.eventLog.size() : g_app.flows.size();
   float maxS = (std::max)(0.0f, (float)cnt * 48.0f - (g_app.height - 120.0f));
   if (g_app.scrollY > maxS) g_app.scrollY = maxS;
   InvalidateRect(hwnd, nullptr, FALSE);
  }
  LeaveCriticalSection(&g_app.dataLock);
  return 0;
 }
 case WM_LBUTTONDOWN: {
  float mx = GET_X_LPARAM(lParam) / g_app.dpiScale, my = GET_Y_LPARAM(lParam) / g_app.dpiScale;
  float W = g_app.width, H = g_app.height;
  for (int i = 0; i < 3; i++) {
   if (PtInRectF(mx, my, RF(W - 132.0f + i * 40.0f, 10.0f, W - 96.0f + i * 40.0f, 36.0f))) {
    if (i == 0) ShowWindow(hwnd, SW_MINIMIZE);
    else if (i == 1) ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
    else if (i == 2) DestroyWindow(hwnd);
    return 0;
   }
  }
  for (int i = 0; i < 3; i++) {
   if (PtInRectF(mx, my, RF(12, 72.0f + i * 44.0f, 174.0f, 108.0f + i * 44.0f))) {
    EnterCriticalSection(&g_app.dataLock);
    g_app.currentTab = i; g_app.scrollY = 0.0f;
    LeaveCriticalSection(&g_app.dataLock);
    InvalidateRect(hwnd, nullptr, FALSE);
    return 0;
   }
  }
  if (g_app.currentTab == 0) {
   if (PtInRectF(mx, my, g_app.rcEyeBtn)) {
    EnterCriticalSection(&g_app.dataLock);
    g_app.maskPublicIp = !g_app.maskPublicIp;
    LeaveCriticalSection(&g_app.dataLock);
    InvalidateRect(hwnd, nullptr, FALSE); return 0;
   }
   if (PtInRectF(mx, my, g_app.rcRefreshIpBtn)) {
    TriggerPublicIpCheck(true); return 0;
   }
   if (PtInRectF(mx, my, g_app.rcFlowsPreviewCard)) {
    EnterCriticalSection(&g_app.dataLock);
    g_app.currentTab = 1; g_app.connFilter = 0; g_app.scrollY = 0.0f;
    LeaveCriticalSection(&g_app.dataLock);
    InvalidateRect(hwnd, nullptr, FALSE); return 0;
   }
  }
  if (PtInRectF(mx, my, RF(W - 126.0f, H - 56.0f, W - 22.0f, H - 16.0f))) {
   EnterCriticalSection(&g_app.dataLock);
   g_app.isPaused = !g_app.isPaused;
   LeaveCriticalSection(&g_app.dataLock);
   InvalidateRect(hwnd, nullptr, FALSE); return 0;
  }
  if (g_app.currentTab == 1) {
   if (PtInRectF(mx, my, g_app.rcClearLogBtn)) {
    EnterCriticalSection(&g_app.dataLock);
    g_app.eventLog.clear(); g_app.scrollY = 0.0f;
    LeaveCriticalSection(&g_app.dataLock);
    InvalidateRect(hwnd, nullptr, FALSE); return 0;
   }
   float fx = 206.0f;
   for (int i = 0; i < 4; i++) {
    if (PtInRectF(mx, my, RF(fx, 54.0f, fx + 150.0f, 84.0f))) {
     EnterCriticalSection(&g_app.dataLock);
     g_app.connFilter = i; g_app.scrollY = 0.0f;
     LeaveCriticalSection(&g_app.dataLock);
     InvalidateRect(hwnd, nullptr, FALSE); return 0;
    }
    fx += 160.0f;
   }
  }
  return 0;
 }
 case WM_PAINT: {
  PAINTSTRUCT ps;
  BeginPaint(hwnd, &ps);
  RenderUI();
  EndPaint(hwnd, &ps);
  return 0;
 }
 case WM_DESTROY: {
  KillTimer(hwnd, 1);
  InterlockedExchange(&g_app.isShuttingDown, 1);
  g_app.hwnd = nullptr;
  for (int i = 0; i < 40; i++) {
   EnterCriticalSection(&g_app.dataLock);
   bool busy = g_app.isUpdatingStats || g_app.isCheckingIp || g_app.ptrWorkerBusy;
   LeaveCriticalSection(&g_app.dataLock);
   if (!busy) break;
   Sleep(15);
  }
  CleanupD2D();
  PostQuitMessage(0);
  return 0;
 }
 }
 return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
 WSADATA wsaData;
 WSAStartup(MAKEWORD(2, 2), &wsaData);
 SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

 HICON hIconBig = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON,
  GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
 HICON hIconSmall = (HICON)LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APP_ICON), IMAGE_ICON,
  GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
 if (!hIconBig)   hIconBig   = LoadIconW(nullptr, IDI_APPLICATION);
 if (!hIconSmall) hIconSmall = hIconBig;

 WNDCLASSEXW wc = { sizeof(WNDCLASSEXW), CS_HREDRAW | CS_VREDRAW, WndProc, 0, 0, hInstance,
                    hIconBig, LoadCursor(nullptr, IDC_ARROW), nullptr, nullptr, L"NativeNetworkClass", hIconSmall };
 RegisterClassExW(&wc);

 HDC screen = GetDC(nullptr);
 float scale = GetDeviceCaps(screen, LOGPIXELSX) / 96.0f;
 ReleaseDC(nullptr, screen);

 int winW = (int)(1040 * scale), winH = (int)(660 * scale);
 int posX = (GetSystemMetrics(SM_CXSCREEN) - winW) / 2;
 int posY = (GetSystemMetrics(SM_CYSCREEN) - winH) / 2;

 HWND hwnd = CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"Network",
  WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU,
  posX, posY, winW, winH, nullptr, nullptr, hInstance, nullptr);

 SendMessageW(hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIconBig);
 SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIconSmall);
 ShowWindow(hwnd, nCmdShow);
 UpdateWindow(hwnd);

 MSG msg;
 while (GetMessageW(&msg, nullptr, 0, 0)) {
  TranslateMessage(&msg);
  DispatchMessageW(&msg);
 }
 WSACleanup();
 return 0;
}