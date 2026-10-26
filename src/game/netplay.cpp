// Local Wi-Fi / Hotspot Dual-Device Sync multiplayer (2 players, Port 0 = Host / P1, Port 1 = Client / P2).
// Designed for zero force-close / zero ANR: non-blocking UDP sockets on a background thread, page-verified guest
// scalar-only memory access (never touching guest pointers), and bounded frame sync waits.
#include "common/netplay.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include "app/app.h"
#include "common/guest.h"
#include "common/options.h"
#include "core/log.h"
#include "kernel/kernel.h"
#include "kernel/memory.h"

namespace netplay {

namespace {

constexpr uint16_t kDefaultPort = 27888;
constexpr uint32_t kMagic = 0x4D4B534Du;  // "MKSM"
constexpr uint8_t kProtoVersion = 1;

enum PacketType : uint8_t {
    kPktDiscover = 1,   // client/host broadcast beacon
    kPktClientPad = 2,  // client -> host: P2 input + ping timestamp
    kPktHostSync = 3,   // host -> client: P1+P2 input + authoritative scalar state
};

#pragma pack(push, 1)
struct WirePad {
    uint8_t connected = 0;
    uint16_t buttons = 0;
    uint8_t analog[8] = {};
    int16_t lx = 0, ly = 0, rx = 0, ry = 0;
};

struct PlayerScalarState {
    uint8_t valid = 0;
    float x = 0, y = 0, z = 0;
    float vx = 0, vy = 0, vz = 0;
    int32_t health = 0;
    int32_t max_health = 0;
    float energy = 0;
    float fatality_meter = 0;
    int32_t fatality_level = 0;
    int32_t experience = 0;
};

struct PacketHeader {
    uint32_t magic = kMagic;
    uint8_t version = kProtoVersion;
    uint8_t type = 0;
    uint8_t role = 0;  // Mode
    uint8_t flags = 0;
    uint32_t seq = 0;
    uint32_t sim_frame = 0;
    uint32_t send_ms = 0;
    uint32_t echo_ms = 0;
};

struct ClientPadPacket {
    PacketHeader hdr;
    WirePad pad1;
};

constexpr uint32_t kEnemySlots = 12;  // character slots p = 2..13 at 0x5D1AB8 + p * 0x3238

struct EnemyScalarState {
    uint8_t active = 0;      // 1 if slot occupied on Host, 0 if empty/despawned
    int16_t entity_id = -1;  // [rec_base + 0x1DFE]
    int32_t health = 0;      // [body_va + 0x368] (<= 0 when dying/dead)
    int32_t max_health = 0;  // [body_va + 0x370]
    float x = 0, y = 0, z = 0;
    float yaw = 0;
    float ground_y = 0;
};

struct HostSyncPacket {
    PacketHeader hdr;
    WirePad pad0;
    WirePad pad1;
    uint32_t body_count = 0;
    PlayerScalarState players[2];
    struct PlayerExtraState {
        float yaw = 0;
        float target_yaw = 0;
        float ground_y = 0;
        uint8_t has_extra = 0;
    } extra[2];
    uint8_t has_enemies = 0;
    EnemyScalarState enemies[kEnemySlots];
};
#pragma pack(pop)

WirePad ToWire(const input::Pad& p) {
    WirePad w;
    w.connected = p.connected ? 1 : 0;
    w.buttons = p.buttons;
    std::memcpy(w.analog, p.analog, 8);
    w.lx = p.lx;
    w.ly = p.ly;
    w.rx = p.rx;
    w.ry = p.ry;
    return w;
}

input::Pad FromWire(const WirePad& w) {
    input::Pad p;
    p.connected = w.connected != 0;
    p.buttons = w.buttons;
    std::memcpy(p.analog, w.analog, 8);
    p.lx = w.lx;
    p.ly = w.ly;
    p.rx = w.rx;
    p.ry = w.ry;
    return p;
}

uint32_t TickMs() {
    using namespace std::chrono;
    return uint32_t(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

// Strict page-level guest memory validation: prevents any SIGSEGV force-close when reading or writing guest RAM.
bool SafeGuestRange(uint32_t va, uint32_t size) {
    if (!size || !mem::Base()) return false;
    if (va < game::kImageBegin) return false;
    uint64_t end = uint64_t(va) + uint64_t(size);
    if (end > game::kPhysicalEnd) return false;
    if (va >= game::kImageEnd && va < game::kPhysicalBegin) {
        // user virtual heap range: check every 4 KB page in [va, end)
    }
    uint32_t first_page = va & ~(mem::kPage - 1);
    uint32_t last_page = uint32_t((end - 1) & ~(uint64_t(mem::kPage) - 1));
    for (uint32_t page = first_page;; page += mem::kPage) {
        if (!mem::IsCommitted(page)) return false;
        if (page == last_page) break;
    }
    return true;
}

bool SafeReadU32(uint32_t va, uint32_t& out) {
    if (!SafeGuestRange(va, 4)) return false;
    out = kernel::R32(va);
    return true;
}

bool SafeWriteU32(uint32_t va, uint32_t val) {
    if (!SafeGuestRange(va, 4)) return false;
    kernel::W32(va, val);
    return true;
}

bool SafeReadFloat(uint32_t va, float& out) {
    uint32_t raw = 0;
    if (!SafeReadU32(va, raw)) return false;
    std::memcpy(&out, &raw, 4);
    return std::isfinite(out);
}

bool SafeWriteFloat(uint32_t va, float val) {
    if (!std::isfinite(val)) return false;
    uint32_t raw = 0;
    std::memcpy(&raw, &val, 4);
    return SafeWriteU32(va, raw);
}

// Guest addresses verified from default.xbe (USA/Europe Xbox release, title 4D570029)
constexpr uint32_t kSimFrameCounter = 0x5AFC60;
constexpr uint32_t kProfilePtr = 0x5ACEBC;
constexpr uint32_t kStoryPlayersOffset = 0x88;
constexpr uint32_t kProfileRecordsOffset = 0x48F0;
constexpr uint32_t kProfileRecordStride = 0x50;
constexpr uint32_t kExpOffset = 0x00;
constexpr uint32_t kFatalityOffset = 0x14;
constexpr uint32_t kFatalityLevelOffset = 0x38;

constexpr uint32_t kPlayerRecordsBase = 0x5D1AB8;
constexpr uint32_t kPlayerRecordStride = 0x3238;
constexpr uint32_t kRecordInactiveOffset = 0x70;      // uint8_t: 0 when active in gameplay
constexpr uint32_t kRecordPosOffset = 0x80;           // float x, y, z
constexpr uint32_t kRecordYawOffset = 0x94;           // float yaw (radians)
constexpr uint32_t kRecordPrevGroundOffset = 0xC0;    // float prev_ground_y
constexpr uint32_t kRecordCurGroundOffset = 0xC4;     // float cur_ground_y
constexpr uint32_t kRecordVelOffset = 0xD0;           // float vx, vy, vz
constexpr uint32_t kRecordRenderPosOffset = 0xE0;     // float render_x, render_y, render_z (0x1C6AE0 / 0x199C00)
constexpr uint32_t kRecordGroundOffset = 0xF4;        // float ground_y
constexpr uint32_t kRecordBodyPtrOffset = 0x200;      // 0x5D1CB8: pointer to character Body
constexpr uint32_t kRecordEntityIdOffset = 0x1DFE;    // int16_t: entity type/slot ID (-1 when empty)
constexpr uint32_t kRecordActionStateOffset = 0x1E04; // int32_t: action state (6 when dying/dead)
constexpr uint32_t kRecordDeathTimerOffset = 0x2648;  // int32_t: corpse despawn timer checked by 0x176F10
constexpr uint32_t kRecordInterpTimerOffset = 0x2BC4; // uint32_t: knockback/grab lerp timer (+0x2BC4) & duration (+0x2BC6)
constexpr uint32_t kRecordInterpTargetOffset = 0x2BD8;// float target_x, target_y, target_z (0x0D6000)
constexpr uint32_t kRecordTargetYawOffset = 0x3120;   // float target_yaw (radians)
constexpr uint32_t kRecordCachedPosOffset = 0x3164;   // float cached_x, cached_y, cached_z
constexpr uint32_t kDespawnTimerLimitAddr = 0x510B70; // int32_t: despawn timer threshold in 0x176F10

constexpr uint32_t kPlayerObjectsTable[2] = {0x51005C, 0x510060};
constexpr uint32_t kBodyCountAddr = 0x5142A4;
constexpr uint32_t kBodyHealthOffset = 0x368;      // int32_t health
constexpr uint32_t kBodyMaxHealthOffset = 0x370;   // int32_t max_health

constexpr uint32_t kEnergyTable = 0x4E65A8;
constexpr uint32_t kEnergyCount = 0x4E65E0;
constexpr uint32_t kEnergyStride = 0x24;

// State protected by g_lock (never held across blocking calls)
std::mutex g_lock;
std::atomic<uint32_t> g_mode{kOff};
std::atomic<bool> g_sync_enabled{true};
std::atomic<uint32_t> g_target_octet{0};  // 0 = AUTO
std::atomic<bool> g_running{false};
std::atomic<bool> g_connected{false};
std::atomic<int> g_ping_ms{0};

input::Pad g_local_pad{.connected = true};
input::Pad g_remote_pad{.connected = false};
input::Pad g_host_pad0{.connected = true};
input::Pad g_host_pad1{.connected = true};

uint32_t g_last_recv_ms = 0;
uint32_t g_last_echo_ms = 0;
uint32_t g_peer_ip = 0;    // network byte order
uint16_t g_peer_port = 0;  // network byte order
std::string g_peer_ip_str;
std::string g_local_ip_str = "0.0.0.0";
uint32_t g_local_ip_net = 0;

HostSyncPacket g_latest_sync{};
HostSyncPacket g_host_cached_sync{};
uint32_t g_last_host_frame_ms = 0;
uint32_t g_last_host_send_ms = 0;
bool g_has_sync = false;
uint32_t g_last_sync_ms = 0;
uint32_t g_last_applied_seq = 0;
uint32_t g_tx_seq = 0;

#ifdef _WIN32
SOCKET g_sock = INVALID_SOCKET;
constexpr SOCKET kBadSocket = INVALID_SOCKET;
void CloseSocket(SOCKET s) {
    if (s != INVALID_SOCKET) closesocket(s);
}
#else
int g_sock = -1;
constexpr int kBadSocket = -1;
void CloseSocket(int s) {
    if (s >= 0) close(s);
}
#endif

std::string IpToString(uint32_t net_ip) {
    if (!net_ip) return "0.0.0.0";
    uint32_t h = ntohl(net_ip);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (h >> 24) & 0xFF, (h >> 16) & 0xFF, (h >> 8) & 0xFF, h & 0xFF);
    return buf;
}

// Discovers the phone's Wi-Fi / Hotspot IPv4 address and subnet broadcast addresses safely without crashing.
std::vector<uint32_t> DiscoverTargetsAndLocalIp() {
    std::vector<uint32_t> targets;
    auto add_target = [&](uint32_t ip_net) {
        if (!ip_net || ip_net == htonl(INADDR_LOOPBACK)) return;
        if (std::find(targets.begin(), targets.end(), ip_net) == targets.end()) targets.push_back(ip_net);
    };

    add_target(htonl(INADDR_BROADCAST));
    // Standard Android Hotspot subnets & gateway IPs (Android 10-15 Wi-Fi hotspot & Wi-Fi Direct ranges)
    const char* kKnownHotspots[] = {
        "192.168.43.1",   "192.168.43.255",
        "192.168.49.1",   "192.168.49.255",
        "192.168.137.1",  "192.168.137.255",
    };
    for (const char* s : kKnownHotspots) {
        in_addr a{};
        if (inet_pton(AF_INET, s, &a) == 1) add_target(a.s_addr);
    }

    uint32_t best_local = 0;
#ifndef _WIN32
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0 && ifa) {
        for (ifaddrs* cur = ifa; cur; cur = cur->ifa_next) {
            if (!cur->ifa_addr || cur->ifa_addr->sa_family != AF_INET) continue;
            if (!(cur->ifa_flags & IFF_UP) || (cur->ifa_flags & IFF_LOOPBACK)) continue;
            uint32_t addr = reinterpret_cast<sockaddr_in*>(cur->ifa_addr)->sin_addr.s_addr;
            if (!addr) continue;
            uint32_t h = ntohl(addr);
            // Ignore cellular/CGNAT/link-local when picking the best LAN/Hotspot IP
            bool private_lan = ((h >> 24) == 192 && ((h >> 16) & 0xFF) == 168) ||
                               ((h >> 24) == 10) ||
                               ((h >> 24) == 172 && (((h >> 16) & 0xF0) == 16));
            if (!best_local || private_lan) best_local = addr;
            if (cur->ifa_broadaddr && cur->ifa_broadaddr->sa_family == AF_INET) {
                add_target(reinterpret_cast<sockaddr_in*>(cur->ifa_broadaddr)->sin_addr.s_addr);
            }
            if (private_lan) {
                add_target(htonl((h & 0xFFFFFF00u) | 0x000000FFu));  // subnet .255 broadcast
                add_target(htonl((h & 0xFFFFFF00u) | 0x00000001u));  // subnet .1 gateway (Hotspot host)
            }
        }
        freeifaddrs(ifa);
    }

    // Fallback via UDP connect trick if getifaddrs is restricted by SELinux on some Android versions
    if (!best_local) {
        int tmp = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp >= 0) {
            sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port = htons(53);
            inet_pton(AF_INET, "192.168.43.1", &dst.sin_addr);
            if (connect(tmp, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) == 0) {
                sockaddr_in name{};
                socklen_t len = sizeof(name);
                if (getsockname(tmp, reinterpret_cast<sockaddr*>(&name), &len) == 0 && name.sin_addr.s_addr) {
                    best_local = name.sin_addr.s_addr;
                    uint32_t h = ntohl(best_local);
                    add_target(htonl((h & 0xFFFFFF00u) | 0x000000FFu));
                    add_target(htonl((h & 0xFFFFFF00u) | 0x00000001u));
                }
            }
            close(tmp);
        }
    }

    // Read default gateway from /proc/net/route (when Client is connected to Host's Hotspot, Host is the gateway!)
    std::ifstream route("/proc/net/route");
    std::string line;
    while (std::getline(route, line)) {
        std::istringstream iss(line);
        std::string iface, dest_hex, gw_hex;
        if (iss >> iface >> dest_hex >> gw_hex) {
            if (dest_hex == "00000000" && gw_hex.size() == 8) {
                char* endp = nullptr;
                unsigned long gw = std::strtoul(gw_hex.c_str(), &endp, 16);
                if (endp && *endp == '\0' && gw != 0) add_target(uint32_t(gw));
            }
        }
    }

    // Read ARP table from /proc/net/arp (when Host runs Hotspot, connected Clients appear here!)
    std::ifstream arp("/proc/net/arp");
    while (std::getline(arp, line)) {
        std::istringstream iss(line);
        std::string ip_str;
        if (iss >> ip_str) {
            in_addr a{};
            if (inet_pton(AF_INET, ip_str.c_str(), &a) == 1) add_target(a.s_addr);
        }
    }
#endif

    // Check explicit target IP from settings or target octet selector
    uint32_t octet = g_target_octet.load(std::memory_order_relaxed);
    if (octet >= 1 && octet <= 254 && best_local) {
        uint32_t h = ntohl(best_local);
        add_target(htonl((h & 0xFFFFFF00u) | octet));
    }
    const std::string& join_ip = app::Get().join_ip;
    if (!join_ip.empty()) {
        in_addr a{};
        if (inet_pton(AF_INET, join_ip.c_str(), &a) == 1) add_target(a.s_addr);
    }

    if (best_local) {
        std::lock_guard lock(g_lock);
        g_local_ip_net = best_local;
        g_local_ip_str = IpToString(best_local);
    }
    return targets;
}

bool EnsureSocket() {
    if (g_sock != kBadSocket) return true;
#ifdef _WIN32
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    auto s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == kBadSocket) return false;

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&yes), sizeof(yes));
    int buf_sz = 262144;
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&buf_sz), sizeof(buf_sz));

#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags >= 0) fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(kDefaultPort);
    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        // Fallback to any available port if 27888 is already bound
        addr.sin_port = 0;
        if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            CloseSocket(s);
            return false;
        }
    }
    g_sock = s;
    LOGI("netplay: UDP socket ready on port %u", kDefaultPort);
    return true;
}

void SendUdp(const void* data, size_t len, uint32_t dst_ip_net, uint16_t dst_port_net) {
    if (g_sock == kBadSocket || !dst_ip_net) return;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = dst_ip_net;
    dst.sin_port = dst_port_net ? dst_port_net : htons(kDefaultPort);
#ifdef MSG_NOSIGNAL
    sendto(g_sock, static_cast<const char*>(data), len, MSG_NOSIGNAL, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
#else
    sendto(g_sock, static_cast<const char*>(data), len, 0, reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
#endif
}

// Reads current player scalar state from guest memory (only called on the game thread).
void CaptureHostState(HostSyncPacket& pkt) {
    uint32_t sim = 0;
    if (SafeReadU32(kSimFrameCounter, sim)) pkt.hdr.sim_frame = sim;

    uint32_t body_count = 0;
    if (SafeReadU32(kBodyCountAddr, body_count) && body_count <= 2048) pkt.body_count = body_count;

    uint32_t profile = 0;
    bool has_profile = SafeReadU32(kProfilePtr, profile) && SafeGuestRange(profile, 0x4A00);

    uint32_t energy_count = 0;
    SafeReadU32(kEnergyCount, energy_count);

    for (uint32_t p = 0; p < 2; p++) {
        PlayerScalarState& out = pkt.players[p];
        auto& ext = pkt.extra[p];
        out.valid = 0;
        ext.has_extra = 0;

        uint32_t rec_base = kPlayerRecordsBase + p * kPlayerRecordStride;
        if (!SafeGuestRange(rec_base, kPlayerRecordStride)) continue;
        if (kernel::G<uint8_t>(rec_base + kRecordInactiveOffset) != 0) continue;

        uint32_t body_va = 0;
        if (!SafeReadU32(rec_base + kRecordBodyPtrOffset, body_va) || !body_va) {
            SafeReadU32(kPlayerObjectsTable[p], body_va);
        }
        if (!body_va || !SafeGuestRange(body_va, 0x380)) continue;

        int32_t hp = 0, max_hp = 0;
        uint32_t hp_u = 0, max_hp_u = 0;
        if (SafeReadU32(body_va + kBodyHealthOffset, hp_u) && SafeReadU32(body_va + kBodyMaxHealthOffset, max_hp_u)) {
            int32_t h = int32_t(hp_u);
            int32_t mh = int32_t(max_hp_u);
            if (mh > 0 && mh <= 100000 && h >= 0 && h <= 100000) {
                hp = h;
                max_hp = mh;
            }
        }

        float x = 0, y = 0, z = 0, vx = 0, vy = 0, vz = 0;
        if (!SafeReadFloat(rec_base + kRecordPosOffset + 0, x) ||
            !SafeReadFloat(rec_base + kRecordPosOffset + 4, y) ||
            !SafeReadFloat(rec_base + kRecordPosOffset + 8, z))
            continue;
        SafeReadFloat(rec_base + kRecordVelOffset + 0, vx);
        SafeReadFloat(rec_base + kRecordVelOffset + 4, vy);
        SafeReadFloat(rec_base + kRecordVelOffset + 8, vz);

        if (std::fabs(x) > 100000.0f || std::fabs(y) > 100000.0f || std::fabs(z) > 100000.0f) continue;

        out.valid = 1;
        out.x = x;
        out.y = y;
        out.z = z;
        out.vx = vx;
        out.vy = vy;
        out.vz = vz;
        out.health = hp;
        out.max_health = max_hp;

        float yaw = 0, target_yaw = 0, ground_y = 0;
        if (SafeReadFloat(rec_base + kRecordYawOffset, yaw) &&
            SafeReadFloat(rec_base + kRecordTargetYawOffset, target_yaw) &&
            SafeReadFloat(rec_base + kRecordGroundOffset, ground_y)) {
            ext.yaw = yaw;
            ext.target_yaw = target_yaw;
            ext.ground_y = ground_y;
            ext.has_extra = 1;
        }

        if (p < energy_count && energy_count <= 4) {
            float en = 0;
            if (SafeReadFloat(kEnergyTable + p * kEnergyStride, en) && en >= 0.0f && en <= 10000.0f) out.energy = en;
        }

        if (has_profile) {
            uint32_t prof_rec = profile + kProfileRecordsOffset + (p + 1) * kProfileRecordStride;
            if (SafeGuestRange(prof_rec, kProfileRecordStride)) {
                uint32_t exp_u = 0, f_lvl_u = 0;
                float f_meter = 0;
                if (SafeReadU32(prof_rec + kExpOffset, exp_u)) out.experience = int32_t(exp_u);
                if (SafeReadFloat(prof_rec + kFatalityOffset, f_meter)) out.fatality_meter = f_meter;
                if (SafeReadU32(prof_rec + kFatalityLevelOffset, f_lvl_u)) out.fatality_level = int32_t(f_lvl_u);
            }
        }
    }

    // Capture all 12 enemy slots (p = 2..13 at 0x5D1AB8 + p * 0x3238) so enemy positions, health, and deaths stay in sync
    pkt.has_enemies = 1;
    for (uint32_t e = 0; e < kEnemySlots; e++) {
        EnemyScalarState& es = pkt.enemies[e];
        es = EnemyScalarState{};
        uint32_t rec_base = kPlayerRecordsBase + (e + 2) * kPlayerRecordStride;
        if (!SafeGuestRange(rec_base, kPlayerRecordStride)) continue;
        uint8_t inactive = kernel::G<uint8_t>(rec_base + kRecordInactiveOffset);
        int16_t ent_id = kernel::G<int16_t>(rec_base + kRecordEntityIdOffset);
        if (inactive != 0 || ent_id < 0) continue;

        uint32_t body_va = 0;
        if (!SafeReadU32(rec_base + kRecordBodyPtrOffset, body_va) || !body_va || !SafeGuestRange(body_va, 0x380)) continue;

        uint32_t hp_u = 0, max_hp_u = 0;
        if (!SafeReadU32(body_va + kBodyHealthOffset, hp_u) || !SafeReadU32(body_va + kBodyMaxHealthOffset, max_hp_u)) continue;
        int32_t mh = int32_t(max_hp_u);
        if (mh <= 0 || mh > 100000) continue;

        float x = 0, y = 0, z = 0;
        if (!SafeReadFloat(rec_base + kRecordPosOffset + 0, x) ||
            !SafeReadFloat(rec_base + kRecordPosOffset + 4, y) ||
            !SafeReadFloat(rec_base + kRecordPosOffset + 8, z))
            continue;
        if (std::fabs(x) > 100000.0f || std::fabs(y) > 100000.0f || std::fabs(z) > 100000.0f) continue;

        es.active = 1;
        es.entity_id = ent_id;
        es.health = int32_t(hp_u);
        es.max_health = mh;
        es.x = x;
        es.y = y;
        es.z = z;
        SafeReadFloat(rec_base + kRecordYawOffset, es.yaw);
        SafeReadFloat(rec_base + kRecordGroundOffset, es.ground_y);
    }
}

uint8_t g_enemy_missing_ticks[kEnemySlots] = {};

// Applies authoritative Host scalar state on the Client (only called on the game thread).
// Never modifies any guest pointer, and only updates when Client is also in an active gameplay frame.
void ApplyHostStateOnClient(const HostSyncPacket& pkt, bool new_packet) {
    if (!g_sync_enabled.load(std::memory_order_relaxed)) return;

    uint32_t profile = 0;
    bool has_profile = SafeReadU32(kProfilePtr, profile) && SafeGuestRange(profile, 0x4A00);

    uint32_t energy_count = 0;
    SafeReadU32(kEnergyCount, energy_count);

    for (uint32_t p = 0; p < 2; p++) {
        const PlayerScalarState& in = pkt.players[p];
        const auto& ext = pkt.extra[p];
        if (!in.valid) continue;

        uint32_t rec_base = kPlayerRecordsBase + p * kPlayerRecordStride;
        if (!SafeGuestRange(rec_base, kPlayerRecordStride)) continue;
        if (kernel::G<uint8_t>(rec_base + kRecordInactiveOffset) != 0) continue;

        uint32_t body_va = 0;
        if (!SafeReadU32(rec_base + kRecordBodyPtrOffset, body_va) || !body_va) {
            SafeReadU32(kPlayerObjectsTable[p], body_va);
        }
        if (!body_va || !SafeGuestRange(body_va, 0x380)) continue;

        if (new_packet) {
            uint32_t cur_max_u = 0, cur_hp_u = 0;
            if (SafeReadU32(body_va + kBodyMaxHealthOffset, cur_max_u) &&
                SafeReadU32(body_va + kBodyHealthOffset, cur_hp_u)) {
                int32_t cur_max = int32_t(cur_max_u);
                int32_t cur_hp = int32_t(cur_hp_u);
                if (cur_max > 0 && cur_max <= 100000 && cur_hp > 0) {
                    if (in.max_health > 0 && in.max_health <= 100000)
                        SafeWriteU32(body_va + kBodyMaxHealthOffset, uint32_t(in.max_health));
                    if (in.health > 0 && in.health <= in.max_health)
                        SafeWriteU32(body_va + kBodyHealthOffset, uint32_t(in.health));
                }
            }
        }

        float cx = 0, cy = 0, cz = 0;
        if (SafeReadFloat(rec_base + kRecordPosOffset + 0, cx) &&
            SafeReadFloat(rec_base + kRecordPosOffset + 4, cy) &&
            SafeReadFloat(rec_base + kRecordPosOffset + 8, cz)) {
            float dx = in.x - cx;
            float dy = in.y - cy;
            float dz = in.z - cz;
            float dist_sq = dx * dx + dy * dy + dz * dz;
            // Sync across the entire arena (up to 10,000 units = dist_sq < 100,000,000):
            // strong blend (0.75) for tiny drift, immediate snap (1.0) for drift > 25 units (dist_sq > 625)
            if (dist_sq > 0.04f && dist_sq < 100000000.0f) {
                float alpha = dist_sq > 625.0f ? 1.0f : 0.75f;
                float nx = cx + dx * alpha;
                float ny = cy + dy * alpha;
                float nz = cz + dz * alpha;
                SafeWriteFloat(rec_base + kRecordPosOffset + 0, nx);
                SafeWriteFloat(rec_base + kRecordPosOffset + 4, ny);
                SafeWriteFloat(rec_base + kRecordPosOffset + 8, nz);
                SafeWriteFloat(rec_base + kRecordRenderPosOffset + 0, nx);
                SafeWriteFloat(rec_base + kRecordRenderPosOffset + 4, ny);
                SafeWriteFloat(rec_base + kRecordRenderPosOffset + 8, nz);
                SafeWriteFloat(rec_base + kRecordCachedPosOffset + 0, nx);
                SafeWriteFloat(rec_base + kRecordCachedPosOffset + 4, ny);
                SafeWriteFloat(rec_base + kRecordCachedPosOffset + 8, nz);
                SafeWriteFloat(rec_base + kRecordVelOffset + 0, in.vx);
                SafeWriteFloat(rec_base + kRecordVelOffset + 4, in.vy);
                SafeWriteFloat(rec_base + kRecordVelOffset + 8, in.vz);
                if (dist_sq > 625.0f) {
                    // Cancel any local-only knockback/grab interpolation (0x0D6000) that would pull the player back
                    SafeWriteU32(rec_base + kRecordInterpTimerOffset, 0);
                    SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 0, nx);
                    SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 4, ny);
                    SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 8, nz);
                }
            }
            if (ext.has_extra) {
                if (std::fabs(ext.ground_y) < 100000.0f) {
                    SafeWriteFloat(rec_base + kRecordGroundOffset, ext.ground_y);
                    if (dist_sq > 625.0f) {
                        SafeWriteFloat(rec_base + kRecordPrevGroundOffset, ext.ground_y);
                        SafeWriteFloat(rec_base + kRecordCurGroundOffset, ext.ground_y);
                    }
                }
                if (std::fabs(ext.yaw) < 100.0f && std::fabs(ext.target_yaw) < 100.0f) {
                    SafeWriteFloat(rec_base + kRecordYawOffset, ext.yaw);
                    SafeWriteFloat(rec_base + kRecordTargetYawOffset, ext.target_yaw);
                }
            }
        }

        if (!new_packet) continue;

        if (p < energy_count && energy_count <= 4 && in.energy >= 0.0f && in.energy <= 10000.0f) {
            SafeWriteFloat(kEnergyTable + p * kEnergyStride, in.energy);
        }

        if (has_profile) {
            uint32_t prof_rec = profile + kProfileRecordsOffset + (p + 1) * kProfileRecordStride;
            if (SafeGuestRange(prof_rec, kProfileRecordStride)) {
                if (in.experience >= 0 && in.experience <= 9999999) SafeWriteU32(prof_rec + kExpOffset, uint32_t(in.experience));
                if (in.fatality_meter >= 0.0f && in.fatality_meter <= 100000.0f) SafeWriteFloat(prof_rec + kFatalityOffset, in.fatality_meter);
                if (in.fatality_level >= 0 && in.fatality_level <= 10) SafeWriteU32(prof_rec + kFatalityLevelOffset, uint32_t(in.fatality_level));
            }
        }
    }

    // Apply authoritative Host enemy state for slots p = 2..13
    if (pkt.has_enemies) {
        for (uint32_t e = 0; e < kEnemySlots; e++) {
            const EnemyScalarState& es = pkt.enemies[e];
            uint32_t rec_base = kPlayerRecordsBase + (e + 2) * kPlayerRecordStride;
            if (!SafeGuestRange(rec_base, kPlayerRecordStride)) continue;

            uint8_t c_inactive = kernel::G<uint8_t>(rec_base + kRecordInactiveOffset);
            int16_t c_ent_id = kernel::G<int16_t>(rec_base + kRecordEntityIdOffset);
            if (c_inactive != 0 || c_ent_id < 0) {
                g_enemy_missing_ticks[e] = 0;
                continue;
            }

            uint32_t body_va = 0;
            if (!SafeReadU32(rec_base + kRecordBodyPtrOffset, body_va) || !body_va || !SafeGuestRange(body_va, 0x380)) continue;

            uint32_t c_hp_u = 0, c_max_u = 0;
            if (!SafeReadU32(body_va + kBodyHealthOffset, c_hp_u) || !SafeReadU32(body_va + kBodyMaxHealthOffset, c_max_u)) continue;
            int32_t c_hp = int32_t(c_hp_u);
            int32_t c_max = int32_t(c_max_u);
            if (c_max <= 0 || c_max > 100000) continue;

            if (es.active && es.health > 0) {
                g_enemy_missing_ticks[e] = 0;
                if (new_packet && c_hp > 0) {
                    if (es.max_health > 0 && es.max_health <= 100000)
                        SafeWriteU32(body_va + kBodyMaxHealthOffset, uint32_t(es.max_health));
                    if (es.health <= es.max_health)
                        SafeWriteU32(body_va + kBodyHealthOffset, uint32_t(es.health));
                }
                float cx = 0, cy = 0, cz = 0;
                if (SafeReadFloat(rec_base + kRecordPosOffset + 0, cx) &&
                    SafeReadFloat(rec_base + kRecordPosOffset + 4, cy) &&
                    SafeReadFloat(rec_base + kRecordPosOffset + 8, cz)) {
                    float dx = es.x - cx;
                    float dy = es.y - cy;
                    float dz = es.z - cz;
                    float dist_sq = dx * dx + dy * dy + dz * dz;
                    if (dist_sq > 0.04f && dist_sq < 100000000.0f) {
                        float alpha = dist_sq > 400.0f ? 1.0f : 0.80f;
                        float nx = cx + dx * alpha;
                        float ny = cy + dy * alpha;
                        float nz = cz + dz * alpha;
                        SafeWriteFloat(rec_base + kRecordPosOffset + 0, nx);
                        SafeWriteFloat(rec_base + kRecordPosOffset + 4, ny);
                        SafeWriteFloat(rec_base + kRecordPosOffset + 8, nz);
                        SafeWriteFloat(rec_base + kRecordRenderPosOffset + 0, nx);
                        SafeWriteFloat(rec_base + kRecordRenderPosOffset + 4, ny);
                        SafeWriteFloat(rec_base + kRecordRenderPosOffset + 8, nz);
                        SafeWriteFloat(rec_base + kRecordCachedPosOffset + 0, nx);
                        SafeWriteFloat(rec_base + kRecordCachedPosOffset + 4, ny);
                        SafeWriteFloat(rec_base + kRecordCachedPosOffset + 8, nz);
                        if (dist_sq > 400.0f) {
                            SafeWriteU32(rec_base + kRecordInterpTimerOffset, 0);
                            SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 0, nx);
                            SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 4, ny);
                            SafeWriteFloat(rec_base + kRecordInterpTargetOffset + 8, nz);
                        }
                    }
                    if (std::fabs(es.ground_y) < 100000.0f) {
                        SafeWriteFloat(rec_base + kRecordGroundOffset, es.ground_y);
                        if (dist_sq > 400.0f) {
                            SafeWriteFloat(rec_base + kRecordPrevGroundOffset, es.ground_y);
                            SafeWriteFloat(rec_base + kRecordCurGroundOffset, es.ground_y);
                        }
                    }
                    if (std::fabs(es.yaw) < 100.0f) {
                        SafeWriteFloat(rec_base + kRecordYawOffset, es.yaw);
                        SafeWriteFloat(rec_base + kRecordTargetYawOffset, es.yaw);
                    }
                }
            } else if (es.active && es.health <= 0) {
                // Enemy is dying / dead on Host: mark dead on Client and start despawn timer (0x176F10)
                if (c_hp > 0) {
                    SafeWriteU32(body_va + kBodyHealthOffset, 0xFFFFFFFFu);
                    SafeWriteU32(rec_base + kRecordActionStateOffset, 6);
                    int32_t cur_timer = int32_t(kernel::R32(rec_base + kRecordDeathTimerOffset));
                    if (cur_timer < 0) SafeWriteU32(rec_base + kRecordDeathTimerOffset, 0);
                }
            } else if (!es.active && new_packet) {
                // Slot is empty/despawned on Host while still occupied on Client: trigger clean despawn via 0x176F10 -> 0x16C6D0
                if (g_enemy_missing_ticks[e] < 255) g_enemy_missing_ticks[e]++;
                if (g_enemy_missing_ticks[e] >= 12) {
                    SafeWriteU32(body_va + kBodyHealthOffset, 0xFFFFFFFFu);
                    SafeWriteU32(rec_base + kRecordActionStateOffset, 6);
                    uint32_t limit = 60;
                    SafeReadU32(kDespawnTimerLimitAddr, limit);
                    if (limit > 10000) limit = 60;
                    SafeWriteU32(rec_base + kRecordDeathTimerOffset, limit + 1);
                    g_enemy_missing_ticks[e] = 0;
                }
            }
        }
    }
}

void ReceiveLoopStep() {
    if (g_sock == kBadSocket) return;
    uint8_t buf[1024];
    for (int iter = 0; iter < 32; iter++) {
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        int n = int(recvfrom(g_sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                             reinterpret_cast<sockaddr*>(&from), &from_len));
        if (n < int(sizeof(PacketHeader))) break;

        PacketHeader hdr{};
        std::memcpy(&hdr, buf, sizeof(hdr));
        if (hdr.magic != kMagic || hdr.version != kProtoVersion) continue;

        uint32_t mode = g_mode.load(std::memory_order_relaxed);
        if (mode == kOff) continue;

        // Ignore our own broadcast packets
        uint32_t from_ip = from.sin_addr.s_addr;
        uint16_t from_port = from.sin_port;
        {
            std::lock_guard lock(g_lock);
            if (from_ip && from_ip == g_local_ip_net) continue;
        }

        // Only accept packets from the opposite role (Host <-> Client)
        if ((mode == kHost && hdr.role != kClient) || (mode == kClient && hdr.role != kHost)) continue;

        uint32_t now = TickMs();
        std::lock_guard lock(g_lock);
        bool newly_connected = !g_connected.load(std::memory_order_relaxed) || g_peer_ip != from_ip;
        g_peer_ip = from_ip;
        g_peer_port = from_port;
        g_peer_ip_str = IpToString(from_ip);
        g_last_recv_ms = now;
        g_last_echo_ms = hdr.send_ms;
        g_connected.store(true, std::memory_order_relaxed);
        if (hdr.echo_ms && now >= hdr.echo_ms && (now - hdr.echo_ms) < 5000) {
            g_ping_ms.store(int(now - hdr.echo_ms), std::memory_order_relaxed);
        }
        if (newly_connected) {
            LOGI("netplay: connected to peer %s:%u (role %u)", g_peer_ip_str.c_str(), ntohs(from_port), hdr.role);
        }

        if (mode == kHost && hdr.type == kPktClientPad && n >= int(sizeof(ClientPadPacket))) {
            ClientPadPacket pkt{};
            std::memcpy(&pkt, buf, sizeof(pkt));
            g_remote_pad = FromWire(pkt.pad1);
            g_remote_pad.connected = true;
        } else if (mode == kClient && hdr.type == kPktHostSync && n >= int(offsetof(HostSyncPacket, extra))) {
            HostSyncPacket pkt{};
            std::memcpy(&pkt, buf, std::min<size_t>(size_t(n), sizeof(pkt)));
            if (pkt.hdr.seq >= g_latest_sync.hdr.seq || (g_latest_sync.hdr.seq - pkt.hdr.seq) > 10000) {
                g_host_pad0 = FromWire(pkt.pad0);
                g_host_pad0.connected = true;
                g_host_pad1 = FromWire(pkt.pad1);
                g_host_pad1.connected = true;
                if (pkt.players[0].valid || pkt.players[1].valid) {
                    g_latest_sync = pkt;
                    g_has_sync = true;
                    g_last_sync_ms = now;
                }
            }
        }
    }
}

void NetplayThreadLoop() {
    uint32_t last_discover_ms = 0;
    std::vector<uint32_t> cached_targets;

    while (g_running.load(std::memory_order_relaxed)) {
        uint32_t mode = g_mode.load(std::memory_order_relaxed);
        if (mode == kOff) {
            g_connected.store(false, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            continue;
        }

        if (!EnsureSocket()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        ReceiveLoopStep();

        uint32_t now = TickMs();
        uint32_t peer_ip = 0;
        uint16_t peer_port = 0;
        uint32_t last_recv = 0;
        {
            std::lock_guard lock(g_lock);
            peer_ip = g_peer_ip;
            peer_port = g_peer_port;
            last_recv = g_last_recv_ms;
        }

        // Timeout connection after 3.5 seconds of silence (auto-reconnects as soon as peer responds)
        if (g_connected.load(std::memory_order_relaxed) && (now - last_recv) > 3500) {
            g_connected.store(false, std::memory_order_relaxed);
            LOGW("netplay: peer timed out, searching again...");
        }

        // Periodic discovery beacon every 400 ms (or every 1200 ms while connected to keep NAT/Hotspot table warm)
        uint32_t disc_interval = g_connected.load(std::memory_order_relaxed) ? 1200u : 400u;
        if (now - last_discover_ms >= disc_interval) {
            last_discover_ms = now;
            cached_targets = DiscoverTargetsAndLocalIp();
            PacketHeader beacon{};
            beacon.type = kPktDiscover;
            beacon.role = uint8_t(mode);
            beacon.seq = ++g_tx_seq;
            beacon.send_ms = now;
            for (uint32_t dst : cached_targets) {
                SendUdp(&beacon, sizeof(beacon), dst, htons(kDefaultPort));
            }
        }

        // Client transmits its controller input at ~120 Hz when connected
        if (mode == kClient && peer_ip) {
            ClientPadPacket pkt{};
            pkt.hdr.type = kPktClientPad;
            pkt.hdr.role = kClient;
            {
                std::lock_guard lock(g_lock);
                pkt.hdr.seq = ++g_tx_seq;
                pkt.hdr.send_ms = now;
                pkt.hdr.echo_ms = g_last_echo_ms;
                pkt.pad1 = ToWire(g_local_pad);
                pkt.pad1.connected = 1;
            }
            SendUdp(&pkt, sizeof(pkt), peer_ip, peer_port);
        } else if (mode == kHost && peer_ip) {
            // Host also sends input/keepalive packets between frames or during level loads so connection never drops
            HostSyncPacket pkt{};
            bool send_now = false;
            {
                std::lock_guard lock(g_lock);
                if (now - g_last_host_send_ms >= 25) {
                    g_last_host_send_ms = now;
                    pkt = g_host_cached_sync;
                    pkt.hdr.type = kPktHostSync;
                    pkt.hdr.role = kHost;
                    pkt.hdr.flags = g_sync_enabled.load(std::memory_order_relaxed) ? 1 : 0;
                    pkt.hdr.seq = ++g_tx_seq;
                    pkt.hdr.send_ms = now;
                    pkt.hdr.echo_ms = g_last_echo_ms;
                    pkt.pad0 = ToWire(g_local_pad);
                    pkt.pad0.connected = 1;
                    pkt.pad1 = ToWire(g_remote_pad);
                    pkt.pad1.connected = 1;
                    // Keepalive packet from background thread: do not overwrite Client positions with stale cache
                    pkt.players[0].valid = 0;
                    pkt.players[1].valid = 0;
                    pkt.has_enemies = 0;
                    send_now = true;
                }
            }
            if (send_now) {
                SendUdp(&pkt, sizeof(pkt), peer_ip, peer_port);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(4));
    }
}

}  // namespace

void Init() {
    if (g_running.exchange(true)) return;
    DiscoverTargetsAndLocalIp();
    std::thread(NetplayThreadLoop).detach();
}

void Shutdown() {
    g_running.store(false, std::memory_order_relaxed);
    CloseSocket(g_sock);
    g_sock = kBadSocket;
}

uint32_t GetMode() { return g_mode.load(std::memory_order_relaxed); }

void SetMode(uint32_t mode) {
    mode %= kModeCount;
    uint32_t prev = g_mode.exchange(mode, std::memory_order_relaxed);
    if (prev != mode) {
        std::lock_guard lock(g_lock);
        g_connected.store(false, std::memory_order_relaxed);
        g_peer_ip = 0;
        g_peer_port = 0;
        g_peer_ip_str.clear();
        g_has_sync = false;
        g_remote_pad = input::Pad{.connected = (mode != kOff)};
        LOGI("netplay: mode set to %s", ModeName());
    }
    if (mode != kOff) Init();
}

const char* ModeName() {
    switch (GetMode()) {
        case kHost: return "HOST (PLAYER 1)";
        case kClient: return "JOIN (PLAYER 2)";
        default: return "OFF (SOLO)";
    }
}

void StepMode(int step) {
    int m = (int(GetMode()) + step) % int(kModeCount);
    if (m < 0) m += int(kModeCount);
    SetMode(uint32_t(m));
}

bool SyncEnabled() { return g_sync_enabled.load(std::memory_order_relaxed); }

void SetSyncEnabled(bool on) { g_sync_enabled.store(on, std::memory_order_relaxed); }

uint32_t TargetHostOctet() { return g_target_octet.load(std::memory_order_relaxed); }

void SetTargetHostOctet(uint32_t octet) { g_target_octet.store(octet % 255, std::memory_order_relaxed); }

void StepTargetHostOctet(int step) {
    int cur = int(g_target_octet.load(std::memory_order_relaxed));
    cur = (cur + step) % 255;
    if (cur < 0) cur += 255;
    g_target_octet.store(uint32_t(cur), std::memory_order_relaxed);
}

std::string TargetHostText() {
    uint32_t octet = TargetHostOctet();
    if (octet == 0) {
        if (!app::Get().join_ip.empty()) return app::Get().join_ip;
        return "AUTO (HOTSPOT / WIFI)";
    }
    std::lock_guard lock(g_lock);
    uint32_t h = ntohl(g_local_ip_net);
    if (h) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (h >> 24) & 0xFF, (h >> 16) & 0xFF, (h >> 8) & 0xFF, octet);
        return buf;
    }
    return "192.168.43." + std::to_string(octet);
}

std::string LocalIpText() {
    std::lock_guard lock(g_lock);
    return g_local_ip_str;
}

std::string StatusText() {
    uint32_t mode = GetMode();
    if (mode == kOff) return "OFFLINE";
    if (!g_connected.load(std::memory_order_relaxed)) {
        return mode == kHost ? "WAITING FOR P2..." : "SEARCHING HOST...";
    }
    std::lock_guard lock(g_lock);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "CONNECTED (%s, %d MS)", g_peer_ip_str.c_str(), g_ping_ms.load(std::memory_order_relaxed));
    return buf;
}

bool IsConnected() { return g_connected.load(std::memory_order_relaxed); }

int PingMs() { return g_ping_ms.load(std::memory_order_relaxed); }

void FilterPad(int port, input::Pad& pad) {
    uint32_t mode = GetMode();
    if (mode == kOff) return;

    if (port == 0) {
        ReceiveLoopStep();
    }

    if (mode == kHost) {
        if (port == 0) {
            pad.connected = true;
            uint32_t peer_ip = 0;
            uint16_t peer_port = 0;
            uint32_t now = TickMs();
            HostSyncPacket pkt{};
            pkt.hdr.type = kPktHostSync;
            pkt.hdr.role = kHost;
            pkt.hdr.flags = g_sync_enabled.load(std::memory_order_relaxed) ? 1 : 0;
            pkt.hdr.send_ms = now;
            CaptureHostState(pkt);
            {
                std::lock_guard lock(g_lock);
                g_local_pad = pad;
                peer_ip = g_peer_ip;
                peer_port = g_peer_port;
                pkt.hdr.seq = ++g_tx_seq;
                pkt.hdr.echo_ms = g_last_echo_ms;
                pkt.pad0 = ToWire(g_local_pad);
                pkt.pad0.connected = 1;
                pkt.pad1 = ToWire(g_remote_pad);
                pkt.pad1.connected = 1;
                g_host_cached_sync = pkt;
                g_last_host_frame_ms = now;
                if (now - g_last_host_send_ms >= 8) {
                    g_last_host_send_ms = now;
                } else {
                    peer_ip = 0;
                }
            }
            if (peer_ip) {
                SendUdp(&pkt, sizeof(pkt), peer_ip, peer_port);
            }
        } else if (port == 1) {
            std::lock_guard lock(g_lock);
            if (g_connected.load(std::memory_order_relaxed)) {
                pad = g_remote_pad;
            }
            // Keep Port 1 marked connected while Host mode is on so Ko-Op & Versus can be entered on the Main Menu
            pad.connected = true;
        }
    } else if (mode == kClient) {
        if (port == 0) {
            // On Android, local Touch Controls / Gamepad / Keyboard arrive on port 0.
            // Save them as Client's Player 2 input, then substitute Host's Player 1 input on port 0!
            HostSyncPacket sync{};
            bool apply = false;
            bool new_packet = false;
            {
                std::lock_guard lock(g_lock);
                pad.connected = true;
                g_local_pad = pad;
                if (g_connected.load(std::memory_order_relaxed)) {
                    pad = g_host_pad0;
                    pad.connected = true;
                    if (g_has_sync && (g_latest_sync.hdr.seq != g_last_applied_seq || (TickMs() - g_last_sync_ms) < 150)) {
                        sync = g_latest_sync;
                        new_packet = (sync.hdr.seq != g_last_applied_seq);
                        g_last_applied_seq = sync.hdr.seq;
                        apply = true;
                    }
                }
            }
            if (apply) {
                ApplyHostStateOnClient(sync, new_packet);
            }
        } else if (port == 1) {
            std::lock_guard lock(g_lock);
            pad = g_local_pad;
            pad.connected = true;
        }
    }
}

void FilterRumble(int port, uint16_t& left, uint16_t& right) {
    uint32_t mode = GetMode();
    if (mode == kHost && port != 0) {
        left = 0;
        right = 0;
    } else if (mode == kClient && port != 1) {
        left = 0;
        right = 0;
    }
}

void OnFrame() {
    uint32_t mode = GetMode();
    if (mode == kOff) return;

    ReceiveLoopStep();

    if (mode == kHost) {
        static uint32_t last_tx_sim = 0;
        uint32_t peer_ip = 0;
        uint16_t peer_port = 0;
        uint32_t now = TickMs();
        HostSyncPacket pkt{};
        pkt.hdr.type = kPktHostSync;
        pkt.hdr.role = kHost;
        pkt.hdr.flags = g_sync_enabled.load(std::memory_order_relaxed) ? 1 : 0;
        pkt.hdr.send_ms = now;
        CaptureHostState(pkt);
        {
            std::lock_guard lock(g_lock);
            peer_ip = g_peer_ip;
            peer_port = g_peer_port;
            pkt.hdr.seq = ++g_tx_seq;
            pkt.hdr.echo_ms = g_last_echo_ms;
            pkt.pad0 = ToWire(g_local_pad);
            pkt.pad0.connected = 1;
            pkt.pad1 = ToWire(g_remote_pad);
            pkt.pad1.connected = 1;
            g_host_cached_sync = pkt;
            g_last_host_frame_ms = now;
            if ((pkt.hdr.sim_frame && pkt.hdr.sim_frame != last_tx_sim) || (now - g_last_host_send_ms >= 6)) {
                last_tx_sim = pkt.hdr.sim_frame;
                g_last_host_send_ms = now;
            } else {
                peer_ip = 0;
            }
        }
        if (peer_ip) {
            SendUdp(&pkt, sizeof(pkt), peer_ip, peer_port);
        }
    } else if (mode == kClient) {
        HostSyncPacket sync{};
        bool apply = false;
        bool new_packet = false;
        {
            std::lock_guard lock(g_lock);
            if (g_connected.load(std::memory_order_relaxed) && g_has_sync &&
                (g_latest_sync.hdr.seq != g_last_applied_seq || (TickMs() - g_last_sync_ms) < 150)) {
                sync = g_latest_sync;
                new_packet = (sync.hdr.seq != g_last_applied_seq);
                g_last_applied_seq = sync.hdr.seq;
                apply = true;
            }
        }
        if (apply) {
            ApplyHostStateOnClient(sync, new_packet);
        }
    }
}

}  // namespace netplay
