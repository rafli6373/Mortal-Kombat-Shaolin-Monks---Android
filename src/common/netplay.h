#pragma once
#include <cstdint>
#include <string>

#include "core/input.h"

namespace netplay {

// 0 off (solo), 1 host (player 1, port 0), 2 join/client (player 2, port 1)
enum Mode : uint32_t {
    kOff = 0,
    kHost = 1,
    kClient = 2,
    kModeCount = 3,
};

void Init();
void Shutdown();

uint32_t GetMode();
void SetMode(uint32_t mode);
const char* ModeName();
void StepMode(int step);

bool SyncEnabled();
void SetSyncEnabled(bool on);

// target host IPv4 last octet (0 = AUTO discovery, 1..254 = subnet.<octet>) or full IP in settings
uint32_t TargetHostOctet();
void SetTargetHostOctet(uint32_t octet);
void StepTargetHostOctet(int step);
std::string TargetHostText();

std::string LocalIpText();
std::string StatusText();
bool IsConnected();
int PingMs();

// called from game::Pad(port, pad) in src/common/game_info.cpp
void FilterPad(int port, input::Pad& pad);
// called from game::Rumble(port, left, right) in src/common/game_info.cpp
void FilterRumble(int port, uint16_t& left, uint16_t& right);

// called once per presented frame on the game thread (src/d3d/d3d8.cpp / src/game/cheats.cpp)
void OnFrame();

}  // namespace netplay
