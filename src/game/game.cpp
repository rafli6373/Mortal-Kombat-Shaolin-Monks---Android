// Mortal Kombat: Shaolin Monks needs no patch of its code to run: the XDK it calls is all on the host. Its own
// hooks go here, [[hook]] entries in config/game.toml and X86_FUNC replacements of recompiled functions.
#include <chrono>
#include <cmath>
#include <cstring>

#include "common/aspect.h"
#include "common/netplay.h"
#include "common/options.h"
#include "cpu/x86_context.h"
#include "kernel/kernel.h"

namespace game {

// the disc has English, French, German, Spanish and Italian; Indonesian is the settings panel's alone
bool LanguageAvailable(const std::string& code) { return KnownLanguage(code); }

// no HUD hook to tell play from a menu: the touch controls stay up
bool HudShown() { return true; }

}  // namespace game

namespace app {

// the console's XC_LANGUAGE the game reads at boot, from the language setting as this run started
uint32_t ConsoleLanguage() {
    const std::string& l = game::BootLanguage();
    if (l == "deu") return 3;
    if (l == "fra") return 4;
    if (l == "esp") return 5;
    if (l == "ita") return 6;
    return 1;  // English, and Indonesian, which the disc lacks
}

}  // namespace app

// Gameplay steps the world by a fixed 1/60 s a frame (0x51003C), so under 60 fps it plays in slow motion.
// IMPORTANT: Inside 0x0CB780 (the simulation step), kSkipDraw (0x5CAB98) must stay 0! If 0x5CAB98 is 1 during
// 0x0CB780, the engine skips combat hitboxes (0x1A5480 at 0x1A549B), character movement (0x0D5606), animation
// (0x0D8A1D), 3D skeleton matrices (0x18AF72), camera updates (0x198500), and enemy wave triggers (0x1ADA00).
// Therefore FrameSkip (at 0x0CB800) always sets 0x5CAB98 = 0 for the simulation step and defers the draw-skip flag
// to KeepFatalityDraw (at 0x1B0B24 inside 0x1B0AF0), so only D3D rendering and Present() are skipped when behind.
namespace {

constexpr uint32_t kSkipDraw = 0x5CAB98;
bool g_skip_next_draw = false;

// Fatalities and the Fatality tutorial run synchronous loops (0x03F020, 0x03E970, 0x03EAF0, 0x03E900) that call
// 0x1B0AF0 directly without returning to 0x0CB780. If kSkipDraw (0x5CAB98) is 1 on entry, 0x1B0AF0 skips rendering
// and Present() on every iteration, either burning through the 200-tick input window in <1 ms (instant auto-cancel)
// or freezing indefinitely during the first Fatality tutorial (0x58A618 != 0).
bool FatalityBusy() {
    return kernel::R32(0x58A610) != 0 || kernel::G<uint8_t>(0x58A614) != 0 || kernel::R32(0x58A618) != 0 ||
           kernel::R32(0x58E4B4) != 0 || kernel::G<uint8_t>(0x58E4B0) != 0 || kernel::G<uint8_t>(0x59D320) != 0;
}

}  // namespace

void FrameSkip(X86Context&, uint8_t*) {
    using clock = std::chrono::steady_clock;
    constexpr auto kStep = std::chrono::microseconds(16667);
    // a load, a pause in the background or a stall: no catching up on it
    constexpr auto kMaxLag = std::chrono::milliseconds(250);
    constexpr int kMaxSkips = 3;  // a frame drawn at least every fourth, the controls answer at 15 fps
    static clock::time_point due;
    static int skips = 0;

    uint32_t game_skip = kernel::R32(kSkipDraw);
    // Always run the full simulation step (movement, combat hitboxes, camera, enemy wave spawners) in 0x0CB780
    kernel::W32(kSkipDraw, 0);

    auto now = clock::now();
    if (FatalityBusy()) {
        g_skip_next_draw = false;
        due = now;
        skips = 0;
        return;
    }
    if (!game::Opt().frame_skip) {
        g_skip_next_draw = (game_skip != 0);
        due = now;  // turned on again, it starts from here
        skips = 0;
        return;
    }
    // ahead of the clock carries no credit: the pacing at the present keeps 60
    if (due > now || now - due > kMaxLag) due = now;
    bool behind = (now - due >= kStep && skips < kMaxSkips);
    g_skip_next_draw = (game_skip != 0) || behind;
    skips = g_skip_next_draw ? skips + 1 : 0;
    due += kStep;
}

void KeepFatalityDraw(X86Context&, uint8_t*) {
    netplay::OnFrame();
    if (FatalityBusy() || !g_skip_next_draw) {
        kernel::W32(kSkipDraw, 0);
    } else {
        kernel::W32(kSkipDraw, 1);
    }
    g_skip_next_draw = false;
}

// The cameras draw a view made for a 4:3 screen whatever the shape it is shown at: the screen's 640 by 480
// (0x1245DC), and 1.2 for gameplay's. Wider settings stretched it. A camera of about 4:3 gets the shown frame's
// aspect instead, the same height of view and more of the sides; render to texture cameras of other shapes keep
// theirs.
void WidenAspect(X86Context& ctx, uint8_t*) {
    if (!game::Ultrawide()) return;
    float aspect;
    std::memcpy(&aspect, &ctx.eax, 4);
    if (aspect < 1.15f || aspect > 1.4f) return;
    aspect = game::Aspect();
    std::memcpy(&ctx.eax, &aspect, 4);
}
