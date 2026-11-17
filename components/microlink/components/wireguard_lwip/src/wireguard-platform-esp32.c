/**
 * @file wireguard-platform-esp32.c
 * @brief ESP32 platform implementation for wireguard-lwip
 */

#include "wireguard-platform.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "nvs.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "lwip/sys.h"
#include <string.h>
#include <sys/time.h>

/* ============================================================================
 * Time Functions
 * ========================================================================== */

uint32_t wireguard_sys_now() {
    // Use lwIP's built-in time function
    return sys_now();
}

/*
 * Handshake timestamp (TAI64N) - MUST be strictly increasing across reboots.
 *
 * A WireGuard peer remembers the greatest timestamp it has accepted from our
 * static key and silently drops any initiation that is not newer (replay
 * protection, WireGuard paper 5.1). The old implementation used uptime, so
 * after a reboot every handshake was rejected as a replay until the new
 * uptime overtook the previous session's - a device that ran for hours could
 * not reconnect (users saw "deleting the node in the admin console fixes it").
 *
 * Scheme (no SNTP required):
 *   t = max(wall_clock_if_valid, base + uptime)
 *   base = (floor persisted in NVS) + SAVE_INTERVAL + 1 at boot, so t always
 *   exceeds anything sent before the last reboot. The floor is re-persisted at
 *   most once per SAVE_INTERVAL (flash wear), and every timestamp handed out
 *   since the last save is < floor + SAVE_INTERVAL by construction.
 *   That bound holds only for saves that reached flash, so the in-RAM floor
 *   advances after a successful commit, and a failed write is retried.
 *   Remaining gap: while one caller's write is in flight, another caller may
 *   hand out (and send) a timestamp above the old floor + SAVE_INTERVAL; a
 *   reboot in that window can repeat it. Initiations are only created on
 *   the wg_mgr task, so in practice there is no second caller.
 *   First boot (no floor yet) starts at 2025-01-01, above any uptime value the
 *   old firmware could have sent, and below real wall-clock time, so adopting
 *   SNTP time later keeps the sequence monotonic.
 */
#define WG_TS_NVS_NAMESPACE     "ml_wg"
#define WG_TS_NVS_KEY           "ts_floor"
#define WG_TS_SAVE_INTERVAL_S   600ULL
#define WG_TS_FIRST_BOOT_BASE   1735689600ULL   /* 2025-01-01T00:00:00Z */
#define WG_TS_MIN_WALLCLOCK     1735689600ULL   /* wall clock below this = not set */

static portMUX_TYPE s_ts_lock = portMUX_INITIALIZER_UNLOCKED;
static bool     s_ts_ready;
static uint64_t s_ts_base;       /* seconds; t = base + uptime */
static uint64_t s_ts_saved;      /* last floor committed to NVS */
static bool     s_ts_saving;     /* a task is writing a new floor */
static bool     s_ts_save_err_logged;
static uint64_t s_ts_last_s;
static uint32_t s_ts_last_ns;

static uint64_t ts_load_floor(void) {
    nvs_handle_t h;
    uint64_t v = 0;
    if (nvs_open(WG_TS_NVS_NAMESPACE, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u64(h, WG_TS_NVS_KEY, &v) != ESP_OK) {
            v = 0;
        }
        nvs_close(h);
    }
    return v;
}

static esp_err_t ts_store_floor(uint64_t v) {
    nvs_handle_t h;
    esp_err_t err = nvs_open(WG_TS_NVS_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u64(h, WG_TS_NVS_KEY, v);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

void wireguard_tai64n_now(uint8_t *output) {
    if (!s_ts_ready) {
        /* NVS may block: read outside the spinlock. A racing first call just
         * computes the same base. */
        uint64_t floor = ts_load_floor();
        uint64_t base = floor ? floor + WG_TS_SAVE_INTERVAL_S + 1 : WG_TS_FIRST_BOOT_BASE;
        portENTER_CRITICAL(&s_ts_lock);
        if (!s_ts_ready) {
            s_ts_base = base;
            s_ts_ready = true;
        }
        portEXIT_CRITICAL(&s_ts_lock);
    }

    const uint64_t now_us = (uint64_t)esp_timer_get_time();
    const uint64_t up_s = now_us / 1000000ULL;
    uint32_t nanoseconds = (uint32_t)(now_us % 1000000ULL) * 1000U;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    const uint64_t wall = (tv.tv_sec > 0 && (uint64_t)tv.tv_sec >= WG_TS_MIN_WALLCLOCK) ? (uint64_t)tv.tv_sec : 0;

    bool save = false;
    uint64_t seconds;
    portENTER_CRITICAL(&s_ts_lock);
    seconds = s_ts_base + up_s;
    if (wall > seconds) {
        /* Adopt wall-clock time; base only ever moves forward. */
        s_ts_base = wall - up_s;
        seconds = wall;
    }
    /* Strictly increasing within a boot, even for back-to-back calls. */
    if (seconds < s_ts_last_s || (seconds == s_ts_last_s && nanoseconds <= s_ts_last_ns)) {
        seconds = s_ts_last_s;
        nanoseconds = s_ts_last_ns + 1;
        if (nanoseconds >= 1000000000U) {
            seconds++;
            nanoseconds = 0;
        }
    }
    s_ts_last_s = seconds;
    s_ts_last_ns = nanoseconds;
    /* s_ts_saved only moves once the floor is really in flash: advancing it
     * first (and ignoring write errors) meant a failed write left flash on
     * the old floor while RAM believed the new one was saved, and the next
     * boot could start below timestamps already sent. A failed write is
     * retried by the next call. */
    if (!s_ts_saving && (s_ts_saved == 0 || seconds >= s_ts_saved + WG_TS_SAVE_INTERVAL_S)) {
        s_ts_saving = true;
        save = true;
    }
    portEXIT_CRITICAL(&s_ts_lock);

    if (save) {
        esp_err_t err = ts_store_floor(seconds);
        bool log_err = false;
        portENTER_CRITICAL(&s_ts_lock);
        if (err == ESP_OK) {
            if (seconds > s_ts_saved) {
                s_ts_saved = seconds;
            }
            s_ts_save_err_logged = false;
        } else if (!s_ts_save_err_logged) {
            s_ts_save_err_logged = true;
            log_err = true;
        }
        s_ts_saving = false;
        portEXIT_CRITICAL(&s_ts_lock);
        if (log_err) {
            ESP_LOGW("wg", "Could not persist the handshake timestamp floor (%s); "
                     "handshakes may be rejected as replays after a reboot until this succeeds",
                     esp_err_to_name(err));
        }
    }

    // TAI64 label: 2^62 + 10 + Unix seconds
    seconds += 0x400000000000000AULL;

    // Write in big-endian format
    output[0] = (seconds >> 56) & 0xFF;
    output[1] = (seconds >> 48) & 0xFF;
    output[2] = (seconds >> 40) & 0xFF;
    output[3] = (seconds >> 32) & 0xFF;
    output[4] = (seconds >> 24) & 0xFF;
    output[5] = (seconds >> 16) & 0xFF;
    output[6] = (seconds >> 8) & 0xFF;
    output[7] = seconds & 0xFF;

    output[8] = (nanoseconds >> 24) & 0xFF;
    output[9] = (nanoseconds >> 16) & 0xFF;
    output[10] = (nanoseconds >> 8) & 0xFF;
    output[11] = nanoseconds & 0xFF;
}

/* ============================================================================
 * Random Number Generation
 * ========================================================================== */

void wireguard_random_bytes(void *bytes, size_t size) {
    // Use ESP32 hardware RNG
    esp_fill_random(bytes, size);
}

/* ============================================================================
 * Load Management
 * ========================================================================== */

bool wireguard_is_under_load() {
    // For now, always return false (not under load)
    // Could be enhanced to check:
    // - Free heap memory
    // - CPU usage
    // - Number of active connections
    return false;
}
