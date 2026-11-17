/*
 * ml_ota: keep a freshly updated firmware only if it can rejoin the tailnet.
 *
 * With the bootloader's app rollback enabled, an image written by OTA boots
 * in the PENDING_VERIFY state. MicroLink marks it valid once it reaches
 * CONNECTED; if that does not happen within CONFIG_ML_OTA_CONFIRM_TIMEOUT_S,
 * it restarts the device and the bootloader goes back to the previous image.
 * A firmware that cannot reach the tailnet would otherwise also be one that
 * can no longer be updated over it.
 */
#include "sdkconfig.h"
#include "microlink_internal.h"

#ifdef CONFIG_ML_OTA_ROLLBACK
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"

static const char *TAG = "ml_ota";
static esp_timer_handle_t s_timer;

static bool running_image_pending(void) {
    esp_ota_img_states_t st;
    const esp_partition_t *p = esp_ota_get_running_partition();
    return p && esp_ota_get_state_partition(p, &st) == ESP_OK &&
           st == ESP_OTA_IMG_PENDING_VERIFY;
}

static void confirm_timeout(void *arg) {
    (void)arg;
    if (running_image_pending()) {
        ESP_LOGE(TAG, "New firmware did not connect within %d s; restarting to roll back",
                 CONFIG_ML_OTA_CONFIRM_TIMEOUT_S);
        esp_restart();
    }
}

void ml_ota_check_pending(void) {
    if (s_timer || !running_image_pending()) return;
    ESP_LOGW(TAG, "Running a new firmware: it is kept once MicroLink connects "
                  "(rollback in %d s otherwise)", CONFIG_ML_OTA_CONFIRM_TIMEOUT_S);
    const esp_timer_create_args_t args = { .callback = confirm_timeout, .name = "ml_ota" };
    if (esp_timer_create(&args, &s_timer) != ESP_OK ||
        esp_timer_start_once(s_timer, (uint64_t)CONFIG_ML_OTA_CONFIRM_TIMEOUT_S * 1000000ULL) != ESP_OK) {
        ESP_LOGE(TAG, "Could not start the rollback timer");
    }
}

void ml_ota_confirm(void) {
    if (!running_image_pending()) return;
    if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
        ESP_LOGI(TAG, "New firmware confirmed (connected to the tailnet)");
    }
    if (s_timer) esp_timer_stop(s_timer);
}

#else

void ml_ota_check_pending(void) {}
void ml_ota_confirm(void) {}

#endif
