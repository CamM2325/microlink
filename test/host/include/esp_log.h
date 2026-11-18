/* Host-test stand-in for esp_log.h. Arguments are still evaluated, so the
 * sanitizers see what the log lines read. */
#pragma once

typedef enum {
	ESP_LOG_NONE, ESP_LOG_ERROR, ESP_LOG_WARN, ESP_LOG_INFO, ESP_LOG_DEBUG, ESP_LOG_VERBOSE,
} esp_log_level_t;

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#endif

static inline esp_log_level_t esp_log_level_get(const char *tag) {
	(void)tag;
	return ESP_LOG_VERBOSE;
}
static inline void host_log_sink(const char *tag, const char *fmt, ...) {
	(void)tag;
	(void)fmt;
}
#define ESP_LOGE(tag, ...) host_log_sink(tag, __VA_ARGS__)
#define ESP_LOGW(tag, ...) host_log_sink(tag, __VA_ARGS__)
#define ESP_LOGI(tag, ...) host_log_sink(tag, __VA_ARGS__)
#define ESP_LOGD(tag, ...) host_log_sink(tag, __VA_ARGS__)
#define ESP_LOGV(tag, ...) host_log_sink(tag, __VA_ARGS__)
