/* Host-test stand-in for the FreeRTOS mutex API used by wireguardif.c.
 * The tests are single-threaded, so a mutex is a flag. Taking a mutex that is
 * already held, or giving one that is not, aborts: on the device the first
 * would deadlock. */
#pragma once
#include <stdlib.h>

typedef int StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
#define portMAX_DELAY 0xffffffffu

static inline SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *buf) {
	*buf = 0;
	return buf;
}
static inline int host_mutex_take(SemaphoreHandle_t m) {
	if (*m) abort();
	*m = 1;
	return 1;
}
static inline int host_mutex_give(SemaphoreHandle_t m) {
	if (!*m) abort();
	*m = 0;
	return 1;
}
#define xSemaphoreTake(m, ticks) host_mutex_take(m)
#define xSemaphoreGive(m)        host_mutex_give(m)
