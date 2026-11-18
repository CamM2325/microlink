/* Host-test stand-in for the ESP-IDF lwIP port's arch/sys_arch.h, as far as
 * wireguardif.c uses it. lwipopts.h sets NO_SYS, so lwip/tcpip.h declares
 * nothing; the test itself plays tcpip_thread. */
#pragma once
#include <stdbool.h>
#include "lwip/err.h"

typedef enum {
	LWIP_CORE_LOCK_QUERY_HOLDER,
} sys_thread_core_lock_t;

static inline bool sys_thread_tcpip(sys_thread_core_lock_t type) {
	(void)type;
	return true;
}

typedef void (*tcpip_callback_fn)(void *ctx);
static inline err_t tcpip_try_callback(tcpip_callback_fn function, void *ctx) {
	function(ctx);
	return ERR_OK;
}
