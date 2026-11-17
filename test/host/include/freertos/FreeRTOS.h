/* Host-test stand-in for the FreeRTOS critical-section API used by nacl_box.c.
 * The tests are single-threaded, so the lock is a no-op. */
#pragma once

typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(mux) ((void)(mux))
#define taskEXIT_CRITICAL(mux)  ((void)(mux))
