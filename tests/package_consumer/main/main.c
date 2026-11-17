/* Compile/link check for the packaged component: uses the public API only. */
#include "microlink.h"

void app_main(void) {
    microlink_config_t cfg = { .auth_key = "", .device_name = "package-check" };
    microlink_t *ml = microlink_init(&cfg);
    if (ml) microlink_start(ml);
}
