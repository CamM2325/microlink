## What & why

<!-- Link the issue this fixes: "Fixes #123" -->

## How was it tested?

- [ ] `test/host` unit tests pass (`cmake -S test/host -B build-host && cmake --build build-host && ctest --test-dir build-host`)
- [ ] Built at least `examples/basic_connect` for esp32s3
- [ ] Tested on hardware (board / transport / control server): <!-- e.g. ESP32-S3 + Wi-Fi + Tailscale -->

## Checklist

- [ ] No credentials, auth keys or personal data in code, logs or commits
- [ ] Per-packet logging uses `ESP_LOGD`/`WG_DEBUG`, not `printf`/`ESP_LOGI`
- [ ] lwIP calls from non-tcpip tasks are wrapped (`LOCK_TCPIP_CORE` / `tcpip_callback`)
