set(SRCS
    "src/microlink.c"
    "src/ml_coord.c"
    "src/ml_coord_tls.c"
    "src/ml_derp.c"
    "src/ml_net_io.c"
    "src/ml_wg_mgr.c"
    "src/ml_stun.c"
    "src/ml_noise.c"
    "src/ml_h2.c"
    "src/ml_udp.c"
    "src/ml_filter.c"
    "src/ml_routes.c"
    "src/ml_nat66.c"
    "src/ml_ota.c"
    "src/ml_tcp.c"
    "src/ml_peer_nvs.c"
    "src/nacl_box.c"
    "src/ml_zerocopy.c"
    "src/ml_cellular.c"
    "src/ml_at_socket.c"
    "src/ml_at_validate.c"
    "src/ml_net_switch.c"
    "src/ml_config_httpd.c"
)

# WireGuard (wireguard-lwip, BSD-3-Clause) is compiled as part of this
# component, so MicroLink is one self-contained component (and one ESP
# Component Registry package). components/wireguard_lwip/CMakeLists.txt is
# only a stub for projects that still list components/microlink/components.
set(WG_DIR "components/wireguard_lwip/src")
set(WG_CRYPTO
    "${WG_DIR}/crypto/refc/blake2s.c"
    "${WG_DIR}/crypto/refc/chacha20.c"
    "${WG_DIR}/crypto/refc/chacha20poly1305.c"
    "${WG_DIR}/crypto/refc/poly1305-donna.c"
    "${WG_DIR}/crypto/refc/x25519.c"
)
list(APPEND SRCS
    "${WG_DIR}/wireguard.c"
    "${WG_DIR}/wireguardif.c"
    "${WG_DIR}/wireguard-filter.c"
    "${WG_DIR}/crypto.c"
    "${WG_DIR}/wireguard-platform-esp32.c"
    ${WG_CRYPTO}
)

set(REQUIRES
    nvs_flash
    esp_wifi
    esp_netif
    esp_event
    esp_timer
    lwip
    mbedtls
    driver
    esp_driver_uart
    esp_driver_gpio
    esp_driver_tsens
    esp_http_server
    app_update
    esp_app_format
    vfs
)

# ESP-IDF 6 no longer ships cJSON as the built-in `json` component; it comes
# from the component registry instead (see idf_component.yml).
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    list(APPEND REQUIRES espressif__cjson)
else()
    list(APPEND REQUIRES json)
endif()

idf_component_register(
    SRCS ${SRCS}
    INCLUDE_DIRS
        "include"
        "src"
    # The WireGuard headers, including the X25519 (crypto/refc/x25519.h) used
    # by microlink.c, ml_noise.c and nacl_box.c
    PRIV_INCLUDE_DIRS
        "${WG_DIR}"
        "${WG_DIR}/crypto/refc"
    REQUIRES ${REQUIRES}
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE WIREGUARD_CRYPTO_REFC=1)

# False positive of GCC's array-bounds check in x25519.c
set_source_files_properties("${WG_DIR}/crypto/refc/x25519.c"
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread")

# CONFIG_ML_LOG_LEVEL_*: compile MicroLink's logs at their own level. A -D is
# seen before any esp_log.h include, unlike a #define in the sources.
if(CONFIG_ML_LOG_LEVEL AND NOT CONFIG_ML_LOG_LEVEL_DEFAULT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE LOG_LOCAL_LEVEL=${CONFIG_ML_LOG_LEVEL})
endif()

# The data path (ChaCha20-Poly1305, BLAKE2s), the handshakes (X25519) and
# the DISCO crypto_box (XSalsa20-Poly1305, every DISCO packet) are the hot
# code: build them with -O2 whatever the project-wide level is (-Os in the
# examples, -Og by default). Only a -O0 debugging build is left alone.
# test/host/test_crypto_kat.c checks the WireGuard crypto at -O2 and -Os.
if(NOT CONFIG_COMPILER_OPTIMIZATION_NONE)
    set_source_files_properties(src/nacl_box.c ${WG_CRYPTO} PROPERTIES COMPILE_OPTIONS "-O2")
endif()
