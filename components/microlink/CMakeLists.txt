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
    REQUIRES ${REQUIRES}
    # wireguard_lwip also provides the X25519 (crypto/refc/x25519.h) used by
    # microlink.c, ml_noise.c and nacl_box.c
    PRIV_REQUIRES
        wireguard_lwip
)

# CONFIG_ML_LOG_LEVEL_*: compile MicroLink's logs at their own level. A -D is
# seen before any esp_log.h include, unlike a #define in the sources.
if(CONFIG_ML_LOG_LEVEL AND NOT CONFIG_ML_LOG_LEVEL_DEFAULT)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE LOG_LOCAL_LEVEL=${CONFIG_ML_LOG_LEVEL})
endif()

# DISCO crypto_box (XSalsa20-Poly1305) runs on every DISCO packet: -O2 like
# the wireguard_lwip crypto (see that CMakeLists).
if(NOT CONFIG_COMPILER_OPTIMIZATION_NONE)
    set_source_files_properties(src/nacl_box.c PROPERTIES COMPILE_OPTIONS "-O2")
endif()
