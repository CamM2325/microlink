idf_component_register(
    SRCS
        "src/wireguard.c"
        "src/wireguardif.c"
        "src/wireguard-filter.c"
        "src/crypto.c"
        "src/wireguard-platform-esp32.c"
        "src/crypto/refc/blake2s.c"
        "src/crypto/refc/chacha20.c"
        "src/crypto/refc/chacha20poly1305.c"
        "src/crypto/refc/poly1305-donna.c"
        "src/crypto/refc/x25519.c"
    INCLUDE_DIRS
        "src"
        "src/crypto/refc"
    REQUIRES
        lwip
        esp_timer
        nvs_flash
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WIREGUARD_CRYPTO_REFC=1
)

# Disable stringop-overread warning for x25519.c (false positive in GCC array bounds check)
set_source_files_properties(
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread"
)

# The data path (ChaCha20-Poly1305, BLAKE2s) and the handshakes (X25519) are
# the hot code: build them with -O2 whatever the project-wide level is (-Os in
# the examples, -Og by default). Only a -O0 debugging build is left alone.
# test/host/test_crypto_kat.c checks these files at -O2 and -Os.
if(NOT CONFIG_COMPILER_OPTIMIZATION_NONE)
    set_source_files_properties(
        src/crypto/refc/blake2s.c
        src/crypto/refc/chacha20.c
        src/crypto/refc/chacha20poly1305.c
        src/crypto/refc/poly1305-donna.c
        src/crypto/refc/x25519.c
        PROPERTIES COMPILE_OPTIONS "-O2"
    )
endif()
