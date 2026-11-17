# Host (PC) unit tests for security-critical wireguard-lwip filters and the
# modem AT command parameter validators.
# No hardware needed. Usage:
#   cmake -S test/host -B build-host -DLWIP_INCLUDE_DIR=$IDF_PATH/components/lwip/lwip/src/include
#   cmake --build build-host && ctest --test-dir build-host --output-on-failure
cmake_minimum_required(VERSION 3.16)
project(microlink_host_tests C)
set(CMAKE_C_STANDARD 11)

if(NOT LWIP_INCLUDE_DIR)
  if(DEFINED ENV{IDF_PATH})
    set(LWIP_INCLUDE_DIR "$ENV{IDF_PATH}/components/lwip/lwip/src/include")
  else()
    message(FATAL_ERROR "Set -DLWIP_INCLUDE_DIR=<lwip>/src/include or export IDF_PATH")
  endif()
endif()

set(WG_SRC ${CMAKE_CURRENT_LIST_DIR}/../../components/microlink/components/wireguard_lwip/src)

add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter -g
                    -fsanitize=address,undefined -fno-omit-frame-pointer)
add_link_options(-fsanitize=address,undefined)

add_executable(test_wg_filter test_wg_filter.c ${WG_SRC}/wireguard-filter.c)
target_include_directories(test_wg_filter PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/include ${WG_SRC} ${LWIP_INCLUDE_DIR})

set(ML_SRC ${CMAKE_CURRENT_LIST_DIR}/../../components/microlink)
add_executable(test_at_validate test_at_validate.c ${ML_SRC}/src/ml_at_validate.c)
target_include_directories(test_at_validate PRIVATE ${ML_SRC}/include)

enable_testing()
add_test(NAME wg_filter COMMAND test_wg_filter)

# Noise control-channel AEAD (wireguard-lwip ChaCha20-Poly1305 + Tailscale nonce)
add_executable(test_noise_aead test_noise_aead.c
  ${WG_SRC}/crypto/refc/chacha20.c
  ${WG_SRC}/crypto/refc/chacha20poly1305.c
  ${WG_SRC}/crypto/refc/poly1305-donna.c
  ${WG_SRC}/crypto.c)
target_include_directories(test_noise_aead PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../components/microlink/src
  ${WG_SRC} ${WG_SRC}/crypto/refc)
# The vendored reference crypto is not -Wextra clean
set_source_files_properties(${WG_SRC}/crypto/refc/chacha20.c
  PROPERTIES COMPILE_OPTIONS -Wno-sign-compare)
add_test(NAME noise_aead COMMAND test_noise_aead)
add_test(NAME at_validate COMMAND test_at_validate)

# Crypto known-answer tests (RFC 7748 / 8439 / 7693 + NaCl box). The firmware
# compiles these sources with -O2 and the rest with -Os, so build the test at
# both levels: optimiser-sensitive UB in the vendored crypto fails here first.
set(CRYPTO_SRC
  ${WG_SRC}/crypto/refc/x25519.c
  ${WG_SRC}/crypto/refc/chacha20.c
  ${WG_SRC}/crypto/refc/chacha20poly1305.c
  ${WG_SRC}/crypto/refc/poly1305-donna.c
  ${WG_SRC}/crypto/refc/blake2s.c
  ${WG_SRC}/crypto.c
  ${ML_SRC}/src/nacl_box.c)
# Same GCC false positive the component CMakeLists silences
set_source_files_properties(${WG_SRC}/crypto/refc/x25519.c
  PROPERTIES COMPILE_OPTIONS -Wno-stringop-overread)
foreach(opt O2 Os)
  add_executable(test_crypto_kat_${opt} test_crypto_kat.c ${CRYPTO_SRC})
  target_compile_options(test_crypto_kat_${opt} PRIVATE -${opt})
  target_include_directories(test_crypto_kat_${opt} PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/include ${ML_SRC}/src ${WG_SRC} ${WG_SRC}/crypto/refc)
  add_test(NAME crypto_kat_${opt} COMMAND test_crypto_kat_${opt})
endforeach()

# Packet filter (tailnet ACL enforcement). Needs cJSON: ESP-IDF's copy by
# default, or pass -DCJSON_DIR=<dir containing cJSON.c/cJSON.h>.
if(NOT CJSON_DIR AND DEFINED ENV{IDF_PATH})
  set(CJSON_DIR "$ENV{IDF_PATH}/components/json/cJSON")
endif()
if(CJSON_DIR AND EXISTS "${CJSON_DIR}/cJSON.c")
  add_library(cjson_host STATIC ${CJSON_DIR}/cJSON.c)
  target_include_directories(cjson_host PUBLIC ${CJSON_DIR})
  target_compile_options(cjson_host PRIVATE -w)
  add_executable(test_filter test_filter.c ${ML_SRC}/src/ml_filter.c ${ML_SRC}/src/ml_routes.c)
  target_include_directories(test_filter PRIVATE ${ML_SRC}/include)
  target_link_libraries(test_filter PRIVATE cjson_host)
  add_test(NAME packet_filter COMMAND test_filter)
else()
  message(WARNING "cJSON not found (set CJSON_DIR or IDF_PATH); skipping packet filter tests")
endif()
