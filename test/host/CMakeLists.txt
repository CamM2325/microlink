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
add_test(NAME at_validate COMMAND test_at_validate)
