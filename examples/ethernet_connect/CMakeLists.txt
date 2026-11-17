# MicroLink over Ethernet: WT32-ETH01 (ESP32 + LAN8720), a W5500 SPI module
# on any ESP32 chip, or QEMU's emulated Ethernet (see sdkconfig.qemu.defaults).
cmake_minimum_required(VERSION 3.16)

set(EXTRA_COMPONENT_DIRS
    "../../components"
    "../../components/microlink/components"
)

# Optional, git-ignored credentials (copy ../basic_connect/sdkconfig.credentials.example).
# Like all sdkconfig defaults, it only applies when sdkconfig is (re)created.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.credentials")
    if(NOT SDKCONFIG_DEFAULTS)
        if(DEFINED ENV{SDKCONFIG_DEFAULTS})
            set(SDKCONFIG_DEFAULTS "$ENV{SDKCONFIG_DEFAULTS}")
        else()
            set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
        endif()
    endif()
    list(APPEND SDKCONFIG_DEFAULTS "sdkconfig.credentials")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(microlink_ethernet_connect)
