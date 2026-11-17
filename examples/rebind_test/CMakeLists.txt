cmake_minimum_required(VERSION 3.16)

# microlink, plus wireguard_lwip which lives inside it
set(EXTRA_COMPONENT_DIRS
    "../../components"
    "../../components/microlink/components"
)

# Optional, git-ignored credentials (copy sdkconfig.credentials.example).
# Like all sdkconfig defaults, it only applies when sdkconfig is (re)created:
# delete sdkconfig or run `idf.py fullclean` after editing it. It is appended
# to SDKCONFIG_DEFAULTS, so an overlay given on the command line, such as
# -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;../sdkconfig.size.defaults",
# still applies.
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
project(rebind_test)
