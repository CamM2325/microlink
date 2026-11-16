cmake_minimum_required(VERSION 3.16)

# microlink, plus wireguard_lwip which lives inside it
set(EXTRA_COMPONENT_DIRS
    "../../components"
    "../../components/microlink/components"
)

# Optional, git-ignored credentials (copy sdkconfig.credentials.example).
# Like all sdkconfig defaults, it only applies when sdkconfig is (re)created:
# delete sdkconfig or run `idf.py fullclean` after editing it.
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/sdkconfig.credentials")
    set(SDKCONFIG_DEFAULTS "sdkconfig.defaults;sdkconfig.credentials")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(rebind_test)
