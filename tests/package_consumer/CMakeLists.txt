# Builds a project that gets MicroLink only from the packed registry archive
# (see the "package" job in .github/workflows/ci.yml).
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(package_consumer)
