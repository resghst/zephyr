# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(peripheral_sc_xor)

# target_sources(app PRIVATE
#   src/*.c
# )
FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE
  ${app_sources}
  )

# zephyr_library_include_directories(${ZEPHYR_BASE}/samples/bluetooth)
