# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 The cappella-mac authors
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Stand-alone host build: the MAC as a static library, the reference crypto, and
# (top level only) the simulation tests.
#
#   cmake -S . -B build && cmake --build build -j && ctest --test-dir build -j
#
# Zephyr builds use zephyr/CMakeLists.txt (zephyr/module.yml), not this file.

cmake_minimum_required(VERSION 3.20)
project(cappella_mac VERSION 0.1.0 LANGUAGES C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(CAPPELLA_MAC_TOP_LEVEL ON)
else()
  set(CAPPELLA_MAC_TOP_LEVEL OFF)
endif()

option(CAPPELLA_MAC_TESTS "Build the host simulation tests" ${CAPPELLA_MAC_TOP_LEVEL})
option(CAPPELLA_MAC_SANITIZE "Build everything with ASan + UBSan" OFF)
option(CAPPELLA_MAC_WERROR "Treat warnings as errors" ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Visible to the functions below wherever they are called from (also from a
# parent project that add_subdirectory()s this one).
set(CAPPELLA_MAC_ROOT ${CMAKE_CURRENT_SOURCE_DIR} CACHE INTERNAL "")
set(CAPPELLA_MAC_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tdma_plan.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tdma_pdu.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tdma_link.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tdma_mac.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/tdma_relay.c
  CACHE INTERNAL "")

# The MAC is strict C99: no heap, no floating point, no OS headers.
set(flags -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
  -Wdouble-promotion -Wfloat-equal -Wvla)
if(CAPPELLA_MAC_WERROR)
  list(APPEND flags -Werror)
endif()
set(CAPPELLA_MAC_STRICT_FLAGS ${flags} CACHE INTERNAL "")
set(CAPPELLA_MAC_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer
  -fno-sanitize-recover=undefined CACHE INTERNAL "")

function(cappella_mac_sanitize target)
  if(CAPPELLA_MAC_SANITIZE)
    target_compile_options(${target} PRIVATE ${CAPPELLA_MAC_SAN_FLAGS})
    target_link_options(${target} PUBLIC -fsanitize=address,undefined)
  endif()
endfunction()

# cappella_mac_library(<name> [DEFINES ...]): one build of the MAC. Compile-time
# sizes (TDMA_MAX_SDU, TDMA_MAX_POSITIONS, ...) change struct tdma_mac, so
# they are PUBLIC definitions: everything that links the library agrees.
function(cappella_mac_library name)
  cmake_parse_arguments(A "" "" "DEFINES" ${ARGN})
  add_library(${name} STATIC ${CAPPELLA_MAC_SOURCES})
  target_include_directories(${name} PUBLIC ${CAPPELLA_MAC_ROOT}/include)
  target_compile_options(${name} PRIVATE ${CAPPELLA_MAC_STRICT_FLAGS})
  if(A_DEFINES)
    target_compile_definitions(${name} PUBLIC ${A_DEFINES})
  endif()
  cappella_mac_sanitize(${name})
endfunction()

cappella_mac_library(cappella_mac)
add_library(cappella::mac ALIAS cappella_mac)

# Reference AES-128-CCM / CMAC / KDF and a struct tdma_sec_ops on top of it.
add_library(cappella_sec_ref STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/port/sec_ref/tdma_sec_ref_crypto.c
  ${CMAKE_CURRENT_SOURCE_DIR}/port/sec_ref/tdma_sec_ref.c
)
target_include_directories(cappella_sec_ref PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(cappella_sec_ref PRIVATE ${CAPPELLA_MAC_STRICT_FLAGS})
cappella_mac_sanitize(cappella_sec_ref)
add_library(cappella::sec_ref ALIAS cappella_sec_ref)

# The simulator and test harness (tests/sim), reusable by downstream suites that
# drive the MAC with their own test files and main():
#   cappella_sim_add(<target> <mac library target> <sources...>)
set(CAPPELLA_SIM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests/sim CACHE INTERNAL "")
function(cappella_sim_add target maclib)
  add_executable(${target}
    ${CAPPELLA_SIM_DIR}/sim.c
    ${CAPPELLA_SIM_DIR}/harness.c
    ${CAPPELLA_MAC_ROOT}/port/sec_ref/tdma_sec_ref_crypto.c
    ${ARGN})
  target_include_directories(${target} PRIVATE ${CAPPELLA_SIM_DIR})
  target_link_libraries(${target} PRIVATE ${maclib})
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-missing-field-initializers)
  if(CAPPELLA_MAC_WERROR)
    target_compile_options(${target} PRIVATE -Werror)
  endif()
  # The tests may use the C library freely (gnu99: POSIX bits of libc).
  set_target_properties(${target} PROPERTIES C_EXTENSIONS ON)
  cappella_mac_sanitize(${target})
endfunction()

if(CAPPELLA_MAC_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
