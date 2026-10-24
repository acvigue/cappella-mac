# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 The cappella-mac authors
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.


cmake_minimum_required(VERSION 3.20.0)

# This sample lives inside the cappella-mac module: add the module itself, so the
# sample builds from a plain NCS workspace without a west manifest entry.
list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_LIST_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cappella_link_demo)

target_sources(app PRIVATE src/main.c)
