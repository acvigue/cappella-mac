#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2026 The cappella-mac authors
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Lint: clang-format (the .clang-format style; CI pins clang-format 21.1.8) and
# cppcheck on the MAC (src/), the reference crypto (port/sec_ref/) and the nRF91
# port (port/nrf_dect_phy/). Warning, performance and portability findings fail;
# style findings are printed with --style.
#
# usage: ci/lint.sh [--fix] [--style]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
fix=0
style=0
for a in "$@"; do
	case "$a" in
	--fix) fix=1 ;;
	--style) style=1 ;;
	*) echo "usage: $0 [--fix] [--style]" >&2; exit 2 ;;
	esac
done

files=()
while IFS= read -r f; do
	files+=("$f")
done < <(find src include port tests samples -name '*.[ch]' | sort)

echo "== clang-format $(clang-format --version | sed 's/.*version //')"
if [ "$fix" = 1 ]; then
	clang-format -i "${files[@]}"
else
	clang-format --dry-run --Werror "${files[@]}"
fi

enable=warning,performance,portability
[ "$style" = 1 ] && enable="$enable,style"
common=(--std=c99 --inline-suppr --error-exitcode=1 --suppress=missingIncludeSystem -q -I include)

echo "== cppcheck $(cppcheck --version | sed 's/Cppcheck //'): src/ port/sec_ref/"
cppcheck "${common[@]}" --enable="$enable" src port/sec_ref

echo "== cppcheck: port/nrf_dect_phy/ (Zephyr macros from ci/cppcheck-zephyr.cfg)"
cppcheck "${common[@]}" --enable="$enable" --suppress=missingInclude \
	--library=ci/cppcheck-zephyr.cfg port/nrf_dect_phy

echo "lint ok"
