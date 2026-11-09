#!/usr/bin/env bash
# Copyright 2025-2026 COMMON CREATION, Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p build/test-deps build/test-classes
sim=build/test-deps/jcardsim-3.0.5.11.jar
if [[ ! -f "$sim" ]]; then
    curl -fsSL https://repo.maven.apache.org/maven2/com/klinec/jcardsim/3.0.5.11/jcardsim-3.0.5.11.jar -o "$sim"
fi
printf '%s  %s\n' f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c "$sim" | sha256sum --check --status
javac -cp "$sim" -d build/test-classes \
    tests/support/org/globalplatform/*.java \
    src/com/common_creation/applet/ara/*.java \
    src/com/common_creation/applet/gp_ara_d/*.java \
    src/com/common_creation/applet/gp_ara_m/*.java \
    tests/ProtocolTest.java tests/SimulatorTest.java
java -cp "build/test-classes:$sim" SimulatorTest
