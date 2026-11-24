#!/usr/bin/env bash
# Runs the offline-core unit tests WITHOUT Gradle: needs only kotlinc (e.g. `nix-shell -p kotlin jdk21`).
# org.junit is replaced by a tiny stand-in (tools/local-junit); under Gradle the real JUnit is used.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(mktemp -d)"; trap 'rm -rf "$OUT"' EXIT
KLIB="$(dirname "$(readlink -f "$(command -v kotlinc)")")/../lib"
kotlinc -jvm-target 21 tools/local-junit/Stub.kt tools/local-junit/Runner.kt -d "$OUT/stub" 2>/dev/null
kotlinc -jvm-target 21 $(find src/main/kotlin -name '*.kt') -d "$OUT/main" 2>/dev/null
cp src/main/resources/* "$OUT/main/"; mkdir -p "$OUT/test"; cp src/test/resources/* "$OUT/test/"
kotlinc -jvm-target 21 -cp "$OUT/main:$OUT/stub" $(find src/test/kotlin -name '*.kt') -d "$OUT/test" 2>/dev/null
CLASSES=$(cd "$OUT/test" && find . -name '*Test.class' | sed 's|^\./||; s|\.class$||; s|/|.|g' | sort | tr '\n' ' ')
java -cp "$OUT/main:$OUT/test:$OUT/stub:$KLIB/kotlin-stdlib.jar" RunnerKt $CLASSES
