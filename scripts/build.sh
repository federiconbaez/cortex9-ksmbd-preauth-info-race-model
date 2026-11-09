#!/bin/sh
# Build and check the model. Used locally and in CI.
#   scripts/build.sh test            strict build + ASan/UBSan, run tests
#   scripts/build.sh results [dir]   regenerate results/ (or dir) + SHA256SUMS
set -eu
CC=${CC:-cc}
STRICT="-std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror -Wshadow -Wpedantic -Wformat=2 -Wformat-security"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"
SRC="src/ks_model.c src/cx9_util.c"
mkdir -p build
case "${1:-}" in
  test)
    $CC $STRICT -O1 -g $SAN -Isrc $SRC tests/test_model.c -o build/test_san
    ./build/test_san fixtures ;;
  results)
    out=${2:-results}
    mkdir -p "$out"
    $CC $STRICT -O2 -Isrc $SRC src/main.c -o build/ksrace
    ./build/ksrace results fixtures/cases.tsv "$out"
    (cd "$out" && sha256sum cases.csv sweep.csv > SHA256SUMS) ;;
  *) echo "usage: $0 test|results [dir]" >&2; exit 2 ;;
esac
