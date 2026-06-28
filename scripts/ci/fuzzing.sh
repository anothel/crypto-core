#!/usr/bin/env bash
set -euo pipefail

mapfile -t sources < <(find src -name '*.cpp' ! -name 'openssl_provider.cpp' -print)
clang++ -std=c++20 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
  -I include -I tests \
  tests/fuzz/fuzz_parser_boundaries.cpp "${sources[@]}" \
  -o fuzz_parser_boundaries

./fuzz_parser_boundaries tests/corpus/invalid -runs="${FUZZ_RUNS:-256}"
