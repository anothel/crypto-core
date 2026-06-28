#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build-analysis \
  -DCRYPTO_CORE_ENABLE_OPENSSL=OFF \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

find src -name '*.cpp' ! -name 'openssl_provider.cpp' -print0 | xargs -0 clang-tidy -p build-analysis
