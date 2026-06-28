#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build-coverage \
  -DCRYPTO_CORE_ENABLE_OPENSSL=OFF \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping"

cmake --build build-coverage --parallel
LLVM_PROFILE_FILE='crypto-core-%p.profraw' ctest --test-dir build-coverage --output-on-failure
llvm-profdata merge -sparse crypto-core-*.profraw -o crypto-core.profdata
mapfile -t objects < <(find build-coverage -type f -executable -name 'crypto_core*_tests' -print)
llvm-cov report -instr-profile=crypto-core.profdata "${objects[@]/#/-object=}" src include
