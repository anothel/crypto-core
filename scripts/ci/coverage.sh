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
profile_dir="build-coverage/profiles"
profdata="build-coverage/crypto-core.profdata"
rm -rf "$profile_dir"
mkdir -p "$profile_dir"
LLVM_PROFILE_FILE="${profile_dir}/crypto-core-%p.profraw" ctest --test-dir build-coverage --output-on-failure
llvm-profdata merge -sparse "${profile_dir}"/crypto-core-*.profraw -o "$profdata"
mapfile -t objects < <(find build-coverage -type f -executable -name 'crypto_core*_tests' -print)
llvm-cov report -instr-profile="$profdata" "${objects[@]/#/-object=}" src include
