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
profile_dir="$PWD/build-coverage/profiles"
profdata="$PWD/build-coverage/crypto-core.profdata"
rm -rf "$profile_dir"
mkdir -p "$profile_dir"
LLVM_PROFILE_FILE="${profile_dir}/crypto-core-%p.profraw" ctest --test-dir build-coverage --output-on-failure
llvm-profdata merge -sparse "${profile_dir}"/crypto-core-*.profraw -o "$profdata"
mapfile -t objects < <(find build-coverage -type f -executable -name 'crypto_core*_tests' -print)
if [ "${#objects[@]}" -eq 0 ]; then
  echo "error: no coverage test binaries found" >&2
  exit 1
fi
llvm_cov_args=("${objects[0]}")
for object in "${objects[@]:1}"; do
  llvm_cov_args+=("-object=${object}")
done
llvm-cov report -instr-profile="$profdata" "${llvm_cov_args[@]}" src include
