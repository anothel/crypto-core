# Analysis CI

Static analysis, coverage, coverage-guided fuzzing, and install-tree smoke are
required CI jobs.

## Required Jobs

- `static-analysis-ubuntu-clang`: configures a native compile database and runs
  `clang-tidy` on native `src/*.cpp`.
- `coverage-ubuntu-clang`: builds with Clang source coverage instrumentation,
  runs tests, and prints an `llvm-cov report`. The CI job installs the LLVM
  tools package for `llvm-profdata` and `llvm-cov`.
- `fuzzing-ubuntu-clang`: builds `tests/fuzz/fuzz_parser_boundaries.cpp` with
  libFuzzer and runs the invalid seed corpus.
- `install-smoke-ubuntu-gcc`: installs the native CMake package and verifies a
  separate consumer can use `find_package(crypto_core CONFIG REQUIRED)`.

## Local Reproduction

Run the same commands as CI on Ubuntu or another Clang/LLVM environment:

```sh
bash scripts/ci/static-analysis.sh
bash scripts/ci/coverage.sh
bash scripts/ci/fuzzing.sh
```

Run the install-tree smoke locally from a built native tree:

```sh
cmake --install build --prefix build-install
cmake -S tests/install_package_smoke -B build-install-smoke \
  -DCMAKE_PREFIX_PATH="$PWD/build-install"
cmake --build build-install-smoke
./build-install-smoke/crypto_core_install_package_smoke
```

Set `FUZZ_RUNS` to change the fuzz smoke budget:

```sh
FUZZ_RUNS=1024 bash scripts/ci/fuzzing.sh
```

## Required-Job Criteria

Keep these jobs required while:

- the job is green on normal pull requests.
- failures are actionable and not toolchain noise.
- runtime is acceptable for the default CI matrix.
- docs explain how to reproduce the job locally.

## Local Fallback

On Windows/MSVC, use the CMake object target and `crypto_core.fuzz_boundary_smoke`
until Clang/libFuzzer and LLVM coverage tools are available.

## Generated Files

The reproduction scripts keep generated artifacts under ignored build
directories:

- coverage profiles: `build-coverage/profiles/`
- merged coverage data: `build-coverage/crypto-core.profdata`
- fuzz binary: `build-fuzz/fuzz_parser_boundaries`
