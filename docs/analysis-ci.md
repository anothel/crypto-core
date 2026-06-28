# Analysis CI

Static analysis, coverage, and coverage-guided fuzzing are non-blocking CI jobs
until their signal is stable.

## Non-Blocking Jobs

- `static-analysis-ubuntu-clang`: configures a native compile database and runs
  `clang-tidy` on native `src/*.cpp`.
- `coverage-ubuntu-clang`: builds with Clang source coverage instrumentation,
  runs tests, and prints an `llvm-cov report`.
- `fuzzing-ubuntu-clang`: builds `tests/fuzz/fuzz_parser_boundaries.cpp` with
  libFuzzer and runs the invalid seed corpus.

## Local Reproduction

Run the same commands as CI on Ubuntu or another Clang/LLVM environment:

```sh
bash scripts/ci/static-analysis.sh
bash scripts/ci/coverage.sh
bash scripts/ci/fuzzing.sh
```

Set `FUZZ_RUNS` to change the fuzz smoke budget:

```sh
FUZZ_RUNS=1024 bash scripts/ci/fuzzing.sh
```

## Promotion Criteria

Move a job from non-blocking to required only after:

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
