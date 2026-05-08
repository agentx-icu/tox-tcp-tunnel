# GitHub Actions Failure Repair Design

## Goal

Repair the failing GitHub Actions workflows for `anonymoussoft/tox-tcp-tunnel` without changing
the intended product behavior.

## Confirmed Failures

From the failing `CI` and `Code Coverage` runs on commit
`316da5eec8d81740b13cc28a4287f2746878b906`, the repository currently has five independent failure
modes:

1. Windows configure fails because `CMakeLists.txt` points at
   `cmake/fake-pkg-config.bat`, but that file was not committed.
2. macOS configure fails because `CLI11 v2.3.2` is incompatible with the CMake 4 runner images.
3. Linux build fails under GCC 13 because a known spdlog/fmt false positive is promoted to
   `-Werror=stringop-overflow`.
4. `build-debug` fails because `BootstrapSourceTest` uses a shared fixed temp directory and breaks
   when CTest runs test cases in parallel.
5. `coverage.yml` fails after tests pass because `lcov/geninfo` aborts on a line-mismatch issue in
   generated coverage metadata.

## Options Considered

### Option 1: Minimal targeted fixes

- Commit the missing shim file.
- Upgrade only `CLI11`.
- Extend the existing GCC warning suppression list.
- Make the bootstrap source test temp directory unique per test.
- Add `lcov` mismatch tolerance in the workflow.
- Format the repository so the style job passes.

Pros:

- Smallest behavioral surface area.
- Directly addresses the observed failures.
- Keeps the current CI design intact.

Cons:

- Leaves the existing dependency set mostly unchanged instead of modernizing more broadly.

### Option 2: Broader dependency and CI modernization

- Upgrade multiple third-party dependencies.
- Rework warning policy and test execution strategy.
- Redesign coverage reporting and packaging.

Pros:

- Could remove more future maintenance burden.

Cons:

- Much larger change set than needed to get CI green.
- Higher regression risk.

## Decision

Use **Option 1**. The repository needs a repair, not a redesign.

## Design

### Build-System Repair

- Track `cmake/fake-pkg-config.bat` so Windows runners can actually use the shim referenced by
  `CMakeLists.txt`.
- Upgrade `CLI11` to a version compatible with current CMake 4 runners.
- Add `-Wno-stringop-overflow` to the existing GCC-only suppression list wherever the project
  currently adds `-Werror`.

### Test Reliability Repair

- Change `BootstrapSourceTest` to use a unique temporary directory per test invocation instead of a
  process-wide fixed path.
- Keep the existing test behavior and assertions unchanged.

### Workflow Repair

- Keep the current workflow structure.
- Update coverage collection to ignore the known `lcov/geninfo` mismatch failure mode so the job
  reflects actual test/build health.
- Run `clang-format` across the repository to satisfy the existing style gate.

## Verification Plan

1. Reproduce the bootstrap-source parallel test race before the fix.
2. Re-run the targeted bootstrap-source tests after the fix to verify the race is gone.
3. Re-run repository formatting check locally.
4. Reconfigure and rebuild locally.
5. Re-run the full test suite, including the debug/ASan configuration.
