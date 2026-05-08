# GitHub Actions Failure Repair Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Repair the failing CI and coverage workflows by applying the smallest set of targeted
code and workflow fixes needed to restore cross-platform GitHub Actions health.

**Architecture:** Preserve the current workflow layout and repository structure. Fix the confirmed
root causes in place: tracked Windows shim file, newer CLI11 for CMake 4 compatibility, GCC 13
warning suppression, per-test temporary directories for bootstrap-source tests, and tolerant lcov
capture settings. Finish by formatting the source tree so the style job reflects repository state
rather than stale formatting drift.

**Tech Stack:** CMake, CTest, Google Test, GitHub Actions, lcov, clang-format, C++20

---

### Task 1: Capture the bootstrap-source race as a red test command

**Files:**
- Modify: `tests/unit/test_bootstrap_source.cpp`

**Step 1: Reproduce the failure**

Run a parallel bootstrap-source test command that currently races because all cases share the same
temp directory.

Expected: at least one test fails in `SetUp()` or `TearDown()` with a filesystem error.

**Step 2: Write the minimal fix**

Make each test case use a unique temporary directory while keeping existing assertions intact.

**Step 3: Re-run the targeted bootstrap-source command**

Expected: the race no longer reproduces.

### Task 2: Repair cross-platform build configuration

**Files:**
- Create: `cmake/fake-pkg-config.bat`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Step 1: Commit the missing shim file**

Add the Windows pkg-config shim file that `CMakeLists.txt` already references.

**Step 2: Update dependency compatibility**

Upgrade `CLI11` to a CMake-4-compatible release and extend the GCC suppression list with
`-Wno-stringop-overflow` for targets currently built with `-Werror`.

**Step 3: Verify local configure/build**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Release`
- `cmake --build build -j4`

Expected: successful local configure/build, with the repository ready for the repaired Linux and
Windows CI paths.

### Task 3: Repair coverage workflow behavior

**Files:**
- Modify: `.github/workflows/coverage.yml`

**Step 1: Make lcov capture resilient**

Adjust the coverage capture command so known line-mismatch metadata does not fail the job after
tests have already passed.

**Step 2: Keep the rest of the workflow unchanged**

Avoid redesigning the coverage job; only repair the failing capture path.

### Task 4: Bring the repository into style compliance

**Files:**
- Modify: source files under `include/`, `src/`, and `tests/` as produced by `clang-format`

**Step 1: Run repository formatting**

Use the configured `clang-format` style across the directories already checked by the workflow.

**Step 2: Verify the formatting gate**

Run the same command used by the `code-style-check` workflow.

Expected: no formatting violations remain.

### Task 5: Final verification

**Files:**
- Inspect only

**Step 1: Debug configuration verification**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTOXTUNNEL_ENABLE_ASAN=ON`
- `cmake --build build -j4`
- `(cd build && ctest --output-on-failure --parallel 4)`

Expected: all tests pass without the bootstrap-source race.

**Step 2: Release configuration verification**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Release`
- `cmake --build build -j4`
- `(cd build && ctest --output-on-failure --parallel 4)`

Expected: all tests pass.

**Step 3: Formatting verification**

Run the workflow’s clang-format check command.

Expected: success.
