# GitHub Actions Release Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a stable cross-platform CI matrix and a tag-driven GitHub Releases publication flow
for Linux, macOS, and Windows on both `x86_64` and `aarch64`.

**Architecture:** Keep a single workflow as the source of truth, use explicit GitHub-hosted runner
labels for each target, package release artifacts from the CMake install tree, and publish them
from a dedicated release job. Patch the vendored Windows dependency discovery just enough to avoid
`PkgConfig` failures under MSVC, and label tests so CI can run unit and integration coverage
separately.

**Tech Stack:** GitHub Actions, CMake, CTest, vcpkg, Google Test, C++20

---

### Task 1: Make test categories addressable in CI

**Files:**
- Modify: `tests/CMakeLists.txt`

**Step 1: Update test discovery metadata**

Label discovered unit tests with `unit` and discovered integration tests with `integration`.

**Step 2: Verify labels are emitted**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j4 && (cd build && ctest -N -L unit && ctest -N -L integration)`

Expected: both label filters list tests instead of returning zero matches.

### Task 2: Make Windows dependency discovery runner-safe

**Files:**
- Modify: `third_party/c-toxcore/cmake/Dependencies.cmake`

**Step 1: Patch the Windows path**

Make `PkgConfig` optional under MSVC and guard `pkg_search_module(...)` calls behind
`PkgConfig_FOUND`.

**Step 2: Verify non-Windows configure still works**

Run: `cmake -B build -DCMAKE_BUILD_TYPE=Release`

Expected: configure succeeds exactly as before on the current machine.

### Task 3: Make the install tree release-friendly

**Files:**
- Modify: `CMakeLists.txt`

**Step 1: Expand install rules**

Install:
- the `toxtunnel` runtime into the standard binary directory,
- `README.md`,
- `LICENSE`.

**Step 2: Verify install output**

Run: `cmake --install build --prefix stage/local-package`

Expected: staged package contains `bin/toxtunnel`, `README.md`, and `LICENSE`.

### Task 4: Replace the workflow with an explicit matrix and release flow

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Redesign triggers and permissions**

Use:
- `pull_request`
- `push` on `master`
- `push` tags `v*`
- `workflow_dispatch`

Add the minimum permissions needed for artifact upload and release publication.

**Step 2: Implement the release build matrix**

Create a six-entry matrix for:
- `ubuntu-24.04`
- `ubuntu-24.04-arm`
- `macos-15-intel`
- `macos-15`
- `windows-2025`
- `windows-11-arm`

Include per-platform dependency setup, CMake configure/build/test, staging, archive creation, and
artifact upload on tag builds.

**Step 3: Preserve supporting validation jobs**

Keep a Linux formatting job and Linux ASan debug build job, updated to the new workflow style.

**Step 4: Add the release publication job**

Download packaged artifacts and publish them to the GitHub Release for the pushed tag.

### Task 5: Verify the end-to-end local contract

**Files:**
- Inspect only

**Step 1: Run local verification**

Run:
- `cmake -B build -DCMAKE_BUILD_TYPE=Release`
- `cmake --build build -j$(sysctl -n hw.ncpu)`
- `cd build && ctest --output-on-failure -L unit -j$(sysctl -n hw.ncpu)`
- `cd build && ctest --output-on-failure -L integration -j$(sysctl -n hw.ncpu)`
- `cmake --install build --prefix stage/local-package`

Expected: all commands succeed.

**Step 2: Inspect staged package**

Run: `find stage/local-package -maxdepth 3 -type f | sort`

Expected: release staging contains the installed binary and packaged docs.

**Step 3: Inspect final diff**

Run:
- `git status --short`
- `git diff --stat`

Expected: only the intended CI, packaging, and documentation changes remain.
