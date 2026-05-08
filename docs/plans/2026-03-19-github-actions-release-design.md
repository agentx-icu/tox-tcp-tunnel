# GitHub Actions Release Pipeline Design

## Goal

Replace the current ad-hoc CI workflow with an explicit cross-platform build matrix that:

- validates Linux, macOS, and Windows builds,
- covers both `x86_64` and `aarch64` runners,
- packages installable release artifacts per target,
- and publishes those artifacts to GitHub Releases when a `v*` tag is pushed.

## Problem Summary

The existing workflow only defines three OS jobs and does not model architecture explicitly. It
also duplicates `push` triggers, runs the same full `ctest` suite twice under different step
names, and has no artifact packaging or GitHub Releases publication path.

There is also a Windows portability gap: the vendored `c-toxcore` CMake files hard-require
`PkgConfig`, which is not reliably present on current GitHub-hosted Windows runners. That makes a
Windows matrix fragile even if the workflow itself is corrected.

## Requirements

### Functional Requirements

1. Run CI on pull requests and pushes to `master`.
2. Publish a GitHub Release when a tag matching `v*` is pushed.
3. Build native binaries for:
   - Linux `x86_64`
   - Linux `aarch64`
   - macOS `x86_64`
   - macOS `aarch64`
   - Windows `x86_64`
   - Windows `aarch64`
4. Package one archive per target with the built `toxtunnel` binary plus top-level project docs.
5. Upload all packaged archives to the corresponding GitHub Release.

### Non-Functional Requirements

1. Use explicit runner labels instead of `*-latest` so the OS/architecture mapping is stable.
2. Keep the build logic readable and centralized in one workflow.
3. Preserve the current local build commands and CMake project structure as much as possible.
4. Avoid relying on undocumented preinstalled Windows tools when a small source-compatible fix is
   available in the project.

## Options Considered

### Option 1: One workflow with CI and release jobs

Pros:

- Single source of truth for the build matrix.
- Straightforward artifact handoff from build jobs to the release job.
- Lowest maintenance overhead.

Cons:

- The workflow file becomes longer.

### Option 2: Separate `ci.yml` and `release.yml`

Pros:

- Clearer conceptual split between verification and publication.

Cons:

- Repeats or shares matrix logic awkwardly.
- Makes artifact flow and consistency checks more complex.

### Option 3: Cross-compile some targets instead of using native runners

Pros:

- Fewer runner labels to manage.

Cons:

- Increases risk dramatically for Windows and macOS packaging.
- Adds more build-system complexity than this repository needs.

## Decision

Adopt **Option 1**: a single workflow with an explicit six-target native matrix, supporting jobs
for formatting and Linux ASan, and a release job that consumes packaged artifacts from successful
tag builds.

## Design

### Workflow Structure

The workflow will use these triggers:

- `pull_request`
- `push` to `master`
- `push` tags matching `v*`
- optional `workflow_dispatch` for manual inspection

Jobs:

1. `build-release-matrix`
   - explicit runner matrix for 6 OS/architecture combinations
   - installs dependencies per platform
   - configures, builds, and runs tests
   - installs into a staging directory and archives the result
   - uploads archives as workflow artifacts only for tag builds

2. `code-style-check`
   - Linux formatting validation

3. `build-debug`
   - Linux ASan debug build and tests

4. `publish-release`
   - runs only on pushed `v*` tags
   - depends on all validation jobs
   - downloads archives from the matrix job
   - publishes them to the GitHub Release for the tag

### Packaging Strategy

Use `cmake --install` into a target-specific staging directory. The install tree will contain:

- `bin/toxtunnel` or `bin/toxtunnel.exe`
- `README.md`
- `LICENSE`

The workflow will then archive that install tree as:

- `.tar.gz` on Linux and macOS
- `.zip` on Windows

This keeps local and CI packaging aligned with CMake install metadata without introducing a full
CPack layer.

### Windows Compatibility Fix

Adjust the vendored `c-toxcore` dependency discovery so `PkgConfig` is optional under MSVC and only
used when present. Windows builds will rely on vcpkg-provided CMake packages for `libsodium`
instead of failing at `find_package(PkgConfig REQUIRED)`.

### Test Execution

Use CTest labels so unit and integration stages are truly separate instead of running the full test
suite twice. The test CMake file will label discovered tests from `unit_tests` as `unit` and those
from `integration_tests` as `integration`.

## Verification Plan

1. Reconfigure and rebuild locally on the current machine.
2. Run `ctest -L unit` and `ctest -L integration` locally to verify label-based separation.
3. Run the full `ctest --output-on-failure` suite.
4. Run a local install into a staging directory and inspect the resulting archive contents.
