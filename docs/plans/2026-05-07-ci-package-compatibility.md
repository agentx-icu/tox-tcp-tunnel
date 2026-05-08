# CI Package Compatibility Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make release CI verify that Linux packages install and start on Ubuntu 20.04 and CentOS 7, while preserving explicit Linux runtime dependency metadata for portable release artifacts.

**Architecture:** Keep the existing cross-platform build matrix and portable Linux build container. Fix Linux package metadata in CPack so portable builds still declare `libsodium`, then add distro-native install verification steps that run inside Ubuntu 20.04 and CentOS 7 containers against the generated `.deb` and `.rpm` artifacts. Leave the current glibc floor and Windows/macOS packaging flow unchanged unless needed to wire the new checks.

**Tech Stack:** GitHub Actions, Docker, CPack DEB/RPM, Bash, CentOS 7 vault repos, EPEL

---

### Task 1: Restore Linux runtime dependency metadata for portable packages

**Files:**
- Modify: `cmake/Packaging.cmake`

**Step 1: Write the failing expectation**

Expectation:
- Portable Linux builds must not clear `libsodium` package metadata.
- Debian packages must continue to declare `libsodium23`.
- RPM packages must continue to declare `libsodium`.

**Step 2: Inspect current packaging logic**

Run: `sed -n '1,220p' cmake/Packaging.cmake`

Expected: portable release path currently clears Linux dependency metadata.

**Step 3: Write the minimal implementation**

Change `cmake/Packaging.cmake` so Linux package dependency metadata remains present even when `TOXTUNNEL_PORTABLE_RELEASE=ON`.

**Step 4: Verify the diff**

Run: `git diff -- cmake/Packaging.cmake`

Expected: Linux dependency metadata is preserved for portable release builds.

---

### Task 2: Add Ubuntu 20.04 and CentOS 7 install verification scripts

**Files:**
- Create: `tests/packaging/verify_linux_deb_install.sh`
- Create: `tests/packaging/verify_linux_rpm_install.sh`

**Step 1: Write the failing expectation**

Expectation:
- `.deb` install verification must fail if package install cannot resolve dependencies or if `toxtunnel --version` cannot run.
- `.rpm` install verification must fail if CentOS 7 cannot resolve dependencies, if `ldd` shows missing libraries, or if `toxtunnel --version` fails.

**Step 2: Write the minimal implementation**

Add scripts that:
- install the package with the distro-native package manager
- verify the installed binary exists
- verify `ldd` has no `not found` entries
- verify `toxtunnel --version` returns the expected version
- for CentOS 7, repoint repos to vault and enable EPEL before RPM install

**Step 3: Verify script syntax**

Run:
- `bash -n tests/packaging/verify_linux_deb_install.sh`
- `bash -n tests/packaging/verify_linux_rpm_install.sh`

Expected: both commands exit successfully.

---

### Task 3: Wire Linux install verification into release CI

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Write the failing expectation**

Expectation:
- Release CI must verify Ubuntu 20.04 `.deb` installability.
- Release CI must verify CentOS 7 `.rpm` installability.
- Existing ABI verification should remain in place.

**Step 2: Write the minimal implementation**

Update the Linux release job so it:
- defines Ubuntu 20.04 and CentOS 7 verification container images per Linux target
- runs the new Debian verification script in the Ubuntu 20.04 container
- runs the new RPM verification script in the CentOS 7 container

**Step 3: Verify the workflow diff**

Run: `git diff -- .github/workflows/ci.yml`

Expected: Linux release job now performs distro-native package installation checks.

---

### Task 4: Run local static verification

**Files:**
- Verify: `cmake/Packaging.cmake`
- Verify: `.github/workflows/ci.yml`
- Verify: `tests/packaging/verify_linux_deb_install.sh`
- Verify: `tests/packaging/verify_linux_rpm_install.sh`

**Step 1: Run syntax and whitespace checks**

Run:
- `bash -n tests/packaging/verify_linux_deb_install.sh`
- `bash -n tests/packaging/verify_linux_rpm_install.sh`
- `git diff --check`

Expected: all commands exit successfully.

**Step 2: Summarize residual risk**

Document whether CentOS 7 still relies on EPEL at install time and whether Windows 7 compatibility remains unverified by CI.
