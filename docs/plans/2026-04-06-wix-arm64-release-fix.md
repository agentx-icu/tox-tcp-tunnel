# WiX ARM64 Release Fix Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Windows ARM64 release packaging robust and publish a new release tag once the fix is
merged to `master`.

**Architecture:** Update only the release workflow’s WiX discovery step. Preserve the existing
CPack/WiX packaging strategy and add a fallback installation path for runners without a preinstalled
WiX Toolset.

**Tech Stack:** GitHub Actions, PowerShell, Chocolatey, CPack, WiX

---

### Task 1: Repair WiX discovery

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Implement resilient WiX lookup**

Search known WiX locations for `candle.exe`, install WiX with Chocolatey when missing, and fail
only if WiX is still unavailable afterward.

**Step 2: Validate workflow syntax**

Run: `ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci.yml"); puts :ok'`

Expected: `ok`

### Task 2: Publish the fix

**Files:**
- Inspect only

**Step 1: Commit the workflow change**

Commit only the release workflow fix.

**Step 2: Push to `master`**

Push the commit to `origin/master`.

**Step 3: Create tag**

Create and push release tag `v0.1.8`.

### Task 3: Verify the release

**Files:**
- Inspect only

**Step 1: Wait for the tagged workflow**

Monitor the release workflow until all jobs complete.

**Step 2: Inspect assets**

Confirm the GitHub Release contains the expected installers for:
- Linux x86_64
- Linux aarch64
- macOS x86_64
- macOS aarch64
- Windows x86_64
- Windows aarch64
