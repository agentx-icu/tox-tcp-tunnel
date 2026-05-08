# WiX ARM64 Release Fix Design

## Goal

Repair the `Package windows-aarch64` release job so tagged releases can publish the full expected
asset set for Linux, macOS, Windows x86_64, and Windows aarch64.

## Observed Failure

Release run `24016922407` succeeds for all test jobs and all package jobs except
`Package windows-aarch64`. The failing step is `Add WiX to PATH (Windows)`, which assumes WiX is
preinstalled at `C:\Program Files (x86)\WiX Toolset v3.14\bin`.

That assumption holds on the x86_64 Windows runner, but not on `windows-11-arm`.

## Decision

Keep the existing WiX-based packaging flow and make the workflow resilient:

- check common preinstalled WiX locations first,
- if WiX is absent, install `wixtoolset` with Chocolatey,
- then add the discovered `bin` directory to `PATH`.

## Verification

1. Validate workflow YAML locally.
2. Commit the workflow change to `master`.
3. Push tag `v0.1.8`.
4. Wait for the release workflows to finish.
5. Confirm the release contains the expected package set, including Windows ARM64.
