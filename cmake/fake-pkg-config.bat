@echo off
setlocal

if "%~1"=="--version" (
  echo 0.0.0
  exit /b 0
)

if "%~1"=="--atleast-pkgconfig-version" (
  exit /b 0
)

if "%~1"=="--help" (
  echo fake pkg-config shim for MSVC builds
  exit /b 0
)

exit /b 1
