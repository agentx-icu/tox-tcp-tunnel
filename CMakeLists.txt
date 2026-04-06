cmake_minimum_required(VERSION 3.16)
project(toxtunnel VERSION 0.1.11 LANGUAGES C CXX)

include(GNUInstallDirs)

if(DEFINED RELEASE_VERSION)
    set(TOXTUNNEL_VERSION "${RELEASE_VERSION}")
else()
    set(TOXTUNNEL_VERSION "${PROJECT_VERSION}")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    # c-toxcore unconditionally calls find_package(PkgConfig REQUIRED).
    # GitHub-hosted Windows runners do not guarantee a pkg-config executable,
    # so provide a tiny shim that lets pkg_search_module() fail cleanly and
    # fall back to vcpkg-discovered CMake packages.
    set(PKG_CONFIG_EXECUTABLE
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/fake-pkg-config.bat"
        CACHE FILEPATH "Pkg-config shim for MSVC builds" FORCE)
endif()

# Options
option(TOXTUNNEL_BUILD_TESTS "Build tests" ON)
option(TOXTUNNEL_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(TOXTUNNEL_WARNINGS_AS_ERRORS "Treat warnings as errors" ON)

# Sanitizer flags (applied globally since they affect linking too)
if(NOT MSVC AND TOXTUNNEL_ENABLE_ASAN)
    add_compile_options(-fsanitize=address,undefined -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# Dependencies
set(BUILD_TOXAV OFF CACHE BOOL "" FORCE)
set(AUTOTEST OFF CACHE BOOL "" FORCE)
set(UNITTEST OFF CACHE BOOL "" FORCE)
set(BUILD_FUN_UTILS OFF CACHE BOOL "" FORCE)
set(DHT_BOOTSTRAP OFF CACHE BOOL "" FORCE)
set(BOOTSTRAP_DAEMON OFF CACHE BOOL "" FORCE)
set(ENABLE_SHARED OFF CACHE BOOL "" FORCE)
set(ENABLE_STATIC ON CACHE BOOL "" FORCE)
add_subdirectory(third_party/c-toxcore EXCLUDE_FROM_ALL)

add_library(toxcore_wrapper INTERFACE)
target_link_libraries(toxcore_wrapper INTERFACE toxcore_static)
target_include_directories(toxcore_wrapper SYSTEM INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/c-toxcore
)

include(FetchContent)

# Asio (standalone, header-only)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-0
)
FetchContent_MakeAvailable(asio)

# spdlog
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.12.0
)
FetchContent_MakeAvailable(spdlog)

# CLI11
FetchContent_Declare(
    cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.6.2
)
FetchContent_MakeAvailable(cli11)

# yaml-cpp
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG yaml-cpp-0.9.0
)
FetchContent_MakeAvailable(yaml-cpp)

# QR Code generator (Nayuki) — source-only library, no CMakeLists.txt
FetchContent_Declare(
    qrcodegen
    GIT_REPOSITORY https://github.com/nayuki/QR-Code-generator.git
    GIT_TAG v1.8.0
)
FetchContent_Populate(qrcodegen)

# Library target
add_library(toxtunnel_lib STATIC)
target_sources(toxtunnel_lib PRIVATE
    ${qrcodegen_SOURCE_DIR}/cpp/qrcodegen.cpp
    src/placeholder.cpp
    src/core/io_context.cpp
    src/core/tcp_connection.cpp
    src/core/tcp_listener.cpp
    src/tunnel/protocol.cpp
    src/tunnel/tunnel.cpp
    src/tunnel/tunnel_manager.cpp
    src/tox/bootstrap_source.cpp
    src/tox/types.cpp
    src/tox/tox_save.cpp
    src/tox/tox_thread.cpp
    src/tox/tox_connection.cpp
    src/tox/tox_adapter.cpp
    src/app/rules_engine.cpp
    src/app/stdio_pipe_bridge.cpp
    src/app/tunnel_client.cpp
    src/app/tunnel_server.cpp
    src/util/config.cpp
    src/util/error.cpp
    src/util/logger.cpp
    src/util/qr_code.cpp
    src/util/systemd_notify.cpp
    src/util/windows_service.cpp
)
target_include_directories(toxtunnel_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${asio_SOURCE_DIR}/asio/include
    ${qrcodegen_SOURCE_DIR}/cpp
)
target_link_libraries(toxtunnel_lib PUBLIC
    toxcore_wrapper
    spdlog::spdlog
    yaml-cpp
)
target_compile_definitions(toxtunnel_lib PUBLIC
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)
# Apply strict warnings only to our own library target
if(MSVC)
    target_compile_options(toxtunnel_lib PRIVATE /W4)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(toxtunnel_lib PRIVATE /WX)
    endif()
else()
    target_compile_options(toxtunnel_lib PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(toxtunnel_lib PRIVATE -Werror)
    endif()
    # GCC 13+ has false positives for array-bounds in spdlog's fmt bundle
    # See: https://github.com/fmtlib/fmt/issues/3413
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(toxtunnel_lib PRIVATE
            -Wno-array-bounds
            -Wno-stringop-overread
            -Wno-stringop-overflow
        )
    endif()
endif()

# Executable target
add_executable(toxtunnel cli/main.cpp)
target_link_libraries(toxtunnel PRIVATE toxtunnel_lib CLI11::CLI11)
target_compile_definitions(toxtunnel PRIVATE TOXTUNNEL_VERSION="${TOXTUNNEL_VERSION}")
if(MSVC)
    target_compile_options(toxtunnel PRIVATE /W4)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(toxtunnel PRIVATE /WX)
    endif()
else()
    target_compile_options(toxtunnel PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(toxtunnel PRIVATE -Werror)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(toxtunnel PRIVATE
            -Wno-array-bounds
            -Wno-stringop-overread
            -Wno-stringop-overflow
        )
    endif()
endif()

set(toxtunnel_fixup_dirs "")
if(DEFINED LIBSODIUM_LIBRARY_DIRS)
    list(APPEND toxtunnel_fixup_dirs ${LIBSODIUM_LIBRARY_DIRS})
endif()
if(DEFINED LIBSODIUM_LIBDIR)
    list(APPEND toxtunnel_fixup_dirs ${LIBSODIUM_LIBDIR})
endif()
if(DEFINED VCPKG_INSTALLED_DIR AND DEFINED VCPKG_TARGET_TRIPLET)
    list(APPEND toxtunnel_fixup_dirs
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin"
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin"
    )
endif()
list(REMOVE_DUPLICATES toxtunnel_fixup_dirs)

if(APPLE OR WIN32)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/FixupInstall.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/FixupInstall.cmake"
        @ONLY
    )
endif()

# Tests
if(TOXTUNNEL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
install(TARGETS toxtunnel
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT toxtunnel_runtime
)
install(FILES README.md LICENSE
    DESTINATION .
    COMPONENT toxtunnel_runtime
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/packaging")
    install(FILES packaging/config.yaml.example
        DESTINATION ${CMAKE_INSTALL_DATADIR}/toxtunnel
        COMPONENT toxtunnel_runtime
        OPTIONAL
    )
    # Linux-specific files
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        install(FILES packaging/linux/toxtunnel.service
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system
            COMPONENT toxtunnel_runtime
            OPTIONAL
        )
        install(PROGRAMS packaging/linux/postinst packaging/linux/prerm
            DESTINATION ${CMAKE_INSTALL_DATADIR}/toxtunnel/scripts
            COMPONENT toxtunnel_runtime
            OPTIONAL
        )
    endif()
    # macOS-specific files
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        install(FILES packaging/macos/com.toxtunnel.daemon.plist
            DESTINATION ${CMAKE_INSTALL_DATADIR}/toxtunnel
            COMPONENT toxtunnel_runtime
            OPTIONAL
        )
    endif()
endif()

if(APPLE)
    install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/FixupInstall.cmake"
        COMPONENT toxtunnel_runtime
    )
endif()

if(WIN32)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/InstallRuntimeDepsWindows.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/InstallRuntimeDepsWindows.cmake"
        @ONLY
    )

    install(SCRIPT "${CMAKE_CURRENT_BINARY_DIR}/InstallRuntimeDepsWindows.cmake"
        COMPONENT toxtunnel_runtime
    )
endif()

include(cmake/Packaging.cmake)
