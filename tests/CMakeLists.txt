# Tests
include(FetchContent)

# Prevent Google Test from installing its own headers/libs into our packages
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# Unit tests
add_executable(unit_tests
    unit/placeholder_test.cpp
    unit/test_bootstrap_source.cpp
    unit/test_expected.cpp
    unit/test_circular_buffer.cpp
    unit/test_config.cpp
    unit/config_reload_test.cpp
    unit/test_known_servers.cpp
    unit/test_metrics.cpp
    unit/test_pipe_mode.cpp
    unit/test_protocol_info.cpp
    unit/test_qr_code.cpp
    unit/test_rules_engine.cpp
    unit/test_inbound_strand.cpp
    unit/test_inspect_server.cpp
    unit/test_tox_adapter.cpp
    unit/test_tunnel.cpp
    unit/test_tunnel_manager.cpp
    unit/tunnel_reaper_test.cpp
    unit/tunnel_coalesce_test.cpp
    unit/client_failover_test.cpp
    unit/zero_copy_read_test.cpp
    unit/socks5_listener_test.cpp
    unit/outbound_zero_copy_test.cpp
    unit/write_coalescer_test.cpp
    unit/rate_limiter_test.cpp
    unit/tox_watchdog_test.cpp
    unit/atomic_file_test.cpp
    unit/tunnel_id_allocator_test.cpp
    unit/tunnel_resume_test.cpp
    unit/t8_data_race_test.cpp
    unit/t2_atomic_persistence_test.cpp
)
target_link_libraries(unit_tests PRIVATE
    toxtunnel_lib
    GTest::gtest_main
    GTest::gmock
)
if(MSVC)
    target_compile_options(unit_tests PRIVATE /W4)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(unit_tests PRIVATE /WX)
    endif()
else()
    target_compile_options(unit_tests PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(unit_tests PRIVATE -Werror)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(unit_tests PRIVATE
            -Wno-array-bounds
            -Wno-stringop-overread
            -Wno-stringop-overflow
        )
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(unit_tests PRIVATE -Wno-deprecated-literal-operator)
    endif()
endif()
gtest_discover_tests(unit_tests
    DISCOVERY_TIMEOUT 60
    # Per-test wall-clock cap so a hung test fails fast (named in the ctest log)
    # instead of stalling the whole job until the 6h GitHub limit. Every unit
    # test finishes in well under a second; the slowest deliberately sleeps a
    # couple of seconds, so 120s is generous headroom even on a loaded runner.
    PROPERTIES LABELS "unit" TIMEOUT 120
)

# Integration tests
add_executable(integration_tests
    integration/test_config_pipeline.cpp
    integration/test_http_scenarios.cpp
    integration/test_inspect_ipc.cpp
    integration/test_pipe_bridge.cpp
    integration/test_rules_integration.cpp
    integration/test_sighup_reload.cpp
    integration/test_tcp_loopback.cpp
    integration/test_tunnel_data_flow.cpp
)
target_link_libraries(integration_tests PRIVATE
    toxtunnel_lib
    GTest::gtest_main
    GTest::gmock
)
if(MSVC)
    target_compile_options(integration_tests PRIVATE /W4)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(integration_tests PRIVATE /WX)
    endif()
else()
    target_compile_options(integration_tests PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(integration_tests PRIVATE -Werror)
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(integration_tests PRIVATE
            -Wno-array-bounds
            -Wno-stringop-overread
            -Wno-stringop-overflow
        )
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(integration_tests PRIVATE -Wno-deprecated-literal-operator)
    endif()
endif()
gtest_discover_tests(integration_tests
    DISCOVERY_TIMEOUT 60
    # Per-test wall-clock cap (see unit_tests above). Integration tests use
    # bounded 5s future waits, so 120s is ample and turns any hang into a fast,
    # named failure rather than a 6h job stall.
    PROPERTIES LABELS "integration" TIMEOUT 120
)

# Soak tests (long-running). Default `ctest` excludes them via labels;
# release-branch CI runs them via `ctest -L soak`.
add_executable(soak_tests
    soak/soak_smoke_test.cpp
)
target_link_libraries(soak_tests PRIVATE
    toxtunnel_lib
    GTest::gtest_main
    GTest::gmock
)
if(NOT MSVC)
    target_compile_options(soak_tests PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(soak_tests PRIVATE -Werror)
    endif()
endif()
gtest_discover_tests(soak_tests
    DISCOVERY_TIMEOUT 60
    PROPERTIES LABELS "soak"
)

# Chaos tests. Default `ctest` excludes them via labels; nightly CI runs
# them via `ctest -L chaos`.
add_executable(chaos_tests
    chaos/chaos_smoke_test.cpp
)
target_link_libraries(chaos_tests PRIVATE
    toxtunnel_lib
    GTest::gtest_main
    GTest::gmock
)
if(NOT MSVC)
    target_compile_options(chaos_tests PRIVATE -Wall -Wextra -Wpedantic)
    if(TOXTUNNEL_WARNINGS_AS_ERRORS)
        target_compile_options(chaos_tests PRIVATE -Werror)
    endif()
endif()
gtest_discover_tests(chaos_tests
    DISCOVERY_TIMEOUT 60
    PROPERTIES LABELS "chaos"
)
