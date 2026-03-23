# Tests
include(FetchContent)

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
    unit/test_pipe_mode.cpp
    unit/test_qr_code.cpp
    unit/test_rules_engine.cpp
    unit/test_tox_adapter.cpp
    unit/test_tunnel.cpp
    unit/test_tunnel_manager.cpp
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
endif()
gtest_discover_tests(unit_tests
    DISCOVERY_TIMEOUT 60
    PROPERTIES LABELS "unit"
)

# Integration tests
add_executable(integration_tests
    integration/test_config_pipeline.cpp
    integration/test_http_scenarios.cpp
    integration/test_pipe_bridge.cpp
    integration/test_rules_integration.cpp
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
endif()
gtest_discover_tests(integration_tests
    DISCOVERY_TIMEOUT 60
    PROPERTIES LABELS "integration"
)
