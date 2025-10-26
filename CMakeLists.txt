cmake_minimum_required(VERSION 3.12)
project(UndownUnlock VERSION 1.0.0 LANGUAGES CXX)

# Include centralized dependency management
include(cmake/dependencies.cmake)

# Configure dependency options and validate environment
configure_dependency_options()
validate_build_environment()
validate_dependencies()

# Define output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Set up dependency targets
setup_dependency_targets()

# Define source files for the DLL hooks library
set(DLL_HOOKS_SOURCES
    src/dllmain.cpp
    src/hooks/windows_api/windows_api_hooks.cpp
    src/hooks/windows_api/hooked_functions.cpp
    src/hooks/windows_api/keyboard_hook.cpp
    src/hooks/windows_api/hook_utils.cpp
    src/hooks/dx_hook_core.cpp
    src/hooks/swap_chain_hook.cpp
    src/memory/memory_scanner.cpp
    src/memory/pattern_scanner.cpp
    src/frame/frame_extractor.cpp
    src/shared/shared_memory_transport.cpp
    src/signatures/dx_signatures.cpp
    src/signatures/lockdown_signatures.cpp
    src/signatures/new_lockdown_signatures.cpp
    src/hooks/exam_signature_patcher.cpp
    src/com_hooks/factory_hooks.cpp
    # Utility components
    src/utils/raii_wrappers.cpp
    src/utils/error_handler.cpp
    src/utils/memory_tracker.cpp
    src/utils/performance_monitor.cpp
    src/utils/crash_reporter.cpp
    # Performance optimization components
    src/optimization/memory_pool.cpp
    src/optimization/thread_pool.cpp
    src/optimization/performance_optimizer.cpp
)

# Define source files for the test client
set(TEST_CLIENT_SOURCES
    src/test_client.cpp
)

# Add the DLL hooks library
add_library(UndownUnlockDXHook SHARED ${DLL_HOOKS_SOURCES})

# Copy the DLL to the runtime output directory so executables can find it
add_custom_command(TARGET UndownUnlockDXHook POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:UndownUnlockDXHook>
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Copying UndownUnlockDXHook DLL to runtime directory"
)

# Set up the DLL properties
target_compile_definitions(UndownUnlockDXHook PRIVATE
    _USRDLL
)

# Add the test client executable
add_executable(UndownUnlockTestClient ${TEST_CLIENT_SOURCES})

# Link targets with dependencies
target_link_libraries(UndownUnlockTestClient PRIVATE
    UndownUnlockDXHook
    UndownUnlockDependencies
)

target_link_libraries(UndownUnlockDXHook PRIVATE
    UndownUnlockDependencies
)

# Installation rules
install(TARGETS UndownUnlockDXHook UndownUnlockTestClient
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Copy the Python injector script to the output directory
configure_file(
    ${CMAKE_SOURCE_DIR}/src/test_injector.py
    ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test_injector.py
    COPYONLY
)

# Add tests if testing is enabled
if(BUILD_TESTING)
    enable_testing()
    setup_test_dependencies()
    add_subdirectory(tests)
endif()

# Print configuration summary
print_dependency_summary()
message(STATUS "CMAKE_GENERATOR: ${CMAKE_GENERATOR}")
message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER_ID: ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "CMAKE_CXX_COMPILER_VERSION: ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
message(STATUS "CMAKE_EXE_LINKER_FLAGS: ${CMAKE_EXE_LINKER_FLAGS}")
message(STATUS "CMAKE_SHARED_LINKER_FLAGS: ${CMAKE_SHARED_LINKER_FLAGS}") 
