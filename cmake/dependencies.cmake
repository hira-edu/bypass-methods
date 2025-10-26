# Dependencies management for UndownUnlock project
# This file centralizes all external dependency declarations and version pinning

# Include FetchContent for dependency management
include(FetchContent)

# Set up dependency versions
set(GOOGLETEST_VERSION "release-1.11.0")
set(DIRECTX_HEADERS_VERSION "v1.4.10")

# Google Test dependency
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG ${GOOGLETEST_VERSION}
)

# Make Google Test available
FetchContent_MakeAvailable(googletest)

# DirectX Headers dependency (optional)
FetchContent_Declare(
    directx-headers
    GIT_REPOSITORY https://github.com/microsoft/DirectX-Headers.git
    GIT_TAG ${DIRECTX_HEADERS_VERSION}
)

# Try to make DirectX Headers available (optional)
FetchContent_GetProperties(directx-headers)
if(NOT directx-headers_POPULATED)
    FetchContent_Populate(directx-headers)
    add_subdirectory(${directx-headers_SOURCE_DIR} ${directx-headers_BINARY_DIR})
endif()

# Function to validate dependencies
function(validate_dependencies)
    message(STATUS "Validating dependencies...")
    
    # Check if Google Test is available
    if(TARGET gtest)
        message(STATUS "✅ Google Test: Available")
    else()
        message(WARNING "⚠️  Google Test: Not available")
    endif()
    
    # Check if DirectX Headers is available
    if(TARGET Microsoft::DirectX-Headers)
        message(STATUS "✅ DirectX Headers: Available")
    else()
        message(STATUS "ℹ️  DirectX Headers: Using system headers")
    endif()
    
    # Check for required system libraries
    find_library(D3D11_LIB d3d11)
    if(D3D11_LIB)
        message(STATUS "✅ D3D11: Found")
    else()
        message(WARNING "⚠️  D3D11: Not found")
    endif()
    
    find_library(DXGI_LIB dxgi)
    if(DXGI_LIB)
        message(STATUS "✅ DXGI: Found")
    else()
        message(WARNING "⚠️  DXGI: Not found")
    endif()
    
    find_library(WINDOWSCODECS_LIB windowscodecs)
    if(WINDOWSCODECS_LIB)
        message(STATUS "✅ Windows Codecs: Found")
    else()
        message(WARNING "⚠️  Windows Codecs: Not found")
    endif()
endfunction()

# Function to configure dependency options
function(configure_dependency_options)
    option(USE_SYSTEM_GOOGLETEST "Use system-installed Google Test" OFF)
    option(USE_SYSTEM_DIRECTX_HEADERS "Use system-installed DirectX Headers" OFF)
    option(BUILD_TESTING "Build tests" ON)
    option(ENABLE_COVERAGE "Enable code coverage" OFF)
    
    # Configure based on options
    if(USE_SYSTEM_GOOGLETEST)
        find_package(GTest REQUIRED)
        message(STATUS "Using system Google Test")
    endif()
    
    if(USE_SYSTEM_DIRECTX_HEADERS)
        find_package(directx-headers CONFIG REQUIRED)
        message(STATUS "Using system DirectX Headers")
    endif()
    
    if(ENABLE_COVERAGE)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
        message(STATUS "Code coverage enabled")
    endif()
endfunction()

# Function to set up dependency targets
function(setup_dependency_targets)
    # Create interface target for common dependencies
    add_library(UndownUnlockDependencies INTERFACE)
    
    # Add DirectX libraries
    target_link_libraries(UndownUnlockDependencies INTERFACE
        d3d11
        dxgi
        windowscodecs
    )
    
    # Add DirectX Headers if available
    if(TARGET Microsoft::DirectX-Headers)
        target_link_libraries(UndownUnlockDependencies INTERFACE
            Microsoft::DirectX-Headers
        )
    endif()
    
    # Add compiler definitions
    target_compile_definitions(UndownUnlockDependencies INTERFACE
        WIN32
        _WINDOWS
        _UNICODE
        UNICODE
        NOMINMAX
    )
    
    # Add include directories
    target_include_directories(UndownUnlockDependencies INTERFACE
        ${CMAKE_SOURCE_DIR}/include
    )
    
    # Set C++ standard
    target_compile_features(UndownUnlockDependencies INTERFACE
        cxx_std_17
    )
endfunction()

# Function to configure test dependencies
function(setup_test_dependencies)
    if(BUILD_TESTING)
        # Ensure Google Test is available
        if(NOT TARGET gtest)
            message(FATAL_ERROR "Google Test is required for testing but not available")
        endif()
        
        # Create test dependencies target
        add_library(UndownUnlockTestDependencies INTERFACE)
        
        target_link_libraries(UndownUnlockTestDependencies INTERFACE
            gtest
            gtest_main
            UndownUnlockDependencies
        )
        
        message(STATUS "Test dependencies configured")
    endif()
endfunction()

# Function to validate build environment
function(validate_build_environment)
    message(STATUS "Validating build environment...")
    
    # Check C++ standard support
    if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.0")
            message(FATAL_ERROR "Visual Studio 2019 or later required")
        endif()
        message(STATUS "✅ MSVC compiler: ${CMAKE_CXX_COMPILER_VERSION}")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "7.0")
            message(FATAL_ERROR "GCC 7.0 or later required")
        endif()
        message(STATUS "✅ GCC compiler: ${CMAKE_CXX_COMPILER_VERSION}")
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "6.0")
            message(FATAL_ERROR "Clang 6.0 or later required")
        endif()
        message(STATUS "✅ Clang compiler: ${CMAKE_CXX_COMPILER_VERSION}")
    else()
        message(WARNING "⚠️  Unknown compiler: ${CMAKE_CXX_COMPILER_ID}")
    endif()
    
    # Check CMake version
    if(CMAKE_VERSION VERSION_LESS "3.12")
        message(FATAL_ERROR "CMake 3.12 or later required")
    endif()
    message(STATUS "✅ CMake version: ${CMAKE_VERSION}")
    
    # Check platform
    if(WIN32)
        message(STATUS "✅ Platform: Windows")
    else()
        message(WARNING "⚠️  Platform: ${CMAKE_SYSTEM_NAME} (may have compatibility issues)")
    endif()
endfunction()

# Function to print dependency summary
function(print_dependency_summary)
    message(STATUS "")
    message(STATUS "=== Dependency Summary ===")
    message(STATUS "Google Test: ${GOOGLETEST_VERSION}")
    message(STATUS "DirectX Headers: ${DIRECTX_HEADERS_VERSION}")
    message(STATUS "Build Testing: ${BUILD_TESTING}")
    message(STATUS "Code Coverage: ${ENABLE_COVERAGE}")
    message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
    message(STATUS "==========================")
    message(STATUS "")
endfunction() 
