cmake_minimum_required(VERSION 3.20)

project(onion VERSION 0.0.0 LANGUAGES CXX)

# Disable in-source build.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source build is not allowed.")
endif()

# CMake build options.
option(ONION_BUILD_SHARED_LIBS "Build onion as shared library." OFF)
option(ONION_WARNINGS_AS_ERRORS "Treat warnings as errors." OFF)
option(ONION_ENABLE_LTO "Enable link-time optimization for onion shared library." OFF)
option(ONION_ENABLE_ASAN "Enable address sanitizer for onion. Cannot be enabled with LTO" OFF)
option(ONION_BUILD_TESTS "Build onion tests." OFF)
option(ONION_BUILD_EXAMPLES "Build onion examples." OFF)

# Build onion library.
file(GLOB_RECURSE ONION_HEADER_FILES "include/*.hpp")
file(GLOB_RECURSE ONION_SOURCE_FILES "src/*.cpp")

if(ONION_BUILD_SHARED_LIBS)
    add_library(onion SHARED ${ONION_HEADER_FILES} ${ONION_SOURCE_FILES})

    # Options for shared library.
    target_compile_definitions(onion PUBLIC "ONION_API=__attribute__((visibility(\"default\")))")

    # Hide symbols and use position independent code.
    set_target_properties(
        onion
        PROPERTIES  POSITION_INDEPENDENT_CODE ON
                    CXX_VISIBILITY_PRESET hidden
                    VISIBILITY_INLINES_HIDDEN ON
    )

    # Enable LTO if supported.
    if(ONION_ENABLE_LTO)
        include(CheckIPOSupported)
        check_ipo_supported(RESULT ONION_SUPPORT_LTO OUTPUT ONION_LTO_ERROR_MESSAGE)

        if(ONION_SUPPORT_LTO)
            message(STATUS "LTO is enabled for onion.")
            set_target_properties(onion PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
        else()
            message(WARNING "LTO is enabled but not supported: ${ONION_LTO_ERROR_MESSAGE}")
        endif()
    endif()
else()
    add_library(onion STATIC ${ONION_HEADER_FILES} ${ONION_SOURCE_FILES})
    target_compile_definitions(onion PUBLIC "ONION_API=")
endif()

# Alias target to be consistent with the project name.
add_library(onion::onion ALIAS onion)

# We need C++20 for coroutine support and C++23 for std::expected.
target_compile_features(onion PUBLIC cxx_std_23)

# Include directories.
target_include_directories(
    onion
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
)

# Compiler options.
include(CheckCXXCompilerFlag)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(onion PRIVATE -Wall -Wextra -Woverloaded-virtual -Wold-style-cast)

    # Treat warnings as errors.
    if(ONION_WARNINGS_AS_ERRORS)
        target_compile_options(onion PRIVATE -Werror)
    endif()

    # Enable address sanitizer.
    if(ONION_ENABLE_ASAN)
        target_compile_options(onion PRIVATE -fsanitize=address)
        target_link_libraries(onion PRIVATE -fsanitize=address)
    endif()
endif()

# Link system libraries. We use io_uring for Linux.
include(cmake/liburing.cmake)
include(cmake/llhttp.cmake)

target_link_libraries(onion PUBLIC uring::uring PRIVATE llhttp::llhttp)

# Add install target if this is the root project.
include(GNUInstallDirs)

install(
    TARGETS     onion
    EXPORT      onion-targets
    RUNTIME     DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY     DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE     DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT      onion-targets
    FILE        onion-targets.cmake
    NAMESPACE   onion::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/onion
)

# Generate the package configuration file.
include(CMakePackageConfigHelpers)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/onion-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/onion-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/onion
)

write_basic_package_version_file(
    onion-config-version.cmake
    VERSION ${PACKAGE_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES       ${CMAKE_CURRENT_BINARY_DIR}/onion-config.cmake
                ${CMAKE_CURRENT_BINARY_DIR}/onion-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/onion
)

# Install the header files.
install(
    DIRECTORY   ${CMAKE_CURRENT_SOURCE_DIR}/include/onion
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Build tests.
if(ONION_BUILD_TESTS)
    # Enable testing support in CMake.
    include(CTest)
    include(cmake/doctest.cmake)

    # Build the test executable.
    file(GLOB_RECURSE ONION_TEST_SOURCE_FILES "tests/*.cpp")
    add_executable(onion-test ${ONION_TEST_SOURCE_FILES})

    target_link_libraries(onion-test PRIVATE onion doctest::doctest)
    if(ONION_ENABLE_ASAN)
        target_link_libraries(onion-test PRIVATE -fsanitize=address)
        target_link_libraries(onion-test PRIVATE -fsanitize=address)
    endif()

    doctest_discover_tests(onion-test)
endif()

# Build examples.
if(ONION_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
