cmake_minimum_required(VERSION 3.20)

project(onion VERSION 0.0.0 LANGUAGES CXX)

# Disable in-source build.
if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source build is not allowed.")
endif()

# CMake build options.
option(ONION_WARNINGS_AS_ERRORS "Treat warnings as errors." OFF)
option(ONION_ENABLE_LTO "Enable link-time optimization for onion shared library." OFF)
option(ONION_BUILD_TESTS "Build onion tests." OFF)
option(ONION_BUILD_EXAMPLES "Build onion examples." OFF)
option(ONION_INSTALL_TARGETS "Generate install targets for onion" ON)

# Build onion library.
file(GLOB_RECURSE ONION_HEADER_FILES "include/*.hpp")
file(GLOB_RECURSE ONION_SOURCE_FILES "src/*.cpp")

add_library(onion ${ONION_HEADER_FILES} ${ONION_SOURCE_FILES})
add_library(onion::onion ALIAS onion)

# C++23 is required.
target_compile_features(onion PUBLIC cxx_std_23)

# Include directories.
target_include_directories(
    onion
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:include>
)

# Options for shared library.
if(BUILD_SHARED_LIBS)
    # Export symbols.
    target_compile_definitions(
        onion
        PRIVATE "ONION_BUILD_SHARED_LIBS=1"
        PUBLIC  "ONION_SHARED_LIBS=1"
    )

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
endif()

# Compile options.
if(MSVC)
    target_compile_options(onion PRIVATE /W4 /permissive-)

    # Treat warnings as errors.
    if(ONION_WARNINGS_AS_ERRORS)
        target_compile_options(onion PRIVATE /WX)
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang|GNU")
    target_compile_options(onion PRIVATE -Wall -Wextra -Woverloaded-virtual -Wold-style-cast)

    # Treat warnings as errors.
    if(ONION_WARNINGS_AS_ERRORS)
        target_compile_options(onion PRIVATE -Werror)
    endif()
endif()

# Link system libraries.
if(WIN32)
    target_link_libraries(onion PUBLIC ws2_32)
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
    # Link system libraries. We use io_uring for Linux.
    include(FindPackageHandleStandardArgs)

    # Try to find liburing as system library.
    find_path(LIBURING_INCLUDE_DIR NAMES liburing.h)
    find_library(LIBURING_LIBRARIES NAMES uring)
    mark_as_advanced(LIBURING_INCLUDE_DIR LIBURING_LIBRARIES)

    find_package_handle_standard_args(
        liburing
        REQUIRED_VARS   LIBURING_INCLUDE_DIR
                        LIBURING_LIBRARIES
    )

    # Find liburing system library.
    if(liburing_FOUND)
        # Add a dummy target to make easier to link against liburing.
        add_library(uring INTERFACE IMPORTED GLOBAL)
        add_library(uring::uring ALIAS uring)
    
        target_include_directories(uring INTERFACE ${LIBURING_INCLUDE_DIR})
        target_link_libraries(uring INTERFACE ${LIBURING_LIBRARIES})
    else()
        message(FATAL_ERROR "liburing not found.")
    endif()

    target_link_libraries(onion PRIVATE uring::uring)
endif()

# Add install target.
if(ONION_INSTALL_TARGETS)
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
endif()

# Build tests.
if(ONION_BUILD_TESTS)
    # Enable testing support in CMake.
    include(CTest)

    find_package(doctest QUIET)

    if(doctest_FOUND)
        include(doctest)
    else()
        message(STATUS "doctest not found, fetching from https://github.com/doctest/doctest")

        # Fetch doctest.
        include(FetchContent)

        # CMake policy CMP0135 controls extraction behavior of the FetchContent module.
        # This policy was introduced in CMake 3.21. We set the policy to NEW to avoid
        # unnecessary downloads of the same content.
        if(POLICY CMP0135)
            cmake_policy(SET CMP0135 NEW)
            set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
        endif()

        FetchContent_Declare(
            doctest
            GIT_REPOSITORY https://github.com/doctest/doctest.git
            GIT_TAG v2.4.11
        )

        set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
        set(DOCTEST_WITH_MAIN_IN_STATIC_LIB OFF CACHE BOOL "" FORCE)
        set(DOCTEST_NO_INSTALL OFF CACHE BOOL "" FORCE)
        set(DOCTEST_USE_STD_HEADERS OFF CACHE BOOL "" FORCE)

        FetchContent_MakeAvailable(doctest)
        include(${doctest_SOURCE_DIR}/scripts/cmake/doctest.cmake)
    endif()

    # Build the test executable.
    file(GLOB_RECURSE ONION_TEST_SOURCE_FILES "tests/*.cpp")
    add_executable(onion-test ${ONION_TEST_SOURCE_FILES})

    target_link_libraries(onion-test PRIVATE onion doctest::doctest)
    doctest_discover_tests(onion-test)
endif()

# Build examples.
if(ONION_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
