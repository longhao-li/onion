# This file could be used on Linux only.
if(NOT (CMAKE_SYSTEM_NAME MATCHES "Linux"))
    message(FATAL_ERROR "Only Linux supports io_uring.")
endif()

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
    # Fetch liburing source code.
    include(FetchContent)

    message(STATUS "liburing not found, fetching from https://github.com/axboe/liburing")
    FetchContent_Declare(
        liburing
        GIT_REPOSITORY https://github.com/axboe/liburing.git
        GIT_TAG liburing-2.8
    )

    FetchContent_MakeAvailable(liburing)

    # Build liburing.
    set(
        LIBURING_SOURCE_FILES
        ${liburing_SOURCE_DIR}/src/setup.c
        ${liburing_SOURCE_DIR}/src/queue.c
        ${liburing_SOURCE_DIR}/src/register.c
        ${liburing_SOURCE_DIR}/src/syscall.c
        ${liburing_SOURCE_DIR}/src/version.c
    )

    add_library(uring STATIC ${LIBURING_HEADER_FILES} ${LIBURING_SOURCE_FILES})
    add_library(uring::uring ALIAS uring)

    # Generate some header files before building.
    set(
        LIBURING_GENERATED_FILES
        ${liburing_SOURCE_DIR}/config.log
        ${liburing_SOURCE_DIR}/config-host.h
        ${liburing_SOURCE_DIR}/config-host.mak
        ${liburing_SOURCE_DIR}/src/include/liburing/compat.h
        ${liburing_SOURCE_DIR}/src/include/liburing/io_uring_version.h
    )

    add_custom_command(
        OUTPUT      ${LIBURING_GENERATED_FILES}
        COMMAND     ./configure --cc=${CMAKE_C_COMPILER} --cxx=${CMAKE_CXX_COMPILER} --use-libc --prefix=${CMAKE_INSTALL_PREFIX}
        COMMENT     "Configuring liburing"
        VERBATIM
        WORKING_DIRECTORY ${liburing_SOURCE_DIR}
    )

    add_custom_target(
        uring-configure
        DEPENDS ${LIBURING_GENERATED_FILES}
    )

    add_dependencies(uring uring-configure)

    # liburing include directories.
    target_include_directories(
        uring
        PRIVATE ${liburing_SOURCE_DIR}/src
        PUBLIC  $<BUILD_INTERFACE:${liburing_SOURCE_DIR}/src/include>
                $<INSTALL_INTERFACE:include>
    )

    # liburing compile options.
    target_compile_options(uring PRIVATE -Wno-unused-parameter)

    # liburing compile definitions.
    target_compile_definitions(
        uring
        PRIVATE "_GNU_SOURCE"
                "_LARGEFILE_SOURCE"
                "_FILE_OFFSET_BITS=64"
                "LIBURING_INTERNAL"
    )

    # Export liburing.
    if(ONION_IS_ROOT_PROJECT)
        include(GNUInstallDirs)

        install(
            TARGETS     uring
            EXPORT      uring-targets
            LIBRARY     DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE     DESTINATION ${CMAKE_INSTALL_LIBDIR}
            INCLUDES    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )

        install(
            EXPORT      uring-targets
            FILE        uring-targets.cmake
            NAMESPACE   uring::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/uring
        )

        install(
            DIRECTORY   ${liburing_SOURCE_DIR}/src/include
            DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        )
    endif()
endif()
