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
    message(FATAL_ERROR "liburing not found.")
endif()
