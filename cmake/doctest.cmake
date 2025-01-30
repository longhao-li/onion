if(NOT ONION_BUILD_TESTS)
    message(FATAL_ERROR "Do not fetch doctest if testing is not enabled.")
endif()

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
