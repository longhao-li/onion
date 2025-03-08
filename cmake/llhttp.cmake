find_package(llhttp QUIET)

if(NOT llhttp_FOUND)
    message(STATUS "llhttp not found, fetching from https://github.com/nodejs/llhttp")

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
        llhttp
        URL https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.2.1.zip
        URL_HASH SHA256=E1B1CB03EFCF4238BCF688064085DF63FE258A7785086E0BDD1794BD2486DCA5
    )

    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(llhttp)
endif()
