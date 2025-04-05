set_project("onion")
set_version("0.0.0")

option("warnings_as_errors", {description = "Treat warnings as errors.", default = false})
option("enable_lto", {description = "Enable link-time optimization for onion shared library.", default = false})
option("build_tests", {description = "Build onion tests.", default = false})
option("build_examples", {description = "Build onion examples.", default = false})

add_requires("llhttp >=9.2.1")

if has_config("build_tests") then
    add_requires("gtest >=1.15.0")
end

if is_plat("linux") then
    add_requires("liburing >=2.8")
end

target("onion")
    set_kind("$(kind)")
    set_default(true)
    set_languages("cxx23")
    set_warnings("allextra")

    add_headerfiles("include/onion/*.hpp")
    add_files("src/onion/*.cpp")

    add_includedirs("include", {public = true})

    if is_mode("debug") then
        set_symbols("debug")
    else
        set_symbols("hidden")
    end

    -- definitions for shared libraries.
    if is_kind("shared") then
        add_defines("ONION_BUILD_SHARED_LIBS=1", {public = false})
        add_defines("ONION_SHARED_LIBS=1", {public = true})

        if has_config("enable_lto") then
            set_policy("build.optimization.lto", true)
        end
    end

    -- compile options.
    add_cxxflags("/permissive-", {tools = {"cl", "clang_cl"}})
    add_cxxflags("-Woverloaded-virtual", {tools = {"gcc", "clang", "appleclang"}})

    if has_config("warnings_as_errors") then
        add_cxxflags("/WX", {tools = {"cl", "clang_cl"}})
        add_cxxflags("-Werror", {tools = {"gcc", "clang", "appleclang"}})
    end

    -- link external libraries.
    add_packages("llhttp")

    -- link system libraries.
    if is_plat("windows") then
        add_syslinks("ws2_32", {public = true})
    elseif is_plat("linux") then
        add_packages("liburing", {public = true})
    end
target_end()

if has_config("build_tests") then
    target("onion-test")
        set_kind("binary")
        set_languages("cxx23")

        add_files("tests/**.cpp")

        add_deps("onion")
        add_packages("gtest")
    target_end()
end

if has_config("build_examples") then
    target("onion-tcp-echo-server")
        set_kind("binary")
        set_languages("cxx23")

        add_files("examples/tcp_echo_server.cpp")
        add_deps("onion")
    target_end()

    target("onion-udp-echo-server")
        set_kind("binary")
        set_languages("cxx23")

        add_files("examples/udp_echo_server.cpp")
        add_deps("onion")
    target_end()

    target("onion-http-server")
        set_kind("binary")
        set_languages("cxx23")

        add_files("examples/http_server.cpp")
        add_deps("onion")
    target_end()
end
