# onion

`onion` is a easy-to-use and high-performance general purpose asynchronous IO framework using C++20 coroutine, which aims to provide a flexible and efficient way to handle asynchronous file IO, network communications and more.

## Getting Started

### Build Requirement

- CMake >= 3.20
- Any Linux distribution with kernel version >= 5.12.
- GCC >= 12 or clang >= 18.
- System liburing package. For Debian-based distributions, this is usually the liburing-dev package.

### Build Options

Use `-DONION_BUILD_SHARED_LIBS=ON` to build `onion` as shared library. Please notice that `BUILD_SHARED_LIBS` option does not affect `onion`.

Use `-DONION_BUILD_TESTS=ON` to build unit tests. Unit tests requires [doctest](https://github.com/doctest/doctest). The build script will automatically fetch [doctest](https://github.com/doctest/doctest) from GitHub if it is not found on the system.

Use `-DONION_BUILD_EXAMPLES=ON` to build examples.

See [CMakeLists.txt](./CMakeLists.txt) for other build options.

### Basic Usage

`onion::Task<T>` is used for general-purpose coroutine. Coroutines should always return `onion::Task<T>`. to support async operations. Here is a minimal example:

```cpp
#include "onion/io_context.hpp"

#include <format>
#include <print>

using namespace onion;

auto hello() noexcept -> Task<> {
    std::println("Hello, world!");
    co_return;
}

auto greetings(std::string name) noexcept -> Task<std::string> {
    co_return std::format("Greetings, {}!", name);
}

auto main() -> int  {
    // Coroutines need a context to be scheduled.
    // IoContext works as a static thread pool. Number of threads will be determined by std::thread::hardware_concurrency().
    IoContext ctx;

    // Schedule work to I don't know which thread.
    ctx.schedule(hello());
    ctx.schedule(greetings("world"));

    // Dispatch hello() to all worker threads.
    ctx.dispatch(hello);

    // Block and wait. Usually, this method could be considered as a noreturn function.
    ctx.start();
}
```

If you want to generate new task to run concurrently with current task, please consider using `onion::schedule`:

```cpp
auto foo() -> Task<> {
    // do something.
}

auto bar() -> Task<> {
    // schedule never suspends current coroutine and there is no mutex lock operation.
    co_await schedule(foo());
}
```

You might also use `ctx.schedule(foo())` to do the same thing, but `IoContext::schedule` requires mutex operations, but `onion::schedule` does not.

One example is the [TCP echo server](./examples/tcp_echo/main.cpp). The acceptor schedules a server coroutine for each incoming connection.

### Asynchronous IO

For async TCP IO operations, please see [TCP echo server](./examples/tcp_echo/main.cpp) for details. Asynchronous UDP and file are still in-progress.

## License

BSD 3-Clause License. See [LICENSE](./LICENSE) for details.
