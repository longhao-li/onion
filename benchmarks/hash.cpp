#include "onion/hash.hpp"

#include <absl/container/flat_hash_set.h>
#include <ankerl/unordered_dense.h>
#include <benchmark/benchmark.h>

#include <random>
#include <unordered_set>

/// \brief
///   Used to acquire global random seed. This ensures that the random engine will generate the same random numbers
///   across different runs of the benchmark.
[[nodiscard]] static auto random_seed() noexcept -> std::uint32_t {
    static const std::uint32_t seed = std::random_device{}();
    return seed;
}

template <template <typename Element, typename Hasher> typename HashSet>
static auto unordered_set_insert(benchmark::State &state) noexcept -> void {
    std::minstd_rand0                                  random{random_seed()};
    HashSet<std::uint64_t, onion::hash<std::uint64_t>> set;

    for (auto _ : state) {
        state.PauseTiming();
        std::uint64_t number = random();
        state.ResumeTiming();

        benchmark::DoNotOptimize(set.insert(number));
    }
}

BENCHMARK(unordered_set_insert<absl::flat_hash_set>);
BENCHMARK(unordered_set_insert<ankerl::unordered_dense::set>);
BENCHMARK(unordered_set_insert<onion::unordered_flat_set>);
BENCHMARK(unordered_set_insert<std::unordered_set>);

template <template <typename Element, typename Hasher> typename HashSet>
static auto unordered_set_insert_existing(benchmark::State &state) noexcept -> void {
    std::minstd_rand0                                  random{random_seed()};
    HashSet<std::uint64_t, onion::hash<std::uint64_t>> set;

    constexpr std::size_t length = 1000000;
    for (std::size_t i = 0; i < length; ++i)
        set.insert(random());

    random = std::minstd_rand0{random_seed()};

    for (auto _ : state) {
        state.PauseTiming();
        std::uint64_t number = random();
        state.ResumeTiming();

        benchmark::DoNotOptimize(set.insert(number));
    }
}

BENCHMARK(unordered_set_insert_existing<absl::flat_hash_set>);
BENCHMARK(unordered_set_insert_existing<ankerl::unordered_dense::set>);
BENCHMARK(unordered_set_insert_existing<onion::unordered_flat_set>);
BENCHMARK(unordered_set_insert_existing<std::unordered_set>);

template <template <typename Element, typename Hasher> typename HashSet>
static auto unordered_set_find_existing(benchmark::State &state) noexcept -> void {
    std::minstd_rand0                                  random{random_seed()};
    HashSet<std::uint64_t, onion::hash<std::uint64_t>> set;

    constexpr std::size_t length = 1000000;
    for (std::size_t i = 0; i < length; ++i)
        set.insert(random());

    random = std::minstd_rand0{random_seed()};

    for (auto _ : state) {
        state.PauseTiming();
        std::uint64_t number = random();
        state.ResumeTiming();

        benchmark::DoNotOptimize(set.find(number));
    }
}

BENCHMARK(unordered_set_find_existing<absl::flat_hash_set>);
BENCHMARK(unordered_set_find_existing<ankerl::unordered_dense::set>);
BENCHMARK(unordered_set_find_existing<onion::unordered_flat_set>);
BENCHMARK(unordered_set_find_existing<std::unordered_set>);

template <template <typename Element, typename Hasher> typename HashSet>
static auto unordered_set_erase(benchmark::State &state) noexcept -> void {
    std::minstd_rand0                                  random{random_seed()};
    HashSet<std::uint64_t, onion::hash<std::uint64_t>> set;

    constexpr std::size_t length = 1000000;
    for (std::size_t i = 0; i < length; ++i)
        set.insert(random());

    random = std::minstd_rand0{random_seed()};

    for (auto _ : state) {
        state.PauseTiming();
        std::uint64_t number = random();
        state.ResumeTiming();

        benchmark::DoNotOptimize(set.erase(number));
    }
}

BENCHMARK(unordered_set_erase<absl::flat_hash_set>);
BENCHMARK(unordered_set_erase<ankerl::unordered_dense::set>);
BENCHMARK(unordered_set_erase<onion::unordered_flat_set>);
BENCHMARK(unordered_set_erase<std::unordered_set>);
