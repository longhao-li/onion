#include "onion/hash.hpp"

alignas(16) const onion::detail::hash_table_state onion::detail::hash_table_state_empty_group[16] = {
    hash_table_state::sentinel, hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
    hash_table_state::empty,    hash_table_state::empty, hash_table_state::empty, hash_table_state::empty,
};
