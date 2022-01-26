// Copyright (c) 2010-2022 The Open-Transactions developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#include "opentxs/Version.hpp"  // IWYU pragma: associated

#if __has_include(<memory_resource>)
#include <memory_resource>  // IWYU pragma: export
#elif __has_include(<experimental/memory_resource>)
// NOTE android ndk r23 and Apple still lack complete c++17 support
#include <experimental/deque>            // IWYU pragma: export
#include <experimental/forward_list>     // IWYU pragma: export
#include <experimental/list>             // IWYU pragma: export
#include <experimental/map>              // IWYU pragma: export
#include <experimental/memory_resource>  // IWYU pragma: export
#include <experimental/set>              // IWYU pragma: export
#include <experimental/string>           // IWYU pragma: export
#include <experimental/unordered_map>    // IWYU pragma: export
#include <experimental/unordered_set>    // IWYU pragma: export
#include <experimental/vector>           // IWYU pragma: export
#else
#error polymorphic allocator support is required
#endif
#include <deque>          // IWYU pragma: export
#include <forward_list>   // IWYU pragma: export
#include <list>           // IWYU pragma: export
#include <map>            // IWYU pragma: export
#include <set>            // IWYU pragma: export
#include <string>         // IWYU pragma: export
#include <unordered_map>  // IWYU pragma: export
#include <unordered_set>  // IWYU pragma: export
#include <vector>         // IWYU pragma: export

namespace opentxs
{
namespace alloc
{
#if __has_include(<memory_resource>)
template <typename T>
using PMR = std::pmr::polymorphic_allocator<T>;
using Resource = std::pmr::memory_resource;
// TODO not yet supported on Android
// using SynchronizedPool = std::pmr::synchronized_pool_resource;
// using UnsynchronizedPool = std::pmr::unsynchronized_pool_resource;
// using Monotonic = std::pmr::monotonic_buffer_resource;
#else
template <typename T>
using PMR = std::experimental::pmr::polymorphic_allocator<T>;
using Resource = std::experimental::pmr::memory_resource;
// TODO not yet supported on Android
// using SynchronizedPool = std::experimental::pmr::synchronized_pool_resource;
// using UnsynchronizedPool =
// std::experimental::pmr::unsynchronized_pool_resource; using Monotonic =
// std::experimental::pmr::monotonic_buffer_resource;
#endif

// TODO not yet supported on Android
// auto System() noexcept -> Resource*;
// auto Null() noexcept -> Resource*;
}  // namespace alloc

#if __has_include(<memory_resource>)
using CString = std::pmr::string;
template <typename T>
using Deque = std::pmr::deque<T>;
template <typename T>
using ForwardList = std::pmr::forward_list<T>;
template <typename T>
using List = std::pmr::list<T>;
template <typename K, typename V>
using Map = std::pmr::map<K, V>;
template <typename T>
using Multiset = std::pmr::multiset<T>;
template <typename K, typename V>
using Multimap = std::pmr::multimap<K, V>;
template <typename T>
using Set = std::pmr::set<T>;
template <typename K, typename V>
using UnorderedMap = std::pmr::unordered_map<K, V>;
template <typename K, typename V>
using UnorderedMultimap = std::pmr::unordered_multimap<K, V>;
template <typename T>
using UnorderedMultiset = std::pmr::unordered_multiset<T>;
template <typename T>
using UnorderedSet = std::pmr::unordered_set<T>;
template <typename T>
using Vector = std::pmr::vector<T>;
#else
using CString = std::experimental::pmr::string;
template <typename T>
using Deque = std::experimental::pmr::deque<T>;
template <typename T>
using ForwardList = std::experimental::pmr::forward_list<T>;
template <typename T>
using List = std::experimental::pmr::list<T>;
template <typename K, typename V>
using Map = std::experimental::pmr::map<K, V>;
template <typename T>
using Multiset = std::experimental::pmr::multiset<T>;
template <typename K, typename V>
using Multimap = std::experimental::pmr::multimap<K, V>;
template <typename T>
using Set = std::experimental::pmr::set<T>;
template <typename K, typename V>
using UnorderedMap = std::experimental::pmr::unordered_map<K, V>;
template <typename K, typename V>
using UnorderedMultimap = std::experimental::pmr::unordered_multimap<K, V>;
template <typename T>
using UnorderedMultiset = std::experimental::pmr::unordered_multiset<T>;
template <typename T>
using UnorderedSet = std::experimental::pmr::unordered_set<T>;
template <typename T>
using Vector = std::experimental::pmr::vector<T>;
#endif
using UnallocatedCString = std::string;
template <typename T>
using UnallocatedDeque = std::deque<T>;
template <typename T>
using UnallocatedForwardList = std::forward_list<T>;
template <typename T>
using UnallocatedList = std::list<T>;
template <typename K, typename V>
using UnallocatedMap = std::map<K, V>;
template <typename T>
using UnallocatedMultiset = std::multiset<T>;
template <typename K, typename V>
using UnallocatedMultimap = std::multimap<K, V>;
template <typename T>
using UnallocatedSet = std::set<T>;
template <typename K, typename V>
using UnallocatedUnorderedMap = std::unordered_map<K, V>;
template <typename K, typename V>
using UnallocatedUnorderedMultimap = std::unordered_multimap<K, V>;
template <typename T>
using UnallocatedUnorderedMultiset = std::unordered_multiset<T>;
template <typename T>
using UnallocatedUnorderedSet = std::unordered_set<T>;
template <typename T>
using UnallocatedVector = std::vector<T>;
}  // namespace opentxs
