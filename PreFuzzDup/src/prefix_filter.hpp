#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace prefuzz {

// Functional two-level Prefix Filter. Each bin retains the smallest mini-
// fingerprints; a full bin forwards its largest fingerprint to the spare.
// The spare is an exact in-memory dictionary rather than the paper's compact
// second-level filter. This keeps the prefix invariant and has no false
// negatives, but does not claim the paper's SIMD or memory benchmarks.
class PrefixFilter {
 public:
  PrefixFilter() = default;
  PrefixFilter(std::size_t capacity, double false_positive_rate) {
    reset(capacity, false_positive_rate);
  }

  void reset(std::size_t capacity, double false_positive_rate) {
    if (capacity == 0 || !(false_positive_rate > 0.0 && false_positive_rate < 1.0))
      throw std::invalid_argument("invalid Prefix Filter capacity or false-positive rate");
    // 32-bit mini-fingerprints support the requested range. Two-level
    // fingerprint collisions can only add false positives.
    const double width = std::ceil(std::log2(4.0 * kBinCapacity / false_positive_rate));
    if (width > 32.0) throw std::invalid_argument("Prefix Filter fpp is too small for 32-bit fingerprints");
    fingerprint_bits_ = std::max(8U, static_cast<unsigned>(width));
    fingerprint_mask_ = fingerprint_bits_ == 32 ? UINT32_MAX : (std::uint32_t{1} << fingerprint_bits_) - 1;
    const auto count = static_cast<std::size_t>(std::ceil(static_cast<double>(capacity) / (kBinCapacity * 0.95)));
    bins_.assign(std::max<std::size_t>(count, 1), Bin{});
    spare_.clear();
  }

  void insert(std::span<const std::uint8_t> value) {
    const auto key = fingerprint(value);
    auto& bin = bins_[key.bin];
    if (bin.count < kBinCapacity) {
      bin.values[bin.count++] = key.mini;
      return;
    }
    const auto max_it = std::max_element(bin.values.begin(), bin.values.begin() + bin.count);
    if (key.mini > *max_it) {
      spare_.insert(key);
    } else {
      spare_.insert(Key{key.bin, *max_it});
      *max_it = key.mini;
    }
    bin.overflowed = true;
  }

  bool maybe_contains(std::span<const std::uint8_t> value) const {
    const auto key = fingerprint(value);
    const auto& bin = bins_[key.bin];
    if (bin.overflowed && key.mini > *std::max_element(bin.values.begin(), bin.values.begin() + bin.count))
      return spare_.contains(key);
    return std::find(bin.values.begin(), bin.values.begin() + bin.count, key.mini) != bin.values.begin() + bin.count;
  }

  void insert(std::string_view value) { insert(as_bytes(value)); }
  bool contains(std::string_view value) const { return maybe_contains(as_bytes(value)); }
  std::size_t bytes_used() const { return bins_.capacity() * sizeof(Bin) + spare_.size() * sizeof(Key); }
  std::size_t bytes() const { return bytes_used(); }

 private:
  static constexpr std::size_t kBinCapacity = 25;
  struct Bin {
    std::array<std::uint32_t, kBinCapacity> values{};
    std::uint8_t count = 0;
    bool overflowed = false;
  };
  struct Key {
    std::size_t bin;
    std::uint32_t mini;
    bool operator==(const Key&) const = default;
  };
  struct KeyHash {
    std::size_t operator()(const Key& key) const {
      return static_cast<std::size_t>(mix64(static_cast<std::uint64_t>(key.bin) ^
                                            (static_cast<std::uint64_t>(key.mini) << 32)));
    }
  };

  static std::span<const std::uint8_t> as_bytes(std::string_view value) {
    return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
  }
  static std::uint64_t mix64(std::uint64_t value) {
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    return value ^ (value >> 31);
  }
  Key fingerprint(std::span<const std::uint8_t> value) const {
    if (bins_.empty()) throw std::logic_error("Prefix Filter is not initialized");
    std::uint64_t hash = UINT64_C(14695981039346656037);
    for (auto byte : value) { hash ^= byte; hash *= UINT64_C(1099511628211); }
    const auto bin = static_cast<std::size_t>(mix64(hash) % bins_.size());
    const auto mini = static_cast<std::uint32_t>(mix64(hash ^ UINT64_C(0x9e3779b97f4a7c15)) & fingerprint_mask_);
    return {bin, mini};
  }

  std::vector<Bin> bins_;
  std::unordered_set<Key, KeyHash> spare_;
  unsigned fingerprint_bits_ = 0;
  std::uint32_t fingerprint_mask_ = 0;
};

}  // namespace prefuzz
