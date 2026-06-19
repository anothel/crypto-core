#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core
{

void secure_zero_memory(void *data, std::size_t size) noexcept;

[[nodiscard]] std::uint8_t constant_time_bool_mask(bool value) noexcept;
[[nodiscard]] std::uint8_t constant_time_is_zero(std::uint8_t value) noexcept;
[[nodiscard]] std::uint8_t constant_time_select(std::uint8_t mask, std::uint8_t if_set, std::uint8_t if_clear) noexcept;
[[nodiscard]] std::size_t constant_time_select_size(std::uint8_t mask, std::size_t if_set, std::size_t if_clear) noexcept;

[[nodiscard]] bool constant_time_equal(
    std::span<const std::uint8_t> lhs,
    std::span<const std::uint8_t> rhs) noexcept;

} // namespace crypto_core
