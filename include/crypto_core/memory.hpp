#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core
{

void secure_zero_memory(void *data, std::size_t size) noexcept;

[[nodiscard]] bool constant_time_equal(
    std::span<const std::uint8_t> lhs,
    std::span<const std::uint8_t> rhs) noexcept;

} // namespace crypto_core
