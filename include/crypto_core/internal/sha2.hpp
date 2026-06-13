#pragma once

#include "crypto_core/provider.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core::internal
{

class Sha256Context final : public IHashContext
{
public:
	Sha256Context() noexcept;

	[[nodiscard]] Result<void> update(std::span<const std::uint8_t> input) noexcept override;
	[[nodiscard]] Result<ByteBuffer> final() noexcept override;

private:
	void transform(const std::uint8_t block[64]) noexcept;

	std::array<std::uint32_t, 8> state_{};
	std::array<std::uint8_t, 64> buffer_{};
	std::uint64_t bit_count_{0};
	std::size_t buffer_size_{0};
	bool finalized_{false};
};

class Sha512Context final : public IHashContext
{
public:
	Sha512Context() noexcept;

	[[nodiscard]] Result<void> update(std::span<const std::uint8_t> input) noexcept override;
	[[nodiscard]] Result<ByteBuffer> final() noexcept override;

private:
	void transform(const std::uint8_t block[128]) noexcept;

	std::array<std::uint64_t, 8> state_{};
	std::array<std::uint8_t, 128> buffer_{};
	std::uint64_t bit_count_low_{0};
	std::uint64_t bit_count_high_{0};
	std::size_t buffer_size_{0};
	bool finalized_{false};
};

} // namespace crypto_core::internal
