#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace crypto_core::internal
{

class AesBlockCipher final
{
public:
	static constexpr std::size_t block_size = 16;

	AesBlockCipher(const AesBlockCipher &) = delete;
	AesBlockCipher &operator=(const AesBlockCipher &) = delete;
	AesBlockCipher(AesBlockCipher &&other) noexcept;
	AesBlockCipher &operator=(AesBlockCipher &&other) noexcept;
	~AesBlockCipher() noexcept;

	[[nodiscard]] static Result<AesBlockCipher> create(std::span<const std::uint8_t> key) noexcept;

	[[nodiscard]] Result<ByteBuffer> encrypt_block(std::span<const std::uint8_t> plaintext) const noexcept;
	[[nodiscard]] Result<ByteBuffer> decrypt_block(std::span<const std::uint8_t> ciphertext) const noexcept;

private:
	AesBlockCipher() = default;

	std::array<std::uint32_t, 60> round_keys_{};
	std::size_t round_key_words_{0};
	std::uint8_t rounds_{0};
};

} // namespace crypto_core::internal
