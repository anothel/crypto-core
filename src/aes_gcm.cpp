#include "crypto_core/internal/aes_gcm.hpp"

#include "crypto_core/internal/aes.hpp"
#include "crypto_core/memory.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace crypto_core::internal
{
namespace
{

using Block = std::array<std::uint8_t, AesBlockCipher::block_size>;

std::size_t expected_key_size(AeadAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case AeadAlgorithm::aes_128_gcm:
		return 16;
	case AeadAlgorithm::aes_192_gcm:
		return 24;
	case AeadAlgorithm::aes_256_gcm:
		return 32;
	}

	return 0;
}

Result<void> validate_encrypt_params(const AeadEncryptParams &params) noexcept
{
	const auto key_size = expected_key_size(params.algorithm);
	if (key_size == 0)
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "aes_gcm", "AEAD algorithm is not supported"));
	}
	if (params.key.size() != key_size)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "aes_gcm", "AES-GCM key size does not match algorithm"));
	}
	if (params.nonce.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_gcm", "AES-GCM nonce must not be empty"));
	}
	if (params.tag_size < 12 || params.tag_size > 16)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_gcm", "AES-GCM tag size must be between 12 and 16 bytes"));
	}
	return Result<void>::success();
}

Result<void> validate_decrypt_params(const AeadDecryptParams &params) noexcept
{
	const auto key_size = expected_key_size(params.algorithm);
	if (key_size == 0)
	{
		return Result<void>::failure(make_error(ErrorCode::unsupported_algorithm, "aes_gcm", "AEAD algorithm is not supported"));
	}
	if (params.key.size() != key_size)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_key, "aes_gcm", "AES-GCM key size does not match algorithm"));
	}
	if (params.nonce.empty())
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_gcm", "AES-GCM nonce must not be empty"));
	}
	if (params.tag.size() < 12 || params.tag.size() > 16)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_gcm", "AES-GCM tag size must be between 12 and 16 bytes"));
	}
	return Result<void>::success();
}

void xor_block(Block &lhs, const Block &rhs) noexcept
{
	for (std::size_t i = 0; i < lhs.size(); ++i)
	{
		lhs[i] ^= rhs[i];
	}
}

bool bit_at(const Block &block, std::size_t bit) noexcept
{
	return ((block[bit / 8U] >> (7U - (bit % 8U))) & 1U) != 0U;
}

void shift_right_one(Block &block) noexcept
{
	std::uint8_t carry = 0;
	for (auto &byte : block)
	{
		const auto next_carry = static_cast<std::uint8_t>(byte & 1U);
		byte = static_cast<std::uint8_t>((byte >> 1U) | (carry << 7U));
		carry = next_carry;
	}
}

Block gf_multiply(const Block &x, const Block &y) noexcept
{
	Block z{};
	auto v = y;
	for (std::size_t bit = 0; bit < 128; ++bit)
	{
		if (bit_at(x, bit))
		{
			xor_block(z, v);
		}

		const auto lsb = static_cast<bool>(v[15] & 1U);
		shift_right_one(v);
		if (lsb)
		{
			v[0] ^= 0xe1U;
		}
	}
	return z;
}

void store_be64(std::uint64_t value, std::uint8_t *out) noexcept
{
	out[0] = static_cast<std::uint8_t>(value >> 56U);
	out[1] = static_cast<std::uint8_t>(value >> 48U);
	out[2] = static_cast<std::uint8_t>(value >> 40U);
	out[3] = static_cast<std::uint8_t>(value >> 32U);
	out[4] = static_cast<std::uint8_t>(value >> 24U);
	out[5] = static_cast<std::uint8_t>(value >> 16U);
	out[6] = static_cast<std::uint8_t>(value >> 8U);
	out[7] = static_cast<std::uint8_t>(value);
}

void ghash_update(Block &y, const Block &h, std::span<const std::uint8_t> input) noexcept
{
	while (!input.empty())
	{
		Block block{};
		const auto take = std::min<std::size_t>(block.size(), input.size());
		std::copy(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(take), block.begin());
		xor_block(y, block);
		y = gf_multiply(y, h);
		input = input.subspan(take);
	}
}

Block ghash(const Block &h, std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext) noexcept
{
	Block y{};
	ghash_update(y, h, aad);
	ghash_update(y, h, ciphertext);

	Block lengths{};
	store_be64(static_cast<std::uint64_t>(aad.size()) * 8ULL, lengths.data());
	store_be64(static_cast<std::uint64_t>(ciphertext.size()) * 8ULL, lengths.data() + 8U);
	xor_block(y, lengths);
	return gf_multiply(y, h);
}

void inc32(Block &counter) noexcept
{
	for (std::size_t i = 16; i > 12; --i)
	{
		++counter[i - 1U];
		if (counter[i - 1U] != 0)
		{
			break;
		}
	}
}

Result<Block> encrypt_block(const AesBlockCipher &cipher, const Block &block) noexcept
{
	auto encrypted = cipher.encrypt_block(block);
	if (!encrypted)
	{
		return Result<Block>::failure(encrypted.error());
	}

	Block output{};
	std::copy(encrypted.value().bytes().begin(), encrypted.value().bytes().end(), output.begin());
	return Result<Block>::success(output);
}

Result<std::vector<std::uint8_t>> gctr(const AesBlockCipher &cipher, Block counter, std::span<const std::uint8_t> input) noexcept
{
	std::vector<std::uint8_t> output;
	output.reserve(input.size());

	while (!input.empty())
	{
		auto encrypted_counter = encrypt_block(cipher, counter);
		if (!encrypted_counter)
		{
			return Result<std::vector<std::uint8_t>>::failure(encrypted_counter.error());
		}

		const auto take = std::min<std::size_t>(AesBlockCipher::block_size, input.size());
		for (std::size_t i = 0; i < take; ++i)
		{
			output.push_back(static_cast<std::uint8_t>(input[i] ^ encrypted_counter.value()[i]));
		}
		input = input.subspan(take);
		inc32(counter);
	}

	return Result<std::vector<std::uint8_t>>::success(std::move(output));
}

Result<Block> make_hash_subkey(const AesBlockCipher &cipher) noexcept
{
	Block zero{};
	return encrypt_block(cipher, zero);
}

Result<Block> make_j0(const Block &h, std::span<const std::uint8_t> nonce) noexcept
{
	if (nonce.size() == 12)
	{
		Block j0{};
		std::copy(nonce.begin(), nonce.end(), j0.begin());
		j0[15] = 1;
		return Result<Block>::success(j0);
	}

	return Result<Block>::success(ghash(h, {}, nonce));
}

Result<Block> compute_tag_block(const AesBlockCipher &cipher, const Block &h, const Block &j0, std::span<const std::uint8_t> aad, std::span<const std::uint8_t> ciphertext) noexcept
{
	auto s = ghash(h, aad, ciphertext);
	auto encrypted_j0 = encrypt_block(cipher, j0);
	if (!encrypted_j0)
	{
		return Result<Block>::failure(encrypted_j0.error());
	}

	xor_block(s, encrypted_j0.value());
	return Result<Block>::success(s);
}

} // namespace

Result<AeadEncryptResult> aes_gcm_encrypt(const AeadEncryptParams &params, std::span<const std::uint8_t> plaintext) noexcept
{
	auto validation = validate_encrypt_params(params);
	if (!validation)
	{
		return Result<AeadEncryptResult>::failure(validation.error());
	}

	auto cipher = AesBlockCipher::create(params.key);
	if (!cipher)
	{
		return Result<AeadEncryptResult>::failure(cipher.error());
	}

	auto h = make_hash_subkey(cipher.value());
	if (!h)
	{
		return Result<AeadEncryptResult>::failure(h.error());
	}
	auto j0 = make_j0(h.value(), params.nonce);
	if (!j0)
	{
		return Result<AeadEncryptResult>::failure(j0.error());
	}

	auto counter = j0.value();
	inc32(counter);
	auto ciphertext = gctr(cipher.value(), counter, plaintext);
	if (!ciphertext)
	{
		return Result<AeadEncryptResult>::failure(ciphertext.error());
	}

	auto tag_block = compute_tag_block(cipher.value(), h.value(), j0.value(), params.aad, ciphertext.value());
	if (!tag_block)
	{
		return Result<AeadEncryptResult>::failure(tag_block.error());
	}

	std::vector<std::uint8_t> tag(tag_block.value().begin(), tag_block.value().begin() + static_cast<std::ptrdiff_t>(params.tag_size));
	return Result<AeadEncryptResult>::success(AeadEncryptResult{ByteBuffer(std::move(ciphertext.value())), ByteBuffer(std::move(tag))});
}

Result<ByteBuffer> aes_gcm_decrypt(const AeadDecryptParams &params, std::span<const std::uint8_t> ciphertext) noexcept
{
	auto validation = validate_decrypt_params(params);
	if (!validation)
	{
		return Result<ByteBuffer>::failure(validation.error());
	}

	auto cipher = AesBlockCipher::create(params.key);
	if (!cipher)
	{
		return Result<ByteBuffer>::failure(cipher.error());
	}

	auto h = make_hash_subkey(cipher.value());
	if (!h)
	{
		return Result<ByteBuffer>::failure(h.error());
	}
	auto j0 = make_j0(h.value(), params.nonce);
	if (!j0)
	{
		return Result<ByteBuffer>::failure(j0.error());
	}

	auto tag_block = compute_tag_block(cipher.value(), h.value(), j0.value(), params.aad, ciphertext);
	if (!tag_block)
	{
		return Result<ByteBuffer>::failure(tag_block.error());
	}

	const auto expected_tag = std::span<const std::uint8_t>(tag_block.value().data(), params.tag.size());
	if (!constant_time_equal(expected_tag, params.tag))
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::authentication_failed, "aes_gcm", "AES-GCM authentication failed"));
	}

	auto counter = j0.value();
	inc32(counter);
	auto plaintext = gctr(cipher.value(), counter, ciphertext);
	if (!plaintext)
	{
		return Result<ByteBuffer>::failure(plaintext.error());
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(plaintext.value())));
}

} // namespace crypto_core::internal
