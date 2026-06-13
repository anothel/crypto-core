#include "crypto_core/internal/aes.hpp"

#include "crypto_core/memory.hpp"

#include <algorithm>
#include <vector>

namespace crypto_core::internal
{
namespace
{

constexpr std::array<std::uint8_t, 256> sbox{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr std::array<std::uint8_t, 256> inv_sbox{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

constexpr std::array<std::uint8_t, 10> rcon{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

constexpr std::uint32_t load_be32(const std::uint8_t *data) noexcept
{
	return (static_cast<std::uint32_t>(data[0]) << 24U) |
	       (static_cast<std::uint32_t>(data[1]) << 16U) |
	       (static_cast<std::uint32_t>(data[2]) << 8U) |
	       static_cast<std::uint32_t>(data[3]);
}

constexpr std::uint32_t rot_word(std::uint32_t word) noexcept
{
	return (word << 8U) | (word >> 24U);
}

constexpr std::uint32_t sub_word(std::uint32_t word) noexcept
{
	return (static_cast<std::uint32_t>(sbox[(word >> 24U) & 0xffU]) << 24U) |
	       (static_cast<std::uint32_t>(sbox[(word >> 16U) & 0xffU]) << 16U) |
	       (static_cast<std::uint32_t>(sbox[(word >> 8U) & 0xffU]) << 8U) |
	       static_cast<std::uint32_t>(sbox[word & 0xffU]);
}

constexpr std::uint8_t xtime(std::uint8_t value) noexcept
{
	return static_cast<std::uint8_t>((value << 1U) ^ ((value & 0x80U) ? 0x1bU : 0x00U));
}

std::uint8_t multiply(std::uint8_t lhs, std::uint8_t rhs) noexcept
{
	std::uint8_t result = 0;
	while (rhs != 0)
	{
		if ((rhs & 1U) != 0U)
		{
			result ^= lhs;
		}
		lhs = xtime(lhs);
		rhs >>= 1U;
	}
	return result;
}

void add_round_key(std::array<std::uint8_t, 16> &state, const std::array<std::uint32_t, 60> &round_keys, std::size_t round) noexcept
{
	for (std::size_t column = 0; column < 4; ++column)
	{
		const auto word = round_keys[(round * 4U) + column];
		state[(column * 4U) + 0U] ^= static_cast<std::uint8_t>(word >> 24U);
		state[(column * 4U) + 1U] ^= static_cast<std::uint8_t>(word >> 16U);
		state[(column * 4U) + 2U] ^= static_cast<std::uint8_t>(word >> 8U);
		state[(column * 4U) + 3U] ^= static_cast<std::uint8_t>(word);
	}
}

void sub_bytes(std::array<std::uint8_t, 16> &state) noexcept
{
	for (auto &byte : state)
	{
		byte = sbox[byte];
	}
}

void inv_sub_bytes(std::array<std::uint8_t, 16> &state) noexcept
{
	for (auto &byte : state)
	{
		byte = inv_sbox[byte];
	}
}

void shift_rows(std::array<std::uint8_t, 16> &state) noexcept
{
	auto copy = state;
	state[1] = copy[5];
	state[5] = copy[9];
	state[9] = copy[13];
	state[13] = copy[1];
	state[2] = copy[10];
	state[6] = copy[14];
	state[10] = copy[2];
	state[14] = copy[6];
	state[3] = copy[15];
	state[7] = copy[3];
	state[11] = copy[7];
	state[15] = copy[11];
}

void inv_shift_rows(std::array<std::uint8_t, 16> &state) noexcept
{
	auto copy = state;
	state[1] = copy[13];
	state[5] = copy[1];
	state[9] = copy[5];
	state[13] = copy[9];
	state[2] = copy[10];
	state[6] = copy[14];
	state[10] = copy[2];
	state[14] = copy[6];
	state[3] = copy[7];
	state[7] = copy[11];
	state[11] = copy[15];
	state[15] = copy[3];
}

void mix_columns(std::array<std::uint8_t, 16> &state) noexcept
{
	for (std::size_t column = 0; column < 4; ++column)
	{
		const auto i = column * 4U;
		const auto a0 = state[i + 0U];
		const auto a1 = state[i + 1U];
		const auto a2 = state[i + 2U];
		const auto a3 = state[i + 3U];
		state[i + 0U] = static_cast<std::uint8_t>(multiply(a0, 2) ^ multiply(a1, 3) ^ a2 ^ a3);
		state[i + 1U] = static_cast<std::uint8_t>(a0 ^ multiply(a1, 2) ^ multiply(a2, 3) ^ a3);
		state[i + 2U] = static_cast<std::uint8_t>(a0 ^ a1 ^ multiply(a2, 2) ^ multiply(a3, 3));
		state[i + 3U] = static_cast<std::uint8_t>(multiply(a0, 3) ^ a1 ^ a2 ^ multiply(a3, 2));
	}
}

void inv_mix_columns(std::array<std::uint8_t, 16> &state) noexcept
{
	for (std::size_t column = 0; column < 4; ++column)
	{
		const auto i = column * 4U;
		const auto a0 = state[i + 0U];
		const auto a1 = state[i + 1U];
		const auto a2 = state[i + 2U];
		const auto a3 = state[i + 3U];
		state[i + 0U] = static_cast<std::uint8_t>(multiply(a0, 14) ^ multiply(a1, 11) ^ multiply(a2, 13) ^ multiply(a3, 9));
		state[i + 1U] = static_cast<std::uint8_t>(multiply(a0, 9) ^ multiply(a1, 14) ^ multiply(a2, 11) ^ multiply(a3, 13));
		state[i + 2U] = static_cast<std::uint8_t>(multiply(a0, 13) ^ multiply(a1, 9) ^ multiply(a2, 14) ^ multiply(a3, 11));
		state[i + 3U] = static_cast<std::uint8_t>(multiply(a0, 11) ^ multiply(a1, 13) ^ multiply(a2, 9) ^ multiply(a3, 14));
	}
}

ByteBuffer state_to_buffer(const std::array<std::uint8_t, 16> &state)
{
	return ByteBuffer(std::vector<std::uint8_t>(state.begin(), state.end()));
}

} // namespace

AesBlockCipher::AesBlockCipher(AesBlockCipher &&other) noexcept
    : round_keys_(other.round_keys_), round_key_words_(other.round_key_words_), rounds_(other.rounds_)
{
	secure_zero_memory(other.round_keys_.data(), other.round_keys_.size() * sizeof(other.round_keys_[0]));
	other.round_key_words_ = 0;
	other.rounds_ = 0;
}

AesBlockCipher &AesBlockCipher::operator=(AesBlockCipher &&other) noexcept
{
	if (this != &other)
	{
		secure_zero_memory(round_keys_.data(), round_keys_.size() * sizeof(round_keys_[0]));
		round_keys_ = other.round_keys_;
		round_key_words_ = other.round_key_words_;
		rounds_ = other.rounds_;
		secure_zero_memory(other.round_keys_.data(), other.round_keys_.size() * sizeof(other.round_keys_[0]));
		other.round_key_words_ = 0;
		other.rounds_ = 0;
	}
	return *this;
}

AesBlockCipher::~AesBlockCipher() noexcept
{
	secure_zero_memory(round_keys_.data(), round_keys_.size() * sizeof(round_keys_[0]));
	round_key_words_ = 0;
	rounds_ = 0;
}

Result<AesBlockCipher> AesBlockCipher::create(std::span<const std::uint8_t> key) noexcept
{
	if (key.size() != 16U && key.size() != 24U && key.size() != 32U)
	{
		return Result<AesBlockCipher>::failure(make_error(ErrorCode::invalid_key, "aes", "AES key size must be exactly 16, 24, or 32 bytes"));
	}

	AesBlockCipher cipher;
	const auto key_words = key.size() / 4U;
	cipher.rounds_ = static_cast<std::uint8_t>(key_words + 6U);
	cipher.round_key_words_ = 4U * (static_cast<std::size_t>(cipher.rounds_) + 1U);

	for (std::size_t i = 0; i < key_words; ++i)
	{
		cipher.round_keys_[i] = load_be32(key.data() + (i * 4U));
	}

	for (std::size_t i = key_words; i < cipher.round_key_words_; ++i)
	{
		auto temp = cipher.round_keys_[i - 1U];
		if ((i % key_words) == 0U)
		{
			temp = sub_word(rot_word(temp)) ^ (static_cast<std::uint32_t>(rcon[(i / key_words) - 1U]) << 24U);
		}
		else if (key_words > 6U && (i % key_words) == 4U)
		{
			temp = sub_word(temp);
		}
		cipher.round_keys_[i] = cipher.round_keys_[i - key_words] ^ temp;
	}

	return Result<AesBlockCipher>::success(std::move(cipher));
}

Result<ByteBuffer> AesBlockCipher::encrypt_block(std::span<const std::uint8_t> plaintext) const noexcept
{
	if (plaintext.size() != block_size)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes", "AES block input must be exactly 16 bytes"));
	}

	std::array<std::uint8_t, 16> state{};
	std::copy(plaintext.begin(), plaintext.end(), state.begin());

	add_round_key(state, round_keys_, 0);
	for (std::size_t round = 1; round < rounds_; ++round)
	{
		sub_bytes(state);
		shift_rows(state);
		mix_columns(state);
		add_round_key(state, round_keys_, round);
	}
	sub_bytes(state);
	shift_rows(state);
	add_round_key(state, round_keys_, rounds_);

	return Result<ByteBuffer>::success(state_to_buffer(state));
}

Result<ByteBuffer> AesBlockCipher::decrypt_block(std::span<const std::uint8_t> ciphertext) const noexcept
{
	if (ciphertext.size() != block_size)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes", "AES block input must be exactly 16 bytes"));
	}

	std::array<std::uint8_t, 16> state{};
	std::copy(ciphertext.begin(), ciphertext.end(), state.begin());

	add_round_key(state, round_keys_, rounds_);
	for (std::size_t round = rounds_ - 1U; round > 0U; --round)
	{
		inv_shift_rows(state);
		inv_sub_bytes(state);
		add_round_key(state, round_keys_, round);
		inv_mix_columns(state);
	}
	inv_shift_rows(state);
	inv_sub_bytes(state);
	add_round_key(state, round_keys_, 0);

	return Result<ByteBuffer>::success(state_to_buffer(state));
}

} // namespace crypto_core::internal
