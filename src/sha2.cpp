#include "crypto_core/internal/sha2.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace crypto_core::internal
{
namespace
{

constexpr std::uint32_t rotr32(std::uint32_t value, unsigned bits) noexcept
{
	return (value >> bits) | (value << (32U - bits));
}

constexpr std::uint64_t rotr64(std::uint64_t value, unsigned bits) noexcept
{
	return (value >> bits) | (value << (64U - bits));
}

constexpr std::uint32_t load_be32(const std::uint8_t *data) noexcept
{
	return (static_cast<std::uint32_t>(data[0]) << 24U) |
	       (static_cast<std::uint32_t>(data[1]) << 16U) |
	       (static_cast<std::uint32_t>(data[2]) << 8U) |
	       static_cast<std::uint32_t>(data[3]);
}

constexpr std::uint64_t load_be64(const std::uint8_t *data) noexcept
{
	return (static_cast<std::uint64_t>(data[0]) << 56U) |
	       (static_cast<std::uint64_t>(data[1]) << 48U) |
	       (static_cast<std::uint64_t>(data[2]) << 40U) |
	       (static_cast<std::uint64_t>(data[3]) << 32U) |
	       (static_cast<std::uint64_t>(data[4]) << 24U) |
	       (static_cast<std::uint64_t>(data[5]) << 16U) |
	       (static_cast<std::uint64_t>(data[6]) << 8U) |
	       static_cast<std::uint64_t>(data[7]);
}

void store_be32(std::uint32_t value, std::uint8_t *out) noexcept
{
	out[0] = static_cast<std::uint8_t>(value >> 24U);
	out[1] = static_cast<std::uint8_t>(value >> 16U);
	out[2] = static_cast<std::uint8_t>(value >> 8U);
	out[3] = static_cast<std::uint8_t>(value);
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

constexpr std::array<std::uint32_t, 64> sha256_k{
    0x428a2f98U,
    0x71374491U,
    0xb5c0fbcfU,
    0xe9b5dba5U,
    0x3956c25bU,
    0x59f111f1U,
    0x923f82a4U,
    0xab1c5ed5U,
    0xd807aa98U,
    0x12835b01U,
    0x243185beU,
    0x550c7dc3U,
    0x72be5d74U,
    0x80deb1feU,
    0x9bdc06a7U,
    0xc19bf174U,
    0xe49b69c1U,
    0xefbe4786U,
    0x0fc19dc6U,
    0x240ca1ccU,
    0x2de92c6fU,
    0x4a7484aaU,
    0x5cb0a9dcU,
    0x76f988daU,
    0x983e5152U,
    0xa831c66dU,
    0xb00327c8U,
    0xbf597fc7U,
    0xc6e00bf3U,
    0xd5a79147U,
    0x06ca6351U,
    0x14292967U,
    0x27b70a85U,
    0x2e1b2138U,
    0x4d2c6dfcU,
    0x53380d13U,
    0x650a7354U,
    0x766a0abbU,
    0x81c2c92eU,
    0x92722c85U,
    0xa2bfe8a1U,
    0xa81a664bU,
    0xc24b8b70U,
    0xc76c51a3U,
    0xd192e819U,
    0xd6990624U,
    0xf40e3585U,
    0x106aa070U,
    0x19a4c116U,
    0x1e376c08U,
    0x2748774cU,
    0x34b0bcb5U,
    0x391c0cb3U,
    0x4ed8aa4aU,
    0x5b9cca4fU,
    0x682e6ff3U,
    0x748f82eeU,
    0x78a5636fU,
    0x84c87814U,
    0x8cc70208U,
    0x90befffaU,
    0xa4506cebU,
    0xbef9a3f7U,
    0xc67178f2U,
};

constexpr std::array<std::uint64_t, 80> sha512_k{
    0x428a2f98d728ae22ULL,
    0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL,
    0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL,
    0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,
    0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,
    0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL,
    0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL,
    0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,
    0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL,
    0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,
    0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,
    0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL,
    0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL,
    0xf40e35855771202aULL,
    0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,
    0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,
    0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL,
    0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,
    0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL,
    0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL,
    0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL,
    0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,
    0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,
    0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL,
    0x6c44198c4a475817ULL,
};

} // namespace

Sha256Context::Sha256Context() noexcept
    : state_{0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU, 0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U}
{
}

Result<void> Sha256Context::update(std::span<const std::uint8_t> input) noexcept
{
	if (finalized_)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "sha256", "cannot update finalized hash context"));
	}

	bit_count_ += static_cast<std::uint64_t>(input.size()) * 8U;

	while (!input.empty())
	{
		const auto space = buffer_.size() - buffer_size_;
		const auto take = std::min(space, input.size());
		std::memcpy(buffer_.data() + buffer_size_, input.data(), take);
		buffer_size_ += take;
		input = input.subspan(take);

		if (buffer_size_ == buffer_.size())
		{
			transform(buffer_.data());
			buffer_size_ = 0;
		}
	}

	return Result<void>::success();
}

Result<ByteBuffer> Sha256Context::final() noexcept
{
	if (finalized_)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "sha256", "hash context is already finalized"));
	}

	finalized_ = true;

	buffer_[buffer_size_++] = 0x80U;
	if (buffer_size_ > 56)
	{
		std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.end(), std::uint8_t{0});
		transform(buffer_.data());
		buffer_size_ = 0;
	}

	std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.begin() + 56, std::uint8_t{0});
	store_be64(bit_count_, buffer_.data() + 56);
	transform(buffer_.data());

	std::vector<std::uint8_t> digest(32);
	for (std::size_t i = 0; i < state_.size(); ++i)
	{
		store_be32(state_[i], digest.data() + (i * 4));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
}

void Sha256Context::transform(const std::uint8_t block[64]) noexcept
{
	std::array<std::uint32_t, 64> w{};
	for (std::size_t i = 0; i < 16; ++i)
	{
		w[i] = load_be32(block + (i * 4));
	}
	for (std::size_t i = 16; i < 64; ++i)
	{
		const auto s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3U);
		const auto s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10U);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	auto a = state_[0];
	auto b = state_[1];
	auto c = state_[2];
	auto d = state_[3];
	auto e = state_[4];
	auto f = state_[5];
	auto g = state_[6];
	auto h = state_[7];

	for (std::size_t i = 0; i < 64; ++i)
	{
		const auto s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		const auto ch = (e & f) ^ (~e & g);
		const auto temp1 = h + s1 + ch + sha256_k[i] + w[i];
		const auto s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		const auto maj = (a & b) ^ (a & c) ^ (b & c);
		const auto temp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state_[0] += a;
	state_[1] += b;
	state_[2] += c;
	state_[3] += d;
	state_[4] += e;
	state_[5] += f;
	state_[6] += g;
	state_[7] += h;
}

Sha512Context::Sha512Context() noexcept
    : state_{0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
          0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL}
{
}

Result<void> Sha512Context::update(std::span<const std::uint8_t> input) noexcept
{
	if (finalized_)
	{
		return Result<void>::failure(make_error(ErrorCode::invalid_argument, "sha512", "cannot update finalized hash context"));
	}

	const auto added_bits = static_cast<std::uint64_t>(input.size()) * 8ULL;
	bit_count_low_ += added_bits;
	if (bit_count_low_ < added_bits)
	{
		++bit_count_high_;
	}
	bit_count_high_ += static_cast<std::uint64_t>(input.size() >> 61U);

	while (!input.empty())
	{
		const auto space = buffer_.size() - buffer_size_;
		const auto take = std::min(space, input.size());
		std::memcpy(buffer_.data() + buffer_size_, input.data(), take);
		buffer_size_ += take;
		input = input.subspan(take);

		if (buffer_size_ == buffer_.size())
		{
			transform(buffer_.data());
			buffer_size_ = 0;
		}
	}

	return Result<void>::success();
}

Result<ByteBuffer> Sha512Context::final() noexcept
{
	if (finalized_)
	{
		return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "sha512", "hash context is already finalized"));
	}

	finalized_ = true;

	buffer_[buffer_size_++] = 0x80U;
	if (buffer_size_ > 112)
	{
		std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.end(), std::uint8_t{0});
		transform(buffer_.data());
		buffer_size_ = 0;
	}

	std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_size_), buffer_.begin() + 112, std::uint8_t{0});
	store_be64(bit_count_high_, buffer_.data() + 112);
	store_be64(bit_count_low_, buffer_.data() + 120);
	transform(buffer_.data());

	std::vector<std::uint8_t> digest(64);
	for (std::size_t i = 0; i < state_.size(); ++i)
	{
		store_be64(state_[i], digest.data() + (i * 8));
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(digest)));
}

void Sha512Context::transform(const std::uint8_t block[128]) noexcept
{
	std::array<std::uint64_t, 80> w{};
	for (std::size_t i = 0; i < 16; ++i)
	{
		w[i] = load_be64(block + (i * 8));
	}
	for (std::size_t i = 16; i < 80; ++i)
	{
		const auto s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7U);
		const auto s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6U);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	auto a = state_[0];
	auto b = state_[1];
	auto c = state_[2];
	auto d = state_[3];
	auto e = state_[4];
	auto f = state_[5];
	auto g = state_[6];
	auto h = state_[7];

	for (std::size_t i = 0; i < 80; ++i)
	{
		const auto s1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
		const auto ch = (e & f) ^ (~e & g);
		const auto temp1 = h + s1 + ch + sha512_k[i] + w[i];
		const auto s0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
		const auto maj = (a & b) ^ (a & c) ^ (b & c);
		const auto temp2 = s0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	state_[0] += a;
	state_[1] += b;
	state_[2] += c;
	state_[3] += d;
	state_[4] += e;
	state_[5] += f;
	state_[6] += g;
	state_[7] += h;
}

} // namespace crypto_core::internal
