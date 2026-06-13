#include "crypto_core/internal/aes_cbc.hpp"

#include "crypto_core/internal/aes.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace crypto_core::internal
{
namespace
{

constexpr std::size_t block_size = AesBlockCipher::block_size;

std::size_t expected_key_size(CipherAlgorithm algorithm) noexcept
{
	switch (algorithm)
	{
	case CipherAlgorithm::aes_128_cbc:
		return 16;
	case CipherAlgorithm::aes_192_cbc:
		return 24;
	case CipherAlgorithm::aes_256_cbc:
		return 32;
	}

	return 0;
}

ByteBuffer copy_to_buffer(const std::vector<std::uint8_t> &bytes)
{
	return ByteBuffer(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

class AesCbcContext final : public ICipherContext
{
public:
	AesCbcContext(AesBlockCipher cipher, std::array<std::uint8_t, block_size> iv, CipherDirection direction, CipherPadding padding) noexcept
	    : cipher_(std::move(cipher)), iv_(iv), direction_(direction), padding_(padding)
	{
	}

	[[nodiscard]] Result<ByteBuffer> update(std::span<const std::uint8_t> input) noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "cannot update finalized cipher context"));
		}

		buffer_.insert(buffer_.end(), input.begin(), input.end());
		return Result<ByteBuffer>::success(ByteBuffer(std::vector<std::uint8_t>{}));
	}

	[[nodiscard]] Result<ByteBuffer> final() noexcept override
	{
		if (finalized_)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "cipher context is already finalized"));
		}
		finalized_ = true;

		if (direction_ == CipherDirection::encrypt)
		{
			return encrypt_final();
		}
		return decrypt_final();
	}

private:
	[[nodiscard]] Result<ByteBuffer> encrypt_final() noexcept
	{
		auto input = buffer_;
		if (padding_ == CipherPadding::pkcs7)
		{
			const auto pad = block_size - (input.size() % block_size);
			input.insert(input.end(), pad, static_cast<std::uint8_t>(pad));
		}
		else if ((input.size() % block_size) != 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "AES-CBC no-padding input must be block aligned"));
		}

		std::vector<std::uint8_t> output;
		output.reserve(input.size());
		auto previous = iv_;
		for (std::size_t offset = 0; offset < input.size(); offset += block_size)
		{
			std::array<std::uint8_t, block_size> block{};
			for (std::size_t i = 0; i < block_size; ++i)
			{
				block[i] = static_cast<std::uint8_t>(input[offset + i] ^ previous[i]);
			}

			auto encrypted = cipher_.encrypt_block(block);
			if (!encrypted)
			{
				return Result<ByteBuffer>::failure(encrypted.error());
			}
			std::copy(encrypted.value().bytes().begin(), encrypted.value().bytes().end(), previous.begin());
			output.insert(output.end(), encrypted.value().bytes().begin(), encrypted.value().bytes().end());
		}

		return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
	}

	[[nodiscard]] Result<ByteBuffer> decrypt_final() noexcept
	{
		if (buffer_.empty() && padding_ == CipherPadding::pkcs7)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "AES-CBC PKCS#7 ciphertext must not be empty"));
		}
		if ((buffer_.size() % block_size) != 0)
		{
			return Result<ByteBuffer>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "AES-CBC ciphertext must be block aligned"));
		}

		std::vector<std::uint8_t> output;
		output.reserve(buffer_.size());
		auto previous = iv_;
		for (std::size_t offset = 0; offset < buffer_.size(); offset += block_size)
		{
			auto decrypted = cipher_.decrypt_block(std::span<const std::uint8_t>(buffer_.data() + offset, block_size));
			if (!decrypted)
			{
				return Result<ByteBuffer>::failure(decrypted.error());
			}

			for (std::size_t i = 0; i < block_size; ++i)
			{
				output.push_back(static_cast<std::uint8_t>(decrypted.value().bytes()[i] ^ previous[i]));
				previous[i] = buffer_[offset + i];
			}
		}

		if (padding_ == CipherPadding::pkcs7)
		{
			auto unpad_result = remove_pkcs7_padding(output);
			if (!unpad_result)
			{
				return Result<ByteBuffer>::failure(unpad_result.error());
			}
		}

		return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
	}

	[[nodiscard]] static Result<void> remove_pkcs7_padding(std::vector<std::uint8_t> &output) noexcept
	{
		if (output.empty())
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "PKCS#7 plaintext is empty"));
		}

		const auto pad = output.back();
		if (pad == 0 || pad > block_size || pad > output.size())
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "invalid PKCS#7 padding"));
		}

		const auto start = output.size() - pad;
		for (std::size_t i = start; i < output.size(); ++i)
		{
			if (output[i] != pad)
			{
				return Result<void>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "invalid PKCS#7 padding"));
			}
		}

		output.resize(start);
		return Result<void>::success();
	}

	AesBlockCipher cipher_;
	std::array<std::uint8_t, block_size> iv_{};
	CipherDirection direction_;
	CipherPadding padding_;
	std::vector<std::uint8_t> buffer_;
	bool finalized_{false};
};

} // namespace

Result<std::unique_ptr<ICipherContext>> create_aes_cbc_context(const CipherParams &params) noexcept
{
	const auto key_size = expected_key_size(params.algorithm);
	if (key_size == 0)
	{
		return Result<std::unique_ptr<ICipherContext>>::failure(make_error(ErrorCode::unsupported_algorithm, "aes_cbc", "cipher algorithm is not supported"));
	}
	if (params.key.size() != key_size)
	{
		return Result<std::unique_ptr<ICipherContext>>::failure(make_error(ErrorCode::invalid_key, "aes_cbc", "AES-CBC key size does not match algorithm"));
	}
	if (params.iv.size() != block_size)
	{
		return Result<std::unique_ptr<ICipherContext>>::failure(make_error(ErrorCode::invalid_argument, "aes_cbc", "AES-CBC IV must be exactly 16 bytes"));
	}

	auto cipher = AesBlockCipher::create(params.key);
	if (!cipher)
	{
		return Result<std::unique_ptr<ICipherContext>>::failure(cipher.error());
	}

	std::array<std::uint8_t, block_size> iv{};
	std::copy(params.iv.begin(), params.iv.end(), iv.begin());

	std::unique_ptr<ICipherContext> context = std::make_unique<AesCbcContext>(std::move(cipher).value(), iv, params.direction, params.padding);
	return Result<std::unique_ptr<ICipherContext>>::success(std::move(context));
}

} // namespace crypto_core::internal
