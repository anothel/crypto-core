#include "crypto_core/internal/ec_der.hpp"

#include "crypto_core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <string_view>
#include <utility>

namespace crypto_core::internal
{
namespace
{

constexpr std::uint8_t der_sequence = 0x30;
constexpr std::uint8_t der_integer = 0x02;
constexpr std::uint8_t der_bit_string = 0x03;
constexpr std::uint8_t der_oid = 0x06;

constexpr std::array<std::uint8_t, 7> id_ec_public_key_oid{
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
constexpr std::array<std::uint8_t, 8> prime256v1_oid{
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

[[nodiscard]] Error der_error(std::string_view message) noexcept
{
	return make_error(ErrorCode::invalid_key, "ec_der", message);
}

struct DerValue final
{
	std::span<const std::uint8_t> content;
};

class DerReader final
{
public:
	explicit DerReader(std::span<const std::uint8_t> data) noexcept
	    : data_(data)
	{
	}

	[[nodiscard]] bool empty() const noexcept
	{
		return offset_ == data_.size();
	}

	[[nodiscard]] Result<DerValue> read(std::uint8_t expected_tag) noexcept
	{
		if (offset_ >= data_.size() || data_[offset_] != expected_tag)
		{
			return Result<DerValue>::failure(der_error("unexpected DER tag"));
		}
		++offset_;

		auto length = read_length();
		if (!length)
		{
			return Result<DerValue>::failure(length.error());
		}
		if (length.value() > data_.size() - offset_)
		{
			return Result<DerValue>::failure(der_error("DER length exceeds input"));
		}

		const auto content = data_.subspan(offset_, length.value());
		offset_ += length.value();
		return Result<DerValue>::success(DerValue{content});
	}

private:
	[[nodiscard]] Result<std::size_t> read_length() noexcept
	{
		if (offset_ >= data_.size())
		{
			return Result<std::size_t>::failure(der_error("missing DER length"));
		}

		const auto first = data_[offset_++];
		if ((first & 0x80U) == 0U)
		{
			return Result<std::size_t>::success(first);
		}

		const auto length_octets = static_cast<std::size_t>(first & 0x7FU);
		if (length_octets == 0 || length_octets > sizeof(std::size_t) || length_octets > data_.size() - offset_)
		{
			return Result<std::size_t>::failure(der_error("invalid DER long length"));
		}
		if (data_[offset_] == 0)
		{
			return Result<std::size_t>::failure(der_error("DER length is not minimally encoded"));
		}

		std::size_t length = 0;
		for (std::size_t i = 0; i < length_octets; ++i)
		{
			if (length > (std::numeric_limits<std::size_t>::max() >> 8U))
			{
				return Result<std::size_t>::failure(der_error("DER length is too large"));
			}
			length = (length << 8U) | data_[offset_++];
		}
		if (length < 128)
		{
			return Result<std::size_t>::failure(der_error("DER length uses overlong encoding"));
		}

		return Result<std::size_t>::success(length);
	}

	std::span<const std::uint8_t> data_;
	std::size_t offset_{0};
};

template <std::size_t Size>
[[nodiscard]] bool bytes_equal(std::span<const std::uint8_t> actual, const std::array<std::uint8_t, Size> &expected) noexcept
{
	return actual.size() == expected.size() && std::equal(actual.begin(), actual.end(), expected.begin());
}

[[nodiscard]] Result<void> read_p256_algorithm_identifier(DerReader &reader) noexcept
{
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<void>::failure(sequence.error());
	}

	DerReader algorithm(sequence.value().content);
	auto algorithm_oid = algorithm.read(der_oid);
	if (!algorithm_oid)
	{
		return Result<void>::failure(algorithm_oid.error());
	}
	if (!bytes_equal(algorithm_oid.value().content, id_ec_public_key_oid))
	{
		return Result<void>::failure(der_error("algorithm identifier is not id-ecPublicKey"));
	}

	auto curve_oid = algorithm.read(der_oid);
	if (!curve_oid)
	{
		return Result<void>::failure(curve_oid.error());
	}
	if (!bytes_equal(curve_oid.value().content, prime256v1_oid))
	{
		return Result<void>::failure(der_error("EC public key curve is not prime256v1"));
	}
	if (!algorithm.empty())
	{
		return Result<void>::failure(der_error("trailing data in EC algorithm identifier"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<ByteBuffer> read_integer(DerReader &reader)
{
	auto value = reader.read(der_integer);
	if (!value)
	{
		return Result<ByteBuffer>::failure(value.error());
	}

	auto content = value.value().content;
	if (content.empty())
	{
		return Result<ByteBuffer>::failure(der_error("DER integer is empty"));
	}
	if ((content[0] & 0x80U) != 0U)
	{
		return Result<ByteBuffer>::failure(der_error("DER integer is negative"));
	}
	if (content.size() > 1 && content[0] == 0)
	{
		if ((content[1] & 0x80U) == 0U)
		{
			return Result<ByteBuffer>::failure(der_error("DER integer is not minimally encoded"));
		}
		content = content.subspan(1);
	}

	return Result<ByteBuffer>::success(ByteBuffer::copy_from(content));
}

[[nodiscard]] Result<EcPublicKeyMaterial> parse_p256_public_key_der_impl(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<EcPublicKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<EcPublicKeyMaterial>::failure(der_error("trailing data after SubjectPublicKeyInfo"));
	}

	DerReader spki(sequence.value().content);
	auto algorithm = read_p256_algorithm_identifier(spki);
	if (!algorithm)
	{
		return Result<EcPublicKeyMaterial>::failure(algorithm.error());
	}

	auto bit_string = spki.read(der_bit_string);
	if (!bit_string)
	{
		return Result<EcPublicKeyMaterial>::failure(bit_string.error());
	}
	const auto point = bit_string.value().content;
	if (point.size() != 66 || point[0] != 0 || point[1] != 0x04)
	{
		return Result<EcPublicKeyMaterial>::failure(der_error("invalid P-256 public key point"));
	}
	if (!spki.empty())
	{
		return Result<EcPublicKeyMaterial>::failure(der_error("trailing data in SubjectPublicKeyInfo"));
	}

	return Result<EcPublicKeyMaterial>::success(EcPublicKeyMaterial{
	    ByteBuffer::copy_from(point.subspan(2, 32)),
	    ByteBuffer::copy_from(point.subspan(34, 32))});
}

[[nodiscard]] Result<EcdsaSignatureMaterial> parse_ecdsa_signature_der_impl(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<EcdsaSignatureMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<EcdsaSignatureMaterial>::failure(der_error("trailing data after ECDSA signature"));
	}

	DerReader signature(sequence.value().content);
	auto r = read_integer(signature);
	if (!r)
	{
		return Result<EcdsaSignatureMaterial>::failure(r.error());
	}
	auto s = read_integer(signature);
	if (!s)
	{
		return Result<EcdsaSignatureMaterial>::failure(s.error());
	}
	if (!signature.empty())
	{
		return Result<EcdsaSignatureMaterial>::failure(der_error("trailing data in ECDSA signature"));
	}

	return Result<EcdsaSignatureMaterial>::success(EcdsaSignatureMaterial{std::move(r.value()), std::move(s.value())});
}

} // namespace

Result<EcPublicKeyMaterial> parse_p256_public_key_der(std::span<const std::uint8_t> der)
{
	return parse_p256_public_key_der_impl(der);
}

Result<EcdsaSignatureMaterial> parse_ecdsa_signature_der(std::span<const std::uint8_t> der)
{
	return parse_ecdsa_signature_der_impl(der);
}

} // namespace crypto_core::internal
