#include "crypto_core/internal/ec_der.hpp"

#include "crypto_core/error.hpp"
#include "crypto_core/internal/p256_fixed.hpp"

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
constexpr std::uint8_t der_octet_string = 0x04;
constexpr std::uint8_t der_oid = 0x06;
constexpr std::uint8_t der_context_0 = 0xA0;
constexpr std::uint8_t der_context_1 = 0xA1;

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

	[[nodiscard]] std::uint8_t next_tag() const noexcept
	{
		if (offset_ >= data_.size())
		{
			return 0;
		}
		return data_[offset_];
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

[[nodiscard]] Result<ByteBuffer> read_octet_string(DerReader &reader)
{
	auto value = reader.read(der_octet_string);
	if (!value)
	{
		return Result<ByteBuffer>::failure(value.error());
	}

	return Result<ByteBuffer>::success(ByteBuffer::copy_from(value.value().content));
}

[[nodiscard]] Result<void> read_optional_p256_parameters(DerReader &reader)
{
	if (reader.next_tag() != der_context_0)
	{
		return Result<void>::success();
	}

	auto parameters = reader.read(der_context_0);
	if (!parameters)
	{
		return Result<void>::failure(parameters.error());
	}

	DerReader explicit_parameters(parameters.value().content);
	auto curve_oid = explicit_parameters.read(der_oid);
	if (!curve_oid)
	{
		return Result<void>::failure(curve_oid.error());
	}
	if (!bytes_equal(curve_oid.value().content, prime256v1_oid))
	{
		return Result<void>::failure(der_error("EC private key curve is not prime256v1"));
	}
	if (!explicit_parameters.empty())
	{
		return Result<void>::failure(der_error("trailing data in EC private key parameters"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<P256Point> read_uncompressed_p256_point(std::span<const std::uint8_t> point)
{
	if (point.size() != 66 || point[0] != 0 || point[1] != 0x04)
	{
		return Result<P256Point>::failure(der_error("invalid P-256 public key point"));
	}

	return p256_fixed_point_from_coordinates(point.subspan(2, 32), point.subspan(34, 32));
}

[[nodiscard]] Result<void> read_optional_p256_public_key(DerReader &reader)
{
	if (reader.next_tag() != der_context_1)
	{
		return Result<void>::success();
	}

	auto public_key = reader.read(der_context_1);
	if (!public_key)
	{
		return Result<void>::failure(public_key.error());
	}

	DerReader explicit_public_key(public_key.value().content);
	auto bit_string = explicit_public_key.read(der_bit_string);
	if (!bit_string)
	{
		return Result<void>::failure(bit_string.error());
	}
	auto point = read_uncompressed_p256_point(bit_string.value().content);
	if (!point)
	{
		return Result<void>::failure(point.error());
	}
	if (!explicit_public_key.empty())
	{
		return Result<void>::failure(der_error("trailing data in EC private key public key"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<EcPrivateKeyMaterial> parse_sec1_p256_private_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<EcPrivateKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("trailing data after EC private key"));
	}

	DerReader private_key(sequence.value().content);
	auto version = read_integer(private_key);
	if (!version)
	{
		return Result<EcPrivateKeyMaterial>::failure(version.error());
	}
	const std::array<std::uint8_t, 1> expected_version{0x01};
	if (!bytes_equal(version.value().bytes(), expected_version))
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("unsupported EC private key version"));
	}

	auto scalar = read_octet_string(private_key);
	if (!scalar)
	{
		return Result<EcPrivateKeyMaterial>::failure(scalar.error());
	}
	if (scalar.value().size() != 32)
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("invalid P-256 private scalar size"));
	}
	auto scalar_valid = p256_fixed_scalar_is_valid_nonzero(scalar.value().bytes());
	if (!scalar_valid)
	{
		return Result<EcPrivateKeyMaterial>::failure(scalar_valid.error());
	}
	if (!scalar_valid.value())
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("invalid P-256 private scalar"));
	}

	auto parameters = read_optional_p256_parameters(private_key);
	if (!parameters)
	{
		return Result<EcPrivateKeyMaterial>::failure(parameters.error());
	}

	auto public_key = read_optional_p256_public_key(private_key);
	if (!public_key)
	{
		return Result<EcPrivateKeyMaterial>::failure(public_key.error());
	}
	if (!private_key.empty())
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("trailing data in EC private key"));
	}

	return Result<EcPrivateKeyMaterial>::success(EcPrivateKeyMaterial{std::move(scalar.value())});
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
	auto point = read_uncompressed_p256_point(bit_string.value().content);
	if (!point)
	{
		return Result<EcPublicKeyMaterial>::failure(point.error());
	}
	if (!spki.empty())
	{
		return Result<EcPublicKeyMaterial>::failure(der_error("trailing data in SubjectPublicKeyInfo"));
	}

	return Result<EcPublicKeyMaterial>::success(EcPublicKeyMaterial{
	    std::move(point.value().x),
	    std::move(point.value().y)});
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

[[nodiscard]] Result<EcPrivateKeyMaterial> parse_pkcs8_p256_private_key(std::span<const std::uint8_t> der);

[[nodiscard]] Result<EcPrivateKeyMaterial> parse_p256_private_key_der_impl(std::span<const std::uint8_t> der)
{
	auto sec1 = parse_sec1_p256_private_key(der);
	if (sec1)
	{
		return sec1;
	}

	return parse_pkcs8_p256_private_key(der);
}

[[nodiscard]] Result<EcPrivateKeyMaterial> parse_pkcs8_p256_private_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<EcPrivateKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("trailing data after PrivateKeyInfo"));
	}

	DerReader pkcs8(sequence.value().content);
	auto version = read_integer(pkcs8);
	if (!version)
	{
		return Result<EcPrivateKeyMaterial>::failure(version.error());
	}
	const std::array<std::uint8_t, 1> expected_version{0x00};
	if (!bytes_equal(version.value().bytes(), expected_version))
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("unsupported PrivateKeyInfo version"));
	}

	auto algorithm = read_p256_algorithm_identifier(pkcs8);
	if (!algorithm)
	{
		return Result<EcPrivateKeyMaterial>::failure(algorithm.error());
	}

	auto private_key = read_octet_string(pkcs8);
	if (!private_key)
	{
		return Result<EcPrivateKeyMaterial>::failure(private_key.error());
	}
	if (!pkcs8.empty())
	{
		return Result<EcPrivateKeyMaterial>::failure(der_error("trailing data in PrivateKeyInfo"));
	}

	return parse_sec1_p256_private_key(private_key.value().bytes());
}

void write_der_length(std::vector<std::uint8_t> &output, std::size_t length)
{
	if (length < 128)
	{
		output.push_back(static_cast<std::uint8_t>(length));
		return;
	}

	std::array<std::uint8_t, sizeof(std::size_t)> encoded{};
	std::size_t count = 0;
	while (length != 0)
	{
		encoded[encoded.size() - 1U - count] = static_cast<std::uint8_t>(length);
		length >>= 8U;
		++count;
	}

	output.push_back(static_cast<std::uint8_t>(0x80U | count));
	output.insert(output.end(), encoded.end() - static_cast<std::ptrdiff_t>(count), encoded.end());
}

void write_der_tlv(std::vector<std::uint8_t> &output, std::uint8_t tag, std::span<const std::uint8_t> content)
{
	output.push_back(tag);
	write_der_length(output, content.size());
	output.insert(output.end(), content.begin(), content.end());
}

[[nodiscard]] std::vector<std::uint8_t> encoded_integer_content(std::span<const std::uint8_t> value)
{
	while (!value.empty() && value.front() == 0)
	{
		value = value.subspan(1);
	}
	if (value.empty())
	{
		return std::vector<std::uint8_t>{0};
	}

	std::vector<std::uint8_t> output;
	if ((value.front() & 0x80U) != 0U)
	{
		output.push_back(0);
	}
	output.insert(output.end(), value.begin(), value.end());
	return output;
}

[[nodiscard]] Result<ByteBuffer> encode_ecdsa_signature_der_impl(std::span<const std::uint8_t> r, std::span<const std::uint8_t> s)
{
	auto r_content = encoded_integer_content(r);
	auto s_content = encoded_integer_content(s);

	std::vector<std::uint8_t> body;
	write_der_tlv(body, der_integer, r_content);
	write_der_tlv(body, der_integer, s_content);

	std::vector<std::uint8_t> output;
	write_der_tlv(output, der_sequence, body);
	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

} // namespace

Result<EcPublicKeyMaterial> parse_p256_public_key_der(std::span<const std::uint8_t> der)
{
	return parse_p256_public_key_der_impl(der);
}

Result<EcPrivateKeyMaterial> parse_p256_private_key_der(std::span<const std::uint8_t> der)
{
	return parse_p256_private_key_der_impl(der);
}

Result<EcPrivateKeyMaterial> parse_p256_pkcs8_private_key_der(std::span<const std::uint8_t> der)
{
	return parse_pkcs8_p256_private_key(der);
}

Result<EcPrivateKeyMaterial> parse_p256_sec1_private_key_der(std::span<const std::uint8_t> der)
{
	return parse_sec1_p256_private_key(der);
}

Result<EcdsaSignatureMaterial> parse_ecdsa_signature_der(std::span<const std::uint8_t> der)
{
	return parse_ecdsa_signature_der_impl(der);
}

Result<ByteBuffer> encode_ecdsa_signature_der(std::span<const std::uint8_t> r, std::span<const std::uint8_t> s)
{
	return encode_ecdsa_signature_der_impl(r, s);
}

} // namespace crypto_core::internal
