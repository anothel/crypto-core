#include "crypto_core/internal/rsa_der.hpp"

#include "crypto_core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

namespace crypto_core::internal
{
namespace
{

constexpr std::uint8_t der_sequence = 0x30;
constexpr std::uint8_t der_integer = 0x02;
constexpr std::uint8_t der_bit_string = 0x03;
constexpr std::uint8_t der_octet_string = 0x04;
constexpr std::uint8_t der_null = 0x05;
constexpr std::uint8_t der_oid = 0x06;

constexpr std::array<std::uint8_t, 9> rsa_encryption_oid{
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01};

[[nodiscard]] Error der_error(std::string_view message) noexcept
{
	return make_error(ErrorCode::invalid_key, "rsa_der", message);
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

[[nodiscard]] Result<ByteBuffer> read_positive_integer(DerReader &reader)
{
	auto value = reader.read(der_integer);
	if (!value)
	{
		return Result<ByteBuffer>::failure(value.error());
	}
	if (value.value().content.empty())
	{
		return Result<ByteBuffer>::failure(der_error("DER integer is empty"));
	}
	if ((value.value().content.front() & 0x80U) != 0U)
	{
		return Result<ByteBuffer>::failure(der_error("DER integer is negative"));
	}
	if (value.value().content.size() > 1 && value.value().content[0] == 0 && (value.value().content[1] & 0x80U) == 0U)
	{
		return Result<ByteBuffer>::failure(der_error("DER integer is not minimally encoded"));
	}

	auto magnitude = value.value().content;
	if (magnitude.size() > 1 && magnitude[0] == 0)
	{
		magnitude = magnitude.subspan(1);
	}

	return Result<ByteBuffer>::success(ByteBuffer::copy_from(magnitude));
}

[[nodiscard]] bool is_zero(std::span<const std::uint8_t> bytes) noexcept
{
	return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) {
		return byte == 0;
	});
}

[[nodiscard]] bool is_one(std::span<const std::uint8_t> bytes) noexcept
{
	return bytes.size() == 1 && bytes.front() == 1;
}

[[nodiscard]] bool is_odd(std::span<const std::uint8_t> bytes) noexcept
{
	return !bytes.empty() && (bytes.back() & 1U) != 0U;
}

[[nodiscard]] Result<ByteBuffer> read_non_zero_integer(DerReader &reader, std::string_view name)
{
	auto value = read_positive_integer(reader);
	if (!value)
	{
		return value;
	}
	if (is_zero(value.value().bytes()))
	{
		return Result<ByteBuffer>::failure(der_error(name));
	}

	return value;
}

[[nodiscard]] Result<ByteBuffer> read_odd_greater_than_one_integer(DerReader &reader, std::string_view name)
{
	auto value = read_non_zero_integer(reader, name);
	if (!value)
	{
		return value;
	}
	if (is_one(value.value().bytes()) || !is_odd(value.value().bytes()))
	{
		return Result<ByteBuffer>::failure(der_error(name));
	}

	return value;
}

[[nodiscard]] Result<void> read_version_zero(DerReader &reader)
{
	auto value = reader.read(der_integer);
	if (!value)
	{
		return Result<void>::failure(value.error());
	}
	if (value.value().content.size() != 1 || value.value().content[0] != 0)
	{
		return Result<void>::failure(der_error("unsupported RSA key version"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<void> read_rsa_algorithm_identifier(DerReader &reader)
{
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<void>::failure(sequence.error());
	}

	DerReader algorithm(sequence.value().content);
	auto oid = algorithm.read(der_oid);
	if (!oid)
	{
		return Result<void>::failure(oid.error());
	}
	if (!std::equal(oid.value().content.begin(), oid.value().content.end(), rsa_encryption_oid.begin(), rsa_encryption_oid.end()))
	{
		return Result<void>::failure(der_error("algorithm identifier is not rsaEncryption"));
	}

	auto null_value = algorithm.read(der_null);
	if (!null_value)
	{
		return Result<void>::failure(null_value.error());
	}
	if (!null_value.value().content.empty() || !algorithm.empty())
	{
		return Result<void>::failure(der_error("invalid rsaEncryption parameters"));
	}

	return Result<void>::success();
}

[[nodiscard]] Result<RsaPublicKeyMaterial> parse_pkcs1_public_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<RsaPublicKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<RsaPublicKeyMaterial>::failure(der_error("trailing data after RSA public key"));
	}

	DerReader key(sequence.value().content);
	auto modulus = read_odd_greater_than_one_integer(key, "RSA modulus must be odd and greater than one");
	auto public_exponent = read_odd_greater_than_one_integer(key, "RSA public exponent must be odd and greater than one");
	if (!modulus)
	{
		return Result<RsaPublicKeyMaterial>::failure(modulus.error());
	}
	if (!public_exponent)
	{
		return Result<RsaPublicKeyMaterial>::failure(public_exponent.error());
	}
	if (!key.empty())
	{
		return Result<RsaPublicKeyMaterial>::failure(der_error("trailing data in RSA public key"));
	}

	return Result<RsaPublicKeyMaterial>::success(RsaPublicKeyMaterial{std::move(modulus.value()), std::move(public_exponent.value())});
}

[[nodiscard]] Result<RsaPublicKeyMaterial> parse_spki_public_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<RsaPublicKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<RsaPublicKeyMaterial>::failure(der_error("trailing data after SubjectPublicKeyInfo"));
	}

	DerReader spki(sequence.value().content);
	auto algorithm = read_rsa_algorithm_identifier(spki);
	if (!algorithm)
	{
		return Result<RsaPublicKeyMaterial>::failure(algorithm.error());
	}

	auto bit_string = spki.read(der_bit_string);
	if (!bit_string)
	{
		return Result<RsaPublicKeyMaterial>::failure(bit_string.error());
	}
	if (bit_string.value().content.empty() || bit_string.value().content[0] != 0)
	{
		return Result<RsaPublicKeyMaterial>::failure(der_error("invalid RSA public key bit string"));
	}
	if (!spki.empty())
	{
		return Result<RsaPublicKeyMaterial>::failure(der_error("trailing data in SubjectPublicKeyInfo"));
	}

	return parse_pkcs1_public_key(bit_string.value().content.subspan(1));
}

[[nodiscard]] Result<RsaPrivateKeyMaterial> parse_pkcs1_private_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<RsaPrivateKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<RsaPrivateKeyMaterial>::failure(der_error("trailing data after RSA private key"));
	}

	DerReader key(sequence.value().content);
	auto version = read_version_zero(key);
	if (!version)
	{
		return Result<RsaPrivateKeyMaterial>::failure(version.error());
	}

	auto modulus = read_odd_greater_than_one_integer(key, "RSA modulus must be odd and greater than one");
	auto public_exponent = read_odd_greater_than_one_integer(key, "RSA public exponent must be odd and greater than one");
	auto private_exponent = read_non_zero_integer(key, "RSA private exponent must be non-zero");
	auto prime1 = read_odd_greater_than_one_integer(key, "RSA prime1 must be odd and greater than one");
	auto prime2 = read_odd_greater_than_one_integer(key, "RSA prime2 must be odd and greater than one");
	auto exponent1 = read_non_zero_integer(key, "RSA exponent1 must be non-zero");
	auto exponent2 = read_non_zero_integer(key, "RSA exponent2 must be non-zero");
	auto coefficient = read_non_zero_integer(key, "RSA coefficient must be non-zero");
	if (!modulus)
	{
		return Result<RsaPrivateKeyMaterial>::failure(modulus.error());
	}
	if (!public_exponent)
	{
		return Result<RsaPrivateKeyMaterial>::failure(public_exponent.error());
	}
	if (!private_exponent)
	{
		return Result<RsaPrivateKeyMaterial>::failure(private_exponent.error());
	}
	if (!prime1)
	{
		return Result<RsaPrivateKeyMaterial>::failure(prime1.error());
	}
	if (!prime2)
	{
		return Result<RsaPrivateKeyMaterial>::failure(prime2.error());
	}
	if (!exponent1)
	{
		return Result<RsaPrivateKeyMaterial>::failure(exponent1.error());
	}
	if (!exponent2)
	{
		return Result<RsaPrivateKeyMaterial>::failure(exponent2.error());
	}
	if (!coefficient)
	{
		return Result<RsaPrivateKeyMaterial>::failure(coefficient.error());
	}
	if (!key.empty())
	{
		return Result<RsaPrivateKeyMaterial>::failure(der_error("trailing data in RSA private key"));
	}

	return Result<RsaPrivateKeyMaterial>::success(RsaPrivateKeyMaterial{
	    std::move(modulus.value()),
	    std::move(public_exponent.value()),
	    std::move(private_exponent.value()),
	    std::move(prime1.value()),
	    std::move(prime2.value()),
	    std::move(exponent1.value()),
	    std::move(exponent2.value()),
	    std::move(coefficient.value())});
}

[[nodiscard]] Result<RsaPrivateKeyMaterial> parse_pkcs8_private_key(std::span<const std::uint8_t> der)
{
	DerReader reader(der);
	auto sequence = reader.read(der_sequence);
	if (!sequence)
	{
		return Result<RsaPrivateKeyMaterial>::failure(sequence.error());
	}
	if (!reader.empty())
	{
		return Result<RsaPrivateKeyMaterial>::failure(der_error("trailing data after PrivateKeyInfo"));
	}

	DerReader private_key_info(sequence.value().content);
	auto version = read_version_zero(private_key_info);
	if (!version)
	{
		return Result<RsaPrivateKeyMaterial>::failure(version.error());
	}

	auto algorithm = read_rsa_algorithm_identifier(private_key_info);
	if (!algorithm)
	{
		return Result<RsaPrivateKeyMaterial>::failure(algorithm.error());
	}

	auto private_key = private_key_info.read(der_octet_string);
	if (!private_key)
	{
		return Result<RsaPrivateKeyMaterial>::failure(private_key.error());
	}
	if (!private_key_info.empty())
	{
		return Result<RsaPrivateKeyMaterial>::failure(der_error("trailing data in PrivateKeyInfo"));
	}

	return parse_pkcs1_private_key(private_key.value().content);
}

} // namespace

Result<RsaPublicKeyMaterial> parse_rsa_public_key_der(std::span<const std::uint8_t> der)
{
	auto pkcs1 = parse_pkcs1_public_key(der);
	if (pkcs1)
	{
		return pkcs1;
	}

	return parse_spki_public_key(der);
}

Result<RsaPublicKeyMaterial> parse_rsa_spki_public_key_der(std::span<const std::uint8_t> der)
{
	return parse_spki_public_key(der);
}

Result<RsaPublicKeyMaterial> parse_rsa_pkcs1_public_key_der(std::span<const std::uint8_t> der)
{
	return parse_pkcs1_public_key(der);
}

Result<RsaPrivateKeyMaterial> parse_rsa_private_key_der(std::span<const std::uint8_t> der)
{
	auto pkcs1 = parse_pkcs1_private_key(der);
	if (pkcs1)
	{
		return pkcs1;
	}

	return parse_pkcs8_private_key(der);
}

Result<RsaPrivateKeyMaterial> parse_rsa_pkcs8_private_key_der(std::span<const std::uint8_t> der)
{
	return parse_pkcs8_private_key(der);
}

Result<RsaPrivateKeyMaterial> parse_rsa_pkcs1_private_key_der(std::span<const std::uint8_t> der)
{
	return parse_pkcs1_private_key(der);
}

} // namespace crypto_core::internal
