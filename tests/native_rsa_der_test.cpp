#include "crypto_core/internal/rsa_der.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <span>

namespace
{

void require(bool condition)
{
	if (!condition)
	{
		std::exit(1);
	}
}

void require_bytes(std::span<const std::uint8_t> actual, std::span<const std::uint8_t> expected)
{
	require(actual.size() == expected.size());
	for (std::size_t i = 0; i < actual.size(); ++i)
	{
		require(actual[i] == expected[i]);
	}
}

void require_invalid_key(auto result)
{
	require(!result.has_value());
	require(result.error().code() == crypto_core::ErrorCode::invalid_key);
}

constexpr std::array<std::uint8_t, 9> pkcs1_public_key_der{
    0x30,
    0x07,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
};

constexpr std::array<std::uint8_t, 29> spki_public_key_der{
    0x30,
    0x1B,
    0x30,
    0x0D,
    0x06,
    0x09,
    0x2A,
    0x86,
    0x48,
    0x86,
    0xF7,
    0x0D,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
    0x03,
    0x0A,
    0x00,
    0x30,
    0x07,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
};

constexpr std::array<std::uint8_t, 31> pkcs1_private_key_der{
    0x30,
    0x1D,
    0x02,
    0x01,
    0x00,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
    0x02,
    0x02,
    0x0A,
    0xC1,
    0x02,
    0x01,
    0x3D,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x31,
    0x02,
    0x01,
    0x26,
};

constexpr std::array<std::uint8_t, 53> pkcs8_private_key_der{
    0x30,
    0x33,
    0x02,
    0x01,
    0x00,
    0x30,
    0x0D,
    0x06,
    0x09,
    0x2A,
    0x86,
    0x48,
    0x86,
    0xF7,
    0x0D,
    0x01,
    0x01,
    0x01,
    0x05,
    0x00,
    0x04,
    0x1F,
    0x30,
    0x1D,
    0x02,
    0x01,
    0x00,
    0x02,
    0x02,
    0x0C,
    0xA1,
    0x02,
    0x01,
    0x11,
    0x02,
    0x02,
    0x0A,
    0xC1,
    0x02,
    0x01,
    0x3D,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x35,
    0x02,
    0x01,
    0x31,
    0x02,
    0x01,
    0x26,
};

void test_parses_pkcs1_public_key()
{
	auto key = crypto_core::internal::parse_rsa_public_key_der(pkcs1_public_key_der);
	require(key.has_value());
	require_bytes(key.value().modulus.bytes(), std::array<std::uint8_t, 2>{0x0C, 0xA1});
	require_bytes(key.value().public_exponent.bytes(), std::array<std::uint8_t, 1>{0x11});
}

void test_parses_spki_public_key()
{
	auto key = crypto_core::internal::parse_rsa_public_key_der(spki_public_key_der);
	require(key.has_value());
	require_bytes(key.value().modulus.bytes(), std::array<std::uint8_t, 2>{0x0C, 0xA1});
	require_bytes(key.value().public_exponent.bytes(), std::array<std::uint8_t, 1>{0x11});
}

void test_parses_pkcs1_private_key()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs1_private_key_der);
	require(key.has_value());
	require_bytes(key.value().modulus.bytes(), std::array<std::uint8_t, 2>{0x0C, 0xA1});
	require_bytes(key.value().public_exponent.bytes(), std::array<std::uint8_t, 1>{0x11});
	require_bytes(key.value().private_exponent.bytes(), std::array<std::uint8_t, 2>{0x0A, 0xC1});
	require_bytes(key.value().prime1.bytes(), std::array<std::uint8_t, 1>{0x3D});
	require_bytes(key.value().prime2.bytes(), std::array<std::uint8_t, 1>{0x35});
	require_bytes(key.value().exponent1.bytes(), std::array<std::uint8_t, 1>{0x35});
	require_bytes(key.value().exponent2.bytes(), std::array<std::uint8_t, 1>{0x31});
	require_bytes(key.value().coefficient.bytes(), std::array<std::uint8_t, 1>{0x26});
}

void test_parses_pkcs8_private_key()
{
	auto key = crypto_core::internal::parse_rsa_private_key_der(pkcs8_private_key_der);
	require(key.has_value());
	require_bytes(key.value().modulus.bytes(), std::array<std::uint8_t, 2>{0x0C, 0xA1});
	require_bytes(key.value().public_exponent.bytes(), std::array<std::uint8_t, 1>{0x11});
}

void test_rejects_malformed_der()
{
	auto truncated = crypto_core::internal::parse_rsa_public_key_der(std::span<const std::uint8_t>(spki_public_key_der.data(), spki_public_key_der.size() - 1));
	require(!truncated.has_value());
	require(truncated.error().code() == crypto_core::ErrorCode::invalid_key);

	const std::array<std::uint8_t, 5> negative_integer_der{
	    0x30,
	    0x03,
	    0x02,
	    0x01,
	    0x80,
	};
	auto negative = crypto_core::internal::parse_rsa_public_key_der(negative_integer_der);
	require(!negative.has_value());
	require(negative.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_rejects_spki_algorithm_variants()
{
	auto wrong_oid = spki_public_key_der;
	wrong_oid[14] = 0x05;
	require_invalid_key(crypto_core::internal::parse_rsa_spki_public_key_der(wrong_oid));

	const std::array<std::uint8_t, 27> missing_null_parameters{
	    0x30, 0x19, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48,
	    0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x03, 0x0A, 0x00,
	    0x30, 0x07, 0x02, 0x02, 0x0C, 0xA1, 0x02, 0x01, 0x11};
	require_invalid_key(crypto_core::internal::parse_rsa_spki_public_key_der(missing_null_parameters));

	auto non_null_parameters = spki_public_key_der;
	non_null_parameters[15] = 0x02;
	require_invalid_key(crypto_core::internal::parse_rsa_spki_public_key_der(non_null_parameters));
}

void test_rejects_pkcs8_algorithm_variants()
{
	auto wrong_oid = pkcs8_private_key_der;
	wrong_oid[17] = 0x05;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs8_private_key_der(wrong_oid));

	const std::array<std::uint8_t, 51> missing_null_parameters{
	    0x30, 0x31, 0x02, 0x01, 0x00, 0x30, 0x0B, 0x06, 0x09,
	    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
	    0x04, 0x1F, 0x30, 0x1D, 0x02, 0x01, 0x00, 0x02, 0x02,
	    0x0C, 0xA1, 0x02, 0x01, 0x11, 0x02, 0x02, 0x0A, 0xC1,
	    0x02, 0x01, 0x3D, 0x02, 0x01, 0x35, 0x02, 0x01, 0x35,
	    0x02, 0x01, 0x31, 0x02, 0x01, 0x26};
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs8_private_key_der(missing_null_parameters));

	auto non_null_parameters = pkcs8_private_key_der;
	non_null_parameters[18] = 0x02;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs8_private_key_der(non_null_parameters));
}

void test_rejects_zero_rsa_integer_fields()
{
	const std::array<std::uint8_t, 8> zero_modulus_public_key_der{
	    0x30,
	    0x06,
	    0x02,
	    0x01,
	    0x00,
	    0x02,
	    0x01,
	    0x11,
	};
	auto zero_modulus = crypto_core::internal::parse_rsa_pkcs1_public_key_der(zero_modulus_public_key_der);
	require(!zero_modulus.has_value());
	require(zero_modulus.error().code() == crypto_core::ErrorCode::invalid_key);

	const std::array<std::uint8_t, 9> zero_exponent_public_key_der{
	    0x30,
	    0x07,
	    0x02,
	    0x02,
	    0x0C,
	    0xA1,
	    0x02,
	    0x01,
	    0x00,
	};
	auto zero_exponent = crypto_core::internal::parse_rsa_pkcs1_public_key_der(zero_exponent_public_key_der);
	require(!zero_exponent.has_value());
	require(zero_exponent.error().code() == crypto_core::ErrorCode::invalid_key);

	auto zero_crt_prime = pkcs1_private_key_der;
	zero_crt_prime[18] = 0x00;
	auto zero_private = crypto_core::internal::parse_rsa_pkcs1_private_key_der(zero_crt_prime);
	require(!zero_private.has_value());
	require(zero_private.error().code() == crypto_core::ErrorCode::invalid_key);
}

void test_rejects_invalid_rsa_key_shape()
{
	const std::array<std::uint8_t, 8> one_modulus_public_key_der{
	    0x30,
	    0x06,
	    0x02,
	    0x01,
	    0x01,
	    0x02,
	    0x01,
	    0x11,
	};
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_public_key_der(one_modulus_public_key_der));

	const std::array<std::uint8_t, 8> even_modulus_public_key_der{
	    0x30,
	    0x06,
	    0x02,
	    0x01,
	    0x12,
	    0x02,
	    0x01,
	    0x11,
	};
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_public_key_der(even_modulus_public_key_der));

	const std::array<std::uint8_t, 9> even_public_exponent_key_der{
	    0x30,
	    0x07,
	    0x02,
	    0x02,
	    0x0C,
	    0xA1,
	    0x02,
	    0x01,
	    0x02,
	};
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_public_key_der(even_public_exponent_key_der));

	auto even_prime_private_key_der = pkcs1_private_key_der;
	even_prime_private_key_der[18] = 0x3C;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(even_prime_private_key_der));
}

void test_rejects_inconsistent_rsa_private_key_math()
{
	auto wrong_modulus = pkcs1_private_key_der;
	wrong_modulus[8] = 0xA3;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(wrong_modulus));

	auto wrong_private_exponent = pkcs1_private_key_der;
	wrong_private_exponent[15] = 0xC3;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(wrong_private_exponent));

	auto wrong_exponent1 = pkcs1_private_key_der;
	wrong_exponent1[24] = 0x37;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(wrong_exponent1));

	auto wrong_exponent2 = pkcs1_private_key_der;
	wrong_exponent2[27] = 0x33;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(wrong_exponent2));

	auto wrong_coefficient = pkcs1_private_key_der;
	wrong_coefficient[30] = 0x27;
	require_invalid_key(crypto_core::internal::parse_rsa_pkcs1_private_key_der(wrong_coefficient));
}

} // namespace

int main()
{
	test_parses_pkcs1_public_key();
	test_parses_spki_public_key();
	test_parses_pkcs1_private_key();
	test_parses_pkcs8_private_key();
	test_rejects_malformed_der();
	test_rejects_spki_algorithm_variants();
	test_rejects_pkcs8_algorithm_variants();
	test_rejects_zero_rsa_integer_fields();
	test_rejects_invalid_rsa_key_shape();
	test_rejects_inconsistent_rsa_private_key_math();
	return 0;
}
