#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

struct RsaPublicKeyMaterial final
{
	ByteBuffer modulus;
	ByteBuffer public_exponent;
};

struct RsaPrivateKeyMaterial final
{
	ByteBuffer modulus;
	ByteBuffer public_exponent;
	ByteBuffer private_exponent;
	ByteBuffer prime1;
	ByteBuffer prime2;
	ByteBuffer exponent1;
	ByteBuffer exponent2;
	ByteBuffer coefficient;
};

[[nodiscard]] Result<RsaPublicKeyMaterial> parse_rsa_public_key_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<RsaPrivateKeyMaterial> parse_rsa_private_key_der(std::span<const std::uint8_t> der);

} // namespace crypto_core::internal
