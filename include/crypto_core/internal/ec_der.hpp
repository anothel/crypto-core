#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>

namespace crypto_core::internal
{

struct EcPublicKeyMaterial final
{
	ByteBuffer x;
	ByteBuffer y;
};

struct EcPrivateKeyMaterial final
{
	ByteBuffer private_scalar;
};

struct EcdsaSignatureMaterial final
{
	ByteBuffer r;
	ByteBuffer s;
};

[[nodiscard]] Result<EcPublicKeyMaterial> parse_p256_public_key_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<EcPrivateKeyMaterial> parse_p256_private_key_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<EcPrivateKeyMaterial> parse_p256_pkcs8_private_key_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<EcPrivateKeyMaterial> parse_p256_sec1_private_key_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<EcdsaSignatureMaterial> parse_ecdsa_signature_der(std::span<const std::uint8_t> der);
[[nodiscard]] Result<ByteBuffer> encode_ecdsa_signature_der(std::span<const std::uint8_t> r, std::span<const std::uint8_t> s);

} // namespace crypto_core::internal
