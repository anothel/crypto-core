#pragma once

#include "crypto_core/byte_buffer.hpp"
#include "crypto_core/result.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace crypto_core
{

struct PemBlock
{
	std::string label;
	ByteBuffer payload;
};

[[nodiscard]] std::string base64_encode(std::span<const std::uint8_t> input);
[[nodiscard]] Result<ByteBuffer> base64_decode(std::string_view input);

[[nodiscard]] std::string base64url_encode(std::span<const std::uint8_t> input);
[[nodiscard]] Result<ByteBuffer> base64url_decode(std::string_view input);

[[nodiscard]] Result<std::string> pem_encode(std::string_view label, std::span<const std::uint8_t> payload);
[[nodiscard]] Result<PemBlock> pem_decode(std::string_view input);

} // namespace crypto_core
