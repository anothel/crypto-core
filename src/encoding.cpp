#include "crypto_core/encoding.hpp"

#include "crypto_core/error.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <vector>

namespace crypto_core
{
namespace
{

constexpr std::string_view standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::string_view url_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

Error encoding_error(std::string_view message) noexcept
{
	return make_error(ErrorCode::invalid_argument, "encoding", message);
}

bool is_line_break(char c) noexcept
{
	return c == '\n' || c == '\r';
}

bool is_valid_pem_label(std::string_view label) noexcept
{
	if (label.empty() || label.front() == ' ' || label.back() == ' ')
	{
		return false;
	}

	for (const char c : label)
	{
		if (c < 0x20 || c > 0x7e || c == '-')
		{
			return false;
		}
	}
	return true;
}

std::array<int, 256> make_decode_table(std::string_view alphabet) noexcept
{
	std::array<int, 256> table{};
	table.fill(-1);
	for (std::size_t i = 0; i < alphabet.size(); ++i)
	{
		table[static_cast<unsigned char>(alphabet[i])] = static_cast<int>(i);
	}
	return table;
}

std::string encode_base64(std::span<const std::uint8_t> input, std::string_view alphabet, bool padding)
{
	std::string output;
	output.reserve(((input.size() + 2U) / 3U) * 4U);

	std::size_t i = 0;
	while (i + 3U <= input.size())
	{
		const auto chunk = (static_cast<std::uint32_t>(input[i]) << 16U) |
		                   (static_cast<std::uint32_t>(input[i + 1U]) << 8U) |
		                   static_cast<std::uint32_t>(input[i + 2U]);
		output.push_back(alphabet[(chunk >> 18U) & 0x3fU]);
		output.push_back(alphabet[(chunk >> 12U) & 0x3fU]);
		output.push_back(alphabet[(chunk >> 6U) & 0x3fU]);
		output.push_back(alphabet[chunk & 0x3fU]);
		i += 3U;
	}

	const auto remaining = input.size() - i;
	if (remaining == 1U)
	{
		const auto chunk = static_cast<std::uint32_t>(input[i]) << 16U;
		output.push_back(alphabet[(chunk >> 18U) & 0x3fU]);
		output.push_back(alphabet[(chunk >> 12U) & 0x3fU]);
		if (padding)
		{
			output.append("==");
		}
	}
	else if (remaining == 2U)
	{
		const auto chunk = (static_cast<std::uint32_t>(input[i]) << 16U) |
		                   (static_cast<std::uint32_t>(input[i + 1U]) << 8U);
		output.push_back(alphabet[(chunk >> 18U) & 0x3fU]);
		output.push_back(alphabet[(chunk >> 12U) & 0x3fU]);
		output.push_back(alphabet[(chunk >> 6U) & 0x3fU]);
		if (padding)
		{
			output.push_back('=');
		}
	}

	return output;
}

Result<ByteBuffer> decode_base64(std::string_view input, std::string_view alphabet, bool allow_unpadded)
{
	if (input.empty())
	{
		return Result<ByteBuffer>::success(ByteBuffer{});
	}
	for (const char c : input)
	{
		if (is_line_break(c) || c == ' ' || c == '\t')
		{
			return Result<ByteBuffer>::failure(encoding_error("base64 input contains whitespace"));
		}
	}

	std::string padded(input);
	if (allow_unpadded)
	{
		const auto remainder = padded.size() % 4U;
		if (remainder == 1U)
		{
			return Result<ByteBuffer>::failure(encoding_error("base64 input has invalid length"));
		}
		if (remainder != 0U)
		{
			padded.append(4U - remainder, '=');
		}
	}
	else if ((padded.size() % 4U) != 0U)
	{
		return Result<ByteBuffer>::failure(encoding_error("base64 input has invalid length"));
	}

	const auto table = make_decode_table(alphabet);
	std::vector<std::uint8_t> output;
	output.reserve((padded.size() / 4U) * 3U);

	for (std::size_t i = 0; i < padded.size(); i += 4U)
	{
		const bool pad2 = padded[i + 2U] == '=';
		const bool pad3 = padded[i + 3U] == '=';
		if (padded[i] == '=' || padded[i + 1U] == '=' || (pad2 && !pad3))
		{
			return Result<ByteBuffer>::failure(encoding_error("base64 input has invalid padding"));
		}
		if ((pad2 || pad3) && i + 4U != padded.size())
		{
			return Result<ByteBuffer>::failure(encoding_error("base64 padding appears before end"));
		}

		const auto a = table[static_cast<unsigned char>(padded[i])];
		const auto b = table[static_cast<unsigned char>(padded[i + 1U])];
		const auto c = pad2 ? 0 : table[static_cast<unsigned char>(padded[i + 2U])];
		const auto d = pad3 ? 0 : table[static_cast<unsigned char>(padded[i + 3U])];
		if (a < 0 || b < 0 || c < 0 || d < 0)
		{
			return Result<ByteBuffer>::failure(encoding_error("base64 input contains invalid character"));
		}

		const auto chunk = (static_cast<std::uint32_t>(a) << 18U) |
		                   (static_cast<std::uint32_t>(b) << 12U) |
		                   (static_cast<std::uint32_t>(c) << 6U) |
		                   static_cast<std::uint32_t>(d);
		output.push_back(static_cast<std::uint8_t>((chunk >> 16U) & 0xffU));
		if (!pad2)
		{
			output.push_back(static_cast<std::uint8_t>((chunk >> 8U) & 0xffU));
		}
		if (!pad3)
		{
			output.push_back(static_cast<std::uint8_t>(chunk & 0xffU));
		}
	}

	return Result<ByteBuffer>::success(ByteBuffer(std::move(output)));
}

Result<std::string> pem_boundary(std::string_view line, std::string_view prefix, std::string_view suffix)
{
	if (!line.starts_with(prefix) || !line.ends_with(suffix))
	{
		return Result<std::string>::failure(encoding_error("PEM boundary is malformed"));
	}
	const auto label = line.substr(prefix.size(), line.size() - prefix.size() - suffix.size());
	if (!is_valid_pem_label(label))
	{
		return Result<std::string>::failure(encoding_error("PEM label is invalid"));
	}
	return Result<std::string>::success(std::string(label));
}

std::string_view trim_trailing_cr(std::string_view line) noexcept
{
	if (!line.empty() && line.back() == '\r')
	{
		return line.substr(0, line.size() - 1U);
	}
	return line;
}

} // namespace

std::string base64_encode(std::span<const std::uint8_t> input)
{
	return encode_base64(input, standard_alphabet, true);
}

Result<ByteBuffer> base64_decode(std::string_view input)
{
	return decode_base64(input, standard_alphabet, false);
}

std::string base64url_encode(std::span<const std::uint8_t> input)
{
	return encode_base64(input, url_alphabet, false);
}

Result<ByteBuffer> base64url_decode(std::string_view input)
{
	return decode_base64(input, url_alphabet, true);
}

Result<std::string> pem_encode(std::string_view label, std::span<const std::uint8_t> payload)
{
	if (!is_valid_pem_label(label))
	{
		return Result<std::string>::failure(encoding_error("PEM label is invalid"));
	}

	auto encoded_payload = base64_encode(payload);
	std::string output;
	output.reserve(label.size() * 2U + encoded_payload.size() + 48U);
	output.append("-----BEGIN ");
	output.append(label);
	output.append("-----\n");
	for (std::size_t i = 0; i < encoded_payload.size(); i += 64U)
	{
		const auto take = std::min<std::size_t>(64U, encoded_payload.size() - i);
		output.append(encoded_payload.substr(i, take));
		output.push_back('\n');
	}
	output.append("-----END ");
	output.append(label);
	output.append("-----\n");
	return Result<std::string>::success(std::move(output));
}

Result<PemBlock> pem_decode(std::string_view input)
{
	const auto first_end = input.find('\n');
	if (first_end == std::string_view::npos)
	{
		return Result<PemBlock>::failure(encoding_error("PEM begin boundary is missing"));
	}

	auto begin_line = trim_trailing_cr(input.substr(0, first_end));
	auto begin_label = pem_boundary(begin_line, "-----BEGIN ", "-----");
	if (!begin_label)
	{
		return Result<PemBlock>::failure(begin_label.error());
	}

	std::string payload_text;
	std::string end_label;
	auto rest = input.substr(first_end + 1U);
	bool found_end = false;
	while (!rest.empty())
	{
		const auto line_end = rest.find('\n');
		const auto raw_line = line_end == std::string_view::npos ? rest : rest.substr(0, line_end);
		auto line = trim_trailing_cr(raw_line);
		rest = line_end == std::string_view::npos ? std::string_view{} : rest.substr(line_end + 1U);

		if (line.starts_with("-----END "))
		{
			auto parsed_end_label = pem_boundary(line, "-----END ", "-----");
			if (!parsed_end_label)
			{
				return Result<PemBlock>::failure(parsed_end_label.error());
			}
			end_label = std::move(parsed_end_label.value());
			found_end = true;
			break;
		}

		payload_text.append(line);
	}

	if (!found_end)
	{
		return Result<PemBlock>::failure(encoding_error("PEM end boundary is missing"));
	}
	if (begin_label.value() != end_label)
	{
		return Result<PemBlock>::failure(encoding_error("PEM labels do not match"));
	}
	while (!rest.empty())
	{
		const auto line_end = rest.find('\n');
		const auto raw_line = line_end == std::string_view::npos ? rest : rest.substr(0, line_end);
		if (!trim_trailing_cr(raw_line).empty())
		{
			return Result<PemBlock>::failure(encoding_error("PEM has trailing data"));
		}
		rest = line_end == std::string_view::npos ? std::string_view{} : rest.substr(line_end + 1U);
	}

	auto payload = base64_decode(payload_text);
	if (!payload)
	{
		return Result<PemBlock>::failure(payload.error());
	}

	return Result<PemBlock>::success(PemBlock{std::move(begin_label.value()), std::move(payload.value())});
}

} // namespace crypto_core
