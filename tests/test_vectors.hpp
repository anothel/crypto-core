#pragma once

#include "crypto_core/error.hpp"
#include "crypto_core/result.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace crypto_core::test_support
{

struct KeyValueRecord
{
	std::string label;
	std::map<std::string, std::string> fields;

	[[nodiscard]] std::string_view field(std::string_view key) const noexcept
	{
		const auto it = fields.find(std::string(key));
		if (it == fields.end())
		{
			return {};
		}
		return it->second;
	}
};

struct CbcTestVector
{
	std::string label;
	std::vector<std::uint8_t> key;
	std::vector<std::uint8_t> iv;
	std::vector<std::uint8_t> plaintext;
	std::vector<std::uint8_t> ciphertext;
};

struct DigestTestVector
{
	std::string label;
	std::vector<std::uint8_t> message;
	std::vector<std::uint8_t> digest;
};

struct MacTestVector
{
	std::string label;
	std::vector<std::uint8_t> key;
	std::vector<std::uint8_t> message;
	std::vector<std::uint8_t> mac;
};

struct Pbkdf2TestVector
{
	std::string label;
	std::vector<std::uint8_t> password;
	std::vector<std::uint8_t> salt;
	std::uint32_t iterations;
	std::vector<std::uint8_t> derived_key;
};

struct HkdfTestVector
{
	std::string label;
	std::vector<std::uint8_t> ikm;
	std::vector<std::uint8_t> salt;
	std::vector<std::uint8_t> info;
	std::vector<std::uint8_t> okm;
};

struct GcmTestVector
{
	std::string label;
	std::vector<std::uint8_t> key;
	std::vector<std::uint8_t> nonce;
	std::vector<std::uint8_t> aad;
	std::vector<std::uint8_t> plaintext;
	std::vector<std::uint8_t> ciphertext;
	std::vector<std::uint8_t> tag;
};

namespace detail
{

inline std::string trim(std::string_view value)
{
	const auto first = value.find_first_not_of(" \t\r");
	if (first == std::string_view::npos)
	{
		return {};
	}
	const auto last = value.find_last_not_of(" \t\r");
	return std::string(value.substr(first, last - first + 1));
}

inline int hex_nibble(char c) noexcept
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	if (c >= 'a' && c <= 'f')
	{
		return 10 + c - 'a';
	}
	if (c >= 'A' && c <= 'F')
	{
		return 10 + c - 'A';
	}
	return -1;
}

} // namespace detail

inline Result<std::vector<std::uint8_t>> decode_hex(std::string_view hex)
{
	if ((hex.size() % 2U) != 0U)
	{
		return Result<std::vector<std::uint8_t>>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "hex input has odd length"));
	}

	std::vector<std::uint8_t> bytes;
	bytes.reserve(hex.size() / 2U);
	for (std::size_t i = 0; i < hex.size(); i += 2U)
	{
		const auto high = detail::hex_nibble(hex[i]);
		const auto low = detail::hex_nibble(hex[i + 1U]);
		if (high < 0 || low < 0)
		{
			return Result<std::vector<std::uint8_t>>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "hex input contains a non-hex character"));
		}
		bytes.push_back(static_cast<std::uint8_t>((high << 4U) | low));
	}

	return Result<std::vector<std::uint8_t>>::success(std::move(bytes));
}

inline std::vector<std::string> parse_label_metadata(const KeyValueRecord &record)
{
	std::vector<std::string> metadata;
	std::string_view label = record.label;
	while (!label.empty())
	{
		const auto first = label.find_first_not_of(" \t\r");
		if (first == std::string_view::npos)
		{
			break;
		}
		label = label.substr(first);
		const auto end = label.find_first_of(" \t\r");
		if (end == std::string_view::npos)
		{
			metadata.emplace_back(label);
			break;
		}
		metadata.emplace_back(label.substr(0, end));
		label = label.substr(end + 1U);
	}
	return metadata;
}

inline Result<std::vector<KeyValueRecord>> parse_key_value_records(std::string_view input)
{
	std::vector<KeyValueRecord> records;
	KeyValueRecord current;

	auto finish_record = [&]() {
		if (!current.label.empty() || !current.fields.empty())
		{
			records.push_back(std::move(current));
			current = KeyValueRecord{};
		}
	};

	while (!input.empty())
	{
		const auto line_end = input.find('\n');
		const auto raw_line = line_end == std::string_view::npos ? input : input.substr(0, line_end);
		input = line_end == std::string_view::npos ? std::string_view{} : input.substr(line_end + 1U);

		auto line = detail::trim(raw_line);
		if (line.empty() || line[0] == '#')
		{
			if (line.empty())
			{
				finish_record();
			}
			continue;
		}

		if (line.front() == '[' && line.back() == ']')
		{
			finish_record();
			current.label = line.substr(1U, line.size() - 2U);
			continue;
		}

		const auto equals = line.find('=');
		if (equals == std::string::npos)
		{
			return Result<std::vector<KeyValueRecord>>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record line is not key/value"));
		}

		auto key = detail::trim(std::string_view(line.data(), equals));
		auto value = detail::trim(std::string_view(line.data() + equals + 1U, line.size() - equals - 1U));
		if (key.empty())
		{
			return Result<std::vector<KeyValueRecord>>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record key is empty"));
		}
		if (current.fields.find(key) != current.fields.end())
		{
			return Result<std::vector<KeyValueRecord>>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record contains a duplicate key"));
		}
		current.fields.emplace(std::move(key), std::move(value));
	}

	finish_record();
	return Result<std::vector<KeyValueRecord>>::success(std::move(records));
}

inline Result<std::string_view> required_field(const KeyValueRecord &record, std::string_view key)
{
	const auto it = record.fields.find(std::string(key));
	if (it == record.fields.end())
	{
		return Result<std::string_view>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record is missing a required field"));
	}
	return Result<std::string_view>::success(std::string_view{it->second});
}

inline Result<void> require_fields(const KeyValueRecord &record, std::initializer_list<std::string_view> required)
{
	for (const auto key : required)
	{
		if (!required_field(record, key))
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record is missing a required field"));
		}
	}
	return Result<void>::success();
}

inline Result<std::vector<std::uint8_t>> hex_field(const KeyValueRecord &record, std::string_view key)
{
	auto field = required_field(record, key);
	if (!field)
	{
		return Result<std::vector<std::uint8_t>>::failure(field.error());
	}
	return decode_hex(field.value());
}

inline Result<std::uint32_t> uint32_field(const KeyValueRecord &record, std::string_view key)
{
	auto field = required_field(record, key);
	if (!field)
	{
		return Result<std::uint32_t>::failure(field.error());
	}

	std::uint32_t value = 0;
	const auto *first = field.value().data();
	const auto *last = first + field.value().size();
	const auto result = std::from_chars(first, last, value, 10);
	if (result.ec != std::errc{} || result.ptr != last)
	{
		return Result<std::uint32_t>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record field is not an unsigned integer"));
	}
	return Result<std::uint32_t>::success(value);
}

inline Result<DigestTestVector> make_digest_vector(const KeyValueRecord &record)
{
	auto message = hex_field(record, "MSG");
	if (!message)
	{
		return Result<DigestTestVector>::failure(message.error());
	}
	auto digest = hex_field(record, "MD");
	if (!digest)
	{
		return Result<DigestTestVector>::failure(digest.error());
	}

	return Result<DigestTestVector>::success(DigestTestVector{
	    record.label,
	    std::move(message.value()),
	    std::move(digest.value()),
	});
}

inline Result<MacTestVector> make_mac_vector(const KeyValueRecord &record)
{
	auto key = hex_field(record, "KEY");
	if (!key)
	{
		return Result<MacTestVector>::failure(key.error());
	}
	auto message = hex_field(record, "MSG");
	if (!message)
	{
		return Result<MacTestVector>::failure(message.error());
	}
	auto mac = hex_field(record, "MAC");
	if (!mac)
	{
		return Result<MacTestVector>::failure(mac.error());
	}

	return Result<MacTestVector>::success(MacTestVector{
	    record.label,
	    std::move(key.value()),
	    std::move(message.value()),
	    std::move(mac.value()),
	});
}

inline Result<Pbkdf2TestVector> make_pbkdf2_vector(const KeyValueRecord &record)
{
	auto password = hex_field(record, "PASSWORD");
	if (!password)
	{
		return Result<Pbkdf2TestVector>::failure(password.error());
	}
	auto salt = hex_field(record, "SALT");
	if (!salt)
	{
		return Result<Pbkdf2TestVector>::failure(salt.error());
	}
	auto iterations = uint32_field(record, "ITERATIONS");
	if (!iterations)
	{
		return Result<Pbkdf2TestVector>::failure(iterations.error());
	}
	auto derived_key = hex_field(record, "DK");
	if (!derived_key)
	{
		return Result<Pbkdf2TestVector>::failure(derived_key.error());
	}

	return Result<Pbkdf2TestVector>::success(Pbkdf2TestVector{
	    record.label,
	    std::move(password.value()),
	    std::move(salt.value()),
	    iterations.value(),
	    std::move(derived_key.value()),
	});
}

inline Result<HkdfTestVector> make_hkdf_vector(const KeyValueRecord &record)
{
	auto ikm = hex_field(record, "IKM");
	if (!ikm)
	{
		return Result<HkdfTestVector>::failure(ikm.error());
	}
	auto salt = hex_field(record, "SALT");
	if (!salt)
	{
		return Result<HkdfTestVector>::failure(salt.error());
	}
	auto info = hex_field(record, "INFO");
	if (!info)
	{
		return Result<HkdfTestVector>::failure(info.error());
	}
	auto okm = hex_field(record, "OKM");
	if (!okm)
	{
		return Result<HkdfTestVector>::failure(okm.error());
	}

	return Result<HkdfTestVector>::success(HkdfTestVector{
	    record.label,
	    std::move(ikm.value()),
	    std::move(salt.value()),
	    std::move(info.value()),
	    std::move(okm.value()),
	});
}

inline Result<CbcTestVector> make_cbc_vector(const KeyValueRecord &record)
{
	auto key = hex_field(record, "KEY");
	if (!key)
	{
		return Result<CbcTestVector>::failure(key.error());
	}
	auto iv = hex_field(record, "IV");
	if (!iv)
	{
		return Result<CbcTestVector>::failure(iv.error());
	}
	auto plaintext = hex_field(record, "PLAINTEXT");
	if (!plaintext)
	{
		return Result<CbcTestVector>::failure(plaintext.error());
	}
	auto ciphertext = hex_field(record, "CIPHERTEXT");
	if (!ciphertext)
	{
		return Result<CbcTestVector>::failure(ciphertext.error());
	}

	return Result<CbcTestVector>::success(CbcTestVector{
	    record.label,
	    std::move(key.value()),
	    std::move(iv.value()),
	    std::move(plaintext.value()),
	    std::move(ciphertext.value()),
	});
}

inline Result<GcmTestVector> make_gcm_vector(const KeyValueRecord &record)
{
	auto key = hex_field(record, "KEY");
	if (!key)
	{
		return Result<GcmTestVector>::failure(key.error());
	}
	auto nonce = hex_field(record, "NONCE");
	if (!nonce)
	{
		return Result<GcmTestVector>::failure(nonce.error());
	}
	auto aad = hex_field(record, "AAD");
	if (!aad)
	{
		return Result<GcmTestVector>::failure(aad.error());
	}
	auto plaintext = hex_field(record, "PLAINTEXT");
	if (!plaintext)
	{
		return Result<GcmTestVector>::failure(plaintext.error());
	}
	auto ciphertext = hex_field(record, "CIPHERTEXT");
	if (!ciphertext)
	{
		return Result<GcmTestVector>::failure(ciphertext.error());
	}
	auto tag = hex_field(record, "TAG");
	if (!tag)
	{
		return Result<GcmTestVector>::failure(tag.error());
	}

	return Result<GcmTestVector>::success(GcmTestVector{
	    record.label,
	    std::move(key.value()),
	    std::move(nonce.value()),
	    std::move(aad.value()),
	    std::move(plaintext.value()),
	    std::move(ciphertext.value()),
	    std::move(tag.value()),
	});
}

} // namespace crypto_core::test_support
