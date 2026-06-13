#pragma once

#include "crypto_core/error.hpp"
#include "crypto_core/result.hpp"

#include <algorithm>
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

inline Result<void> require_fields(const KeyValueRecord &record, std::initializer_list<std::string_view> required)
{
	for (const auto key : required)
	{
		if (record.fields.find(std::string(key)) == record.fields.end())
		{
			return Result<void>::failure(make_error(ErrorCode::invalid_argument, "test_vectors", "record is missing a required field"));
		}
	}
	return Result<void>::success();
}

} // namespace crypto_core::test_support
