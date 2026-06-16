#pragma once

#include "crypto_core/asymmetric.hpp"
#include "crypto_core/key.hpp"
#include "crypto_core/result.hpp"

#include <string>
#include <string_view>
#include <unordered_map>

namespace crypto_core
{

class KeyStore final
{
public:
	[[nodiscard]] Result<void> insert_secret(std::string id, SecretKey key);
	[[nodiscard]] Result<void> insert_public(std::string id, PublicKey key);
	[[nodiscard]] Result<void> insert_private(std::string id, PrivateKey key);

	[[nodiscard]] bool contains(std::string_view id) const noexcept;

	[[nodiscard]] const SecretKey *find_secret(std::string_view id) const noexcept;
	[[nodiscard]] const PublicKey *find_public(std::string_view id) const noexcept;
	[[nodiscard]] const PrivateKey *find_private(std::string_view id) const noexcept;

	[[nodiscard]] Result<const SecretKey *> require_secret(std::string_view id, KeyUsage usage) const noexcept;
	[[nodiscard]] Result<const PublicKey *> require_public(std::string_view id, KeyUsage usage) const noexcept;
	[[nodiscard]] Result<const PrivateKey *> require_private(std::string_view id, KeyUsage usage) const noexcept;

private:
	[[nodiscard]] bool has_id(std::string_view id) const noexcept;
	[[nodiscard]] Result<void> validate_new_id(std::string_view id) const noexcept;

	std::unordered_map<std::string, SecretKey> secret_keys_;
	std::unordered_map<std::string, PublicKey> public_keys_;
	std::unordered_map<std::string, PrivateKey> private_keys_;
};

} // namespace crypto_core
