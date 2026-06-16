#include "crypto_core/key_store.hpp"

#include "crypto_core/error.hpp"

namespace crypto_core
{
namespace
{

[[nodiscard]] Error key_store_error(ErrorCode code, std::string_view message) noexcept
{
	return make_error(code, "key_store", message);
}

template <typename Key>
[[nodiscard]] Result<const Key *> require_key(const Key *key, KeyUsage usage, std::string_view missing_message, std::string_view usage_message) noexcept
{
	if (key == nullptr)
	{
		return Result<const Key *>::failure(key_store_error(ErrorCode::invalid_key, missing_message));
	}
	if (!key->allows(usage))
	{
		return Result<const Key *>::failure(key_store_error(ErrorCode::invalid_key, usage_message));
	}

	return Result<const Key *>::success(key);
}

} // namespace

Result<void> KeyStore::insert_secret(std::string id, SecretKey key)
{
	auto validation = validate_new_id(id);
	if (!validation)
	{
		return validation;
	}

	secret_keys_.emplace(std::move(id), std::move(key));
	return Result<void>::success();
}

Result<void> KeyStore::insert_public(std::string id, PublicKey key)
{
	auto validation = validate_new_id(id);
	if (!validation)
	{
		return validation;
	}

	public_keys_.emplace(std::move(id), std::move(key));
	return Result<void>::success();
}

Result<void> KeyStore::insert_private(std::string id, PrivateKey key)
{
	auto validation = validate_new_id(id);
	if (!validation)
	{
		return validation;
	}

	private_keys_.emplace(std::move(id), std::move(key));
	return Result<void>::success();
}

bool KeyStore::contains(std::string_view id) const noexcept
{
	return has_id(id);
}

const SecretKey *KeyStore::find_secret(std::string_view id) const noexcept
{
	const auto entry = secret_keys_.find(std::string(id));
	if (entry == secret_keys_.end())
	{
		return nullptr;
	}

	return &entry->second;
}

const PublicKey *KeyStore::find_public(std::string_view id) const noexcept
{
	const auto entry = public_keys_.find(std::string(id));
	if (entry == public_keys_.end())
	{
		return nullptr;
	}

	return &entry->second;
}

const PrivateKey *KeyStore::find_private(std::string_view id) const noexcept
{
	const auto entry = private_keys_.find(std::string(id));
	if (entry == private_keys_.end())
	{
		return nullptr;
	}

	return &entry->second;
}

Result<const SecretKey *> KeyStore::require_secret(std::string_view id, KeyUsage usage) const noexcept
{
	return require_key(find_secret(id), usage, "secret key id was not found", "secret key usage is not allowed");
}

Result<const PublicKey *> KeyStore::require_public(std::string_view id, KeyUsage usage) const noexcept
{
	return require_key(find_public(id), usage, "public key id was not found", "public key usage is not allowed");
}

Result<const PrivateKey *> KeyStore::require_private(std::string_view id, KeyUsage usage) const noexcept
{
	return require_key(find_private(id), usage, "private key id was not found", "private key usage is not allowed");
}

bool KeyStore::has_id(std::string_view id) const noexcept
{
	return secret_keys_.find(std::string(id)) != secret_keys_.end() ||
	       public_keys_.find(std::string(id)) != public_keys_.end() ||
	       private_keys_.find(std::string(id)) != private_keys_.end();
}

Result<void> KeyStore::validate_new_id(std::string_view id) const noexcept
{
	if (id.empty())
	{
		return Result<void>::failure(key_store_error(ErrorCode::invalid_argument, "key id must not be empty"));
	}
	if (has_id(id))
	{
		return Result<void>::failure(key_store_error(ErrorCode::invalid_argument, "key id already exists"));
	}

	return Result<void>::success();
}

} // namespace crypto_core
