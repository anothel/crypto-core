#pragma once

#include "crypto_core/provider.hpp"

namespace crypto_core::internal
{

[[nodiscard]] Result<std::unique_ptr<ICipherContext>> create_aes_cbc_context(const CipherParams &params) noexcept;

} // namespace crypto_core::internal
