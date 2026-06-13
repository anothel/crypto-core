#include "crypto_core/version.hpp"

#ifndef CRYPTO_CORE_VERSION_STRING
#define CRYPTO_CORE_VERSION_STRING "0.0.0"
#endif

namespace crypto_core {

std::string_view project_name() noexcept
{
    return "crypto-core";
}

std::string_view version() noexcept
{
    return CRYPTO_CORE_VERSION_STRING;
}

}  // namespace crypto_core
