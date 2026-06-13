#pragma once

#include <string_view>

namespace crypto_core {

std::string_view project_name() noexcept;
std::string_view version() noexcept;

}  // namespace crypto_core
