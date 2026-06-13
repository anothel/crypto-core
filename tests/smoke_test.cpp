#include "crypto_core/crypto_core.hpp"

#include <cassert>
#include <string_view>

int main()
{
    assert(crypto_core::project_name() == std::string_view{"crypto-core"});
    assert(!crypto_core::version().empty());
    return 0;
}
