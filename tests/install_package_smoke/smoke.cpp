#include "crypto_core/crypto_core.hpp"

#include <string_view>

int main()
{
	return crypto_core::version().empty() ? 1 : 0;
}
