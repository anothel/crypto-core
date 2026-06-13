cmake_minimum_required(VERSION 3.24)

project(
    crypto_core
    VERSION 0.1.0
    DESCRIPTION "Production-oriented cryptographic engine written in modern C++"
    LANGUAGES CXX
)

option(CRYPTO_CORE_BUILD_TESTS "Build crypto-core tests" ON)
option(CRYPTO_CORE_ENABLE_OPENSSL "Enable optional OpenSSL provider" OFF)

add_library(crypto_core
    src/hash.cpp
    src/hmac.cpp
    src/kdf.cpp
    src/kdf_native.cpp
    src/mac.cpp
    src/memory.cpp
    src/native_provider.cpp
    src/provider.cpp
    src/sha2.cpp
    src/version.cpp
)

add_library(crypto_core::crypto_core ALIAS crypto_core)

target_compile_features(crypto_core PUBLIC cxx_std_20)

target_compile_definitions(crypto_core
    PRIVATE
        CRYPTO_CORE_VERSION_STRING="${PROJECT_VERSION}"
)

target_include_directories(crypto_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(CRYPTO_CORE_ENABLE_OPENSSL)
    find_package(OpenSSL REQUIRED)

    target_sources(crypto_core
        PRIVATE
            src/openssl_provider.cpp
    )

    target_link_libraries(crypto_core
        PUBLIC
            OpenSSL::Crypto
    )

    target_compile_definitions(crypto_core
        PUBLIC
            CRYPTO_CORE_ENABLE_OPENSSL
    )
endif()

if(MSVC)
    target_compile_options(crypto_core PRIVATE /W4)
else()
    target_compile_options(crypto_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(CRYPTO_CORE_BUILD_TESTS)
    include(CTest)
    enable_testing()

    add_executable(crypto_core_smoke_tests
        tests/smoke_test.cpp
    )

    target_link_libraries(crypto_core_smoke_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.smoke COMMAND crypto_core_smoke_tests)

    add_executable(crypto_core_foundation_tests
        tests/foundation_test.cpp
    )

    target_link_libraries(crypto_core_foundation_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.foundation COMMAND crypto_core_foundation_tests)

    add_executable(crypto_core_provider_api_tests
        tests/provider_api_test.cpp
    )

    target_link_libraries(crypto_core_provider_api_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.provider_api COMMAND crypto_core_provider_api_tests)

    add_executable(crypto_core_native_hash_tests
        tests/native_hash_test.cpp
    )

    target_link_libraries(crypto_core_native_hash_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_hash COMMAND crypto_core_native_hash_tests)

    add_executable(crypto_core_mac_tests
        tests/mac_test.cpp
    )

    target_link_libraries(crypto_core_mac_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.mac COMMAND crypto_core_mac_tests)

    add_executable(crypto_core_kdf_tests
        tests/kdf_test.cpp
    )

    target_link_libraries(crypto_core_kdf_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.kdf COMMAND crypto_core_kdf_tests)

    if(CRYPTO_CORE_ENABLE_OPENSSL)
        add_executable(crypto_core_openssl_provider_tests
            tests/openssl_provider_test.cpp
        )

        target_link_libraries(crypto_core_openssl_provider_tests
            PRIVATE
                crypto_core::crypto_core
        )

        add_test(NAME crypto_core.openssl_provider COMMAND crypto_core_openssl_provider_tests)
    endif()
endif()
