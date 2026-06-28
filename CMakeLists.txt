cmake_minimum_required(VERSION 3.24)

project(
    crypto_core
    VERSION 0.1.0
    DESCRIPTION "Native-first cryptographic engine written in modern C++"
    LANGUAGES CXX
)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(CRYPTO_CORE_BUILD_TESTS "Build crypto-core tests" ON)
option(CRYPTO_CORE_ENABLE_OPENSSL "Enable optional OpenSSL provider" OFF)

add_library(crypto_core
    src/aead.cpp
    src/aes.cpp
    src/aes_cbc.cpp
    src/aes_gcm.cpp
    src/asymmetric.cpp
    src/bigint.cpp
    src/cipher.cpp
    src/ecdsa.cpp
    src/ec_der.cpp
    src/ed25519.cpp
    src/encoding.cpp
    src/hash.cpp
    src/hmac.cpp
    src/key.cpp
    src/key_store.cpp
    src/kdf.cpp
    src/kdf_native.cpp
    src/mac.cpp
    src/memory.cpp
    src/native_provider.cpp
    src/os_rng.cpp
    src/provider.cpp
    src/p256.cpp
    src/p256_fixed.cpp
    src/rng.cpp
    src/rsa.cpp
    src/rsa_der.cpp
    src/rsa_fixed_bigint.cpp
    src/rsa_oaep.cpp
    src/rsa_pss.cpp
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
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(WIN32)
    target_link_libraries(crypto_core
        PRIVATE
            bcrypt
    )
endif()

if(APPLE)
    target_link_libraries(crypto_core
        PRIVATE
            "-framework Security"
    )
endif()

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

set(crypto_core_config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/crypto_core")

install(TARGETS crypto_core
    EXPORT crypto_core-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    PATTERN "internal" EXCLUDE
)

install(EXPORT crypto_core-targets
    NAMESPACE crypto_core::
    DESTINATION ${crypto_core_config_install_dir}
)

configure_package_config_file(
    cmake/crypto_core-config.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_core-config.cmake"
    INSTALL_DESTINATION ${crypto_core_config_install_dir}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_core-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_core-config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/crypto_core-config-version.cmake"
    DESTINATION ${crypto_core_config_install_dir}
)

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

    target_compile_definitions(crypto_core_provider_api_tests
        PRIVATE
            CRYPTO_CORE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
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

    add_executable(crypto_core_native_bigint_tests
        tests/native_bigint_test.cpp
    )

    target_link_libraries(crypto_core_native_bigint_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_bigint COMMAND crypto_core_native_bigint_tests)

    add_executable(crypto_core_native_rsa_fixed_bigint_tests
        tests/native_rsa_fixed_bigint_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_fixed_bigint_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_fixed_bigint COMMAND crypto_core_native_rsa_fixed_bigint_tests)

    add_executable(crypto_core_mac_tests
        tests/mac_test.cpp
    )

    target_link_libraries(crypto_core_mac_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.mac COMMAND crypto_core_mac_tests)

    add_executable(crypto_core_cipher_tests
        tests/cipher_test.cpp
    )

    target_link_libraries(crypto_core_cipher_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.cipher COMMAND crypto_core_cipher_tests)

    add_executable(crypto_core_aead_tests
        tests/aead_test.cpp
    )

    target_link_libraries(crypto_core_aead_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.aead COMMAND crypto_core_aead_tests)

    add_executable(crypto_core_kdf_tests
        tests/kdf_test.cpp
    )

    target_link_libraries(crypto_core_kdf_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.kdf COMMAND crypto_core_kdf_tests)

    add_executable(crypto_core_key_tests
        tests/key_test.cpp
    )

    target_link_libraries(crypto_core_key_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.key COMMAND crypto_core_key_tests)

    add_executable(crypto_core_asymmetric_api_tests
        tests/asymmetric_api_test.cpp
    )

    target_link_libraries(crypto_core_asymmetric_api_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.asymmetric_api COMMAND crypto_core_asymmetric_api_tests)

    add_executable(crypto_core_encoding_tests
        tests/encoding_test.cpp
    )

    target_link_libraries(crypto_core_encoding_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.encoding COMMAND crypto_core_encoding_tests)

    add_executable(crypto_core_api_stability_tests
        tests/api_stability_test.cpp
    )

    target_link_libraries(crypto_core_api_stability_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.api_stability COMMAND crypto_core_api_stability_tests)

    add_executable(crypto_core_test_vector_tests
        tests/test_vectors_test.cpp
    )

    target_link_libraries(crypto_core_test_vector_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.test_vectors COMMAND crypto_core_test_vector_tests)

    add_executable(crypto_core_native_aes_block_tests
        tests/native_aes_block_test.cpp
    )

    target_link_libraries(crypto_core_native_aes_block_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_aes_block COMMAND crypto_core_native_aes_block_tests)

    add_executable(crypto_core_native_rsa_der_tests
        tests/native_rsa_der_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_der_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_der COMMAND crypto_core_native_rsa_der_tests)

    add_executable(crypto_core_native_ecdsa_der_tests
        tests/native_ecdsa_der_test.cpp
    )

    target_link_libraries(crypto_core_native_ecdsa_der_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_ecdsa_der COMMAND crypto_core_native_ecdsa_der_tests)

    add_executable(crypto_core_native_p256_tests
        tests/native_p256_test.cpp
    )

    target_link_libraries(crypto_core_native_p256_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_p256 COMMAND crypto_core_native_p256_tests)

    add_executable(crypto_core_native_ecdsa_verify_tests
        tests/native_ecdsa_verify_test.cpp
    )

    target_link_libraries(crypto_core_native_ecdsa_verify_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_ecdsa_verify COMMAND crypto_core_native_ecdsa_verify_tests)

    add_executable(crypto_core_native_ed25519_tests
        tests/native_ed25519_test.cpp
    )

    target_link_libraries(crypto_core_native_ed25519_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_ed25519 COMMAND crypto_core_native_ed25519_tests)

    add_executable(crypto_core_native_rsa_primitive_tests
        tests/native_rsa_primitive_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_primitive_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_primitive COMMAND crypto_core_native_rsa_primitive_tests)

    add_executable(crypto_core_native_rsa_pss_tests
        tests/native_rsa_pss_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_pss_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_pss COMMAND crypto_core_native_rsa_pss_tests)

    add_executable(crypto_core_native_rsa_oaep_tests
        tests/native_rsa_oaep_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_oaep_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_oaep COMMAND crypto_core_native_rsa_oaep_tests)

    add_executable(crypto_core_native_rsa_provider_tests
        tests/native_rsa_provider_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_provider_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_provider COMMAND crypto_core_native_rsa_provider_tests)

    add_executable(crypto_core_native_rsa_reference_vectors_tests
        tests/native_rsa_reference_vectors_test.cpp
    )

    target_link_libraries(crypto_core_native_rsa_reference_vectors_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.native_rsa_reference_vectors COMMAND crypto_core_native_rsa_reference_vectors_tests)

    add_executable(crypto_core_rng_tests
        tests/rng_test.cpp
    )

    target_link_libraries(crypto_core_rng_tests
        PRIVATE
            crypto_core::crypto_core
    )

    add_test(NAME crypto_core.rng COMMAND crypto_core_rng_tests)

    add_executable(crypto_core_fuzz_boundary_smoke_tests
        tests/fuzz_boundary_smoke_test.cpp
    )

    target_link_libraries(crypto_core_fuzz_boundary_smoke_tests
        PRIVATE
            crypto_core::crypto_core
    )

    target_compile_definitions(crypto_core_fuzz_boundary_smoke_tests
        PRIVATE
            CRYPTO_CORE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
    )

    add_test(NAME crypto_core.fuzz_boundary_smoke COMMAND crypto_core_fuzz_boundary_smoke_tests)

    add_library(crypto_core_fuzz_parser_boundaries_object OBJECT
        tests/fuzz/fuzz_parser_boundaries.cpp
    )

    target_link_libraries(crypto_core_fuzz_parser_boundaries_object
        PRIVATE
            crypto_core::crypto_core
    )

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
