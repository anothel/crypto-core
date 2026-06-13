cmake_minimum_required(VERSION 3.24)

project(
    crypto_core
    VERSION 0.1.0
    DESCRIPTION "Production-oriented cryptographic engine written in modern C++"
    LANGUAGES CXX
)

option(CRYPTO_CORE_BUILD_TESTS "Build crypto-core tests" ON)

add_library(crypto_core
    src/memory.cpp
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
endif()
