cmake_minimum_required (VERSION 3.10)
project(sign-pkcs12)
file(GLOB PRG_SRC
    "main.cpp"
)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(sign-pkcs12 ${PRG_SRC})
set_property(TARGET sign-pkcs12 PROPERTY CXX_STANDARD 17)
set_property(TARGET sign-pkcs12 PROPERTY CXX_STANDARD_REQUIRED ON)
target_link_libraries(sign-pkcs12
    OpenSSL::SSL 
    OpenSSL::Crypto
    ZLIB::ZLIB
)
set_target_properties(sign-pkcs12 PROPERTIES OUTPUT_NAME "sign-with-pkcs12")