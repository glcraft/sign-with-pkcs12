cmake_minimum_required (VERSION 3.10)
project(T01)
file(GLOB T01_SRC
    "main.cpp"
)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(T01 ${T01_SRC})
set_property(TARGET T01 PROPERTY CXX_STANDARD 17)
set_property(TARGET T01 PROPERTY CXX_STANDARD_REQUIRED ON)
target_link_libraries(T01
    OpenSSL::SSL 
    OpenSSL::Crypto
    ZLIB::ZLIB
)
find_package(Libssh2 CONFIG REQUIRED)
target_link_libraries(T01 Libssh2::libssh2)