cmake_minimum_required(VERSION 3.24)

find_library(etftp_server HINTS ${CMAKE_BINARY_DIR})
find_library(etftp_common HINTS ${CMAKE_BINARY_DIR})

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

add_executable(etftp_server_cli etftp_server_cli.cpp)
target_link_libraries(etftp_server_cli PRIVATE etftp_server etftp_common OpenSSL::Crypto curl sqlite3)

add_executable(etftp etftp_client_cli.cpp)
target_link_libraries(etftp PRIVATE etftp_client etftp_common OpenSSL::Crypto curl)