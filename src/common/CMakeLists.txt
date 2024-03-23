file(GLOB SOURCES "*.cpp")

add_library(etftp_common STATIC ${SOURCES})

target_include_directories(etftp_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})