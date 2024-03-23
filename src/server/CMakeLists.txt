file(GLOB SOURCES "*.cpp")

add_library(etftp_server STATIC ${SOURCES})

target_include_directories(etftp_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)

target_link_libraries(etftp_server PUBLIC etftp_common)