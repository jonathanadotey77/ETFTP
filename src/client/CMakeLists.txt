file(GLOB SOURCES "*.cpp")

add_library(etftp_client STATIC ${SOURCES})

target_include_directories(etftp_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../common)

target_link_libraries(etftp_client PUBLIC etftp_common)