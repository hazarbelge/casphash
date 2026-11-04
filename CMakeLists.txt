cmake_minimum_required(VERSION 3.17)
project(kasphash LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(kasphash source/main.c)
set_target_properties(kasphash PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/output"
)
target_link_libraries(kasphash PRIVATE OpenSSL::Crypto)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(kasphash PRIVATE -Wall -Wextra -Wpedantic)
endif()
