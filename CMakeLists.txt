cmake_minimum_required(VERSION 3.17)
project(casphash LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_executable(casphash source/main.c)
set_target_properties(casphash PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/output"
)
target_link_libraries(casphash PRIVATE OpenSSL::Crypto Threads::Threads)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(casphash PRIVATE -Wall -Wextra -Wpedantic)
endif()
