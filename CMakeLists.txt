cmake_minimum_required(VERSION 3.20)
project(psafe CXX)
set(CMAKE_CXX_STANDARD 11)


# Place build products in the top build directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

include_directories(BEFORE "${CMAKE_CURRENT_SOURCE_DIR}")
include_directories(AFTER "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_subdirectory(lib)

add_subdirectory(cmds)

enable_testing()
add_subdirectory(test)
