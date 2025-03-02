cmake_minimum_required(VERSION 3.20)
project(psafe)
set(C_STANDARD 11)

enable_testing()

# Place build products in the top build directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

include_directories(AFTER "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_subdirectory(src)
