cmake_minimum_required(VERSION 3.20)
project(psafe CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_testing()
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Place final build products in the top build directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBGCRYPT libgcrypt REQUIRED)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt")

pkg_check_modules(LIBGPG_ERROR gpg-error REQUIRED)
find_path(LIBGPG_ERROR_INCLUDE_DIR NAMES "gpg-error.h")
find_library(LIBGPG_ERROR_LIBRARY NAMES "gpg-error")

pkg_search_module(UUID REQUIRED uuid)

add_subdirectory(src)
