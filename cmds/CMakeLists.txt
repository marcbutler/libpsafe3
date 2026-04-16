find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

include_directories(AFTER "${CMAKE_SOURCE_DIR}")

add_executable(psafe3dump psafe3dump.cpp)
target_link_libraries(psafe3dump PRIVATE psafe3_static)
target_include_directories(psafe3dump PUBLIC ${LIBGCRYPT_INCLUDE_DIR})

add_executable(psafe3chkpass psafe3chkpass.cpp)
target_link_libraries(psafe3chkpass PRIVATE psafe3_static)
