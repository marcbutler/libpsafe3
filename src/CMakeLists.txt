find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

include_directories(AFTER "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(psafe3)

add_executable(psafe3dump psafe3dump.c)
target_link_libraries(psafe3dump PRIVATE psafe3_static)
target_include_directories(psafe3dump PUBLIC ${LIBGCRYPT_INCLUDE_DIR})

add_executable(psafe3chkpass psafe3chkpass.c)
target_link_libraries(psafe3chkpass PRIVATE psafe3_static)

add_subdirectory(test)
