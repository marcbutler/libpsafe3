find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

add_library(psafe STATIC crypto.c psafe.c pws3.c)
target_include_directories(psafe PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe ${LIBGCRYPT_LIBRARY} util)
