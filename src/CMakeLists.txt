
find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

add_library(psafe STATIC crypto.c ioport.c psafe.c pws3.c util.c)
target_include_directories(psafe PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
add_executable(test_util test_util.c util.c)
