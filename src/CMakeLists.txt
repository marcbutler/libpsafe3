
find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

add_library(psafe STATIC crypto.c ioport.c pws3.c util.c)
target_include_directories(psafe PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe ${LIBGCRYPT_LIBRARY})

add_executable(psafedump psafe.c)
target_link_libraries(psafedump PRIVATE psafe)

enable_testing()
add_executable(test_util test_util.c)
target_link_libraries(test_util PRIVATE psafe)
add_test(test_util test_util)
