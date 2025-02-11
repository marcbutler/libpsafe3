find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

include_directories(AFTER ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(util)
add_subdirectory(psafe)
add_subdirectory(libpsafe3)

add_executable(psafedump psafedump.c)
target_link_libraries(psafedump PRIVATE psafe_static psafe3_static)

add_executable(test_util test_util.c)
target_link_libraries(test_util PRIVATE util)
add_test(NAME util COMMAND test_util)
