find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt REQUIRED)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

# Build library objects for both static and shared libraries only once.
add_library(psafe3_objlib OBJECT libpsafe3.c crypto_gcrypt.c)
set_property(TARGET psafe3_objlib PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(psafe3_objlib PUBLIC ${LIBGCRYPT_INCLUDE_DIR})

add_library(psafe3_shared SHARED $<TARGET_OBJECTS:psafe3_objlib>)
set_target_properties(psafe3_shared PROPERTIES OUTPUT_NAME psafe3)
target_include_directories(psafe3_shared PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe3_shared PUBLIC ${LIBGCRYPT_LIBRARY})

add_library(psafe3_static STATIC $<TARGET_OBJECTS:psafe3_objlib>)
set_target_properties(psafe3_static PROPERTIES OUTPUT_NAME psafe3)
target_include_directories(psafe3_static PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe3_static PUBLIC ${LIBGCRYPT_LIBRARY})
