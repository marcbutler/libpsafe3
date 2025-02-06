find_package(PkgConfig QUIET)
pkg_check_modules(LIBGCRYPT libgcrypt REQUIRED)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt" "libgcrypt")

# Build library objects only once.
add_library(psafe_objlib OBJECT crypto.c psafe.c pws3.c)
set_property(TARGET psafe_objlib PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(psafe_objlib PUBLIC ${LIBGCRYPT_INCLUDE_DIR})


add_library(psafe_shared SHARED $<TARGET_OBJECTS:psafe_objlib>)
set_target_properties(psafe_shared PROPERTIES OUTPUT_NAME psafe)
target_include_directories(psafe_shared PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe_shared PUBLIC ${LIBGCRYPT_LIBRARY} util)
set_target_properties(psafe_shared PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_library(psafe_static STATIC $<TARGET_OBJECTS:psafe_objlib>)
set_target_properties(psafe_static PROPERTIES OUTPUT_NAME psafe)
target_include_directories(psafe_static PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
target_link_libraries(psafe_static PUBLIC ${LIBGCRYPT_LIBRARY} util)
set_target_properties(psafe_shared PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
