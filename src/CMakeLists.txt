find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBGCRYPT libgcrypt REQUIRED)
find_path(LIBGCRYPT_INCLUDE_DIR NAMES "gcrypt.h")
find_library(LIBGCRYPT_LIBRARY NAMES "gcrypt")

pkg_check_modules(LIBGPG_ERROR gpg-error REQUIRED)
find_path(LIBGPG_ERROR_INCLUDE_DIR NAMES "gpg-error.h")
find_library(LIBGPG_ERROR_LIBRARY NAMES "gpg-error")

pkg_search_module(UUID REQUIRED uuid)

include_directories(AFTER "${CMAKE_CURRENT_SOURCE_DIR}")

set(LIB_SRC crypto.cpp mapped_file.cpp mapped_memory.cpp pws3.cpp safe.cpp safeio.cpp secure_bytes.cpp util.cpp)

# Build library objects for both static and shared libraries only once.
add_library(psafe3_objlib OBJECT ${LIB_SRC})
set_property(TARGET psafe3_objlib PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(psafe3_objlib PUBLIC ${LIBGCRYPT_INCLUDE_DIR} ${LIBGPG_ERROR_INCLUDE_DIR} ${UUID_INCLUDE_DIR})
target_link_libraries(psafe3_objlib PUBLIC ${LIBGCRYPT_LIBRARY} ${LIBGPG_ERROR_LIBRARY} ${UUID_LIBRARY})

add_library(psafe3_shared SHARED $<TARGET_OBJECTS:psafe3_objlib>)
set_target_properties(psafe3_shared PROPERTIES OUTPUT_NAME psafe3)
target_include_directories(psafe3_shared PUBLIC ${LIBGCRYPT_INCLUDE_DIR} ${LIBGPG_ERROR_INCLUDE_DIR} ${UUID_INCLUDE_DIR})
target_link_libraries(psafe3_shared PUBLIC ${LIBGCRYPT_LIBRARY} ${LIBGPG_ERROR_LIBRARY} ${UUID_LIBRARY})

add_library(psafe3_static STATIC $<TARGET_OBJECTS:psafe3_objlib>)
set_target_properties(psafe3_static PROPERTIES OUTPUT_NAME psafe3)
target_include_directories(psafe3_static PUBLIC ${LIBGCRYPT_INCLUDE_DIR} ${LIBGPG_ERROR_INCLUDE_DIR} ${UUID_INCLUDE_DIR})
target_link_libraries(psafe3_static PUBLIC ${LIBGCRYPT_LIBRARY} ${LIBGPG_ERROR_LIBRARY} ${UUID_LIBRARY})

add_executable(psafe3dump psafe3dump.cpp)
target_link_libraries(psafe3dump PRIVATE psafe3_static)

add_executable(psafe3pass psafe3pass.cpp)
target_link_libraries(psafe3pass PRIVATE psafe3_static)

add_subdirectory(test)
