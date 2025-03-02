add_executable(test_util test_util.c)
target_link_libraries(test_util PRIVATE psafe3_static)
add_test(NAME util COMMAND test_util)

add_test(NAME dump COMMAND psafe3dump "${PROJECT_SOURCE_DIR}/testdata/test.psafe3" "Open sesame!")
