add_executable(test_util test_util.cpp)
target_link_libraries(test_util PRIVATE psafe3_static)
add_test(NAME util COMMAND test_util)

add_executable(test_utility test_utility.cpp)
target_link_libraries(test_utility PRIVATE psafe3_static)
add_test(NAME utility COMMAND test_utility)

add_executable(test_mapped_file test_mapped_file.cpp)
target_link_libraries(test_mapped_file PRIVATE psafe3_static)
target_compile_definitions(test_mapped_file PRIVATE
    TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/data/test")
add_test(NAME mapped_file COMMAND test_mapped_file)

add_test(NAME dump COMMAND psafe3dump "${PROJECT_SOURCE_DIR}/data/test/test.psafe3" "Open sesame!")

add_test(NAME checkpass COMMAND psafe3pass "${PROJECT_SOURCE_DIR}/data/test/test.psafe3" "Open sesame!")
