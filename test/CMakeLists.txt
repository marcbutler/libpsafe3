add_executable(test_util test_util.cpp)
target_link_libraries(test_util PRIVATE psafe3_static)

add_test(NAME util COMMAND test_util)
add_test(NAME dump COMMAND psafe3dump "data/test.psafe3" "Open sesame!")
add_test(NAME checkpass COMMAND psafe3chkpass "data/test.psafe3" "Open sesame!")
