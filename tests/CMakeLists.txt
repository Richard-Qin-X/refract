include(CTest)

# Unit test for internal::mem_wipe
add_executable(test_mem_wipe test_mem_wipe.cc)
target_link_libraries(test_mem_wipe PRIVATE refract_static)
target_include_directories(test_mem_wipe PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Unit test for refract::span_utils
add_executable(test_span_utils test_span_utils.cc)
target_link_libraries(test_span_utils PRIVATE refract_static)
target_include_directories(test_span_utils PRIVATE ${PROJECT_SOURCE_DIR}/include)

# Register tests with CTest
add_test(NAME test_mem_wipe COMMAND test_mem_wipe)
add_test(NAME test_span_utils COMMAND test_span_utils)