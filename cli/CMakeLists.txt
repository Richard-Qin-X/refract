# find_package(CURL REQUIRED)
# find_package(Curses REQUIRED)

add_executable(refract_cli "main.cc")

set_target_properties(refract_cli PROPERTIES OUTPUT_NAME "refract")

target_link_libraries(refract_cli 
    PRIVATE 
        refract_static 
        # CURL::libcurl
        # ${CURSES_LIBRARIES}
)

target_include_directories(refract_cli PRIVATE 
    ${PROJECT_SOURCE_DIR}/include
    ${CURSES_INCLUDE_DIRS}
)