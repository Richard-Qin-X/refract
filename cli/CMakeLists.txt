add_executable(refract_cli "main.cc")

set_target_properties(refract_cli PROPERTIES OUTPUT_NAME "refract")
target_link_libraries(refract_cli 
    PRIVATE 
        refract_static 
        curl 
        ncurses
)

target_include_directories(refract_cli PRIVATE ${PROJECT_SOURCE_DIR}/include)