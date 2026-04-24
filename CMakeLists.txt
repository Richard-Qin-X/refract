cmake_minimum_required(VERSION 3.25)

project(
    Refract
    VERSION 0.1.0
    DESCRIPTION "A fast, secure, and efficient cryptographic tool."
    LANGUAGES CXX C ASM
)

if(${PROJECT_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "Refract must be built outside its source directory, e.g. `cmake -B build`.")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${CMAKE_BINARY_DIR}/lib)
endforeach()

include(etc/build_type.cmake)
include(etc/cflags.cmake)
include(etc/scanners.cmake)
include(etc/tests.cmake)

add_subdirectory(src)

option(REFRACT_BUILD_CLI "Build the command-line interface tool" ON)
if(REFRACT_BUILD_CLI)
    add_subdirectory(cli)
endif()

add_subdirectory(tests)

install(TARGETS refract_static refract_shared
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
)

install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/
        DESTINATION include
)

if(REFRACT_BUILD_CLI)
    install(TARGETS refract_cli
            RUNTIME DESTINATION bin
    )
endif()

if(NOT TARGET uninstall)
  configure_file(
    "${PROJECT_SOURCE_DIR}/etc/cmake_uninstall.cmake.in"
    "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P "${PROJECT_BINARY_DIR}/cmake_uninstall.cmake")
endif()