string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" SYSTEM_PROC)

set(REFRACT_CORE_SOURCES
    # "big_int.cc"
    # "sha256.cc"
)

if(SYSTEM_PROC MATCHES "^(x86_64|amd64)$")
    message(STATUS "[Refract] Enabling x86_64 optimizations")
    list(APPEND REFRACT_CORE_SOURCES 
        "arch/x86_64/sha256_avx2.S"
        "arch/x86_64/aes_ni.c"
    )
elseif(SYSTEM_PROC MATCHES "^(riscv64)$")
    message(STATUS "[Refract] Enabling RISC-V optimizations")
    list(APPEND REFRACT_CORE_SOURCES 
        "arch/riscv64/sha256_zvkb.S"
    )
endif()

add_library(refract_obj OBJECT ${REFRACT_CORE_SOURCES})
set_target_properties(refract_obj PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(refract_obj PUBLIC ${PROJECT_SOURCE_DIR}/include)
add_library(refract_static STATIC $<TARGET_OBJECTS:refract_obj>)
set_target_properties(refract_static PROPERTIES OUTPUT_NAME "refract")

add_library(refract_shared SHARED $<TARGET_OBJECTS:refract_obj>)
set_target_properties(refract_shared PROPERTIES OUTPUT_NAME "refract")