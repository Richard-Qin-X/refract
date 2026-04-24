set (CMAKE_CXX_STANDARD 26)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

set (CMAKE_C_STANDARD 17)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_C_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler-specific flags
if(MSVC)
    # Microsoft Visual C++ Flags
    add_compile_options(/W4 /WX /permissive- /utf-8)
else()
    # GCC and Clang Flags
    add_compile_options(
        -Wall 
        -Wextra 
        -Wpedantic 
        -Werror 
        -Wshadow 
        -Wpointer-arith 
        -Wcast-qual 
        -Wformat=2
    )

    # CXX specific flags
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Weffc++>)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wno-unqualified-std-cast-call>)
    add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wno-non-virtual-dtor>)

    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -march=native")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native")

    # Sanitizers in Debug
    set(SANITIZING_FLAGS "-fno-sanitize-recover=all -fsanitize=undefined -fsanitize=address")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${SANITIZING_FLAGS}")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${SANITIZING_FLAGS}")
endif()