
# Refract

## Overview
Refract is a modern cryptographic library and command-line utility. It is implemented in C++26 and utilizes architecture-specific assembly (x86_64 AVX2/AES-NI and RISC-V Zvkb) for hardware-accelerated cryptographic operations. The project provides both a core library (`librefract.a` / `librefract.so`) and a standalone CLI tool.

## Usage

### As a Library
Integrate Refract into your CMake project:

```cmake
add_subdirectory(path/to/refract)

# Link statically
target_link_libraries(your_app PRIVATE refract_static)

# Or link dynamically
target_link_libraries(your_app PRIVATE refract_shared)
```

Include the headers in your C++ code:

```C++
#include <refract/sha256.hh>
// ...
```

### As a CLI Tool

You can use the built-in command-line interface for direct operations:

```bash
# Example: Hash a file using SHA-256
./build/bin/refract sha256 input.txt
```

## Build & Run

### Prerequisites

- **Compiler**: C++26 compatible compiler (Clang 18+ or GCC 14+ recommended)
    
- **Build System**: CMake 3.25 or higher
    
- **Dependencies**: `libcurl`, `ncurses` (for the CLI tool)
    

### Build Instructions

The project strictly uses out-of-source builds.


```bash
# 1. Clone the repository
git clone git@github.com:Richard-Qin-X/refract.git
cd refract

# 2. Configure the build (Default is Debug with sanitizers, use Release for performance)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 3. Compile
cmake --build build -j$(nproc)
```

### Installation

To install the shared/static libraries and the CLI binary to your system (`/usr/local` by default):

```bash
sudo cmake --install build
```

## License
Refract is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License (GPL) v3**. Please refer to [LICENSE](LICENSE) for more information.