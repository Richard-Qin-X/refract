/*
 * Refract - A fast, simple, and efficient cryptographic utility library.
 * Copyright (C) 2026  Richard Qin
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <cstddef>
#include <cstring>
#include <span>

#if defined( _WIN32 )
#include <windows.h>
#elif defined( __linux__ ) || defined( __FreeBSD__ ) || defined( __OpenBSD__ ) || defined( __NetBSD__ )            \
  || defined( __APPLE__ )
#include <strings.h>
#endif

namespace refract::internal {

/**
 * @brief Securely clears memory to zero, preventing compiler optimization.
 */
inline void secure_memzero( void* ptr, std::size_t size )
{
  if ( ptr == nullptr || size == 0 ) {
    return;
  }

#if defined( __cpp_lib_memset_explicit ) && __cpp_lib_memset_explicit >= 202207L
  // C++ standard secure memory zero
  std::memset_explicit( ptr, 0, size );
#elif defined( _WIN32 )
  // Windows-specific secure memory zero
  SecureZeroMemory( ptr, size );
#elif defined( __linux__ ) || defined( __FreeBSD__ ) || defined( __OpenBSD__ ) || defined( __NetBSD__ )            \
  || defined( __APPLE__ )
  // POSIX-specific secure memory zero (glibc 2.25+, BSD, macOS)
  explicit_bzero( ptr, size );
#else
  // Portable fallback: Use a volatile pointer loop.
  volatile unsigned char* p = static_cast<volatile unsigned char*>( ptr );
  while ( size-- ) {
    *p++ = 0;
  }
#endif
}

/**
 * @brief Wipes memory for an array of elements.
 *
 * @param ptr Pointer to the start of the memory.
 * @param count Number of elements of type T to wipe.
 */
template<typename T>
inline void mem_wipe( T* ptr, std::size_t count )
{
  secure_memzero( static_cast<void*>( ptr ), count * sizeof( T ) );
}

/**
 * @brief Wipes memory for a single object.
 */
template<typename T>
inline void mem_wipe( T& obj )
{
  secure_memzero( static_cast<void*>( &obj ), sizeof( T ) );
}

/**
 * @brief Wipes memory for a span of elements.
 */
template<typename T, std::size_t Extent>
inline void mem_wipe( std::span<T, Extent> s )
{
  secure_memzero( s.data(), s.size_bytes() );
}

} // namespace refract::internal