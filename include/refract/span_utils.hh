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

#include <algorithm>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace refract {

/**
 * @brief Convenience aliases for byte spans.
 */
using bytes_span = std::span<uint8_t>;
using const_bytes_span = std::span<const uint8_t>;

/**
 * @brief XOR two memory blocks (dst ^= src).
 * @throws std::invalid_argument if span sizes are not equal.
 */
constexpr void xor_buffers( bytes_span dst, const_bytes_span src )
{
  if ( dst.size() != src.size() ) {
    throw std::invalid_argument( "[Refract] xor_buffers: span sizes must be equal!" );
  }

  for ( std::size_t i = 0; i < dst.size(); ++i ) {
    dst[i] ^= src[i];
  }
}

/**
 * @brief Constant-time equality check for two spans.
 *
 * Compares two spans in constant time regardless of their contents to prevent timing attacks.
 * Returns true if the spans are equal in both size and content.
 */
inline bool secure_compare( const_bytes_span a, const_bytes_span b )
{
  if ( a.size() != b.size() ) {
    return false;
  }
  uint8_t diff = 0;
  for ( std::size_t i = 0; i < a.size(); ++i ) {
    diff |= ( a[i] ^ b[i] );
  }
  return diff == 0;
}

/**
 * @brief Safely copies data from src to dst with bounds checking.
 * @throws std::out_of_range if destination span is too small.
 */
inline void copy_to( const_bytes_span src, bytes_span dst )
{
  if ( src.size() > dst.size() ) {
    throw std::out_of_range( "[Refract] copy_to: source too large for destination!" );
  }
  std::ranges::copy( src, dst.begin() );
}

/**
 * @brief Safely get a subspan from a mutable span with bounds checking.
 * @throws std::out_of_range if offset is out of bounds.
 */
constexpr bytes_span safe_subspan( bytes_span buffer, std::size_t offset, std::size_t count = std::dynamic_extent )
{
  if ( offset > buffer.size() ) {
    throw std::out_of_range( "[Refract] safe_subspan: offset out of bounds!" );
  }

  return buffer.subspan( offset, count );
}

/**
 * @brief Safely get a subspan from a const span with bounds checking.
 * @throws std::out_of_range if offset is out of bounds.
 */
constexpr const_bytes_span safe_subspan( const_bytes_span buffer,
                                         std::size_t offset,
                                         std::size_t count = std::dynamic_extent )
{
  if ( offset > buffer.size() ) {
    throw std::out_of_range( "[Refract] safe_subspan: offset out of bounds!" );
  }

  return buffer.subspan( offset, count );
}

/**
 * @brief View any trivial/POD-like object as a constant byte span.
 */
template<typename T>
const_bytes_span as_bytes( const T& obj )
{
  static_assert( std::is_standard_layout_v<T> && std::is_trivially_default_constructible_v<T>
                   && std::is_trivially_copyable_v<T>,
                 "Object must be standard layout and trivial to be viewed as bytes." );
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return std::span { reinterpret_cast<const uint8_t*>( &obj ), sizeof( T ) };
}

/**
 * @brief View any trivial/POD-like object as a writable byte span.
 */
template<typename T>
bytes_span as_writable_bytes( T& obj )
{
  static_assert( std::is_standard_layout_v<T> && std::is_trivially_default_constructible_v<T>
                   && std::is_trivially_copyable_v<T> && !std::is_const_v<T>,
                 "Object must be non-const, standard layout and trivial to be viewed as bytes." );
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return std::span { reinterpret_cast<uint8_t*>( &obj ), sizeof( T ) };
}

/**
 * @brief Convert a byte span to a lowercase hexadecimal string.
 */
inline std::string to_hex( const_bytes_span data )
{
  static constexpr std::string_view hex_chars = "0123456789abcdef";
  std::string res;
  res.reserve( data.size() * 2 );
  for ( const uint8_t b : data ) {
    res.push_back( hex_chars[( b >> 4 ) & 0x0F] );
    res.push_back( hex_chars[b & 0x0F] );
  }
  return res;
}

/**
 * @brief Populates a byte span from a hexadecimal string.
 * @return The number of bytes written.
 * @throws std::invalid_argument if hex string is malformed.
 * @throws std::out_of_range if destination span is too small.
 */
inline std::size_t from_hex( std::string_view hex, bytes_span dst )
{
  if ( hex.length() % 2 != 0 ) {
    throw std::invalid_argument( "[Refract] from_hex: hex string must have even length!" );
  }

  const std::size_t byte_count = hex.length() / 2;
  if ( dst.size() < byte_count ) {
    throw std::out_of_range( "[Refract] from_hex: destination span too small!" );
  }

  auto hex_to_int = []( char c ) -> uint8_t {
    if ( c >= '0' && c <= '9' ) {
      return static_cast<uint8_t>( c - '0' );
    }
    if ( c >= 'a' && c <= 'f' ) {
      return static_cast<uint8_t>( c - 'a' + 10 );
    }
    if ( c >= 'A' && c <= 'F' ) {
      return static_cast<uint8_t>( c - 'A' + 10 );
    }
    throw std::invalid_argument( "[Refract] from_hex: invalid hex character!" );
  };

  for ( std::size_t i = 0; i < byte_count; ++i ) {
    const auto high = static_cast<uint8_t>( hex_to_int( hex[i * 2] ) << 4 );
    const auto low = hex_to_int( hex[( i * 2 ) + 1] );
    dst[i] = high | low;
  }
  return byte_count;
}

} // namespace refract