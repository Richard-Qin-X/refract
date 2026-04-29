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

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>

#include "../../internal/mem_wipe.hh"
#include "../../internal/sha256_impl.hh"

namespace refract::internal {

namespace {

inline uint32_t ch( uint32_t x, uint32_t y, uint32_t z )
{
  return ( x & y ) ^ ( ~x & z );
}
inline uint32_t maj( uint32_t x, uint32_t y, uint32_t z )
{
  return ( x & y ) ^ ( x & z ) ^ ( y & z );
}
inline uint32_t ep0( uint32_t x )
{
  return std::rotr( x, 2 ) ^ std::rotr( x, 13 ) ^ std::rotr( x, 22 );
}
inline uint32_t ep1( uint32_t x )
{
  return std::rotr( x, 6 ) ^ std::rotr( x, 11 ) ^ std::rotr( x, 25 );
}
inline uint32_t sig0( uint32_t x )
{
  return std::rotr( x, 7 ) ^ std::rotr( x, 18 ) ^ ( x >> 3 );
}
inline uint32_t sig1( uint32_t x )
{
  return std::rotr( x, 17 ) ^ std::rotr( x, 19 ) ^ ( x >> 10 );
}

constexpr std::array<uint32_t, 64> K
  = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
} // namespace

void sha256_process_block_generic( std::span<uint32_t, 8> state, std::span<const uint8_t, 64> block )
{
  std::array<uint32_t, 64> w {};
  auto w_span = std::span( w );
  auto k_span = std::span( K );

  for ( size_t i = 0; i < 16; ++i ) {
    uint32_t word = 0;
    std::memcpy( &word, block.subspan( i * 4, 4 ).data(), 4 );
    w_span[i] = std::byteswap( word );
  }

  for ( size_t i = 16; i < 64; ++i ) {
    w_span[i] = w_span[i - 16] + sig0( w_span[i - 15] ) + w_span[i - 7] + sig1( w_span[i - 2] );
  }

  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];
  uint32_t f = state[5];
  uint32_t g = state[6];
  uint32_t h = state[7];

  for ( size_t i = 0; i < 64; ++i ) {
    const uint32_t T1 = h + ep1( e ) + ch( e, f, g ) + k_span[i] + w_span[i];
    const uint32_t T2 = ep0( a ) + maj( a, b, c );
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;

  mem_wipe( w );
}

} // namespace refract::internal