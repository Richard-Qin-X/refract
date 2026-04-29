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

#include <cstdint>
#include <cstring>
#include <span>

#if defined( __x86_64__ ) || defined( _M_X64 )
#include <immintrin.h>

#include "../../internal/sha256_impl.hh"

namespace refract::internal {

// NOLINTBEGIN(portability-simd-intrinsics)

namespace {
// NOLINTBEGIN(hicpp-avoid-c-arrays, cert-err58-cpp, cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)
const __m128i K256[16]
  = { _mm_set_epi32( static_cast<int>( 0xe9b5dba5 ), static_cast<int>( 0xb5c0fbcf ), 0x71374491, 0x428a2f98 ),
      _mm_set_epi32( static_cast<int>( 0xab1c5ed5 ), static_cast<int>( 0x923f82a4 ), 0x59f111f1, 0x3956c25b ),
      _mm_set_epi32( 0x550c7dc3, 0x243185be, 0x12835b01, static_cast<int>( 0xd807aa98 ) ),
      _mm_set_epi32( static_cast<int>( 0xc19bf174 ),
                     static_cast<int>( 0x9bdc06a7 ),
                     static_cast<int>( 0x80deb1fe ),
                     0x72be5d74 ),
      _mm_set_epi32( 0x240ca1cc, 0x0fc19dc6, static_cast<int>( 0xefbe4786 ), static_cast<int>( 0xe49b69c1 ) ),
      _mm_set_epi32( 0x76f988da, 0x5cb0a9dc, 0x4a7484aa, 0x2de92c6f ),
      _mm_set_epi32( static_cast<int>( 0xbf597fc7 ),
                     static_cast<int>( 0xb00327c8 ),
                     static_cast<int>( 0xa831c66d ),
                     static_cast<int>( 0x983e5152 ) ),
      _mm_set_epi32( 0x14292967, 0x06ca6351, static_cast<int>( 0xd5a79147 ), static_cast<int>( 0xc6e00bf3 ) ),
      _mm_set_epi32( 0x53380d13, 0x4d2c6dfc, 0x2e1b2138, 0x27b70a85 ),
      _mm_set_epi32( static_cast<int>( 0x92722c85 ), static_cast<int>( 0x81c2c92e ), 0x766a0abb, 0x650a7354 ),
      _mm_set_epi32( static_cast<int>( 0xc76c51a3 ),
                     static_cast<int>( 0xc24b8b70 ),
                     static_cast<int>( 0xa81a664b ),
                     static_cast<int>( 0xa2bfe8a1 ) ),
      _mm_set_epi32( 0x106aa070,
                     static_cast<int>( 0xf40e3585 ),
                     static_cast<int>( 0xd6990624 ),
                     static_cast<int>( 0xd192e819 ) ),
      _mm_set_epi32( 0x34b0bcb5, 0x2748774c, 0x1e376c08, 0x19a4c116 ),
      _mm_set_epi32( 0x682e6ff3, 0x5b9cca4f, 0x4ed8aa4a, 0x391c0cb3 ),
      _mm_set_epi32( static_cast<int>( 0x8cc70208 ), static_cast<int>( 0x84c87814 ), 0x78a5636f, 0x748f82ee ),
      _mm_set_epi32( static_cast<int>( 0xc67178f2 ),
                     static_cast<int>( 0xbef9a3f7 ),
                     static_cast<int>( 0xa4506ceb ),
                     static_cast<int>( 0x90befffa ) ) };
// NOLINTEND(hicpp-avoid-c-arrays, cert-err58-cpp, cppcoreguidelines-avoid-c-arrays, modernize-avoid-c-arrays)

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define SHA256_4_ROUNDS( MSG, K )                                                                                  \
  TMP = _mm_add_epi32( ( MSG ), ( K ) );                                                                           \
  STATE1 = _mm_sha256rnds2_epu32( STATE1, STATE0, TMP );                                                           \
  TMP = _mm_shuffle_epi32( TMP, 0x0E );                                                                            \
  STATE0 = _mm_sha256rnds2_epu32( STATE0, STATE1, TMP );

#define SHA256_MSG_SCHED( MSG0, MSG1, MSG2, MSG3 )                                                                 \
  TMP = _mm_alignr_epi8( ( MSG3 ), ( MSG2 ), 4 );                                                                  \
  ( MSG0 ) = _mm_add_epi32( TMP, _mm_sha256msg1_epu32( ( MSG0 ), ( MSG1 ) ) );                                     \
  ( MSG0 ) = _mm_sha256msg2_epu32( ( MSG0 ), ( MSG3 ) );
// NOLINTEND(cppcoreguidelines-macro-usage)

inline __m128i load_u128( const void* ptr )
{
  __m128i res;
  std::memcpy( &res, ptr, 16 );
  return res;
}

inline void store_u128( void* ptr, __m128i val )
{
  std::memcpy( ptr, &val, 16 );
}

} // namespace

void sha256_process_block_ni( std::span<uint32_t, 8> state, std::span<const uint8_t, 64> block )
{
  __m128i XMM0 = load_u128( state.data() );
  __m128i XMM1 = load_u128( state.subspan( 4 ).data() );

  XMM0 = _mm_shuffle_epi32( XMM0, 0xB1 );
  XMM1 = _mm_shuffle_epi32( XMM1, 0xB1 );

  __m128i STATE0 = _mm_unpacklo_epi64( XMM1, XMM0 );
  __m128i STATE1 = _mm_unpackhi_epi64( XMM1, XMM0 );

  const __m128i ABEF_SAVE = STATE0;
  const __m128i CDGH_SAVE = STATE1;
  __m128i TMP;

  const __m128i shuf_mask = _mm_set_epi8( 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 );
  __m128i MSG0 = _mm_shuffle_epi8( load_u128( block.data() ), shuf_mask );
  __m128i MSG1 = _mm_shuffle_epi8( load_u128( block.subspan( 16 ).data() ), shuf_mask );
  __m128i MSG2 = _mm_shuffle_epi8( load_u128( block.subspan( 32 ).data() ), shuf_mask );
  __m128i MSG3 = _mm_shuffle_epi8( load_u128( block.subspan( 48 ).data() ), shuf_mask );

  SHA256_4_ROUNDS( MSG0, K256[0] );
  SHA256_4_ROUNDS( MSG1, K256[1] );
  SHA256_4_ROUNDS( MSG2, K256[2] );
  SHA256_4_ROUNDS( MSG3, K256[3] );

  SHA256_MSG_SCHED( MSG0, MSG1, MSG2, MSG3 );
  SHA256_4_ROUNDS( MSG0, K256[4] );
  SHA256_MSG_SCHED( MSG1, MSG2, MSG3, MSG0 );
  SHA256_4_ROUNDS( MSG1, K256[5] );
  SHA256_MSG_SCHED( MSG2, MSG3, MSG0, MSG1 );
  SHA256_4_ROUNDS( MSG2, K256[6] );
  SHA256_MSG_SCHED( MSG3, MSG0, MSG1, MSG2 );
  SHA256_4_ROUNDS( MSG3, K256[7] );

  SHA256_MSG_SCHED( MSG0, MSG1, MSG2, MSG3 );
  SHA256_4_ROUNDS( MSG0, K256[8] );
  SHA256_MSG_SCHED( MSG1, MSG2, MSG3, MSG0 );
  SHA256_4_ROUNDS( MSG1, K256[9] );
  SHA256_MSG_SCHED( MSG2, MSG3, MSG0, MSG1 );
  SHA256_4_ROUNDS( MSG2, K256[10] );
  SHA256_MSG_SCHED( MSG3, MSG0, MSG1, MSG2 );
  SHA256_4_ROUNDS( MSG3, K256[11] );

  SHA256_MSG_SCHED( MSG0, MSG1, MSG2, MSG3 );
  SHA256_4_ROUNDS( MSG0, K256[12] );
  SHA256_MSG_SCHED( MSG1, MSG2, MSG3, MSG0 );
  SHA256_4_ROUNDS( MSG1, K256[13] );
  SHA256_MSG_SCHED( MSG2, MSG3, MSG0, MSG1 );
  SHA256_4_ROUNDS( MSG2, K256[14] );
  SHA256_MSG_SCHED( MSG3, MSG0, MSG1, MSG2 );
  SHA256_4_ROUNDS( MSG3, K256[15] );

  STATE0 = _mm_add_epi32( STATE0, ABEF_SAVE );
  STATE1 = _mm_add_epi32( STATE1, CDGH_SAVE );

  const __m128i TEMP0 = _mm_unpackhi_epi64( STATE0, STATE1 );
  const __m128i TEMP1 = _mm_unpacklo_epi64( STATE0, STATE1 );

  XMM0 = _mm_shuffle_epi32( TEMP0, 0xB1 );
  XMM1 = _mm_shuffle_epi32( TEMP1, 0xB1 );

  store_u128( state.data(), XMM0 );
  store_u128( state.subspan( 4 ).data(), XMM1 );
}

} // namespace refract::internal

#endif

// NOLINTEND(portability-simd-intrinsics)