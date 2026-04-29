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

#include "internal/mem_wipe.hh"
#include "internal/sha256_impl.hh"
#include <algorithm>
#include <bit>
#include <cstring>
#include <refract/sha256.hh>
#include <refract/span_utils.hh>

namespace refract::internal {

namespace {

using ProcessBlockFunc = void ( * )( std::span<uint32_t, 8>, std::span<const uint8_t, 64> );

ProcessBlockFunc resolve_dispatcher()
{
#if defined( __x86_64__ ) || defined( _M_X64 )
  __builtin_cpu_init();
  if ( __builtin_cpu_supports( "sha" ) ) {
    return sha256_process_block_ni;
  }
#endif
  return sha256_process_block_generic;
}

ProcessBlockFunc get_process_block()
{
  static ProcessBlockFunc func = resolve_dispatcher();
  return func;
}

} // namespace

} // namespace refract::internal

namespace refract {

Sha256::Sha256()
  : state_ { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }
{}

Sha256::~Sha256()
{
  internal::mem_wipe( state_ );
  internal::mem_wipe( buffer_ );
}

void Sha256::process_block( std::span<uint32_t, 8> state, std::span<const uint8_t, BLOCK_SIZE> block )
{
  internal::get_process_block()( state, block );
}

void Sha256::update( const_bytes_span data )
{
  if ( finalized_ ) {
    return;
  }

  const size_t offset = total_bytes_ % BLOCK_SIZE;
  total_bytes_ += data.size();

  if ( offset > 0 ) {
    const size_t chunk = std::min( data.size(), BLOCK_SIZE - offset );
    std::memcpy( std::span( buffer_ ).subspan( offset, chunk ).data(), data.data(), chunk );
    data = data.subspan( chunk );
    if ( ( offset + chunk ) % BLOCK_SIZE == 0 ) {
      process_block( state_, buffer_ );
    }
  }

  while ( data.size() >= BLOCK_SIZE ) {
    process_block( state_, data.first<BLOCK_SIZE>() );
    data = data.subspan( BLOCK_SIZE );
  }

  if ( !data.empty() ) {
    std::memcpy( buffer_.data(), data.data(), data.size() );
  }
}

Sha256::Digest Sha256::finalize()
{
  if ( !finalized_ ) {
    const uint64_t bit_len = total_bytes_ * 8;
    const uint8_t pad = 0x80;
    update( { &pad, 1 } );

    while ( total_bytes_ % BLOCK_SIZE != 56 ) {
      const uint8_t zero = 0x00;
      update( { &zero, 1 } );
    }

    const uint64_t be_len = std::byteswap( bit_len );
    update( refract::as_bytes( be_len ) );
    finalized_ = true;
  }

  Digest res;
  auto state_span = std::span( state_ );
  for ( size_t i = 0; i < 8; ++i ) {
    uint32_t word = std::byteswap( state_span[i] );
    std::memcpy( std::span( res ).subspan( i * 4, 4 ).data(), &word, 4 );
  }
  return res;
}

Sha256::Digest Sha256::hash( const_bytes_span data )
{
  Sha256 ctx;
  ctx.update( data );
  return ctx.finalize();
}

bool Sha256::verify( const_bytes_span data, const Digest& expected )
{
  return secure_compare( hash( data ), expected );
}

} // namespace refract
