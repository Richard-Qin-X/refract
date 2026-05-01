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

#include "refract/big_int.hh"
#include "internal/mem_wipe.hh"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#if defined( __linux__ )
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined( _WIN32 )
#include <bcrypt.h>
#include <windows.h>
#elif defined( __APPLE__ ) || defined( __FreeBSD__ ) || defined( __OpenBSD__ )
#include <stdlib.h> // arc4random_buf
#endif

namespace refract {

namespace {

int char_to_digit( char c )
{
  if ( c >= '0' && c <= '9' ) {
    return c - '0';
  }
  if ( c >= 'a' && c <= 'z' ) {
    return c - 'a' + 10;
  }
  if ( c >= 'A' && c <= 'Z' ) {
    return c - 'A' + 10;
  }
  return -1;
}

std::pair<int, std::string_view> resolve_base( std::string_view str, int base )
{
  if ( base != 0 ) {
    return { base, str };
  }

  if ( str.size() >= 2 && str[0] == '0' ) {
    const char prefix = str[1];
    if ( prefix == 'x' || prefix == 'X' ) {
      return { 16, str.substr( 2 ) };
    }
    if ( prefix == 'b' || prefix == 'B' ) {
      return { 2, str.substr( 2 ) };
    }
    return { 8, str.substr( 1 ) };
  }
  return { 10, str };
}

} // namespace

void OSRandom::next_bytes( std::span<uint8_t> buffer )
{
  if ( buffer.empty() ) {
    return;
  }

#if defined( __linux__ )
  size_t offset = 0;
  const size_t len = buffer.size();

  while ( offset < len ) {
#if defined( SYS_getrandom )
    ssize_t ret = syscall( SYS_getrandom, buffer.subspan( offset ).data(), len - offset, 0 );
#else
    ssize_t ret = -1;
    errno = ENOSYS;
#endif

    if ( ret < 0 ) {
      if ( errno == EINTR ) {
        continue;
      }

      const int fd = open( "/dev/urandom", O_RDONLY | O_CLOEXEC );
      if ( fd == -1 ) {
        throw std::runtime_error( "OSRandom: Failed to open /dev/urandom fallback" );
      }

      while ( offset < len ) {
        ret = read( fd, buffer.subspan( offset ).data(), len - offset );
        if ( ret <= 0 ) {
          if ( ret == -1 && errno == EINTR ) {
            continue;
          }
          close( fd );
          throw std::runtime_error( "OSRandom: Failed to read from /dev/urandom" );
        }
        offset += static_cast<size_t>( ret );
      }
      close( fd );
      return;
    }
    offset += static_cast<size_t>( ret );
  }

#elif defined( _WIN32 )
  size_t offset = 0;
  const size_t len = buffer.size();

  while ( offset < len ) {
    const size_t chunk_size = std::min( len - offset, static_cast<size_t>( 0xFFFFFFFFUL ) );

    if ( !BCRYPT_SUCCESS( BCryptGenRandom(
           NULL, buffer.data() + offset, static_cast<ULONG>( chunk_size ), BCRYPT_USE_SYSTEM_PREFERRED_RNG ) ) ) {
      throw std::runtime_error( "OSRandom: BCryptGenRandom failed" );
    }
    offset += chunk_size;
  }

#elif defined( __APPLE__ ) || defined( __FreeBSD__ ) || defined( __OpenBSD__ )
  arc4random_buf( buffer.data(), buffer.size() );

#else
  throw std::runtime_error( "OSRandom: Unsupported OS for cryptographic random generation" );
#endif
}

uint8_t RandomNumberGenerator::next_u8()
{
  std::array<uint8_t, 1> b {};
  next_bytes( b );
  return b[0];
}

uint32_t RandomNumberGenerator::next_u32()
{
  std::array<uint8_t, 4> b {};
  next_bytes( b );
  return static_cast<uint32_t>( b[0] ) | ( static_cast<uint32_t>( b[1] ) << 8 )
         | ( static_cast<uint32_t>( b[2] ) << 16 ) | ( static_cast<uint32_t>( b[3] ) << 24 );
}

uint64_t RandomNumberGenerator::next_u64()
{
  std::array<uint8_t, 8> b {};
  next_bytes( b );
  return static_cast<uint64_t>( b[0] ) | ( static_cast<uint64_t>( b[1] ) << 8 )
         | ( static_cast<uint64_t>( b[2] ) << 16 ) | ( static_cast<uint64_t>( b[3] ) << 24 )
         | ( static_cast<uint64_t>( b[4] ) << 32 ) | ( static_cast<uint64_t>( b[5] ) << 40 )
         | ( static_cast<uint64_t>( b[6] ) << 48 ) | ( static_cast<uint64_t>( b[7] ) << 56 );
}

bool RandomNumberGenerator::next_bool()
{
  return ( next_u8() & 1 ) != 0;
}

BigInt::BigInt( int64_t val )
{
  if ( val == 0 ) {
    return;
  }

  if ( val > 0 ) {
    limbs_.assign( 1, static_cast<uint64_t>( val ) );
    sign_ = Sign::Positive;
  } else {
    limbs_.assign( 1, static_cast<uint64_t>( -val ) );
    sign_ = Sign::Negative;
  }
}

BigInt::BigInt( uint64_t val )
{
  if ( val == 0 ) {
    return;
  }

  limbs_.assign( 1, val );
  sign_ = Sign::Positive;
}

BigInt::BigInt( Sign s, std::vector<uint64_t> limbs )
{
  if ( limbs.empty() ) {
    sign_ = Sign::Zero;
    return;
  }

  limbs_ = std::move( limbs );
  sign_ = s;
  trim();
}

BigInt::BigInt( std::string_view str, int base )
{
  if ( str.empty() ) {
    sign_ = Sign::Zero;
    return;
  }

  if ( str[0] == '-' ) {
    sign_ = Sign::Negative;
    str = str.substr( 1 );
  } else {
    sign_ = Sign::Positive;
    if ( !str.empty() && str[0] == '+' ) {
      str = str.substr( 1 );
    }
  }

  if ( str.empty() ) {
    sign_ = Sign::Zero;
    return;
  }

  auto [actual_base, content] = resolve_base( str, base );
  if ( actual_base < 2 || actual_base > 36 ) {
    sign_ = Sign::Zero;
    return;
  }

  for ( const char c : content ) {
    const int digit = char_to_digit( c );
    if ( digit == -1 || digit >= actual_base ) {
      break;
    }

    this->mul_low_by_word( static_cast<uint64_t>( actual_base ) );
    *this += static_cast<uint64_t>( digit );
  }

  trim();
}

BigInt::BigInt( std::span<const uint8_t> bytes, Endian e, bool is_negative )
{
  if ( bytes.empty() ) {
    sign_ = Sign::Zero;
    return;
  }

  sign_ = is_negative ? Sign::Negative : Sign::Positive;

  const size_t n = bytes.size();
  const size_t limb_count = ( n + 7 ) / 8;
  limbs_.resize( limb_count );

  if ( e == Endian::Big ) {
    for ( size_t i = 0; i < n; ++i ) {
      const uint8_t byte = bytes[n - 1 - i];
      const size_t limb_idx = i / 8;
      const size_t bit_shift = ( i % 8 ) * 8;
      limbs_[limb_idx] |= static_cast<uint64_t>( byte ) << bit_shift;
    }
  } else {
    for ( size_t i = 0; i < n; ++i ) {
      const uint8_t byte = bytes[i];
      const size_t limb_idx = i / 8;
      const size_t bit_shift = ( i % 8 ) * 8;
      limbs_[limb_idx] |= static_cast<uint64_t>( byte ) << bit_shift;
    }
  }

  trim();
}

BigInt::~BigInt()
{
  internal::mem_wipe( limbs_ );
}

BigInt::Sign BigInt::sign() const
{
  return sign_;
}

bool BigInt::is_negative() const
{
  return sign_ == Sign::Negative;
}

bool BigInt::is_positive() const
{
  return sign_ == Sign::Positive;
}

bool BigInt::is_zero() const
{
  return sign_ == Sign::Zero;
}

bool BigInt::is_one() const
{
  return ( limbs_.size() == 1 && limbs_[0] == 1 && sign_ == Sign::Positive );
}

bool BigInt::is_odd() const
{
  return !limbs_.empty() && ( limbs_[0] & 1 ) == 1;
}

bool BigInt::is_even() const
{
  return limbs_.empty() || ( limbs_[0] & 1 ) == 0;
}

void BigInt::set_sign( Sign s )
{
  sign_ = ( limbs_.empty() && s != Sign::Zero ) ? Sign::Zero : s;
}

BigInt BigInt::abs() const
{
  BigInt result = *this;
  result.sign_ = ( result.sign_ == Sign::Negative ) ? Sign::Positive : result.sign_;
  return result;
}

BigInt BigInt::negate() const
{
  BigInt result = *this;
  switch ( result.sign_ ) {
    case Sign::Negative:
      result.sign_ = Sign::Positive;
      break;
    case Sign::Positive:
      result.sign_ = Sign::Negative;
      break;
    default:
      result.sign_ = Sign::Zero;
      break;
  }
  return result;
}

BigInt BigInt::operator-() const
{
  return negate();
}

size_t BigInt::bit_length() const
{
  if ( limbs_.empty() ) {
    return 0;
  }
  const size_t num_limbs = limbs_.size();
  const uint64_t last_limb = limbs_.back();
  return ( ( num_limbs - 1 ) * 64 ) + ( 64 - __builtin_clzll( last_limb ) );
}

size_t BigInt::byte_length() const
{
  return ( bit_length() + 7 ) / 8;
}

size_t BigInt::limb_count() const
{
  return limbs_.size();
}

uint64_t BigInt::get_limb( size_t index ) const
{
  return index < limbs_.size() ? limbs_[index] : 0;
}

BigInt& BigInt::operator+=( const BigInt& other )
{
  if ( other.is_zero() ) {
    return *this;
  }

  if ( sign_ == Sign::Zero ) {
    *this = other;
    return *this;
  }

  if ( sign_ == other.sign_ ) {
    add_magnitude( other );
    return *this;
  }

  const int cmp = cmp_magnitude( other );
  if ( cmp == 0 ) {
    sign_ = Sign::Zero;
    limbs_.clear();
    return *this;
  }

  if ( cmp > 0 ) {
    sub_magnitude( other );
    return *this;
  }

  BigInt temp = other;
  temp.sub_magnitude( *this );

  limbs_ = std::move( temp.limbs_ );
  sign_ = temp.sign_;

  return *this;
}

BigInt& BigInt::operator-=( const BigInt& other )
{
  if ( other.is_zero() ) {
    return *this;
  }

  if ( sign_ == Sign::Zero ) {
    *this = other;
    sign_ = ( other.sign_ == Sign::Negative ) ? Sign::Positive : Sign::Negative;
    return *this;
  }

  if ( sign_ != other.sign_ ) {
    add_magnitude( other );
    return *this;
  }

  const int cmp = cmp_magnitude( other );
  if ( cmp == 0 ) {
    sign_ = Sign::Zero;
    limbs_.clear();
    return *this;
  }

  if ( cmp > 0 ) {
    sub_magnitude( other );
    return *this;
  }

  BigInt temp = other;
  temp.sub_magnitude( *this );

  limbs_ = std::move( temp.limbs_ );
  sign_ = ( other.sign_ == Sign::Negative ) ? Sign::Positive : Sign::Negative;

  return *this;
}

void BigInt::reserve( size_t bits )
{
  limbs_.reserve( ( bits + 63 ) / 64 );
}

const BigInt& BigInt::zero()
{
  static const BigInt zero_;
  return zero_;
}

const BigInt& BigInt::one()
{
  static const BigInt one_ { Sign::Positive, { 1 } };
  return one_;
}

void BigInt::trim()
{
  size_t n = limbs_.size();
  while ( n > 0 && limbs_[n - 1] == 0 ) {
    --n;
  }

  if ( n != limbs_.size() ) {
    limbs_.resize( n );
  }

  if ( n == 0 ) {
    sign_ = Sign::Zero;
  }
}

void BigInt::pad_to( size_t target_limbs )
{
  if ( target_limbs > limbs_.size() ) {
    limbs_.resize( target_limbs, 0 );
  }
}

void BigInt::zeroify()
{
  internal::mem_wipe( limbs_ );
  limbs_.clear();
  sign_ = Sign::Zero;
}

int BigInt::cmp_magnitude( const BigInt& other ) const
{
  const size_t a = limbs_.size();
  const size_t b = other.limbs_.size();

  if ( a != b ) {
    return a > b ? 1 : -1;
  }

  for ( size_t i = a; i > 0; --i ) {
    const size_t idx = i - 1;
    if ( limbs_[idx] != other.limbs_[idx] ) {
      return limbs_[idx] > other.limbs_[idx] ? 1 : -1;
    }
  }

  return 0;
}

void BigInt::add_magnitude( const BigInt& other )
{
  const size_t n2 = other.limbs_.size();
  if ( n2 == 0 ) {
    return;
  }

  if ( limbs_.size() < n2 ) {
    limbs_.resize( n2, 0 );
  }

  const size_t n = limbs_.size();

  uint64_t carry = 0;
  size_t i = 0;

  for ( ; i < n2; i++ ) {
    const __uint128_t sum = ( static_cast<__uint128_t>( limbs_[i] ) + static_cast<__uint128_t>( other.limbs_[i] ) )
                            + static_cast<__uint128_t>( carry );
    limbs_[i] = static_cast<uint64_t>( sum );
    carry = static_cast<uint64_t>( sum >> 64 );
  }

  for ( ; i < n && carry != 0; i++ ) {
    const __uint128_t sum = static_cast<__uint128_t>( limbs_[i] ) + static_cast<__uint128_t>( carry );
    limbs_[i] = static_cast<uint64_t>( sum );
    carry = static_cast<uint64_t>( sum >> 64 );
  }

  if ( carry != 0 ) {
    limbs_.push_back( carry );
  }
}

void BigInt::sub_magnitude( const BigInt& other )
{
  uint64_t borrow = 0;
  const size_t n2 = other.limbs_.size();
  const size_t n1 = limbs_.size();

  for ( size_t i = 0; i < n1; ++i ) {
    const uint64_t l2 = ( i < n2 ) ? other.limbs_[i] : 0;
    const __uint128_t diff = static_cast<__uint128_t>( limbs_[i] ) - l2 - borrow;
    limbs_[i] = static_cast<uint64_t>( diff );
    borrow = ( diff >> 64 ) ? 1 : 0;
  }

  trim();
}

void BigInt::lshift_limbs( size_t words )
{
  if ( words == 0 || is_zero() ) {
    return;
  }

  limbs_.insert( limbs_.begin(), words, 0 );
}

void BigInt::rshift_limbs( size_t words )
{
  if ( words == 0 ) {
    return;
  }

  if ( words >= limbs_.size() ) {
    limbs_.clear();
    sign_ = Sign::Zero;
    return;
  }

  limbs_.erase( limbs_.begin(), limbs_.begin() + static_cast<std::ptrdiff_t>( words ) );

  if ( limbs_.empty() ) {
    sign_ = Sign::Zero;
  }
}

void BigInt::lshift_bits( size_t bits )
{
  if ( bits == 0 || is_zero() ) {
    return;
  }

  const size_t words = bits / 64;
  const size_t shift = bits % 64;

  if ( words > 0 ) {
    lshift_limbs( words );
  }

  if ( shift > 0 ) {
    uint64_t carry = 0;
    for ( uint64_t& limb : limbs_ ) {
      const uint64_t next_carry = limb >> ( 64 - shift );
      limb = ( limb << shift ) | carry;
      carry = next_carry;
    }
    if ( carry > 0 ) {
      limbs_.push_back( carry );
    }
  }
}

void BigInt::rshift_bits( size_t bits )
{
  if ( bits == 0 || is_zero() ) {
    return;
  }

  const size_t words = bits / 64;
  const size_t shift = bits % 64;

  if ( words > 0 ) {
    rshift_limbs( words );
    if ( is_zero() ) {
      return;
    }
  }

  if ( shift > 0 ) {
    uint64_t borrow = 0;
    for ( size_t i = limbs_.size(); i > 0; --i ) {
      const size_t idx = i - 1;
      const uint64_t next_borrow = limbs_[idx] << ( 64 - shift );
      limbs_[idx] = ( limbs_[idx] >> shift ) | borrow;
      borrow = next_borrow;
    }
    trim();
  }
}

void BigInt::mul_low_by_word( uint64_t word )
{
  if ( word == 0 || limbs_.empty() ) {
    limbs_.clear();
    sign_ = Sign::Zero;
    return;
  }

  if ( word == 1 ) {
    return;
  }

  uint64_t carry = 0;
  const size_t n = limbs_.size();

  for ( size_t i = 0; i < n; i++ ) {
    const __uint128_t prod = ( static_cast<__uint128_t>( limbs_[i] ) * word ) + static_cast<__uint128_t>( carry );
    limbs_[i] = static_cast<uint64_t>( prod );
    carry = static_cast<uint64_t>( prod >> 64 );
  }

  if ( carry != 0 ) {
    limbs_.push_back( carry );
  }
}

void BigInt::mul_high_by_word( uint64_t word, uint64_t* carry )
{
  if ( word == 0 ) {
    limbs_.clear();
    sign_ = Sign::Zero;
    if ( carry ) {
      *carry = 0;
    }
    return;
  }

  uint64_t c = ( carry ) ? *carry : 0;
  for ( auto& limb : limbs_ ) {
    const __uint128_t prod = ( static_cast<__uint128_t>( limb ) * word ) + c;
    limb = static_cast<uint64_t>( prod );
    c = static_cast<uint64_t>( prod >> 64 );
  }

  if ( carry ) {
    *carry = c;
  }
  if ( c ) {
    limbs_.push_back( c );
  }
}

void BigInt::div_qr_word( uint64_t divisor, uint64_t* remainder )
{
  if ( divisor == 0 ) {
    throw std::domain_error( "refract::BigInt::div_qr_word: division by zero" );
  }

  if ( limbs_.empty() ) {
    if ( remainder ) {
      *remainder = 0;
    }
    return;
  }

  uint64_t r = 0;
  for ( size_t i = limbs_.size(); i > 0; --i ) {
    const size_t idx = i - 1;
    const __uint128_t temp = ( static_cast<__uint128_t>( r ) << 64 ) | limbs_[idx];
    limbs_[idx] = static_cast<uint64_t>( temp / divisor );
    r = static_cast<uint64_t>( temp % divisor );
  }

  if ( remainder ) {
    *remainder = r;
  }

  trim();
}

} // namespace refract