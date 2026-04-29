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

#include <compare>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace refract {

class RandomNumberGenerator;

// Endianness definition for serialization/deserialization
enum class Endian : uint8_t { Big, Little };

class BigInt {
public:
  enum class Sign : int8_t { Negative = -1, Zero = 0, Positive = 1 };

  // Constructors & Factory Methods
  BigInt() = default;
  explicit BigInt( int64_t val );
  explicit BigInt( uint64_t val );
  explicit BigInt( Sign s, std::vector<uint64_t> limbs );
  explicit BigInt( std::string_view str, int base = 10 );
  
  // Endian-aware constructor from byte stream
  explicit BigInt( std::span<const uint8_t> bytes, Endian e = Endian::Big, bool is_negative = false );

  ~BigInt(); // Securely wipes memory

  BigInt( const BigInt& other ) = default;
  BigInt& operator=( const BigInt& other ) = default;
  BigInt( BigInt&& other ) noexcept = default;
  BigInt& operator=( BigInt&& other ) noexcept = default;

  // Secure Random Generation (CSPRNG)
  static BigInt random_bits( size_t bits, RandomNumberGenerator& rng );
  static BigInt random_integer( const BigInt& min, const BigInt& max, RandomNumberGenerator& rng );

  // Properties & Sign Management
  Sign sign() const { return sign_; }
  bool is_negative() const { return sign_ == Sign::Negative; }
  bool is_positive() const { return sign_ == Sign::Positive; }
  bool is_zero() const { return sign_ == Sign::Zero; }
  bool is_one() const;
  bool is_odd() const;
  bool is_even() const;

  void set_sign( Sign s ) { sign_ = ( limbs_.empty() && s != Sign::Zero ) ? Sign::Zero : s; }
  BigInt abs() const;
  BigInt negate() const;
  BigInt operator-() const { return negate(); }

  size_t bit_length() const;
  size_t byte_length() const;
  size_t limb_count() const { return limbs_.size(); }
  uint64_t get_limb( size_t index ) const { return index < limbs_.size() ? limbs_[index] : 0; }

  // Basic Arithmetic Operations
  BigInt& operator+=( const BigInt& other );
  BigInt& operator-=( const BigInt& other );
  BigInt& operator*=( const BigInt& other );
  BigInt& operator/=( const BigInt& other );
  BigInt& operator%=( const BigInt& other );

  friend BigInt operator+( BigInt lhs, const BigInt& rhs ) { return lhs += rhs; }
  friend BigInt operator-( BigInt lhs, const BigInt& rhs ) { return lhs -= rhs; }
  friend BigInt operator*( BigInt lhs, const BigInt& rhs ) { return lhs *= rhs; }
  friend BigInt operator/( BigInt lhs, const BigInt& rhs ) { return lhs /= rhs; }
  friend BigInt operator%( BigInt lhs, const BigInt& rhs ) { return lhs %= rhs; }

  static std::pair<BigInt, BigInt> div_qr( const BigInt& dividend, const BigInt& divisor );
  BigInt square() const;
  BigInt sqrt() const;

  // Word-level Fast-paths
  BigInt& operator+=( uint64_t word );
  BigInt& operator-=( uint64_t word );
  BigInt& operator*=( uint64_t word );
  BigInt& operator/=( uint64_t word );
  BigInt& operator%=( uint64_t word );

  friend BigInt operator+( BigInt lhs, uint64_t rhs ) { return lhs += rhs; }
  friend BigInt operator-( BigInt lhs, uint64_t rhs ) { return lhs -= rhs; }
  friend BigInt operator*( BigInt lhs, uint64_t rhs ) { return lhs *= rhs; }
  friend BigInt operator/( BigInt lhs, uint64_t rhs ) { return lhs /= rhs; }
  friend BigInt operator%( BigInt lhs, uint64_t rhs ) { return lhs %= rhs; }

  static std::pair<BigInt, uint64_t> div_qr( const BigInt& dividend, uint64_t divisor );

  // Modular Arithmetic
  static BigInt nnmod( const BigInt& a, const BigInt& mod ); // Non-negative modulo
  
  static BigInt mod_add( const BigInt& a, const BigInt& b, const BigInt& mod );
  static BigInt mod_sub( const BigInt& a, const BigInt& b, const BigInt& mod );
  static BigInt mod_mul( const BigInt& a, const BigInt& b, const BigInt& mod );
  static BigInt mod_sqr( const BigInt& a, const BigInt& mod );
  static BigInt mod_pow( const BigInt& base, const BigInt& exp, const BigInt& mod );
  static BigInt mod_inverse( const BigInt& a, const BigInt& n );
  static BigInt mod_sqrt( const BigInt& a, const BigInt& p );

  // Bitwise Operations & Shifting
  bool test_bit( size_t n ) const;
  void set_bit( size_t n );
  void clear_bit( size_t n );
  void flip_bit( size_t n );
  size_t scan_first_set() const;

  BigInt& operator<<=( size_t shift );
  BigInt& operator>>=( size_t shift );
  BigInt& operator&=( const BigInt& other );
  BigInt& operator|=( const BigInt& other );
  BigInt& operator^=( const BigInt& other );
  BigInt operator~() const;

  friend BigInt operator<<( BigInt lhs, size_t shift ) { return lhs <<= shift; }
  friend BigInt operator>>( BigInt lhs, size_t shift ) { return lhs >>= shift; }

  // Number Theory Tools
  static BigInt gcd( const BigInt& a, const BigInt& b );
  static BigInt lcm( const BigInt& a, const BigInt& b );

  bool is_prime( size_t iterations = 40 ) const;
  static BigInt next_prime( const BigInt& start );

  // Constant-Time Operations (Side-channel Resistance)
  // mask must be 0x0 or 0xFF...FF
  void ct_cond_assign( uint64_t mask, const BigInt& other );
  static void ct_cond_swap( uint64_t mask, BigInt& a, BigInt& b );
  void ct_cond_negate( uint64_t mask );
  uint64_t ct_equal( const BigInt& other ) const;
  uint64_t ct_is_less_than( const BigInt& other ) const;
  uint64_t ct_is_zero() const;

  // Comparison Operations
  std::strong_ordering operator<=>( const BigInt& other ) const;
  bool operator==( const BigInt& other ) const;

  // Serialization & Utilities
  std::string to_string( int base = 10 ) const;
  
  // Fixed-length export with zero-padding (crucial for ECDSA, etc.)
  std::vector<uint8_t> to_bytes( Endian e = Endian::Big, size_t len = 0 ) const;

  void reserve( size_t bits );

  // Static Constants
  static const BigInt& zero();
  static const BigInt& one();

private:
  Sign sign_ = Sign::Zero;
  std::vector<uint64_t> limbs_{};

  void trim();

  int cmp_magnitude( const BigInt& other ) const;

  void add_magnitude( const BigInt& other );

  void sub_magnitude( const BigInt& other );

  void mul_low_by_word( uint64_t word );

  void mul_high_by_word( uint64_t word, uint64_t* carry );

  void div_qr_word( uint64_t divisor, uint64_t* remainder );

};

} // namespace refract
