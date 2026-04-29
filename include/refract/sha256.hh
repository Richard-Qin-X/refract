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

#include "span_utils.hh"
#include <array>
#include <cstdint>
#include <span>

namespace refract {

class Sha256
{
public:
  static const size_t BLOCK_SIZE = 64;
  static const size_t HASH_SIZE = 32;

  using Digest = std::array<uint8_t, HASH_SIZE>;

  Sha256();
  ~Sha256();

  Sha256( const Sha256& ) = delete;
  Sha256& operator=( const Sha256& ) = delete;

  Sha256( Sha256&& ) noexcept = default;
  Sha256& operator=( Sha256&& ) noexcept = default;

  void update( const_bytes_span data );
  Digest finalize();

  static Digest hash( const_bytes_span data );
  static bool verify( const_bytes_span data, const Digest& expected );

private:
  static void process_block( std::span<uint32_t, 8> state, std::span<const uint8_t, BLOCK_SIZE> block );

  std::array<uint32_t, 8> state_;
  std::array<uint8_t, BLOCK_SIZE> buffer_ {};
  uint64_t total_bytes_ { 0 };
  bool finalized_ { false };
};

} // namespace refract