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

#include <cstdint>
#include <span>

namespace refract::internal {

/**
 * @brief Generic C++ implementation of the SHA-256 compression function.
 */
void sha256_process_block_generic( std::span<uint32_t, 8> state, std::span<const uint8_t, 64> block );

#if defined( __x86_64__ ) || defined( _M_X64 )
/**
 * @brief Intel SHA-NI accelerated implementation of the SHA-256 compression function.
 */
void sha256_process_block_ni( std::span<uint32_t, 8> state, std::span<const uint8_t, 64> block );
#endif

} // namespace refract::internal
