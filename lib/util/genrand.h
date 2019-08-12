/*
   Unix SMB/CIFS implementation.

   Functions to create reasonable random numbers for crypto use.

   Copyright (C) Jeremy Allison 2001

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @brief Generate random values for session and temporary keys.
 *
 * @param[in]  out  A pointer to the buffer to fill with random data.
 *
 * @param[in]  len  The size of the buffer to fill.
 */
void generate_random_buffer(uint8_t *out, int len);

/**
 * @brief Generate random values for long term keys and passwords.
 *
 * @param[in]  out  A pointer to the buffer to fill with random data.
 *
 * @param[in]  len  The size of the buffer to fill.
 */
void generate_secret_buffer(uint8_t *out, int len);

/**
 * @brief Generate random values for a nonce buffer.
 *
 * This is also known as initialization vector.
 *
 * @param[in]  out  A pointer to the buffer to fill with random data.
 *
 * @param[in]  len  The size of the buffer to fill.
 */
void generate_nonce_buffer(uint8_t *out, int len);
