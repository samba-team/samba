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
 Interface to the (hopefully) good crypto random number generator.
 Will use our internal PRNG if more than 40 bytes of random generation
 has been requested, otherwise tries to read from /dev/random
**/
void generate_random_buffer(uint8_t *out, int len);

/**
 Interface to the (hopefully) good crypto random number generator.
 Will always use /dev/urandom if available.
**/
void generate_secret_buffer(uint8_t *out, int len);
