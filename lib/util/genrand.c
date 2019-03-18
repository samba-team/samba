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

#include "replace.h"
#include "lib/util/genrand.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/* TODO: Add API for generating nonce or use gnutls_rnd directly everywhere. */

_PUBLIC_ void generate_random_buffer(uint8_t *out, int len)
{
	/* Thread and fork safe random number generator for temporary keys. */
	gnutls_rnd(GNUTLS_RND_RANDOM, out, len);
}

/*
 * Keep generate_secret_buffer in case we ever want to do something
 * different
 */
_PUBLIC_ void generate_secret_buffer(uint8_t *out, int len)
{
	/* Thread and fork safe random number generator for long term keys. */
	gnutls_rnd(GNUTLS_RND_KEY, out, len);
}
