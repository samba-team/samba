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
#include "lib/util/fault.h"
#include "lib/util/genrand.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/*
 * Details about the GnuTLS CSPRNG:
 *
 * https://nikmav.blogspot.com/2017/03/improving-by-simplifying-gnutls-prng.html
 */


_NORETURN_ static void genrand_panic(int err,
				     const char *location,
				     const char *func)
{
	char buf[200];
	snprintf(buf, sizeof(buf),
		 "%s:%s: GnuTLS could not generate a random buffer: %s [%d]\n",
		 location, func, gnutls_strerror_name(err), err);
	smb_panic(buf);
}


_PUBLIC_ void generate_random_buffer(uint8_t *out, size_t len)
{
	/* Random number generator for temporary keys. */
	int ret = gnutls_rnd(GNUTLS_RND_RANDOM, out, len);
	if (ret != 0) {
		genrand_panic(ret, __location__, __func__);
	}
}

_PUBLIC_ void generate_secret_buffer(uint8_t *out, size_t len)
{
	/*
	 * Random number generator for long term keys.
	 *
	 * The key generator, will re-seed after a fixed amount of bytes is
	 * generated (typically less than the nonce), and will also re-seed
	 * based on time, i.e., after few hours of operation without reaching
	 * the limit for a re-seed. For its re-seed it mixes data obtained
	 * from the OS random device with the previous key.
	 */
	int ret = gnutls_rnd(GNUTLS_RND_KEY, out, len);
	if (ret != 0) {
		genrand_panic(ret, __location__, __func__);
	}
}

_PUBLIC_ void generate_nonce_buffer(uint8_t *out, size_t len)
{
	/*
	 * Random number generator for nonce and initialization vectors.
	 *
	 * The nonce generator will reseed after outputting a fixed amount of
	 * bytes (typically few megabytes), or after few hours of operation
	 * without reaching the limit has passed.
	 */
	int ret = gnutls_rnd(GNUTLS_RND_NONCE, out, len);
	if (ret != 0) {
		genrand_panic(ret, __location__, __func__);
	}
}
