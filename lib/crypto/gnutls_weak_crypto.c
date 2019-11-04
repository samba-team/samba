/*
 * Copyright (c) 2019      Andreas Schneider <asn@samba.org>
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/crypto/gnutls_helpers.h"

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

bool samba_gnutls_weak_crypto_allowed(void)
{
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t key = {
		.data = discard_const_p(unsigned char, "SystemLibraryDTC"),
		.size = 16,
	};
	int rc;

	/*
	 * If RC4 is not allowed to be initialzed then weak crypto is not
	 * allowed.
	 */
	rc = gnutls_cipher_init(&cipher_hnd,
				GNUTLS_CIPHER_ARCFOUR_128,
				&key,
				NULL);
	if (rc == GNUTLS_E_UNWANTED_ALGORITHM) {
		return false;
	}

	gnutls_cipher_deinit(cipher_hnd);

	return true;
}
