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

#ifndef _GNUTLS_HELPERS_H
#define _GNUTLS_HELPERS_H

#include <gnutls/gnutls.h>

#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"

/* Those macros are only available in GnuTLS >= 3.6.4 */
#ifndef GNUTLS_FIPS140_SET_LAX_MODE
#define GNUTLS_FIPS140_SET_LAX_MODE()
#endif

#ifndef GNUTLS_FIPS140_SET_STRICT_MODE
#define GNUTLS_FIPS140_SET_STRICT_MODE()
#endif

#ifdef DOXYGEN
/**
 * @brief Convert a gnutls error code to a corresponding NTSTATUS.
 *
 * @param[in]  gnutls_rc      The GnuTLS return code.
 *
 * @param[in]  blocked_status The NTSTATUS return code which should be returned
 *                            in case the e.g. the cipher might be blocked due
 *                            to FIPS mode.
 *
 * @return A corresponding NTSTATUS code.
 */
NTSTATUS gnutls_error_to_ntstatus(int gnutls_rc,
				  NTSTATUS blocked_status);
#else
NTSTATUS _gnutls_error_to_ntstatus(int gnutls_rc,
				   NTSTATUS blocked_status,
				   const char *function,
				   const char *location);
#define gnutls_error_to_ntstatus(gnutls_rc, blocked_status) \
	_gnutls_error_to_ntstatus(gnutls_rc, blocked_status, \
				  __FUNCTION__, __location__)
#endif

#ifdef DOXYGEN
/**
 * @brief Convert a gnutls error code to a corresponding WERROR.
 *
 * @param[in]  gnutls_rc      The GnuTLS return code.
 *
 * @param[in]  blocked_werr   The WERROR code which should be returned if e.g
 *                            the cipher we want to used it not allowed to be
 *                            used because of FIPS mode.
 *
 * @return A corresponding WERROR code.
 */
WERROR gnutls_error_to_werror(int gnutls_rc,
			       WERROR blocked_werr);
#else
WERROR _gnutls_error_to_werror(int gnutls_rc,
			       WERROR blocked_werr,
			       const char *function,
			       const char *location);
#define gnutls_error_to_werror(gnutls_rc, blocked_werr) \
	_gnutls_error_to_werror(gnutls_rc, blocked_werr, \
				__FUNCTION__, __location__)
#endif

enum samba_gnutls_direction {
	SAMBA_GNUTLS_ENCRYPT,
	SAMBA_GNUTLS_DECRYPT
};

/**
 * @brief Encrypt or decrypt a data blob using RC4 with a key and salt.
 *
 * One of the key input should be a session key and the other a confounder
 * (aka salt). Which one depends on the implementation details of the
 * protocol.
 *
 * @param[in]  key_input1 Either a session_key or a confounder.
 *
 * @param[in]  key_input2 Either a session_key or a confounder.
 *
 * @param[in]  data       The data blob to either encrypt or decrypt. The data
 *                        will be encrypted or decrypted in place.
 *
 * @param[in]  encrypt    The encryption direction.
 *
 * @return A gnutls error code.
 */
int samba_gnutls_arcfour_confounded_md5(const DATA_BLOB *key_input1,
					const DATA_BLOB *key_input2,
					DATA_BLOB *data,
					enum samba_gnutls_direction encrypt);

/**
 * @brief Check if weak crypto is allowed.
 *
 * @return true if weak crypo is allowed, false otherwise.
 */
bool samba_gnutls_weak_crypto_allowed(void);

#endif /* _GNUTLS_HELPERS_H */
