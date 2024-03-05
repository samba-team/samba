/*
 * Copyright (C) 2002-2016 Free Software Foundation, Inc.
 * Copyright (C) 2014-2016 Nikos Mavrogiannopoulos
 * Copyright (C) 2015-2018 Red Hat, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 *
 */

#include "replace.h"
#include "gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

int legacy_gnutls_server_end_point_cb(gnutls_session_t session,
				      bool is_server,
				      gnutls_datum_t * cb)
{
	/*
	 * copied from the logic in gnutls_session_channel_binding()
	 * introduced by gnutls commit (as LGPL 2.1+):
	 *
	 * commit 9ebee00c793e40e3e8c797c645577c9e025b9f1e
	 * Author: Ruslan N. Marchenko <me@ruff.mobi>
	 * Date:   Sat May 1 23:05:54 2021 +0200
	 *
	 *  Add tls-server-end-point tls channel binding implementation.
	 *  ...
	 */
	const gnutls_datum_t *ders = NULL;
	unsigned int num_certs = 1;
	int ret;
	size_t rlen;
	gnutls_x509_crt_t cert;
	gnutls_digest_algorithm_t algo;

	/* Only X509 certificates are supported for this binding type */
	ret = gnutls_certificate_type_get(session);
	if (ret != GNUTLS_CRT_X509) {
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	if (is_server) {
		ders = gnutls_certificate_get_ours(session);
	} else {
		ders = gnutls_certificate_get_peers(session, &num_certs);
	}

	/* Previous check indicated we have x509 but you never know */
	if (!ders || num_certs == 0) {
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	ret = gnutls_x509_crt_list_import(&cert,
					  &num_certs,
					  ders,
					  GNUTLS_X509_FMT_DER,
					  0);
	/* Again, this is not supposed to happen (normally) */
	if (ret < 0 || num_certs == 0) {
		return GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE;
	}

	/* Obtain signature algorithm used by certificate */
	ret = gnutls_x509_crt_get_signature_algorithm(cert);
	if (ret < 0 || ret == GNUTLS_SIGN_UNKNOWN) {
		gnutls_x509_crt_deinit(cert);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	}

	/* obtain hash function from signature and normalize it */
	algo = gnutls_sign_get_hash_algorithm(ret);
	switch (algo) {
	case GNUTLS_DIG_MD5:
	case GNUTLS_DIG_SHA1:
		algo = GNUTLS_DIG_SHA256;
		break;
	case GNUTLS_DIG_UNKNOWN:
	case GNUTLS_DIG_NULL:
	case GNUTLS_DIG_MD5_SHA1:
		/* double hashing not supported either */
		gnutls_x509_crt_deinit(cert);
		return GNUTLS_E_UNIMPLEMENTED_FEATURE;
	default:
		break;
	}

	/* preallocate 512 bits buffer as maximum supported digest */
	rlen = 64;
	cb->data = gnutls_malloc(rlen);
	if (cb->data == NULL) {
		gnutls_x509_crt_deinit(cert);
		return GNUTLS_E_MEMORY_ERROR;
	}

	ret = gnutls_x509_crt_get_fingerprint(cert,
					      algo,
					      cb->data,
					      &rlen);
	if (ret == GNUTLS_E_SHORT_MEMORY_BUFFER) {
		cb->data = gnutls_realloc(cb->data, cb->size);
		if (cb->data == NULL) {
			gnutls_x509_crt_deinit(cert);
			return GNUTLS_E_MEMORY_ERROR;
		}
		ret = gnutls_x509_crt_get_fingerprint(cert,
						      algo,
						      cb->data,
						      &rlen);
	}

	cb->size = rlen;
	gnutls_x509_crt_deinit(cert);
	return ret;
}
