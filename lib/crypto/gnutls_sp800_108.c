/*
   Unix SMB/CIFS implementation.
   Wrapper for gnutls key derivation functions

   Copyright (C) Stefan Metzmacher 2009
   Copyright (C) Catalyst.Net Ltd 2023

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

#include "includes.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include "gnutls_helpers.h"

static NTSTATUS samba_gnutls_sp800_108_derive_key_part(
	const gnutls_hmac_hd_t hmac_hnd,
	const uint8_t *Label,
	const size_t Label_len,
	const uint8_t *Context,
	const size_t Context_len,
	const uint32_t L,
	const uint32_t i,
	uint8_t *digest)
{
	uint8_t buf[4];
	static const uint8_t zero = 0;
	int rc;

	RSIVAL(buf, 0, i);
	rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, Label, Label_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, &zero, 1);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	rc = gnutls_hmac(hmac_hnd, Context, Context_len);
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	RSIVAL(buf, 0, L);
	rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
	if (rc < 0) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	gnutls_hmac_deinit(hmac_hnd, digest);

	return NT_STATUS_OK;
}

/**
 * @brief Derive a key using the NIST SP 800‐108 algorithm.
 *
 * The details of the algorithm can be found at
 * https://csrc.nist.gov/pubs/sp/800/108/r1/final.
 *
 * @param KI            The key‐derivation key used as input.
 *
 * @param KI_len        The length of the key‐derivation key.
 *
 * @param Label         A label that identifies the purpose for the derived key.
 *                      Ignored if FixedData is non‐NULL.
 *
 * @param Label_len     The length of the label.
 *
 * @param Context       Information related to the derived key. Ignored if
 *                      FixedData is non‐NULL.
 *
 * @param Context_len   The length of the context data.
 *
 * @param algorithm     The HMAC algorithm to use.
 *
 * @param KO            A buffer to receive the derived key.
 *
 * @param KO_len        The length of the key to be derived.
 *
 * @return NT_STATUS_OK on success, an NT status error code otherwise.
 */
NTSTATUS samba_gnutls_sp800_108_derive_key(
	const uint8_t *KI,
	size_t KI_len,
	const uint8_t *Label,
	size_t Label_len,
	const uint8_t *Context,
	size_t Context_len,
	const gnutls_mac_algorithm_t algorithm,
	uint8_t *KO,
	size_t KO_len)
{
	gnutls_hmac_hd_t hmac_hnd = NULL;
	const size_t digest_len = gnutls_hmac_get_len(algorithm);
	uint8_t digest[digest_len];
	uint32_t i = 1;
	uint32_t L = KO_len * 8;
	NTSTATUS status;
	int rc;

	if (KO_len > digest_len) {
		DBG_ERR("KO_len[%zu] > digest_len[%zu]\n", KO_len, digest_len);
		return NT_STATUS_INTERNAL_ERROR;
	}

	switch (KO_len) {
	case 16:
	case 32:
		break;
	default:
		DBG_ERR("KO_len[%zu] not supported\n", KO_len);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * a simplified version of
	 * "NIST Special Publication 800-108" section 5.1.
	 */
	rc = gnutls_hmac_init(&hmac_hnd,
			      algorithm,
			      KI,
			      KI_len);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}

	status = samba_gnutls_sp800_108_derive_key_part(hmac_hnd,
							Label,
							Label_len,
							Context,
							Context_len,
							L,
							i,
							digest);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	memcpy(KO, digest, KO_len);

	ZERO_ARRAY(digest);

	return NT_STATUS_OK;
}
