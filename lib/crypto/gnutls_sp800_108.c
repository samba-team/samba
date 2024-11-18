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
	const uint8_t *FixedData,
	const size_t FixedData_len,
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

	PUSH_BE_U32(buf, 0, i);
	rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc,
						NT_STATUS_HMAC_NOT_SUPPORTED);
	}
	if (FixedData != NULL) {
		rc = gnutls_hmac(hmac_hnd, FixedData, FixedData_len);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(
				rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
	} else {
		rc = gnutls_hmac(hmac_hnd, Label, Label_len);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(
				rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		rc = gnutls_hmac(hmac_hnd, &zero, 1);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(
				rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		rc = gnutls_hmac(hmac_hnd, Context, Context_len);
		if (rc < 0) {
			return gnutls_error_to_ntstatus(
				rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
		PUSH_BE_U32(buf, 0, L);
		rc = gnutls_hmac(hmac_hnd, buf, sizeof(buf));
		if (rc < 0) {
			return gnutls_error_to_ntstatus(
				rc, NT_STATUS_HMAC_NOT_SUPPORTED);
		}
	}

	gnutls_hmac_output(hmac_hnd, digest);

	return NT_STATUS_OK;
}

static size_t ceiling_div(const size_t a, const size_t b)
{
	return a / b + (a % b != 0);
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
 * @param FixedData     If non‐NULL, specifies fixed data to be used in place of
 *                      that constructed from the Label and Context parameters.
 *
 * @param FixedData_len The length of the fixed data, if it is present.
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
	const uint8_t *FixedData,
	size_t FixedData_len,
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
	uint32_t i;
	uint32_t L = KO_len * 8;
	size_t KO_idx;
	NTSTATUS status = NT_STATUS_OK;
	int rc;

	if (KO_len > UINT32_MAX / 8) {
		/* The calculation of L has overflowed. */
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (digest_len == 0) {
		return NT_STATUS_HMAC_NOT_SUPPORTED;
	}

	{
		const size_t n_iterations = ceiling_div(KO_len, digest_len);
		/*
		 * To ensure that the counter values are distinct, n shall not
		 * be larger than 2ʳ−1, where r = 32. We have made sure that
		 * |KO| × 8 < 2³², and we know that n ≤ |KO| from its
		 * definition. Thus n ≤ |KO| ≤ |KO| × 8 < 2³², and so the
		 * requirement n ≤ 2³² − 1 must always hold.
		 */
		SMB_ASSERT(n_iterations <= UINT32_MAX);
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

	/* (This loop would make an excellent candidate for parallelization.) */

	for (KO_idx = 0, i = 1; KO_len - KO_idx >= digest_len;
	     KO_idx += digest_len, ++i)
	{
		status = samba_gnutls_sp800_108_derive_key_part(hmac_hnd,
								FixedData,
								FixedData_len,
								Label,
								Label_len,
								Context,
								Context_len,
								L,
								i,
								KO + KO_idx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	if (KO_idx < KO_len) {
		/* Get the last little bit. */
		uint8_t digest[digest_len];
		status = samba_gnutls_sp800_108_derive_key_part(hmac_hnd,
								FixedData,
								FixedData_len,
								Label,
								Label_len,
								Context,
								Context_len,
								L,
								i,
								digest);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		memcpy(KO + KO_idx, digest, KO_len - KO_idx);

		ZERO_ARRAY(digest);
	}

out:
	if (hmac_hnd != NULL) {
		gnutls_hmac_deinit(hmac_hnd, NULL);
	}
	if (!NT_STATUS_IS_OK(status)) {
		/* Hide the evidence. */
		ZERO_ARRAY_LEN(KO, KO_idx);
	}

	return status;
}
