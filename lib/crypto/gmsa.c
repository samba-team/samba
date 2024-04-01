/*
   Unix SMB/CIFS implementation.
   Group Managed Service Account functions

   Copyright (C) Catalyst.Net Ltd 2024

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include <gnutls/gnutls.h>
#include "lib/crypto/gnutls_helpers.h"
#include "lib/crypto/gkdi.h"
#include "lib/crypto/gmsa.h"
#include "librpc/gen_ndr/ndr_security.h"

static const uint8_t gmsa_security_descriptor[] = {
	/* O:SYD:(A;;FRFW;;;S-1-5-9) */
	0x01, 0x00, 0x04, 0x80, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x00, 0x1c, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x9f, 0x01, 0x12, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00,
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00};

static const uint8_t gmsa_password_label[] = {
	/* GMSA PASSWORD as a NULL‐terminated UTF‐16LE string. */
	'G', 0, 'M', 0, 'S', 0, 'A', 0, ' ', 0, 'P', 0, 'A', 0,
	'S', 0, 'S', 0, 'W', 0, 'O', 0, 'R', 0, 'D', 0, 0,   0,
};

static NTSTATUS generate_gmsa_password(
	const uint8_t key[static const GKDI_KEY_LEN],
	const struct dom_sid *const account_sid,
	const struct KdfAlgorithm kdf_algorithm,
	uint8_t password[static const GMSA_PASSWORD_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	gnutls_mac_algorithm_t algorithm;

	algorithm = get_sp800_108_mac_algorithm(kdf_algorithm);
	if (algorithm == GNUTLS_MAC_UNKNOWN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	if (account_sid == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	{
		uint8_t encoded_sid[ndr_size_dom_sid(account_sid, 0)];
		{
			struct ndr_push ndr = {
				.data = encoded_sid,
				.alloc_size = sizeof encoded_sid,
				.fixed_buf_size = true,
			};
			enum ndr_err_code ndr_err;

			ndr_err = ndr_push_dom_sid(&ndr,
						   NDR_SCALARS | NDR_BUFFERS,
						   account_sid);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				status = ndr_map_error2ntstatus(ndr_err);
				goto out;
			}
		}

		status = samba_gnutls_sp800_108_derive_key(
			key,
			GKDI_KEY_LEN,
			NULL,
			0,
			gmsa_password_label,
			sizeof gmsa_password_label,
			encoded_sid,
			sizeof encoded_sid,
			algorithm,
			password,
			GMSA_PASSWORD_LEN);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

static void gmsa_post_process_password_buffer(
	uint8_t password[static const GMSA_PASSWORD_NULL_TERMINATED_LEN])
{
	size_t n;

	for (n = 0; n < GMSA_PASSWORD_LEN; n += 2) {
		const uint8_t a = password[n];
		const uint8_t b = password[n + 1];
		if (!a && !b) {
			/*
			 * There is a 0.2% chance that the generated password
			 * will contain an embedded null terminator, which will
			 * need to be converted into U+0001.
			 */
			password[n] = 1;
		}
	}

	/* Null‐terminate the password. */
	password[GMSA_PASSWORD_LEN] = 0;
	password[GMSA_PASSWORD_LEN + 1] = 0;
}

NTSTATUS gmsa_password_based_on_key_id(
	TALLOC_CTX *mem_ctx,
	const struct Gkid gkid,
	const NTTIME current_time,
	const struct ProvRootKey *const root_key,
	const struct dom_sid *const account_sid,
	uint8_t password[static const GMSA_PASSWORD_NULL_TERMINATED_LEN])
{
	NTSTATUS status = NT_STATUS_OK;

	/* Ensure that a specific seed key is being requested. */

	if (!gkid_is_valid(gkid)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (gkid_key_type(gkid) != GKID_L2_SEED_KEY) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/* Require the root key ID for the moment. */
	if (root_key == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	/* Assert that the root key may be used at this time. */
	if (current_time < root_key->use_start_time) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	{
		/*
		 * The key being requested must not be from the future. That
		 * said, we allow for a little bit of clock skew so that samdb
		 * can compute the next managed password prior to the expiration
		 * of the current one.
		 */
		const struct Gkid current_gkid = gkdi_get_interval_id(
			current_time + gkdi_max_clock_skew);
		if (!gkid_less_than_or_equal_to(gkid, current_gkid)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto out;
		}
	}

	/*
	 * Windows’ GetKey() might return not the specified L2 seed key, but an
	 * earlier L2 seed key, or an L1 seed key, leaving the client to perform
	 * the rest of the derivation. We are able to simplify things by always
	 * deriving the specified L2 seed key, but if we implement a
	 * client‐accessible GetKey(), we must take care that it match the
	 * Windows implementation.
	 */

	/*
	 * Depending on the GKID that was requested, Windows’ GetKey() might
	 * return a different L1 or L2 seed key, leaving the client with some
	 * further derivation to do. Our simpler implementation will return
	 * either the exact key the caller requested, or an error code if the
	 * client is not suitably authorized.
	 */

	{
		uint8_t key[GKDI_KEY_LEN];

		status = compute_seed_key(
			mem_ctx,
			data_blob_const(gmsa_security_descriptor,
					sizeof gmsa_security_descriptor),
			root_key,
			gkid,
			key);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = generate_gmsa_password(key,
						account_sid,
						root_key->kdf_algorithm,
						password);
		ZERO_ARRAY(key);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	gmsa_post_process_password_buffer(password);

out:
	return status;
}

NTSTATUS gmsa_talloc_password_based_on_key_id(
	TALLOC_CTX *mem_ctx,
	const struct Gkid gkid,
	const NTTIME current_time,
	const struct ProvRootKey *const root_key,
	const struct dom_sid *const account_sid,
	struct gmsa_null_terminated_password **password_out)
{
	struct gmsa_null_terminated_password *password = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (password_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	password = talloc(mem_ctx, struct gmsa_null_terminated_password);
	if (password == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = gmsa_password_based_on_key_id(mem_ctx,
					       gkid,
					       current_time,
					       root_key,
					       account_sid,
					       password->buf);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(password);
		return status;
	}

	*password_out = password;
	return status;
}

bool gmsa_current_time(NTTIME *current_time_out)
{
	struct timespec current_timespec;
	int ret;

	ret = clock_gettime(CLOCK_REALTIME, &current_timespec);
	if (ret) {
		return false;
	}

	*current_time_out = full_timespec_to_nt_time(&current_timespec);
	return true;
}
