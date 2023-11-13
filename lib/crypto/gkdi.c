/*
   Unix SMB/CIFS implementation.
   Group Key Distribution Protocol functions

   Copyright (C) Catalyst.Net Ltd 2023

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
#include <gnutls/crypto.h>

#include "lib/crypto/gnutls_helpers.h"

#include "lib/util/bytearray.h"

#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/gkdi.h"
#include "librpc/gen_ndr/ndr_gkdi.h"

#include "lib/crypto/gkdi.h"

static const uint8_t kds_service[] = {
	/* “KDS service” as a NULL‐terminated UTF‐16LE string. */
	'K', 0, 'D', 0, 'S', 0, ' ', 0, 's', 0, 'e', 0,
	'r', 0, 'v', 0, 'i', 0, 'c', 0, 'e', 0, 0,   0,
};

struct GkdiContextShort {
	uint8_t buf[sizeof((struct GUID_ndr_buf){}.buf) + sizeof(int32_t) +
		    sizeof(int32_t) + sizeof(int32_t)];
};

static NTSTATUS make_gkdi_context(const struct GkdiDerivationCtx *ctx,
				  struct GkdiContextShort *out_ctx)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB b = {.data = out_ctx->buf, .length = sizeof out_ctx->buf};

	if (ctx->target_security_descriptor.length) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ndr_err = ndr_push_struct_into_fixed_blob(
		&b, ctx, (ndr_push_flags_fn_t)ndr_push_GkdiDerivationCtx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

static NTSTATUS make_gkdi_context_security_descriptor(
	TALLOC_CTX *mem_ctx,
	const struct GkdiDerivationCtx *ctx,
	const DATA_BLOB security_descriptor,
	DATA_BLOB *out_ctx)
{
	enum ndr_err_code ndr_err;
	struct GkdiDerivationCtx ctx_with_sd = *ctx;

	if (ctx_with_sd.target_security_descriptor.length) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ctx_with_sd.target_security_descriptor = security_descriptor;

	ndr_err = ndr_push_struct_blob(out_ctx,
				       mem_ctx,
				       &ctx_with_sd,
				       (ndr_push_flags_fn_t)
					       ndr_push_GkdiDerivationCtx);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

struct GkdiContext {
	struct GkdiDerivationCtx ctx;
	gnutls_mac_algorithm_t algorithm;
};

gnutls_mac_algorithm_t get_sp800_108_mac_algorithm(
	const struct KdfAlgorithm kdf_algorithm)
{
	switch (kdf_algorithm.id) {
	case KDF_ALGORITHM_SP800_108_CTR_HMAC:
		switch (kdf_algorithm.param.sp800_108) {
		case KDF_PARAM_SHA1:
			return GNUTLS_MAC_SHA1;
		case KDF_PARAM_SHA256:
			return GNUTLS_MAC_SHA256;
		case KDF_PARAM_SHA384:
			return GNUTLS_MAC_SHA384;
		case KDF_PARAM_SHA512:
			return GNUTLS_MAC_SHA512;
		}
		break;
	}

	return GNUTLS_MAC_UNKNOWN;
}

static NTSTATUS GkdiContext(const struct ProvRootKey *const root_key,
			    struct GkdiContext *const ctx)
{
	NTSTATUS status = NT_STATUS_OK;
	gnutls_mac_algorithm_t algorithm = GNUTLS_MAC_UNKNOWN;

	if (ctx == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (root_key == NULL) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (root_key->version != root_key_version_1) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	if (root_key->data.length != GKDI_KEY_LEN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	algorithm = get_sp800_108_mac_algorithm(root_key->kdf_algorithm);
	if (algorithm == GNUTLS_MAC_UNKNOWN) {
		status = NT_STATUS_NOT_SUPPORTED;
		goto out;
	}

	/*
	 * The context comprises the GUID corresponding to the root key, the
	 * GKID (which we shall initialize to zero), and the encoded target
	 * security descriptor (which will initially be empty).
	 */
	*ctx = (struct GkdiContext){
		.ctx = {.guid = root_key->id,
			.l0_idx = 0,
			.l1_idx = 0,
			.l2_idx = 0,
			.target_security_descriptor = {}},
		.algorithm = algorithm,
	};
out:
	return status;
}

static NTSTATUS compute_l1_seed_key(
	TALLOC_CTX *mem_ctx,
	struct GkdiContext *ctx,
	const DATA_BLOB security_descriptor,
	const struct ProvRootKey *const root_key,
	const struct Gkid gkid,
	uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	struct GkdiContextShort short_ctx;
	int8_t n;

	ctx->ctx.l0_idx = gkid.l0_idx;
	ctx->ctx.l1_idx = -1;
	ctx->ctx.l2_idx = -1;

	status = make_gkdi_context(&ctx->ctx, &short_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* Derive an L0 seed key with GKID = (L0, −1, −1). */

	status = samba_gnutls_sp800_108_derive_key(root_key->data.data,
						   root_key->data.length,
						   NULL,
						   0,
						   kds_service,
						   sizeof kds_service,
						   short_ctx.buf,
						   sizeof short_ctx.buf,
						   ctx->algorithm,
						   key,
						   GKDI_KEY_LEN);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	/* Derive an L1 seed key with GKID = (L0, 31, −1). */

	ctx->ctx.l1_idx = 31;

	{
		DATA_BLOB security_descriptor_ctx;

		status = make_gkdi_context_security_descriptor(
			mem_ctx,
			&ctx->ctx,
			security_descriptor,
			&security_descriptor_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(
			key,
			GKDI_KEY_LEN,
			NULL,
			0,
			kds_service,
			sizeof kds_service,
			security_descriptor_ctx.data,
			security_descriptor_ctx.length,
			ctx->algorithm,
			key,
			GKDI_KEY_LEN);
		data_blob_free(&security_descriptor_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	for (n = 30; n >= gkid.l1_idx; --n) {
		/* Derive an L1 seed key with GKID = (L0, n, −1). */

		ctx->ctx.l1_idx = n;

		status = make_gkdi_context(&ctx->ctx, &short_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(key,
							   GKDI_KEY_LEN,
							   NULL,
							   0,
							   kds_service,
							   sizeof kds_service,
							   short_ctx.buf,
							   sizeof short_ctx.buf,
							   ctx->algorithm,
							   key,
							   GKDI_KEY_LEN);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

static NTSTATUS derive_l2_seed_key(struct GkdiContext *ctx,
				   const struct Gkid gkid,
				   uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	int8_t n;

	ctx->ctx.l0_idx = gkid.l0_idx;
	ctx->ctx.l1_idx = gkid.l1_idx;

	for (n = 31; n >= gkid.l2_idx; --n) {
		struct GkdiContextShort short_ctx;

		/* Derive an L2 seed key with GKID = (L0, L1, n). */

		ctx->ctx.l2_idx = n;

		status = make_gkdi_context(&ctx->ctx, &short_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		status = samba_gnutls_sp800_108_derive_key(key,
							   GKDI_KEY_LEN,
							   NULL,
							   0,
							   kds_service,
							   sizeof kds_service,
							   short_ctx.buf,
							   sizeof short_ctx.buf,
							   ctx->algorithm,
							   key,
							   GKDI_KEY_LEN);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}

static enum GkidType gkid_key_type(const struct Gkid gkid)
{
	if (gkid.l0_idx == -1) {
		return GKID_DEFAULT;
	}

	if (gkid.l1_idx == -1) {
		return GKID_L0_SEED_KEY;
	}

	if (gkid.l2_idx == -1) {
		return GKID_L1_SEED_KEY;
	}

	return GKID_L2_SEED_KEY;
}

static bool gkid_is_valid(const struct Gkid gkid)
{
	if (gkid.l0_idx < -1) {
		return false;
	}

	if (gkid.l1_idx < -1 || gkid.l1_idx >= gkdi_l1_key_iteration) {
		return false;
	}

	if (gkid.l2_idx < -1 || gkid.l2_idx >= gkdi_l2_key_iteration) {
		return false;
	}

	if (gkid.l0_idx == -1 && gkid.l1_idx != -1) {
		return false;
	}

	if (gkid.l1_idx == -1 && gkid.l2_idx != -1) {
		return false;
	}

	return true;
}

NTSTATUS compute_seed_key(
	TALLOC_CTX *mem_ctx,
	const DATA_BLOB target_security_descriptor,
	const struct ProvRootKey *const root_key,
	const struct Gkid gkid,
	uint8_t key[static const GKDI_KEY_LEN])
{
	NTSTATUS status = NT_STATUS_OK;
	enum GkidType gkid_type;
	struct GkdiContext ctx;

	if (!gkid_is_valid(gkid)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	gkid_type = gkid_key_type(gkid);
	if (gkid_type < GKID_L1_SEED_KEY) {
		/* Don’t allow derivation of L0 seed keys. */
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = GkdiContext(root_key, &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = compute_l1_seed_key(
		mem_ctx, &ctx, target_security_descriptor, root_key, gkid, key);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (gkid_type == GKID_L2_SEED_KEY) {
		status = derive_l2_seed_key(&ctx, gkid, key);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

out:
	return status;
}
