/*
   Unix SMB/CIFS implementation.
   Copyright (C) Guenther Deschner    2009

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
#include "librpc/gen_ndr/ndr_secrets.h"
#include "secrets.h"

/******************************************************************************
*******************************************************************************/

static char *lsa_secret_key(TALLOC_CTX *mem_ctx,
			    const char *secret_name)
{
	return talloc_asprintf_strupper_m(mem_ctx, "SECRETS/LSA/%s",
					  secret_name);
}

/******************************************************************************
*******************************************************************************/

static NTSTATUS lsa_secret_get_common(TALLOC_CTX *mem_ctx,
				      const char *secret_name,
				      struct lsa_secret *secret)
{
	char *key;
	DATA_BLOB blob;
	enum ndr_err_code ndr_err;

	ZERO_STRUCTP(secret);

	key = lsa_secret_key(mem_ctx, secret_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	blob.data = (uint8_t *)secrets_fetch(key, &blob.length);
	talloc_free(key);

	if (!blob.data) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, secret,
				(ndr_pull_flags_fn_t)ndr_pull_lsa_secret);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		SAFE_FREE(blob.data);
		return ndr_map_error2ntstatus(ndr_err);
	}

	SAFE_FREE(blob.data);

	return NT_STATUS_OK;
}

/******************************************************************************
*******************************************************************************/

NTSTATUS lsa_secret_get(TALLOC_CTX *mem_ctx,
			const char *secret_name,
			DATA_BLOB *secret_current,
			NTTIME *secret_current_lastchange,
			DATA_BLOB *secret_old,
			NTTIME *secret_old_lastchange,
			struct security_descriptor **sd)
{
	NTSTATUS status;
	struct lsa_secret secret;

	status = lsa_secret_get_common(mem_ctx, secret_name, &secret);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (secret_current) {
		*secret_current = data_blob_null;
		if (secret.secret_current) {
			*secret_current = *secret.secret_current;
		}
	}
	if (secret_current_lastchange) {
		*secret_current_lastchange = secret.secret_current_lastchange;
	}
	if (secret_old) {
		*secret_old = data_blob_null;
		if (secret.secret_old) {
			*secret_old = *secret.secret_old;
		}
	}
	if (secret_old_lastchange) {
		*secret_old_lastchange = secret.secret_old_lastchange;
	}
	if (sd) {
		*sd = secret.sd;
	}

	return NT_STATUS_OK;
}

/******************************************************************************
*******************************************************************************/

static NTSTATUS lsa_secret_set_common(TALLOC_CTX *mem_ctx,
				      const char *key,
				      struct lsa_secret *secret,
				      DATA_BLOB *secret_current,
				      DATA_BLOB *secret_old,
				      struct security_descriptor *sd)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;
	struct timeval now = timeval_current();

	if (!secret) {
		secret = talloc_zero(mem_ctx, struct lsa_secret);
	}

	if (!secret) {
		return NT_STATUS_NO_MEMORY;
	}

	if (secret_old) {
		secret->secret_old = secret_old;
		secret->secret_old_lastchange = timeval_to_nttime(&now);
	} else {
		if (secret->secret_current) {
			secret->secret_old = secret->secret_current;
			secret->secret_old_lastchange = secret->secret_current_lastchange;
		} else {
			secret->secret_old = NULL;
			secret->secret_old_lastchange = timeval_to_nttime(&now);
		}
	}
	if (secret_current) {
		secret->secret_current = secret_current;
		secret->secret_current_lastchange = timeval_to_nttime(&now);
	} else {
		secret->secret_current = NULL;
		secret->secret_current_lastchange = timeval_to_nttime(&now);
	}
	if (sd) {
		secret->sd = sd;
	}

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, secret,
				(ndr_push_flags_fn_t)ndr_push_lsa_secret);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	if (!secrets_store(key, blob.data, blob.length)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}

/******************************************************************************
*******************************************************************************/

NTSTATUS lsa_secret_set(const char *secret_name,
			DATA_BLOB *secret_current,
			DATA_BLOB *secret_old,
			struct security_descriptor *sd)
{
	char *key;
	struct lsa_secret secret;
	NTSTATUS status;

	key = lsa_secret_key(talloc_tos(), secret_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	status = lsa_secret_get_common(talloc_tos(), secret_name, &secret);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		talloc_free(key);
		return status;
	}

	status = lsa_secret_set_common(talloc_tos(), key,
				       &secret,
				       secret_current,
				       secret_old,
				       sd);
	talloc_free(key);

	return status;
}

/******************************************************************************
*******************************************************************************/

NTSTATUS lsa_secret_delete(const char *secret_name)
{
	char *key;
	struct lsa_secret secret;
	NTSTATUS status;

	key = lsa_secret_key(talloc_tos(), secret_name);
	if (!key) {
		return NT_STATUS_NO_MEMORY;
	}

	status = lsa_secret_get_common(talloc_tos(), secret_name, &secret);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(key);
		return status;
	}

	if (!secrets_delete(key)) {
		talloc_free(key);
		return NT_STATUS_ACCESS_DENIED;
	}

	talloc_free(key);

	return NT_STATUS_OK;
}
