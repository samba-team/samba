/*
   Unix SMB/CIFS implementation.

   Extract the user/system database from a remote SamSync server

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Guenther Deschner <gd@samba.org> 2008

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

/**
 * Decrypt and extract the user's passwords.
 *
 * The writes decrypted (no longer 'RID encrypted' or arcfour encrypted)
 * passwords back into the structure
 */

static NTSTATUS fix_user(TALLOC_CTX *mem_ctx,
			 DATA_BLOB *session_key,
			 bool rid_crypt,
			 enum netr_SamDatabaseID database_id,
			 struct netr_DELTA_ENUM *delta)
{

	uint32_t rid = delta->delta_id_union.rid;
	struct netr_DELTA_USER *user = delta->delta_union.user;
	struct samr_Password lm_hash;
	struct samr_Password nt_hash;

	if (rid_crypt) {
		if (user->lm_password_present) {
			sam_pwd_hash(rid, user->lmpassword.hash, lm_hash.hash, 0);
			user->lmpassword = lm_hash;
		}

		if (user->nt_password_present) {
			sam_pwd_hash(rid, user->ntpassword.hash, nt_hash.hash, 0);
			user->ntpassword = nt_hash;
		}
	}

	if (user->user_private_info.SensitiveData) {
		DATA_BLOB data;
		struct netr_USER_KEYS keys;
		enum ndr_err_code ndr_err;
		data.data = user->user_private_info.SensitiveData;
		data.length = user->user_private_info.DataLength;
		SamOEMhashBlob(data.data, data.length, session_key);
		user->user_private_info.SensitiveData = data.data;
		user->user_private_info.DataLength = data.length;

		ndr_err = ndr_pull_struct_blob(&data, mem_ctx, &keys,
			(ndr_pull_flags_fn_t)ndr_pull_netr_USER_KEYS);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			dump_data(10, data.data, data.length);
			return ndr_map_error2ntstatus(ndr_err);
		}

		if (keys.keys.keys2.lmpassword.length == 16) {
			if (rid_crypt) {
				sam_pwd_hash(rid,
					     keys.keys.keys2.lmpassword.pwd.hash,
					     lm_hash.hash, 0);
				user->lmpassword = lm_hash;
			} else {
				user->lmpassword = keys.keys.keys2.lmpassword.pwd;
			}
			user->lm_password_present = true;
		}
		if (keys.keys.keys2.ntpassword.length == 16) {
			if (rid_crypt) {
				sam_pwd_hash(rid,
					     keys.keys.keys2.ntpassword.pwd.hash,
					     nt_hash.hash, 0);
				user->ntpassword = nt_hash;
			} else {
				user->ntpassword = keys.keys.keys2.ntpassword.pwd;
			}
			user->nt_password_present = true;
		}
		/* TODO: rid decrypt history fields */
	}
	return NT_STATUS_OK;
}

/**
 * Decrypt and extract the secrets
 *
 * The writes decrypted secrets back into the structure
 */
static NTSTATUS fix_secret(TALLOC_CTX *mem_ctx,
			   DATA_BLOB *session_key,
			   enum netr_SamDatabaseID database_id,
			   struct netr_DELTA_ENUM *delta)
{
	struct netr_DELTA_SECRET *secret = delta->delta_union.secret;

	SamOEMhashBlob(secret->current_cipher.cipher_data,
		       secret->current_cipher.maxlen,
		       session_key);

	SamOEMhashBlob(secret->old_cipher.cipher_data,
		       secret->old_cipher.maxlen,
		       session_key);

	return NT_STATUS_OK;
}

/**
 * Fix up the delta, dealing with encryption issues so that the final
 * callback need only do the printing or application logic
 */

static NTSTATUS samsync_fix_delta(TALLOC_CTX *mem_ctx,
				  DATA_BLOB *session_key,
				  bool rid_crypt,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM *delta)
{
	NTSTATUS status = NT_STATUS_OK;

	switch (delta->delta_type) {
		case NETR_DELTA_USER:

			status = fix_user(mem_ctx,
					  session_key,
					  rid_crypt,
					  database_id,
					  delta);
			break;
		case NETR_DELTA_SECRET:

			status = fix_secret(mem_ctx,
					    session_key,
					    database_id,
					    delta);
			break;
		default:
			break;
	}

	return status;
}

/**
 * Fix up the delta, dealing with encryption issues so that the final
 * callback need only do the printing or application logic
 */

NTSTATUS samsync_fix_delta_array(TALLOC_CTX *mem_ctx,
				 DATA_BLOB *session_key,
				 bool rid_crypt,
				 enum netr_SamDatabaseID database_id,
				 struct netr_DELTA_ENUM_ARRAY *r)
{
	NTSTATUS status;
	int i;

	for (i = 0; i < r->num_deltas; i++) {

		status = samsync_fix_delta(mem_ctx,
					   session_key,
					   rid_crypt,
					   database_id,
					   &r->delta_enum[i]);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}
