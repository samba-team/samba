/*
   Unix SMB/CIFS implementation.
   msDS-ManagedPassword attribute for Group Managed Service Accounts

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
#include "ldb.h"
#include "ldb_module.h"
#include "ldb_errors.h"
#include "ldb_private.h"
#include "lib/crypto/gkdi.h"
#include "lib/crypto/gmsa.h"
#include "lib/util/data_blob.h"
#include "lib/util/fault.h"
#include "lib/util/time.h"
#include "libcli/security/access_check.h"
#include "libcli/security/session.h"
#include "librpc/gen_ndr/auth.h"
#include "librpc/gen_ndr/ndr_gkdi.h"
#include "librpc/gen_ndr/ndr_gmsa.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "dsdb/common/util.h"
#include "dsdb/gmsa/gkdi.h"
#include "dsdb/gmsa/util.h"
#include "dsdb/samdb/samdb.h"

#undef strcasecmp

enum RootKeyType {
	ROOT_KEY_NONE,
	ROOT_KEY_SPECIFIC,
	ROOT_KEY_NONSPECIFIC,
	ROOT_KEY_OBTAINED,
};

struct RootKey {
	TALLOC_CTX *mem_ctx;
	enum RootKeyType type;
	union {
		struct KeyEnvelopeId specific;
		struct {
			NTTIME key_start_time;
		} nonspecific;
		struct {
			struct gmsa_update_pwd_part key;
			struct gmsa_null_terminated_password *password;
		} obtained;
	} u;
};

static const struct RootKey empty_root_key = {.type = ROOT_KEY_NONE};

int gmsa_allowed_to_view_managed_password(TALLOC_CTX *mem_ctx,
					  struct ldb_context *ldb,
					  const struct ldb_message *msg,
					  const struct dom_sid *account_sid,
					  bool *allowed_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct security_descriptor group_msa_membership_sd = {};
	const struct security_token *user_token = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	if (allowed_out == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}
	*allowed_out = false;

	{
		const struct auth_session_info *session_info = ldb_get_opaque(
			ldb, DSDB_SESSION_INFO);
		const enum security_user_level level =
			security_session_user_level(session_info, NULL);

		if (level == SECURITY_SYSTEM) {
			*allowed_out = true;
			ret = LDB_SUCCESS;
			goto out;
		}

		if (session_info == NULL) {
			ret = dsdb_werror(ldb,
					  LDB_ERR_OPERATIONS_ERROR,
					  WERR_DS_CANT_RETRIEVE_ATTS,
					  "no right to view attribute");
			goto out;
		}

		user_token = session_info->security_token;
	}

	tmp_ctx = talloc_new(msg);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		const struct ldb_val *group_msa_membership = NULL;
		enum ndr_err_code err;

		/* [MS-ADTS] 3.1.1.4.4: Extended Access Checks. */
		group_msa_membership = ldb_msg_find_ldb_val(
			msg, "msDS-GroupMSAMembership");
		if (group_msa_membership == NULL) {
			ret = dsdb_werror(ldb,
					  LDB_ERR_OPERATIONS_ERROR,
					  WERR_DS_CANT_RETRIEVE_ATTS,
					  "no right to view attribute");
			goto out;
		}

		err = ndr_pull_struct_blob_all(
			group_msa_membership,
			tmp_ctx,
			&group_msa_membership_sd,
			(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			status = ndr_map_error2ntstatus(err);
			DBG_WARNING("msDS-GroupMSAMembership pull failed: %s\n",
				    nt_errstr(status));
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	{
		const uint32_t access_desired = SEC_ADS_READ_PROP;
		uint32_t access_granted = 0;

		status = sec_access_check_ds(&group_msa_membership_sd,
					     user_token,
					     access_desired,
					     &access_granted,
					     NULL,
					     account_sid);
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			/*
			 * The principal is not allowed to view the managed
			 * password.
			 */
		} else if (!NT_STATUS_IS_OK(status)) {
			DBG_WARNING("msDS-GroupMSAMembership: "
				    "sec_access_check_ds(access_desired=%#08x, "
				    "access_granted:%#08x) failed with: %s\n",
				    access_desired,
				    access_granted,
				    nt_errstr(status));

			ret = dsdb_werror(
				ldb,
				LDB_ERR_OPERATIONS_ERROR,
				WERR_DS_CANT_RETRIEVE_ATTS,
				"access check to view managed password failed");
			goto out;
		} else {
			/* Cool, the principal may view the password. */
			*allowed_out = true;
		}
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static NTSTATUS gmsa_managed_pwd_id(struct ldb_context *ldb,
				    TALLOC_CTX *mem_ctx,
				    const struct ldb_val *pwd_id_blob,
				    const struct ProvRootKey *root_key,
				    struct KeyEnvelope *pwd_id_out)
{
	if (root_key == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (pwd_id_blob != NULL) {
		return gkdi_pull_KeyEnvelope(mem_ctx, pwd_id_blob, pwd_id_out);
	}

	{
		const char *domain_name = NULL;
		const char *forest_name = NULL;

		domain_name = samdb_default_domain_name(ldb, mem_ctx);
		if (domain_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		forest_name = samdb_forest_name(ldb, mem_ctx);
		if (forest_name == NULL) {
			/* We leak ‘domain_name’, but that can’t be helped. */
			return NT_STATUS_NO_MEMORY;
		}

		*pwd_id_out = (struct KeyEnvelope){
			.version = root_key->version,
			.flags = ENVELOPE_FLAG_KEY_MAY_ENCRYPT_NEW_DATA,
			.domain_name = domain_name,
			.forest_name = forest_name,
		};
	}

	return NT_STATUS_OK;
}

void gmsa_update_managed_pwd_id(struct KeyEnvelope *pwd_id,
				const struct gmsa_update_pwd_part *new_pwd)
{
	pwd_id->l0_index = new_pwd->gkid.l0_idx;
	pwd_id->l1_index = new_pwd->gkid.l1_idx;
	pwd_id->l2_index = new_pwd->gkid.l2_idx;
	pwd_id->root_key_id = new_pwd->root_key->id;
}

NTSTATUS gmsa_pack_managed_pwd_id(TALLOC_CTX *mem_ctx,
				  const struct KeyEnvelope *pwd_id,
				  DATA_BLOB *pwd_id_out)
{
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err;

	err = ndr_push_struct_blob(pwd_id_out,
				   mem_ctx,
				   pwd_id,
				   (ndr_push_flags_fn_t)ndr_push_KeyEnvelope);
	status = ndr_map_error2ntstatus(err);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("KeyEnvelope push failed: %s\n", nt_errstr(status));
	}

	return status;
}

static int gmsa_specific_password(TALLOC_CTX *mem_ctx,
				  struct ldb_context *ldb,
				  const struct KeyEnvelopeId pwd_id,
				  struct gmsa_update_pwd_part *new_pwd_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		const struct ldb_message *root_key_msg = NULL;

		ret = gkdi_root_key_from_id(tmp_ctx,
					    ldb,
					    &pwd_id.root_key_id,
					    &root_key_msg);
		if (ret) {
			goto out;
		}

		status = gkdi_root_key_from_msg(mem_ctx,
						pwd_id.root_key_id,
						root_key_msg,
						&new_pwd_out->root_key);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	new_pwd_out->gkid = pwd_id.gkid;

out:
	talloc_free(tmp_ctx);
	return ret;
}

static int gmsa_nonspecific_password(TALLOC_CTX *mem_ctx,
				     struct ldb_context *ldb,
				     const NTTIME key_start_time,
				     const NTTIME current_time,
				     struct gmsa_update_pwd_part *new_pwd_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = LDB_SUCCESS;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		const struct ldb_message *root_key_msg = NULL;
		struct GUID root_key_id;
		NTSTATUS status = NT_STATUS_OK;

		ret = gkdi_most_recently_created_root_key(tmp_ctx,
							  ldb,
							  current_time,
							  key_start_time,
							  &root_key_id,
							  &root_key_msg);
		if (ret) {
			goto out;
		}

		status = gkdi_root_key_from_msg(mem_ctx,
						root_key_id,
						root_key_msg,
						&new_pwd_out->root_key);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	new_pwd_out->gkid = gkdi_get_interval_id(key_start_time);

out:
	talloc_free(tmp_ctx);
	return ret;
}

static int gmsa_specifc_root_key(TALLOC_CTX *mem_ctx,
				 const struct KeyEnvelopeId pwd_id,
				 struct RootKey *root_key_out)
{
	if (root_key_out == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*root_key_out = (struct RootKey){.mem_ctx = mem_ctx,
					 .type = ROOT_KEY_SPECIFIC,
					 .u.specific = pwd_id};
	return LDB_SUCCESS;
}

static int gmsa_nonspecifc_root_key(TALLOC_CTX *mem_ctx,
				    const NTTIME key_start_time,
				    struct RootKey *root_key_out)
{
	if (root_key_out == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*root_key_out = (struct RootKey){
		.mem_ctx = mem_ctx,
		.type = ROOT_KEY_NONSPECIFIC,
		.u.nonspecific.key_start_time = key_start_time};
	return LDB_SUCCESS;
}

static int gmsa_obtained_root_key_steal(
	TALLOC_CTX *mem_ctx,
	const struct gmsa_update_pwd_part key,
	struct gmsa_null_terminated_password *password,
	struct RootKey *root_key_out)
{
	if (root_key_out == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* Steal the data on to the appropriate memory context. */
	talloc_steal(mem_ctx, key.root_key);
	talloc_steal(mem_ctx, password);

	*root_key_out = (struct RootKey){.mem_ctx = mem_ctx,
					 .type = ROOT_KEY_OBTAINED,
					 .u.obtained = {.key = key,
							.password = password}};
	return LDB_SUCCESS;
}

static int gmsa_fetch_root_key(struct ldb_context *ldb,
			       const NTTIME current_time,
			       struct RootKey *root_key,
			       const struct dom_sid *const account_sid)
{
	TALLOC_CTX *tmp_ctx = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	if (root_key == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}

	switch (root_key->type) {
	case ROOT_KEY_SPECIFIC:
	case ROOT_KEY_NONSPECIFIC: {
		struct gmsa_null_terminated_password *password = NULL;
		struct gmsa_update_pwd_part key;

		tmp_ctx = talloc_new(NULL);
		if (tmp_ctx == NULL) {
			ret = ldb_oom(ldb);
			goto out;
		}

		if (root_key->type == ROOT_KEY_SPECIFIC) {
			/* Search for a specific root key. */
			ret = gmsa_specific_password(tmp_ctx,
						     ldb,
						     root_key->u.specific,
						     &key);
			if (ret) {
				/*
				 * We couldn’t find a specific key — treat this
				 * as an error.
				 */
				goto out;
			}
		} else {
			/*
			 * Search for the most recent root key meeting the start
			 * time requirement.
			 */
			ret = gmsa_nonspecific_password(
				tmp_ctx,
				ldb,
				root_key->u.nonspecific.key_start_time,
				current_time,
				&key);
			/* Handle errors below. */
		}
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			/*
			 * We couldn’t find a key meeting the requirements —
			 * that’s OK, presumably. It’s not critical if we can’t
			 * find a key for deriving a previous gMSA password, for
			 * example.
			 */
			ret = LDB_SUCCESS;
			*root_key = empty_root_key;
		} else if (ret) {
			goto out;
		} else {
			/* Derive the password. */
			status = gmsa_talloc_password_based_on_key_id(
				tmp_ctx,
				key.gkid,
				current_time,
				key.root_key,
				account_sid,
				&password);
			if (!NT_STATUS_IS_OK(status)) {
				ret = ldb_operr(ldb);
				goto out;
			}

			/*
			 * Initialize the obtained structure, and give it the
			 * appropriate memory context.
			 */
			ret = gmsa_obtained_root_key_steal(root_key->mem_ctx,
							   key,
							   password,
							   root_key);
			if (ret) {
				goto out;
			}
		}
	} break;
	case ROOT_KEY_NONE:
		/* No key is available. */
		break;
	case ROOT_KEY_OBTAINED:
		/* The key has already been obtained. */
		break;
	default:
		ret = ldb_operr(ldb);
		goto out;
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

/*
 * Get the password and update information associated with a root key. The
 * caller *does not* own these structures; the root key object retains
 * ownership.
 */
static int gmsa_get_root_key(
	struct ldb_context *ldb,
	const NTTIME current_time,
	const struct dom_sid *const account_sid,
	struct RootKey *root_key,
	struct gmsa_null_terminated_password **password_out,
	struct gmsa_update_pwd_part *update_out)
{
	int ret = LDB_SUCCESS;

	if (password_out == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}
	*password_out = NULL;

	if (update_out != NULL) {
		*update_out = (struct gmsa_update_pwd_part){};
	}

	/* Fetch the root key from the database and obtain the password. */
	ret = gmsa_fetch_root_key(ldb, current_time, root_key, account_sid);
	if (ret) {
		goto out;
	}

	switch (root_key->type) {
	case ROOT_KEY_NONE:
		/* No key is available. */
		break;
	case ROOT_KEY_OBTAINED:
		*password_out = root_key->u.obtained.password;
		if (update_out != NULL) {
			*update_out = root_key->u.obtained.key;
		}
		break;
	default:
		/* Unexpected. */
		ret = ldb_operr(ldb);
		goto out;
	}

out:
	return ret;
}

static int gmsa_system_update_password_id_req(
	struct ldb_context *ldb,
	TALLOC_CTX *mem_ctx,
	const struct ldb_message *msg,
	const struct gmsa_update_pwd *new_pwd,
	const bool current_key_becomes_previous,
	struct ldb_request **req_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	const struct ldb_val *pwd_id_blob = ldb_msg_find_ldb_val(
		msg, "msDS-ManagedPasswordId");
	struct KeyEnvelope pwd_id;
	struct ldb_message *mod_msg = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	/* Create a new ldb message. */
	mod_msg = ldb_msg_new(tmp_ctx);
	if (mod_msg == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}
	{
		struct ldb_dn *dn = ldb_dn_copy(mod_msg, msg->dn);
		if (dn == NULL) {
			ret = ldb_oom(ldb);
			goto out;
		}
		mod_msg->dn = dn;
	}

	/* Get the Managed Password ID. */
	status = gmsa_managed_pwd_id(
		ldb, tmp_ctx, pwd_id_blob, new_pwd->new_id.root_key, &pwd_id);
	if (!NT_STATUS_IS_OK(status)) {
		ret = ldb_operr(ldb);
		goto out;
	}

	/* Update the password ID to contain the new GKID and root key ID. */
	gmsa_update_managed_pwd_id(&pwd_id, &new_pwd->new_id);

	{
		DATA_BLOB new_pwd_id_blob = {};

		/* Pack the current password ID. */
		status = gmsa_pack_managed_pwd_id(tmp_ctx,
						  &pwd_id,
						  &new_pwd_id_blob);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}

		/* Update the msDS-ManagedPasswordId attribute. */
		ret = ldb_msg_append_steal_value(mod_msg,
						 "msDS-ManagedPasswordId",
						 &new_pwd_id_blob,
						 LDB_FLAG_MOD_REPLACE);
		if (ret) {
			goto out;
		}
	}

	{
		DATA_BLOB *prev_pwd_id_blob = NULL;
		DATA_BLOB _prev_pwd_id_blob;
		DATA_BLOB prev_pwd_id = {};

		if (new_pwd->prev_id.root_key != NULL) {
			/*
			 * Update the password ID to contain the previous GKID
			 * and root key ID.
			 */
			gmsa_update_managed_pwd_id(&pwd_id, &new_pwd->prev_id);

			/* Pack the previous password ID. */
			status = gmsa_pack_managed_pwd_id(tmp_ctx,
							  &pwd_id,
							  &prev_pwd_id);
			if (!NT_STATUS_IS_OK(status)) {
				ret = ldb_operr(ldb);
				goto out;
			}

			prev_pwd_id_blob = &prev_pwd_id;
		} else if (current_key_becomes_previous && pwd_id_blob != NULL)
		{
			/* Copy the current password ID to the previous ID. */
			_prev_pwd_id_blob = ldb_val_dup(tmp_ctx, pwd_id_blob);
			if (_prev_pwd_id_blob.length != pwd_id_blob->length) {
				ret = ldb_oom(ldb);
				goto out;
			}

			prev_pwd_id_blob = &_prev_pwd_id_blob;
		}

		if (prev_pwd_id_blob != NULL) {
			/*
			 * Update the msDS-ManagedPasswordPreviousId attribute.
			 */
			ret = ldb_msg_append_steal_value(
				mod_msg,
				"msDS-ManagedPasswordPreviousId",
				prev_pwd_id_blob,
				LDB_FLAG_MOD_REPLACE);
			if (ret) {
				goto out;
			}
		}
	}

	{
		struct ldb_request *req = NULL;

		/* Build the ldb request to return. */
		ret = ldb_build_mod_req(&req,
					ldb,
					tmp_ctx,
					mod_msg,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
		if (ret) {
			goto out;
		}

		/* Tie the lifetime of the message to that of the request. */
		talloc_steal(req, mod_msg);

		/* Make sure the password ID update happens as System. */
		ret = dsdb_request_add_controls(req, DSDB_FLAG_AS_SYSTEM);
		if (ret) {
			goto out;
		}

		*req_out = talloc_steal(mem_ctx, req);
	}

out:
	talloc_free(tmp_ctx);
	return ret;
}

int gmsa_generate_blobs(struct ldb_context *ldb,
			TALLOC_CTX *mem_ctx,
			const NTTIME current_time,
			const struct dom_sid *const account_sid,
			DATA_BLOB *pwd_id_blob_out,
			struct gmsa_null_terminated_password **password_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	struct KeyEnvelope pwd_id;
	const struct ProvRootKey *root_key = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		const struct ldb_message *root_key_msg = NULL;
		struct GUID root_key_id;
		const NTTIME one_interval = gkdi_key_cycle_duration +
					    gkdi_max_clock_skew;
		const NTTIME one_interval_ago = current_time -
						MIN(one_interval, current_time);

		ret = gkdi_most_recently_created_root_key(tmp_ctx,
							  ldb,
							  current_time,
							  one_interval_ago,
							  &root_key_id,
							  &root_key_msg);
		if (ret) {
			goto out;
		}

		status = gkdi_root_key_from_msg(tmp_ctx,
						root_key_id,
						root_key_msg,
						&root_key);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	/* Get the Managed Password ID. */
	status = gmsa_managed_pwd_id(ldb, tmp_ctx, NULL, root_key, &pwd_id);
	if (!NT_STATUS_IS_OK(status)) {
		ret = ldb_operr(ldb);
		goto out;
	}

	{
		const struct Gkid current_gkid = gkdi_get_interval_id(
			current_time);

		/* Derive the password. */
		status = gmsa_talloc_password_based_on_key_id(tmp_ctx,
							      current_gkid,
							      current_time,
							      root_key,
							      account_sid,
							      password_out);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}

		{
			const struct gmsa_update_pwd_part new_id = {
				.root_key = root_key,
				.gkid = current_gkid,
			};

			/*
			 * Update the password ID to contain the new GKID and
			 * root key ID.
			 */
			gmsa_update_managed_pwd_id(&pwd_id, &new_id);
		}
	}

	/* Pack the current password ID. */
	status = gmsa_pack_managed_pwd_id(mem_ctx, &pwd_id, pwd_id_blob_out);
	if (!NT_STATUS_IS_OK(status)) {
		ret = ldb_operr(ldb);
		goto out;
	}

	/* Transfer ownership of the password to the caller’s memory context. */
	talloc_steal(mem_ctx, *password_out);

out:
	talloc_free(tmp_ctx);
	return ret;
}

static int gmsa_create_update(TALLOC_CTX *mem_ctx,
			      struct ldb_context *ldb,
			      const struct ldb_message *msg,
			      const NTTIME current_time,
			      const struct dom_sid *account_sid,
			      const bool current_key_becomes_previous,
			      struct RootKey *current_key,
			      struct RootKey *previous_key,
			      struct gmsa_update **update_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	const DATA_BLOB *found_pwd_id = NULL;
	struct ldb_request *old_pw_req = NULL;
	struct ldb_request *new_pw_req = NULL;
	struct ldb_request *pwd_id_req = NULL;
	struct ldb_dn *account_dn = NULL;
	struct gmsa_update_pwd new_pwd = {};
	struct gmsa_update *update = NULL;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;

	if (update_out == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}
	*update_out = NULL;

	if (current_key == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	{
		/*
		 * The password_hash module expects these passwords to be
		 * null‐terminated.
		 */
		struct gmsa_null_terminated_password *new_password = NULL;

		ret = gmsa_get_root_key(ldb,
					current_time,
					account_sid,
					current_key,
					&new_password,
					&new_pwd.new_id);
		if (ret) {
			goto out;
		}

		if (new_password == NULL) {
			ret = ldb_operr(ldb);
			goto out;
		}

		status = gmsa_system_password_update_request(
			ldb, tmp_ctx, msg->dn, new_password->buf, &new_pw_req);
		if (!NT_STATUS_IS_OK(status)) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	/* Does the previous password need to be updated? */
	if (current_key_becomes_previous) {
		/*
		 * When we perform the password set, the now‐current password
		 * will become the previous password automatically. We don’t
		 * have to manage that ourselves.
		 */
	} else {
		struct gmsa_null_terminated_password *old_password = NULL;

		/* The current key cannot be reused as the previous key. */
		ret = gmsa_get_root_key(ldb,
					current_time,
					account_sid,
					previous_key,
					&old_password,
					&new_pwd.prev_id);
		if (ret) {
			goto out;
		}

		if (old_password != NULL) {
			status = gmsa_system_password_update_request(
				ldb,
				tmp_ctx,
				msg->dn,
				old_password->buf,
				&old_pw_req);
			if (!NT_STATUS_IS_OK(status)) {
				ret = ldb_operr(ldb);
				goto out;
			}
		}
	}

	/* Ready the update of the msDS-ManagedPasswordId attribute. */
	ret = gmsa_system_update_password_id_req(ldb,
						 tmp_ctx,
						 msg,
						 &new_pwd,
						 current_key_becomes_previous,
						 &pwd_id_req);
	if (ret) {
		goto out;
	}

	{
		/*
		 * Remember the original managed password ID so that we can
		 * confirm it hasn’t changed when we perform the update.
		 */

		const struct ldb_val *pwd_id_blob = ldb_msg_find_ldb_val(
			msg, "msDS-ManagedPasswordId");

		if (pwd_id_blob != NULL) {
			DATA_BLOB found_pwd_id_data = {};
			DATA_BLOB *found_pwd_id_blob = NULL;

			found_pwd_id_blob = talloc(tmp_ctx, DATA_BLOB);
			if (found_pwd_id_blob == NULL) {
				ret = ldb_oom(ldb);
				goto out;
			}

			found_pwd_id_data = data_blob_dup_talloc(
				found_pwd_id_blob, *pwd_id_blob);
			if (found_pwd_id_data.length != pwd_id_blob->length) {
				ret = ldb_oom(ldb);
				goto out;
			}

			*found_pwd_id_blob = found_pwd_id_data;
			found_pwd_id = found_pwd_id_blob;
		}
	}

	account_dn = ldb_dn_copy(tmp_ctx, msg->dn);
	if (account_dn == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	update = talloc(tmp_ctx, struct gmsa_update);
	if (update == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	*update = (struct gmsa_update){
		.dn = talloc_steal(update, account_dn),
		.found_pwd_id = talloc_steal(update, found_pwd_id),
		.old_pw_req = talloc_steal(update, old_pw_req),
		.new_pw_req = talloc_steal(update, new_pw_req),
		.pwd_id_req = talloc_steal(update, pwd_id_req)};

	*update_out = talloc_steal(mem_ctx, update);

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

NTSTATUS gmsa_pack_managed_pwd(TALLOC_CTX *mem_ctx,
			       const uint8_t *new_password,
			       const uint8_t *old_password,
			       uint64_t query_interval,
			       uint64_t unchanged_interval,
			       DATA_BLOB *managed_pwd_out)
{
	const struct MANAGEDPASSWORD_BLOB managed_pwd = {
		.passwords = {.current = new_password,
			      .previous = old_password,
			      .query_interval = &query_interval,
			      .unchanged_interval = &unchanged_interval}};
	NTSTATUS status = NT_STATUS_OK;
	enum ndr_err_code err;

	err = ndr_push_struct_blob(managed_pwd_out,
				   mem_ctx,
				   &managed_pwd,
				   (ndr_push_flags_fn_t)
					   ndr_push_MANAGEDPASSWORD_BLOB);
	status = ndr_map_error2ntstatus(err);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("MANAGEDPASSWORD_BLOB push failed: %s\n",
			    nt_errstr(status));
	}

	return status;
}

bool dsdb_account_is_gmsa(struct ldb_context *ldb,
			  const struct ldb_message *msg)
{
	/*
	 * Check if the account has objectClass
	 * ‘msDS-GroupManagedServiceAccount’.
	 */
	return samdb_find_attribute(ldb,
				    msg,
				    "objectclass",
				    "msDS-GroupManagedServiceAccount") != NULL;
}

static struct new_key {
	NTTIME start_time;
	bool immediately_follows_previous;
} calculate_new_key(const NTTIME current_time,
		    const NTTIME current_key_expiration_time,
		    const NTTIME rollover_interval)
{
	NTTIME new_key_start_time = current_key_expiration_time;
	bool immediately_follows_previous = false;

	if (new_key_start_time < current_time && rollover_interval) {
		/*
		 * Advance the key start time by the rollover interval until it
		 * would be greater than the current time.
		 */
		const NTTIME time_to_advance_by = current_time + 1 -
						  new_key_start_time;
		const uint64_t stale_count = time_to_advance_by /
					     rollover_interval;
		new_key_start_time += stale_count * rollover_interval;

		SMB_ASSERT(new_key_start_time <= current_time);

		immediately_follows_previous = stale_count == 0;
	} else {
		/*
		 * It is possible that new_key_start_time ≥ current_time;
		 * specifically, if there is no password ID, and the creation
		 * time of the gMSA is in the future (perhaps due to replication
		 * weirdness).
		 */
	}

	return (struct new_key){
		.start_time = new_key_start_time,
		.immediately_follows_previous = immediately_follows_previous};
}

static bool gmsa_creation_time(const struct ldb_message *msg,
			       const NTTIME current_time,
			       NTTIME *creation_time_out)
{
	const struct ldb_val *when_created = NULL;
	time_t creation_unix_time;
	int ret;

	when_created = ldb_msg_find_ldb_val(msg, "whenCreated");
	ret = ldb_val_to_time(when_created, &creation_unix_time);
	if (ret) {
		/* Fail if we can’t read the attribute or it isn’t present. */
		return false;
	}

	unix_to_nt_time(creation_time_out, creation_unix_time);
	return true;
}

static const struct KeyEnvelopeId *gmsa_get_managed_pwd_id_attr_name(
	const struct ldb_message *msg,
	const char *attr_name,
	struct KeyEnvelopeId *key_env_out)
{
	const struct ldb_val *pwd_id_blob = ldb_msg_find_ldb_val(msg,
								 attr_name);
	if (pwd_id_blob == NULL) {
		return NULL;
	}

	return gkdi_pull_KeyEnvelopeId(*pwd_id_blob, key_env_out);
}

const struct KeyEnvelopeId *gmsa_get_managed_pwd_id(
	const struct ldb_message *msg,
	struct KeyEnvelopeId *key_env_out)
{
	return gmsa_get_managed_pwd_id_attr_name(msg,
						 "msDS-ManagedPasswordId",
						 key_env_out);
}

static const struct KeyEnvelopeId *gmsa_get_managed_pwd_prev_id(
	const struct ldb_message *msg,
	struct KeyEnvelopeId *key_env_out)
{
	return gmsa_get_managed_pwd_id_attr_name(
		msg, "msDS-ManagedPasswordPreviousId", key_env_out);
}

static bool samdb_result_gkdi_rollover_interval(const struct ldb_message *msg,
						NTTIME *rollover_interval_out)
{
	int64_t managed_password_interval;

	managed_password_interval = ldb_msg_find_attr_as_int64(
		msg, "msDS-ManagedPasswordInterval", 30);
	return gkdi_rollover_interval(managed_password_interval,
				      rollover_interval_out);
}

bool samdb_gmsa_key_is_recent(const struct ldb_message *msg,
			      const NTTIME current_time)
{
	const struct KeyEnvelopeId *pwd_id = NULL;
	struct KeyEnvelopeId pwd_id_buf;
	NTTIME key_start_time;
	bool ok;

	pwd_id = gmsa_get_managed_pwd_id(msg, &pwd_id_buf);
	if (pwd_id == NULL) {
		return false;
	}

	ok = gkdi_get_key_start_time(pwd_id->gkid, &key_start_time);
	if (!ok) {
		return false;
	}

	if (current_time < key_start_time) {
		return false;
	}

	return current_time - key_start_time < gkdi_max_clock_skew;
}

/*
 * Recalculate the managed password of an account. The account referred to by
 * ‘msg’ should be a Group Managed Service Account.
 *
 * Updated passwords are returned in ‘update_out’.
 *
 * Pass in a non‐NULL pointer for ‘return_out’ if you want the passwords as
 * reflected by the msDS-ManagedPassword operational attribute.
 */
int gmsa_recalculate_managed_pwd(TALLOC_CTX *mem_ctx,
				 struct ldb_context *ldb,
				 const struct ldb_message *msg,
				 const NTTIME current_time,
				 struct gmsa_update **update_out,
				 struct gmsa_return_pwd *return_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = LDB_SUCCESS;
	NTTIME rollover_interval;
	NTTIME current_key_expiration_time;
	NTTIME key_expiration_time;
	struct dom_sid account_sid;
	struct KeyEnvelopeId pwd_id_buf;
	const struct KeyEnvelopeId *pwd_id = NULL;
	struct RootKey previous_key = empty_root_key;
	struct RootKey current_key = empty_root_key;
	struct gmsa_update *update = NULL;
	struct gmsa_null_terminated_password *previous_password = NULL;
	struct gmsa_null_terminated_password *current_password = NULL;
	NTTIME query_interval = 0;
	NTTIME unchanged_interval = 0;
	NTTIME creation_time = 0;
	NTTIME account_age = 0;
	NTTIME key_start_time = 0;
	bool have_key_start_time = false;
	bool ok = true;
	bool current_key_is_valid = false;

	if (update_out == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}
	*update_out = NULL;

	/* Calculate the rollover interval. */
	ok = samdb_result_gkdi_rollover_interval(msg, &rollover_interval);
	if (!ok || rollover_interval == 0) {
		/* We can’t do anything if the rollover interval is zero. */
		ret = ldb_operr(ldb);
		goto out;
	}

	ok = gmsa_creation_time(msg, current_time, &creation_time);
	if (!ok) {
		return ldb_error(ldb,
				 LDB_ERR_OPERATIONS_ERROR,
				 "unable to determine creation time of Group "
				 "Managed Service Account");
	}
	account_age = current_time - MIN(creation_time, current_time);

	/* Calculate the expiration time of the current key. */
	pwd_id = gmsa_get_managed_pwd_id(msg, &pwd_id_buf);
	if (pwd_id != NULL &&
	    gkdi_get_key_start_time(pwd_id->gkid, &key_start_time))
	{
		have_key_start_time = true;

		/* Check for overflow. */
		if (key_start_time > UINT64_MAX - rollover_interval) {
			ret = ldb_operr(ldb);
			goto out;
		}
		current_key_expiration_time = key_start_time +
					      rollover_interval;
	} else {
		/*
		 * [MS-ADTS] does not say to use gkdi_get_interval_start_time(),
		 * but surely it makes no sense to have keys starting or ending
		 * at random times.
		 */
		current_key_expiration_time = gkdi_get_interval_start_time(
			creation_time);
	}

	/* Fetch the account’s SID, necessary for deriving passwords. */
	ret = samdb_result_dom_sid_buf(msg, "objectSid", &account_sid);
	if (ret) {
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	/*
	 * In determining whether the account’s passwords should be updated, we
	 * do not validate that the unicodePwd attribute is up‐to‐date, or even
	 * that it exists. We rely entirely on the fact that the managed
	 * password ID should be updated *only* as part of a successful gMSA
	 * password update. In any case, unicodePwd is optional in Samba — save
	 * for machine accounts (which gMSAs are :)) — and we can’t always rely
	 * on its presence.
	 *
	 * All this means that an admin (or a DC that doesn’t support gMSAs)
	 * could reset a gMSA’s password outside of the normal procedure, and
	 * the account would then have the wrong password until the key was due
	 * to roll over again. There’s nothing much we can do about this if we
	 * don’t want to re‐derive and verify the password every time we look up
	 * the keys.
	 */

	/*
	 * Administrators should be careful not to set a DC’s clock too far in
	 * the future, or a gMSA’s keys may be stuck at that future time and
	 * stop updating until said time rolls around for real.
	 */

	current_key_is_valid = pwd_id != NULL &&
			       current_time < current_key_expiration_time;
	if (current_key_is_valid) {
		key_expiration_time = current_key_expiration_time;

		if (return_out != NULL) {
			struct KeyEnvelopeId prev_pwd_id_buf;
			const struct KeyEnvelopeId *prev_pwd_id = NULL;

			ret = gmsa_specifc_root_key(tmp_ctx,
						    *pwd_id,
						    &current_key);
			if (ret) {
				goto out;
			}

			if (account_age >= rollover_interval) {
				prev_pwd_id = gmsa_get_managed_pwd_prev_id(
					msg, &prev_pwd_id_buf);
				if (prev_pwd_id != NULL) {
					ret = gmsa_specifc_root_key(
						tmp_ctx,
						*prev_pwd_id,
						&previous_key);
					if (ret) {
						goto out;
					}
				} else if (have_key_start_time &&
					   key_start_time >= rollover_interval)
				{
					/*
					 * The account’s old enough to have a
					 * previous password, but it doesn’t
					 * have a previous password ID for some
					 * reason. This can happen in our tests
					 * (python/samba/krb5/gmsa_tests.py)
					 * when we’re mucking about with times.
					 * Just produce what would have been the
					 * previous key.
					 */
					ret = gmsa_nonspecifc_root_key(
						tmp_ctx,
						key_start_time -
							rollover_interval,
						&previous_key);
					if (ret) {
						goto out;
					}
				}
			} else {
				/*
				 * The account is not old enough to have a
				 * previous password. The old password will not
				 * be returned.
				 */
			}
		}
	} else {
		/* Calculate the start time of the new key. */
		const struct new_key new_key = calculate_new_key(
			current_time,
			current_key_expiration_time,
			rollover_interval);
		const bool current_key_becomes_previous =
			pwd_id != NULL && new_key.immediately_follows_previous;

		/* Check for overflow. */
		if (new_key.start_time > UINT64_MAX - rollover_interval) {
			ret = ldb_operr(ldb);
			goto out;
		}
		key_expiration_time = new_key.start_time + rollover_interval;

		ret = gmsa_nonspecifc_root_key(tmp_ctx,
					       new_key.start_time,
					       &current_key);
		if (ret) {
			goto out;
		}

		if (account_age >= rollover_interval) {
			/* Check for underflow. */
			if (new_key.start_time < rollover_interval) {
				ret = ldb_operr(ldb);
				goto out;
			}
			ret = gmsa_nonspecifc_root_key(
				tmp_ctx,
				new_key.start_time - rollover_interval,
				&previous_key);
			if (ret) {
				goto out;
			}
		} else {
			/*
			 * The account is not old enough to have a previous
			 * password. The old password will not be returned.
			 */
		}

		/*
		 * The current GMSA key, according to the Managed Password ID,
		 * is no longer valid. We should update the account’s Managed
		 * Password ID and keys in anticipation of their being needed in
		 * the near future.
		 */

		ret = gmsa_create_update(tmp_ctx,
					 ldb,
					 msg,
					 current_time,
					 &account_sid,
					 current_key_becomes_previous,
					 &current_key,
					 &previous_key,
					 &update);
		if (ret) {
			goto out;
		}
	}

	if (return_out != NULL) {
		bool return_future_key;

		unchanged_interval = query_interval = key_expiration_time -
						      MIN(current_time,
							  key_expiration_time);

		/* Derive the current and previous passwords. */
		return_future_key = query_interval <= gkdi_max_clock_skew;
		if (return_future_key) {
			struct RootKey future_key = empty_root_key;

			/*
			 * The current key hasn’t expired yet, but it
			 * soon will. Return a new key that will be valid in the
			 * next epoch.
			 */

			ret = gmsa_nonspecifc_root_key(tmp_ctx,
						       key_expiration_time,
						       &future_key);
			if (ret) {
				goto out;
			}

			ret = gmsa_get_root_key(ldb,
						current_time,
						&account_sid,
						&future_key,
						&current_password,
						NULL);
			if (ret) {
				goto out;
			}

			ret = gmsa_get_root_key(ldb,
						current_time,
						&account_sid,
						&current_key,
						&previous_password,
						NULL);
			if (ret) {
				goto out;
			}

			/* Check for overflow. */
			if (unchanged_interval > UINT64_MAX - rollover_interval)
			{
				ret = ldb_operr(ldb);
				goto out;
			}
			unchanged_interval += rollover_interval;
		} else {
			/*
			 * Note that a gMSA will become unusable (at least until
			 * the next rollover) if its associated root key is ever
			 * deleted.
			 */

			ret = gmsa_get_root_key(ldb,
						current_time,
						&account_sid,
						&current_key,
						&current_password,
						NULL);
			if (ret) {
				goto out;
			}

			ret = gmsa_get_root_key(ldb,
						current_time,
						&account_sid,
						&previous_key,
						&previous_password,
						NULL);
			if (ret) {
				goto out;
			}
		}

		unchanged_interval -= MIN(gkdi_max_clock_skew,
					  unchanged_interval);
	}

	*update_out = talloc_steal(mem_ctx, update);
	if (return_out != NULL) {
		*return_out = (struct gmsa_return_pwd){
			.prev_pwd = talloc_steal(mem_ctx, previous_password),
			.new_pwd = talloc_steal(mem_ctx, current_password),
			.query_interval = query_interval,
			.unchanged_interval = unchanged_interval,
		};
	}

out:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static void gmsa_update_debug(const struct gmsa_update *gmsa_update)
{
	struct ldb_dn *dn = NULL;
	const char *account_dn = "<unknown>";

	if (!CHECK_DEBUGLVL(DBGLVL_NOTICE)) {
		return;
	}

	dn = gmsa_update->dn;
	if (dn != NULL) {
		const char *dn_str = NULL;

		dn_str = ldb_dn_get_linearized(dn);
		if (dn_str != NULL) {
			account_dn = dn_str;
		}
	}

	DBG_NOTICE("Updating keys for Group Managed Service Account %s\n",
		   account_dn);
}

static int gmsa_perform_request(struct ldb_context *ldb,
				struct ldb_request *req)
{
	int ret = LDB_SUCCESS;

	if (req == NULL) {
		return LDB_SUCCESS;
	}

	ret = ldb_request(ldb, req);
	if (ret) {
		return ret;
	}

	return ldb_wait(req->handle, LDB_WAIT_ALL);
}

static bool dsdb_data_blobs_equal(const DATA_BLOB *d1, const DATA_BLOB *d2)
{
	if (d1 == NULL && d2 == NULL) {
		return true;
	}

	if (d1 == NULL || d2 == NULL) {
		return false;
	}

	{
		const int cmp = data_blob_cmp(d1, d2);
		return cmp == 0;
	}
}

int dsdb_update_gmsa_entry_keys(TALLOC_CTX *mem_ctx,
				struct ldb_context *ldb,
				const struct gmsa_update *gmsa_update)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = LDB_SUCCESS;
	bool in_transaction = false;

	if (gmsa_update == NULL) {
		ret = ldb_operr(ldb);
		goto out;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	gmsa_update_debug(gmsa_update);

	/* The following must take place in a single transaction. */
	ret = ldb_transaction_start(ldb);
	if (ret) {
		goto out;
	}
	in_transaction = true;

	{
		/*
		 * Before performing the update, ensure that the managed
		 * password ID in the database has the value we expect.
		 */

		struct ldb_result *res = NULL;
		const struct ldb_val *pwd_id_blob = NULL;
		static const char *const managed_pwd_id_attr[] = {
			"msDS-ManagedPasswordId",
			NULL,
		};

		if (gmsa_update->dn == NULL) {
			ret = ldb_operr(ldb);
			goto out;
		}

		ret = dsdb_search_dn(ldb,
				     tmp_ctx,
				     &res,
				     gmsa_update->dn,
				     managed_pwd_id_attr,
				     0);
		if (ret) {
			goto out;
		}

		if (res->count != 1) {
			ret = ldb_error(
				ldb,
				LDB_ERR_NO_SUCH_OBJECT,
				"failed to find Group Managed Service Account "
				"to verify managed password ID");
			goto out;
		}

		pwd_id_blob = ldb_msg_find_ldb_val(res->msgs[0],
						   "msDS-ManagedPasswordId");
		if (!dsdb_data_blobs_equal(pwd_id_blob,
					   gmsa_update->found_pwd_id))
		{
			/*
			 * The account’s managed password ID doesn’t match what
			 * we thought it was — cancel the update. If the caller
			 * needs the latest values, it will retry the search,
			 * performing the update again if necessary.
			 */
			ret = LDB_SUCCESS;
			goto out;
		}
	}

	/*
	 * First update the previous password (if the request is not NULL,
	 * indicating that the previous password already matches the password of
	 * the account).
	 */
	ret = gmsa_perform_request(ldb, gmsa_update->old_pw_req);
	if (ret) {
		goto out;
	}

	/* Then update the current password. */
	ret = gmsa_perform_request(ldb, gmsa_update->new_pw_req);
	if (ret) {
		goto out;
	}

	/* Finally, update the msDS-ManagedPasswordId attribute. */
	ret = gmsa_perform_request(ldb, gmsa_update->pwd_id_req);
	if (ret) {
		goto out;
	}

	/* Commit the transaction. */
	ret = ldb_transaction_commit(ldb);
	in_transaction = false;
	if (ret) {
		goto out;
	}

out:
	if (in_transaction) {
		int ret2 = ldb_transaction_cancel(ldb);
		if (ret2) {
			ret = ret2;
		}
	}
	talloc_free(tmp_ctx);
	return ret;
}

int dsdb_update_gmsa_keys(TALLOC_CTX *mem_ctx,
			  struct ldb_context *ldb,
			  const struct ldb_result *res,
			  bool *retry_out)
{
	TALLOC_CTX *tmp_ctx = NULL;
	int ret = LDB_SUCCESS;
	bool retry = false;
	unsigned i;
	NTTIME current_time;
	bool am_rodc = true;

	/*
	 * This is non-zero if we are local to the sam.ldb, this is an
	 * opaque set by the samba_dsdb module
	 */
	void *samba_dsdb_opaque = ldb_get_opaque(
		ldb, DSDB_OPAQUE_PARTITION_MODULE_MSG_OPAQUE_NAME);

	if (samba_dsdb_opaque == NULL) {
		/*
		 * We are not connected locally, so no point trying to
		 * set passwords
		 */
		*retry_out = false;
		return LDB_SUCCESS;
	}

	{
		/* Calculate the current time, as reckoned for gMSAs. */
		bool ok = dsdb_gmsa_current_time(ldb, &current_time);
		if (!ok) {
			ret = ldb_operr(ldb);
			goto out;
		}
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		ret = ldb_oom(ldb);
		goto out;
	}

	/* Are we operating as an RODC? */
	ret = samdb_rodc(ldb, &am_rodc);
	if (ret != LDB_SUCCESS) {
		DBG_WARNING("unable to tell if we are an RODC\n");
		goto out;
	}

	/* Loop through each entry in the results. */
	for (i = 0; i < res->count; ++i) {
		struct ldb_message *msg = res->msgs[i];
		struct gmsa_update *gmsa_update = NULL;
		const bool is_gmsa = dsdb_account_is_gmsa(ldb, msg);

		/* Is the account a Group Managed Service Account? */
		if (!is_gmsa) {
			/*
			 * It’s not a gMSA, and there’s nothing more to do for
			 * this result.
			 */
			continue;
		}

		if (am_rodc) {
			static const char *const secret_attributes[] = {
				DSDB_SECRET_ATTRIBUTES};
			size_t j;

			/*
			 * If we’re an RODC, we won’t be able to update the
			 * database entry with the new gMSA keys. The simplest
			 * thing to do is redact all the password attributes in
			 * the message. If our caller is the KDC, it will
			 * recognize the missing keys and dispatch a referral to
			 * a writable DC. */
			for (j = 0; j < ARRAY_SIZE(secret_attributes); ++j) {
				ldb_msg_remove_attr(msg, secret_attributes[j]);
			}

			/* Proceed to the next search result. */
			continue;
		}

		/* Update any old gMSA state. */
		ret = gmsa_recalculate_managed_pwd(
			tmp_ctx, ldb, msg, current_time, &gmsa_update, NULL);
		if (ret) {
			goto out;
		}

		if (gmsa_update == NULL) {
			/*
			 * The usual case; the keys are up‐to‐date, and there’s
			 * nothing more to do for this result.
			 */
			continue;
		}

		ret = dsdb_update_gmsa_entry_keys(tmp_ctx,
						  ldb,
						  gmsa_update);
		if (ret) {
			goto out;
		}

		/*
		 * Since the database entry has been updated, the caller will
		 * need to perform the search again.
		 */
		retry = true;
	}

	*retry_out = retry;

out:
	talloc_free(tmp_ctx);
	return ret;
}

bool dsdb_gmsa_current_time(struct ldb_context *ldb, NTTIME *current_time_out)
{
	const unsigned long long *gmsa_time = talloc_get_type(
		ldb_get_opaque(ldb, DSDB_GMSA_TIME_OPAQUE), unsigned long long);

	if (gmsa_time != NULL) {
		*current_time_out = *gmsa_time;
		return true;
	}

	return gmsa_current_time(current_time_out);
}

/* Set the current time.  Caller to supply valid unsigned long long talloc pointer and manage lifetime */
bool dsdb_gmsa_set_current_time(struct ldb_context *ldb, unsigned long long *current_time_talloc)
{
	int ret = ldb_set_opaque(ldb, DSDB_GMSA_TIME_OPAQUE, current_time_talloc);
	if (ret != LDB_SUCCESS) {

		return false;
	}
	return true;
}
