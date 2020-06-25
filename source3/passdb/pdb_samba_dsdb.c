/*
   Unix SMB/CIFS implementation.
   pdb glue module for direct access to the dsdb via LDB APIs
   Copyright (C) Volker Lendecke 2009-2011
   Copyright (C) Andrew Bartlett 2010-2012
   Copyright (C) Matthias Dieter Wallnöfer                 2009

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

/* This module, is a port of Volker's pdb_ads to ldb and DSDB APIs */

#include "includes.h"
#include "source3/include/passdb.h"
#include "source4/dsdb/samdb/samdb.h"
#include "ldb_errors.h"
#include "libcli/security/dom_sid.h"
#include "source4/winbind/idmap.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "libds/common/flag_mapping.h"
#include "source4/lib/events/events.h"
#include "source4/auth/session.h"
#include "source4/auth/system_session_proto.h"
#include "lib/param/param.h"
#include "source4/dsdb/common/util.h"
#include "source3/include/secrets.h"
#include "source4/auth/auth_sam.h"
#include "auth/credentials/credentials.h"
#include "lib/util/base64.h"
#include "libcli/ldap/ldap_ndr.h"
#include "lib/util/util_ldb.h"

struct pdb_samba_dsdb_state {
	struct tevent_context *ev;
	struct ldb_context *ldb;
	struct idmap_context *idmap_ctx;
	struct loadparm_context *lp_ctx;
};

static NTSTATUS pdb_samba_dsdb_getsampwsid(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const struct dom_sid *sid);
static NTSTATUS pdb_samba_dsdb_getsamupriv(struct pdb_samba_dsdb_state *state,
				    const char *filter,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_message **pmsg);
static bool pdb_samba_dsdb_sid_to_id(struct pdb_methods *m, const struct dom_sid *sid,
				 struct unixid *id);

static bool pdb_samba_dsdb_pull_time(struct ldb_message *msg, const char *attr,
			      time_t *ptime)
{
	uint64_t tmp;
	if (! ldb_msg_find_element(msg, attr)) {
		return false;
	}
	tmp = ldb_msg_find_attr_as_uint64(msg, attr, 0);
	*ptime = nt_time_to_unix(tmp);
	return true;
}

static struct pdb_domain_info *pdb_samba_dsdb_get_domain_info(
	struct pdb_methods *m, TALLOC_CTX *mem_ctx)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct pdb_domain_info *info;
	struct dom_sid *domain_sid;
	struct ldb_dn *forest_dn, *domain_dn;
	struct ldb_result *dom_res = NULL;
	const char *dom_attrs[] = {
		"objectSid",
		"objectGUID",
		"fSMORoleOwner",
		NULL
	};
	char *p;
	int ret;

	info = talloc(mem_ctx, struct pdb_domain_info);
	if (info == NULL) {
		return NULL;
	}

	domain_dn = ldb_get_default_basedn(state->ldb);

	ret = ldb_search(state->ldb, info, &dom_res,
			 domain_dn, LDB_SCOPE_BASE, dom_attrs, NULL);
	if (ret != LDB_SUCCESS) {
		goto fail;
	}
	if (dom_res->count != 1) {
		goto fail;
	}

	info->guid = samdb_result_guid(dom_res->msgs[0], "objectGUID");

	domain_sid = samdb_result_dom_sid(state, dom_res->msgs[0], "objectSid");
	if (!domain_sid) {
		goto fail;
	}
	info->sid = *domain_sid;

	TALLOC_FREE(dom_res);

	info->name = talloc_strdup(info, lpcfg_sam_name(state->lp_ctx));
	info->dns_domain = ldb_dn_canonical_string(info, domain_dn);

	if (!info->dns_domain) {
		goto fail;
	}
	p = strchr(info->dns_domain, '/');
	if (p) {
		*p = '\0';
	}

	forest_dn = ldb_get_root_basedn(state->ldb);
	if (!forest_dn) {
		goto fail;
	}

	info->dns_forest = ldb_dn_canonical_string(info, forest_dn);
	if (!info->dns_forest) {
		goto fail;
	}
	p = strchr(info->dns_forest, '/');
	if (p) {
		*p = '\0';
	}

	return info;

fail:
	TALLOC_FREE(dom_res);
	TALLOC_FREE(info);
	return NULL;
}

static struct ldb_message *pdb_samba_dsdb_get_samu_private(
	struct pdb_methods *m, struct samu *sam)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_message *msg;
	struct dom_sid_buf sidstr;
	char *filter;
	NTSTATUS status;

	msg = (struct ldb_message *)
		pdb_get_backend_private_data(sam, m);

	if (msg != NULL) {
		return talloc_get_type_abort(msg, struct ldb_message);
	}

	filter = talloc_asprintf(
		talloc_tos(),
		"(&(objectsid=%s)(objectclass=user))",
		dom_sid_str_buf(pdb_get_user_sid(sam), &sidstr));
	if (filter == NULL) {
		return NULL;
	}

	status = pdb_samba_dsdb_getsamupriv(state, filter, sam, &msg);
	TALLOC_FREE(filter);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	return msg;
}

static NTSTATUS pdb_samba_dsdb_init_sam_from_priv(struct pdb_methods *m,
					   struct samu *sam,
					   struct ldb_message *msg)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_INTERNAL_DB_CORRUPTION;
	const char *str;
	time_t tmp_time;
	struct dom_sid *sid, group_sid;
	uint64_t n;
	const DATA_BLOB *blob;

	str = ldb_msg_find_attr_as_string(msg, "samAccountName", NULL);
	if (str == NULL) {
		DEBUG(10, ("no samAccountName\n"));
		goto fail;
	}
	pdb_set_username(sam, str, PDB_SET);

	if (pdb_samba_dsdb_pull_time(msg, "lastLogon", &tmp_time)) {
		pdb_set_logon_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_samba_dsdb_pull_time(msg, "lastLogoff", &tmp_time)) {
		pdb_set_logoff_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_samba_dsdb_pull_time(msg, "pwdLastSet", &tmp_time)) {
		pdb_set_pass_last_set_time(sam, tmp_time, PDB_SET);
	}
	if (pdb_samba_dsdb_pull_time(msg, "accountExpires", &tmp_time)) {
		pdb_set_kickoff_time(sam, tmp_time, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "displayName",
					    NULL);
	if (str != NULL) {
		pdb_set_fullname(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "homeDirectory",
					    NULL);
	if (str != NULL) {
		pdb_set_homedir(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "homeDrive", NULL);
	if (str != NULL) {
		pdb_set_dir_drive(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "scriptPath", NULL);
	if (str != NULL) {
		pdb_set_logon_script(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "profilePath",
					    NULL);
	if (str != NULL) {
		pdb_set_profile_path(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "comment",
					    NULL);
	if (str != NULL) {
		pdb_set_comment(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "description",
					    NULL);
	if (str != NULL) {
		pdb_set_acct_desc(sam, str, PDB_SET);
	}

	str = ldb_msg_find_attr_as_string(msg, "userWorkstations",
					    NULL);
	if (str != NULL) {
		pdb_set_workstations(sam, str, PDB_SET);
	}

	blob = ldb_msg_find_ldb_val(msg, "userParameters");
	if (blob != NULL) {
		str = base64_encode_data_blob(frame, *blob);
		if (str == NULL) {
			DEBUG(0, ("base64_encode_data_blob() failed\n"));
			goto fail;
		}
		pdb_set_munged_dial(sam, str, PDB_SET);
	}

	sid = samdb_result_dom_sid(talloc_tos(), msg, "objectSid");
	if (!sid) {
		DEBUG(10, ("Could not pull SID\n"));
		goto fail;
	}
	pdb_set_user_sid(sam, sid, PDB_SET);

	n = samdb_result_acct_flags(msg, "msDS-User-Account-Control-Computed");
	if (n == 0) {
		DEBUG(10, ("Could not pull userAccountControl\n"));
		goto fail;
	}
	pdb_set_acct_ctrl(sam, n, PDB_SET);

	blob = ldb_msg_find_ldb_val(msg, "unicodePwd");
	if (blob) {
		if (blob->length != NT_HASH_LEN) {
			DEBUG(0, ("Got NT hash of length %d, expected %d\n",
				  (int)blob->length, NT_HASH_LEN));
			goto fail;
		}
		pdb_set_nt_passwd(sam, blob->data, PDB_SET);
	}

	blob = ldb_msg_find_ldb_val(msg, "dBCSPwd");
	if (blob) {
		if (blob->length != LM_HASH_LEN) {
			DEBUG(0, ("Got LM hash of length %d, expected %d\n",
				  (int)blob->length, LM_HASH_LEN));
			goto fail;
		}
		pdb_set_lanman_passwd(sam, blob->data, PDB_SET);
	}

	n = ldb_msg_find_attr_as_uint(msg, "primaryGroupID", 0);
	if (n == 0) {
		DEBUG(10, ("Could not pull primaryGroupID\n"));
		goto fail;
	}
	sid_compose(&group_sid, samdb_domain_sid(state->ldb), n);
	pdb_set_group_sid(sam, &group_sid, PDB_SET);

	status = NT_STATUS_OK;
fail:
	TALLOC_FREE(frame);
	return status;
}

static bool pdb_samba_dsdb_add_time(struct ldb_message *msg,
				const char *attrib, time_t t)
{
	uint64_t nt_time;

	unix_to_nt_time(&nt_time, t);

	return ldb_msg_add_fmt(msg, attrib, "%llu", (unsigned long long) nt_time);
}

static int pdb_samba_dsdb_replace_by_sam(struct pdb_samba_dsdb_state *state,
				     bool (*need_update)(const struct samu *,
							 enum pdb_elements),
				     struct ldb_dn *dn,
				     struct samu *sam)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int ret = LDB_SUCCESS;
	const char *pw;
	struct ldb_message *msg;
	struct ldb_request *req;
	uint32_t dsdb_flags = 0;
	/* TODO: All fields :-) */

	msg = ldb_msg_new(frame);
	if (!msg) {
		talloc_free(frame);
		return false;
	}

	msg->dn = dn;

	/* build modify request */
	ret = ldb_build_mod_req(&req, state->ldb, frame, msg, NULL, NULL,
				ldb_op_default_callback,
				NULL);
        if (ret != LDB_SUCCESS) {
		talloc_free(frame);
		return ret;
        }

	/* If we set a plaintext password, the system will
	 * force the pwdLastSet to now() */
	if (need_update(sam, PDB_PASSLASTSET)) {
		dsdb_flags |= DSDB_PASSWORD_BYPASS_LAST_SET;

		ret |= pdb_samba_dsdb_add_time(msg, "pwdLastSet",
					   pdb_get_pass_last_set_time(sam));
	}

	pw = pdb_get_plaintext_passwd(sam);
	if (need_update(sam, PDB_PLAINTEXT_PW)) {
		struct ldb_val pw_utf16;
		if (pw == NULL) {
			talloc_free(frame);
			return LDB_ERR_OPERATIONS_ERROR;
		}

		if (!convert_string_talloc(msg,
					   CH_UNIX, CH_UTF16,
					   pw, strlen(pw),
					   (void *)&pw_utf16.data,
					   &pw_utf16.length)) {
			talloc_free(frame);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		ret |= ldb_msg_add_value(msg, "clearTextPassword", &pw_utf16, NULL);
	} else {
		bool changed_lm_pw = false;
		bool changed_nt_pw = false;
		bool changed_history = false;
		if (need_update(sam, PDB_LMPASSWD)) {
			struct ldb_val val;
			val.data = discard_const_p(uint8_t, pdb_get_lanman_passwd(sam));
			if (!val.data) {
				samdb_msg_add_delete(state->ldb, msg, msg,
						     "dBCSPwd");
			} else {
				val.length = LM_HASH_LEN;
				ret |= ldb_msg_add_value(msg, "dBCSPwd", &val, NULL);
			}
			changed_lm_pw = true;
		}
		if (need_update(sam, PDB_NTPASSWD)) {
			struct ldb_val val;
			val.data = discard_const_p(uint8_t, pdb_get_nt_passwd(sam));
			if (!val.data) {
				samdb_msg_add_delete(state->ldb, msg, msg,
						     "unicodePwd");
			} else {
				val.length = NT_HASH_LEN;
				ret |= ldb_msg_add_value(msg, "unicodePwd", &val, NULL);
			}
			changed_nt_pw = true;
		}

		/* Try to ensure we don't get out of sync */
		if (changed_lm_pw && !changed_nt_pw) {
			samdb_msg_add_delete(state->ldb, msg, msg,
					     "unicodePwd");
		} else if (changed_nt_pw && !changed_lm_pw) {
			samdb_msg_add_delete(state->ldb, msg, msg,
					     "dBCSPwd");
		}
		if (changed_lm_pw || changed_nt_pw) {
			samdb_msg_add_delete(state->ldb, msg, msg,
					     "supplementalCredentials");

		}

		if (need_update(sam, PDB_PWHISTORY)) {
			uint32_t current_hist_len;
			const uint8_t *history = pdb_get_pw_history(sam, &current_hist_len);

			bool invalid_history = false;
			struct samr_Password *history_hashes = talloc_array(talloc_tos(), struct samr_Password,
									    current_hist_len);
			if (!history) {
				invalid_history = true;
			} else {
				unsigned int i;
				/* Parse the history into the correct format */
				for (i = 0; i < current_hist_len; i++) {
					if (!all_zero(&history[i*PW_HISTORY_ENTRY_LEN],
						      16)) {
						/* If the history is in the old format, with a salted hash, then we can't migrate it to AD format */
						invalid_history = true;
						break;
					}
					/* Copy out the 2nd 16 bytes of the 32 byte password history, containing the NT hash */
					memcpy(history_hashes[i].hash,
					       &history[(i*PW_HISTORY_ENTRY_LEN) + PW_HISTORY_SALT_LEN],
					       sizeof(history_hashes[i].hash));
				}
			}
			if (invalid_history) {
				ret |= samdb_msg_add_delete(state->ldb, msg, msg,
						     "ntPwdHistory");

				ret |= samdb_msg_add_delete(state->ldb, msg, msg,
						     "lmPwdHistory");
			} else {
				ret |= samdb_msg_add_hashes(state->ldb, msg, msg,
							    "ntPwdHistory",
							    history_hashes,
							    current_hist_len);
			}
			changed_history = true;
		}
		if (changed_lm_pw || changed_nt_pw || changed_history) {
			/* These attributes can only be modified directly by using a special control */
			dsdb_flags |= DSDB_BYPASS_PASSWORD_HASH;
		}
	}

	/* PDB_USERSID is only allowed on ADD, handled in caller */
	if (need_update(sam, PDB_GROUPSID)) {
		const struct dom_sid *sid = pdb_get_group_sid(sam);
		uint32_t rid;
		NTSTATUS status = dom_sid_split_rid(NULL, sid, NULL, &rid);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(frame);
			return LDB_ERR_OPERATIONS_ERROR;
		}
		if (!dom_sid_in_domain(samdb_domain_sid(state->ldb), sid)) {
			talloc_free(frame);
			return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
		}
		ret |= samdb_msg_add_uint(state->ldb, msg, msg, "primaryGroupID", rid);
	}
	if (need_update(sam, PDB_FULLNAME)) {
		ret |= ldb_msg_add_string(msg, "displayName", pdb_get_fullname(sam));
	}

	if (need_update(sam, PDB_SMBHOME)) {
		ret |= ldb_msg_add_string(msg, "homeDirectory",
					  pdb_get_homedir(sam));
	}

	if (need_update(sam, PDB_PROFILE)) {
		ret |= ldb_msg_add_string(msg, "profilePath",
					  pdb_get_profile_path(sam));
	}

	if (need_update(sam, PDB_DRIVE)) {
		ret |= ldb_msg_add_string(msg, "homeDrive",
					  pdb_get_dir_drive(sam));
	}

	if (need_update(sam, PDB_LOGONSCRIPT)) {
		ret |= ldb_msg_add_string(msg, "scriptPath",
					  pdb_get_logon_script(sam));
	}

	if (need_update(sam, PDB_KICKOFFTIME)) {
		ret |= pdb_samba_dsdb_add_time(msg, "accountExpires",
					pdb_get_kickoff_time(sam));
	}

	if (need_update(sam, PDB_LOGONTIME)) {
		ret |= pdb_samba_dsdb_add_time(msg, "lastLogon",
					pdb_get_logon_time(sam));
	}

	if (need_update(sam, PDB_LOGOFFTIME)) {
		ret |= pdb_samba_dsdb_add_time(msg, "lastLogoff",
					pdb_get_logoff_time(sam));
	}

	if (need_update(sam, PDB_USERNAME)) {
		ret |= ldb_msg_add_string(msg, "samAccountName",
					  pdb_get_username(sam));
	}

	if (need_update(sam, PDB_HOURSLEN) || need_update(sam, PDB_HOURS)) {
		struct ldb_val hours = data_blob_const(pdb_get_hours(sam), pdb_get_hours_len(sam));
		ret |= ldb_msg_add_value(msg, "logonHours",
					 &hours, NULL);
	}

	if (need_update(sam, PDB_ACCTCTRL)) {
		ret |= samdb_msg_add_acct_flags(state->ldb, msg, msg,
						"userAccountControl", pdb_get_acct_ctrl(sam));
	}

	if (need_update(sam, PDB_COMMENT)) {
		ret |= ldb_msg_add_string(msg, "comment",
					  pdb_get_comment(sam));
	}

	if (need_update(sam, PDB_ACCTDESC)) {
		ret |= ldb_msg_add_string(msg, "description",
					  pdb_get_acct_desc(sam));
	}

	if (need_update(sam, PDB_WORKSTATIONS)) {
		ret |= ldb_msg_add_string(msg, "userWorkstations",
					  pdb_get_workstations(sam));
	}

	/* This will need work, it is actually a UTF8 'string' with internal NULLs, to handle TS parameters */
	if (need_update(sam, PDB_MUNGEDDIAL)) {
		const char *base64_munged_dial = NULL;

		base64_munged_dial = pdb_get_munged_dial(sam);
		if (base64_munged_dial != NULL && strlen(base64_munged_dial) > 0) {
			struct ldb_val blob;

			blob = base64_decode_data_blob_talloc(msg,
							base64_munged_dial);
			if (blob.data == NULL) {
				DEBUG(0, ("Failed to decode userParameters from "
					  "munged dialback string[%s] for %s\n",
					  base64_munged_dial,
					  ldb_dn_get_linearized(msg->dn)));
				talloc_free(frame);
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
			ret |= ldb_msg_add_steal_value(msg, "userParameters",
						       &blob);
		}
	}

	if (need_update(sam, PDB_COUNTRY_CODE)) {
		ret |= ldb_msg_add_fmt(msg, "countryCode",
				       "%i", (int)pdb_get_country_code(sam));
	}

	if (need_update(sam, PDB_CODE_PAGE)) {
		ret |= ldb_msg_add_fmt(msg, "codePage",
				       "%i", (int)pdb_get_code_page(sam));
	}

	/* Not yet handled here or not meaningful for modifies on a Samba_Dsdb backend:
	PDB_BAD_PASSWORD_TIME,
	PDB_CANCHANGETIME, - these are calculated per policy, not stored
	PDB_DOMAIN,
	PDB_NTUSERNAME, - this makes no sense, and never really did
	PDB_LOGONDIVS,
	PDB_USERSID, - Handled in pdb_samba_dsdb_add_sam_account()
	PDB_FIELDS_PRESENT,
	PDB_BAD_PASSWORD_COUNT,
	PDB_LOGON_COUNT,
	PDB_UNKNOWN6,
	PDB_BACKEND_PRIVATE_DATA,

 */
	if (ret != LDB_SUCCESS) {
		talloc_free(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	if (msg->num_elements == 0) {
		talloc_free(frame);
		/* Nothing to do, just return success */
		return LDB_SUCCESS;
	}

	ret = dsdb_replace(state->ldb, msg, dsdb_flags);

	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to modify account record %s to set user attributes: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(state->ldb)));
	}

	talloc_free(frame);
	return ret;
}

static NTSTATUS pdb_samba_dsdb_getsamupriv(struct pdb_samba_dsdb_state *state,
				    const char *filter,
				    TALLOC_CTX *mem_ctx,
				    struct ldb_message **msg)
{
	const char * attrs[] = {
		"lastLogon", "lastLogoff", "pwdLastSet", "accountExpires",
		"sAMAccountName", "displayName", "homeDirectory",
		"homeDrive", "scriptPath", "profilePath", "description",
		"userWorkstations", "comment", "userParameters", "objectSid",
		"primaryGroupID", "userAccountControl",
		"msDS-User-Account-Control-Computed", "logonHours",
		"badPwdCount", "logonCount", "countryCode", "codePage",
		"unicodePwd", "dBCSPwd", NULL };

	int rc = dsdb_search_one(state->ldb, mem_ctx, msg, ldb_get_default_basedn(state->ldb), LDB_SCOPE_SUBTREE, attrs, 0, "%s", filter);
	if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   ldb_errstring(state->ldb)));
		return NT_STATUS_LDAP(rc);
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_getsampwfilter(struct pdb_methods *m,
					  struct pdb_samba_dsdb_state *state,
					  struct samu *sam_acct,
					  const char *exp_fmt, ...)
					  PRINTF_ATTRIBUTE(4,5);

static NTSTATUS pdb_samba_dsdb_getsampwfilter(struct pdb_methods *m,
					  struct pdb_samba_dsdb_state *state,
					  struct samu *sam_acct,
					  const char *exp_fmt, ...)
{
	struct ldb_message *priv;
	NTSTATUS status;
	va_list ap;
	char *expression = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(state);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	va_start(ap, exp_fmt);
	expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
	va_end(ap);

	if (!expression) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_samba_dsdb_getsamupriv(state, expression, sam_acct, &priv);
	talloc_free(tmp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_samba_dsdb_getsamupriv failed: %s\n",
			   nt_errstr(status)));
		return status;
	}

	status = pdb_samba_dsdb_init_sam_from_priv(m, sam_acct, priv);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_samba_dsdb_init_sam_from_priv failed: %s\n",
			   nt_errstr(status)));
		TALLOC_FREE(priv);
		return status;
	}

	pdb_set_backend_private_data(sam_acct, priv, NULL, m, PDB_SET);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_getsampwnam(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const char *username)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);

	return pdb_samba_dsdb_getsampwfilter(m, state, sam_acct,
					 "(&(samaccountname=%s)(objectclass=user))",
					 username);
}

static NTSTATUS pdb_samba_dsdb_getsampwsid(struct pdb_methods *m,
				    struct samu *sam_acct,
				    const struct dom_sid *sid)
{
	NTSTATUS status;
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid_buf buf;

	status = pdb_samba_dsdb_getsampwfilter(m, state, sam_acct,
					   "(&(objectsid=%s)(objectclass=user))",
					   dom_sid_str_buf(sid, &buf));
	return status;
}

static NTSTATUS pdb_samba_dsdb_create_user(struct pdb_methods *m,
				    TALLOC_CTX *mem_ctx,
				    const char *name, uint32_t acct_flags,
				    uint32_t *rid)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid *sid;
	struct ldb_dn *dn;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	/* Internally this uses transactions to ensure all the steps
	 * happen or fail as one */
	status = dsdb_add_user(state->ldb, tmp_ctx, name, acct_flags, NULL,
			       &sid, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}
	sid_peek_rid(sid, rid);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_delete_user(struct pdb_methods *m,
				       TALLOC_CTX *mem_ctx,
				       struct samu *sam)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_dn *dn;
	int rc;
	struct dom_sid_buf buf;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(
		tmp_ctx,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(pdb_get_user_sid(sam), &buf));
	if (!dn || !ldb_dn_validate(dn)) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rc = ldb_delete(state->ldb, dn);

	if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldb_delete for %s failed: %s\n", ldb_dn_get_linearized(dn),
			   ldb_errstring(state->ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_LDAP(rc);
	}
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/* This interface takes a fully populated struct samu and places it in
 * the database.  This is not implemented at this time as we need to
 * be careful around the creation of arbitrary SIDs (ie, we must ensure
 * they are not left in a RID pool */
static NTSTATUS pdb_samba_dsdb_add_sam_account(struct pdb_methods *m,
					struct samu *sampass)
{
	int ret;
	NTSTATUS status;
	struct ldb_dn *dn;
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	uint32_t acb_flags = pdb_get_acct_ctrl(sampass);
	const char *username = pdb_get_username(sampass);
	const struct dom_sid *user_sid = pdb_get_user_sid(sampass);
	TALLOC_CTX *tframe = talloc_stackframe();

	acb_flags &= (ACB_NORMAL|ACB_WSTRUST|ACB_SVRTRUST|ACB_DOMTRUST);

	ret = ldb_transaction_start(state->ldb);
	if (ret != LDB_SUCCESS) {
		talloc_free(tframe);
		return NT_STATUS_LOCK_NOT_GRANTED;
	}

	status = dsdb_add_user(state->ldb, talloc_tos(), username,
			       acb_flags, user_sid, NULL, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		ldb_transaction_cancel(state->ldb);
		talloc_free(tframe);
		return status;
	}

	ret = pdb_samba_dsdb_replace_by_sam(state, pdb_element_is_set_or_changed,
					dn, sampass);
	if (ret != LDB_SUCCESS) {
		ldb_transaction_cancel(state->ldb);
		talloc_free(tframe);
		return dsdb_ldb_err_to_ntstatus(ret);
	}

	ret = ldb_transaction_commit(state->ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to commit transaction to add and modify account record %s: %s\n",
			 ldb_dn_get_linearized(dn),
			 ldb_errstring(state->ldb)));
		talloc_free(tframe);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_free(tframe);
	return NT_STATUS_OK;
}

/*
 * Update the Samba_Dsdb LDB with the changes from a struct samu.
 *
 * This takes care not to update elements that have not been changed
 * by the caller
 */
static NTSTATUS pdb_samba_dsdb_update_sam_account(struct pdb_methods *m,
					   struct samu *sam)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_message *msg = pdb_samba_dsdb_get_samu_private(
		m, sam);
	int ret;

	ret = pdb_samba_dsdb_replace_by_sam(state, pdb_element_is_changed, msg->dn,
					sam);
	return dsdb_ldb_err_to_ntstatus(ret);
}

static NTSTATUS pdb_samba_dsdb_delete_sam_account(struct pdb_methods *m,
					   struct samu *username)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);
	status = pdb_samba_dsdb_delete_user(m, tmp_ctx, username);
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_rename_sam_account(struct pdb_methods *m,
					   struct samu *oldname,
					   const char *newname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* This is not implemented, as this module is expected to be used
 * with auth_samba_dsdb, and this is responsible for login counters etc
 *
 */
static NTSTATUS pdb_samba_dsdb_update_login_attempts(struct pdb_methods *m,
					      struct samu *sam_acct,
					      bool success)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_getgrfilter(struct pdb_methods *m,
					   GROUP_MAP *map,
					   const char *exp_fmt, ...)
					   PRINTF_ATTRIBUTE(3,4);

static NTSTATUS pdb_samba_dsdb_getgrfilter(struct pdb_methods *m, GROUP_MAP *map,
				    const char *exp_fmt, ...)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	const char *attrs[] = { "objectClass", "objectSid", "description", "samAccountName", "groupType",
				NULL };
	struct ldb_message *msg;
	va_list ap;
	char *expression = NULL;
	struct dom_sid *sid;
	const char *str;
	int rc;
	struct id_map id_map;
	struct id_map *id_maps[2];
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	va_start(ap, exp_fmt);
	expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
	va_end(ap);

	if (!expression) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	rc = dsdb_search_one(state->ldb, tmp_ctx, &msg, ldb_get_default_basedn(state->ldb), LDB_SCOPE_SUBTREE, attrs, 0, "%s", expression);
	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_SUCH_GROUP;
	} else if (rc != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		DEBUG(10, ("dsdb_search_one failed %s\n",
			   ldb_errstring(state->ldb)));
		return NT_STATUS_LDAP(rc);
	}

	sid = samdb_result_dom_sid(tmp_ctx, msg, "objectSid");
	if (!sid) {
		talloc_free(tmp_ctx);
		DEBUG(10, ("Could not pull SID\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	map->sid = *sid;

	if (samdb_find_attribute(state->ldb, msg, "objectClass", "group")) {
		NTSTATUS status;
		uint32_t grouptype = ldb_msg_find_attr_as_uint(msg, "groupType", 0);
		switch (grouptype) {
		case GTYPE_SECURITY_BUILTIN_LOCAL_GROUP:
		case GTYPE_SECURITY_DOMAIN_LOCAL_GROUP:
			map->sid_name_use = SID_NAME_ALIAS;
			break;
		case GTYPE_SECURITY_GLOBAL_GROUP:
			map->sid_name_use = SID_NAME_DOM_GRP;
			break;
		default:
			talloc_free(tmp_ctx);
			DEBUG(10, ("Could not pull groupType\n"));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ZERO_STRUCT(id_map);
		id_map.sid = sid;
		id_maps[0] = &id_map;
		id_maps[1] = NULL;

		status = idmap_sids_to_xids(state->idmap_ctx, tmp_ctx, id_maps);

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
		if (id_map.xid.type == ID_TYPE_GID || id_map.xid.type == ID_TYPE_BOTH) {
			map->gid = id_map.xid.id;
		} else {
			DEBUG(1, (__location__ "Did not get GUID when mapping SID for %s", expression));
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else if (samdb_find_attribute(state->ldb, msg, "objectClass", "user")) {
		DEBUG(1, (__location__ "Got SID_NAME_USER when searching for a group with %s", expression));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	str = ldb_msg_find_attr_as_string(msg, "samAccountName",
					  NULL);
	if (str == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	map->nt_name = talloc_strdup(map, str);
	if (!map->nt_name) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "description",
					    NULL);
	if (str != NULL) {
		map->comment = talloc_strdup(map, str);
	} else {
		map->comment = talloc_strdup(map, "");
	}
	if (!map->comment) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_getgrsid(struct pdb_methods *m, GROUP_MAP *map,
				 struct dom_sid sid)
{
	char *filter;
	NTSTATUS status;
	struct dom_sid_buf buf;

	filter = talloc_asprintf(talloc_tos(),
				 "(&(objectsid=%s)(objectclass=group))",
				 dom_sid_str_buf(&sid, &buf));
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_samba_dsdb_getgrfilter(m, map, "%s", filter);
	TALLOC_FREE(filter);
	return status;
}

static NTSTATUS pdb_samba_dsdb_getgrgid(struct pdb_methods *m, GROUP_MAP *map,
				 gid_t gid)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	NTSTATUS status;
	struct id_map id_map;
	struct id_map *id_maps[2];
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	id_map.xid.id = gid;
	id_map.xid.type = ID_TYPE_GID;
	id_maps[0] = &id_map;
	id_maps[1] = NULL;

	status = idmap_xids_to_sids(state->idmap_ctx, tmp_ctx, id_maps);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}
	status = pdb_samba_dsdb_getgrsid(m, map, *id_map.sid);
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_getgrnam(struct pdb_methods *m, GROUP_MAP *map,
				 const char *name)
{
	char *filter;
	NTSTATUS status;

	filter = talloc_asprintf(talloc_tos(),
				 "(&(samaccountname=%s)(objectclass=group))",
				 name);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_samba_dsdb_getgrfilter(m, map, "%s", filter);
	TALLOC_FREE(filter);
	return status;
}

static NTSTATUS pdb_samba_dsdb_create_dom_group(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx, const char *name,
					 uint32_t *rid)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	NTSTATUS status;
	struct dom_sid *sid;
	struct ldb_dn *dn;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	status = dsdb_add_domain_group(state->ldb, tmp_ctx, name, &sid, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	sid_peek_rid(sid, rid);
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_delete_dom_group(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx, uint32_t rid)
{
	const char *attrs[] = { NULL };
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid sid;
	struct ldb_message *msg;
	struct ldb_dn *dn;
	int rc;
	struct dom_sid_buf buf;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	sid_compose(&sid, samdb_domain_sid(state->ldb), rid);

	if (ldb_transaction_start(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Unable to start transaction in pdb_samba_dsdb_delete_dom_group()\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	dn = ldb_dn_new_fmt(
		tmp_ctx,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(&sid, &buf));
	if (!dn || !ldb_dn_validate(dn)) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_NO_MEMORY;
	}
	rc = dsdb_search_one(state->ldb, tmp_ctx, &msg, dn, LDB_SCOPE_BASE, attrs, 0, "objectclass=group");
	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_NO_SUCH_GROUP;
	}
	rc = ldb_delete(state->ldb, dn);
	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_NO_SUCH_GROUP;
	} else if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldb_delete failed %s\n",
			   ldb_errstring(state->ldb)));
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_LDAP(rc);
	}

	if (ldb_transaction_commit(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Unable to commit transaction in pdb_samba_dsdb_delete_dom_group()\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_add_group_mapping_entry(struct pdb_methods *m,
						GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_update_group_mapping_entry(struct pdb_methods *m,
						   GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_delete_group_mapping_entry(struct pdb_methods *m,
						   struct dom_sid sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_enum_group_mapping(struct pdb_methods *m,
					   const struct dom_sid *sid,
					   enum lsa_SidType sid_name_use,
					   GROUP_MAP ***pp_rmap,
					   size_t *p_num_entries,
					   bool unix_only)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_enum_group_members(struct pdb_methods *m,
					   TALLOC_CTX *mem_ctx,
					   const struct dom_sid *group,
					   uint32_t **pmembers,
					   size_t *pnum_members)
{
	unsigned int i, num_sids, num_members;
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid *members_as_sids;
	struct dom_sid *dom_sid;
	uint32_t *members;
	struct ldb_dn *dn;
	NTSTATUS status;
	struct dom_sid_buf buf;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(
		tmp_ctx,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(group, &buf));
	if (!dn || !ldb_dn_validate(dn)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dsdb_enum_group_mem(state->ldb, tmp_ctx, dn, &members_as_sids, &num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}
	status = dom_sid_split_rid(tmp_ctx, group, &dom_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	*pmembers = members = talloc_array(mem_ctx, uint32_t, num_sids);
	if (*pmembers == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	num_members = 0;

	for (i = 0; i < num_sids; i++) {
		if (!dom_sid_in_domain(dom_sid, &members_as_sids[i])) {
			continue;
		}
		status = dom_sid_split_rid(NULL, &members_as_sids[i],
					   NULL, &members[num_members]);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
		num_members++;
	}
	*pnum_members = num_members;
	return NT_STATUS_OK;
}

/* Just convert the primary group SID into a group */
static NTSTATUS fake_enum_group_memberships(struct pdb_samba_dsdb_state *state,
					    TALLOC_CTX *mem_ctx,
					    struct samu *user,
					    struct dom_sid **pp_sids,
					    gid_t **pp_gids,
					    uint32_t *p_num_groups)
{
	NTSTATUS status;
	size_t num_groups = 0;
	struct dom_sid *group_sids = NULL;
	gid_t *gids = NULL;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	if (user->group_sid) {
		struct id_map *id_maps[2];
		struct id_map id_map;

		num_groups = 1;

		group_sids = talloc_array(tmp_ctx, struct dom_sid, num_groups);
		if (group_sids == NULL) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		gids = talloc_array(tmp_ctx, gid_t, num_groups);
		if (gids == NULL) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		group_sids[0] = *user->group_sid;

		ZERO_STRUCT(id_map);
		id_map.sid = &group_sids[0];
		id_maps[0] = &id_map;
		id_maps[1] = NULL;

		status = idmap_sids_to_xids(state->idmap_ctx, tmp_ctx, id_maps);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
		if (id_map.xid.type == ID_TYPE_GID || id_map.xid.type == ID_TYPE_BOTH) {
			gids[0] = id_map.xid.id;
		} else {
			struct dom_sid_buf buf1, buf2;
			DEBUG(1, (__location__
				  "Group %s, of which %s is a member, could not be converted to a GID\n",
				  dom_sid_str_buf(&group_sids[0], &buf1),
				  dom_sid_str_buf(&user->user_sid, &buf2)));
			talloc_free(tmp_ctx);
			/* We must error out, otherwise a user might
			 * avoid a DENY acl based on a group they
			 * missed out on */
			return NT_STATUS_NO_SUCH_GROUP;
		}
	}

	*pp_sids = talloc_steal(mem_ctx, group_sids);
	*pp_gids = talloc_steal(mem_ctx, gids);
	*p_num_groups = num_groups;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_enum_group_memberships(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       struct samu *user,
					       struct dom_sid **pp_sids,
					       gid_t **pp_gids,
					       uint32_t *p_num_groups)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_message *msg = pdb_samba_dsdb_get_samu_private(
		m, user);
	const char *attrs[] = { "tokenGroups", NULL};
	struct ldb_message *tokengroups_msg;
	struct ldb_message_element *tokengroups;
	int i, rc;
	NTSTATUS status;
	unsigned int count = 0;
	size_t num_groups;
	struct dom_sid *group_sids;
	gid_t *gids;
	TALLOC_CTX *tmp_ctx;

	if (msg == NULL) {
		/* Fake up some things here */
		return fake_enum_group_memberships(state,
						   mem_ctx,
						   user, pp_sids,
						   pp_gids, p_num_groups);
	}

	tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	rc = dsdb_search_one(state->ldb, tmp_ctx, &tokengroups_msg, msg->dn, LDB_SCOPE_BASE, attrs, 0, NULL);

	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_SUCH_USER;
	} else if (rc != LDB_SUCCESS) {
		DEBUG(10, ("dsdb_search_one failed %s\n",
			   ldb_errstring(state->ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_LDAP(rc);
	}

	tokengroups = ldb_msg_find_element(tokengroups_msg, "tokenGroups");

	if (tokengroups) {
		count = tokengroups->num_values;
	}

	group_sids = talloc_array(tmp_ctx, struct dom_sid, count);
	if (group_sids == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	gids = talloc_array(tmp_ctx, gid_t, count);
	if (gids == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	num_groups = 0;

	for (i=0; i<count; i++) {
		struct id_map *id_maps[2];
		struct id_map id_map;
		struct ldb_val *v = &tokengroups->values[i];
		enum ndr_err_code ndr_err
			= ndr_pull_struct_blob(v, group_sids, &group_sids[num_groups],
					       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ZERO_STRUCT(id_map);
		id_map.sid = &group_sids[num_groups];
		id_maps[0] = &id_map;
		id_maps[1] = NULL;

		status = idmap_sids_to_xids(state->idmap_ctx, tmp_ctx, id_maps);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
		if (id_map.xid.type == ID_TYPE_GID || id_map.xid.type == ID_TYPE_BOTH) {
			gids[num_groups] = id_map.xid.id;
		} else {
			struct dom_sid_buf buf;
			DEBUG(1, (__location__
				  "Group %s, of which %s is a member, could not be converted to a GID\n",
				  dom_sid_str_buf(&group_sids[num_groups],
						  &buf),
				  ldb_dn_get_linearized(msg->dn)));
			talloc_free(tmp_ctx);
			/* We must error out, otherwise a user might
			 * avoid a DENY acl based on a group they
			 * missed out on */
			return NT_STATUS_NO_SUCH_GROUP;
		}

		num_groups += 1;
		if (num_groups == count) {
			break;
		}
	}

	*pp_sids = talloc_steal(mem_ctx, group_sids);
	*pp_gids = talloc_steal(mem_ctx, gids);
	*p_num_groups = num_groups;
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_set_unix_primary_group(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       struct samu *user)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_mod_groupmem_by_sid(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       const struct dom_sid *groupsid,
					       const struct dom_sid *membersid,
					       int mod_op)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_message *msg;
	int ret;
	struct ldb_message_element *el;
	struct dom_sid_buf buf;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);
	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_new_fmt(
		msg,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(groupsid, &buf));
	if (!msg->dn || !ldb_dn_validate(msg->dn)) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_msg_add_fmt(
		msg,
		"member",
		"<SID=%s>",
		dom_sid_str_buf(membersid, &buf));
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	el = ldb_msg_find_element(msg, "member");
	el->flags = mod_op;

	/* No need for transactions here, the ldb auto-transaction
	 * code will handle things for the single operation */
	ret = ldb_modify(state->ldb, msg);
	talloc_free(tmp_ctx);
	if (ret != LDB_SUCCESS) {
		DEBUG(10, ("ldb_modify failed: %s\n",
			   ldb_errstring(state->ldb)));
		if (ret == LDB_ERR_ATTRIBUTE_OR_VALUE_EXISTS) {
			return NT_STATUS_MEMBER_IN_GROUP;
		}
		if (ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			return NT_STATUS_MEMBER_NOT_IN_GROUP;
		}
		return NT_STATUS_LDAP(ret);
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_mod_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32_t grouprid, uint32_t memberrid,
				     int mod_op)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	const struct dom_sid *dom_sid, *groupsid, *membersid;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dom_sid = samdb_domain_sid(state->ldb);

	groupsid = dom_sid_add_rid(tmp_ctx, dom_sid, grouprid);
	if (groupsid == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	membersid = dom_sid_add_rid(tmp_ctx, dom_sid, memberrid);
	if (membersid == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	status = pdb_samba_dsdb_mod_groupmem_by_sid(m, tmp_ctx, groupsid, membersid, mod_op);
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_add_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32_t group_rid, uint32_t member_rid)
{
	return pdb_samba_dsdb_mod_groupmem(m, mem_ctx, group_rid, member_rid,
				    LDB_FLAG_MOD_ADD);
}

static NTSTATUS pdb_samba_dsdb_del_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32_t group_rid, uint32_t member_rid)
{
	return pdb_samba_dsdb_mod_groupmem(m, mem_ctx, group_rid, member_rid,
				       LDB_FLAG_MOD_DELETE);
}

static NTSTATUS pdb_samba_dsdb_create_alias(struct pdb_methods *m,
				     const char *name, uint32_t *rid)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid *sid;

	struct ldb_dn *dn;
	NTSTATUS status;

	/* Internally this uses transactions to ensure all the steps
	 * happen or fail as one */
	status = dsdb_add_domain_alias(state->ldb, frame, name, &sid, &dn);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
	}

	sid_peek_rid(sid, rid);
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_delete_alias(struct pdb_methods *m,
				     const struct dom_sid *sid)
{
	const char *attrs[] = { NULL };
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_message *msg;
	struct ldb_dn *dn;
	int rc;
	struct dom_sid_buf buf;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(
		tmp_ctx,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(sid, &buf));
	if (!dn || !ldb_dn_validate(dn)) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	if (ldb_transaction_start(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to start transaction in dsdb_add_domain_alias(): %s\n", ldb_errstring(state->ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	rc = dsdb_search_one(state->ldb, tmp_ctx, &msg, dn, LDB_SCOPE_BASE, attrs, 0, "(objectclass=group)"
			     "(|(grouptype=%d)(grouptype=%d)))",
			     GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
			     GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_NO_SUCH_ALIAS;
	}
	rc = ldb_delete(state->ldb, dn);
	if (rc == LDB_ERR_NO_SUCH_OBJECT) {
		talloc_free(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return NT_STATUS_NO_SUCH_ALIAS;
	} else if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldb_delete failed %s\n",
			   ldb_errstring(state->ldb)));
		ldb_transaction_cancel(state->ldb);
		talloc_free(tmp_ctx);
		return NT_STATUS_LDAP(rc);
	}

	if (ldb_transaction_commit(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to commit transaction in pdb_samba_dsdb_delete_alias(): %s\n",
			  ldb_errstring(state->ldb)));
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

#if 0
static NTSTATUS pdb_samba_dsdb_set_aliasinfo(struct pdb_methods *m,
				      const struct dom_sid *sid,
				      struct acct_info *info)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct tldap_context *ld;
	const char *attrs[3] = { "objectSid", "description",
				 "samAccountName" };
	struct ldb_message **msg;
	char *sidstr, *dn;
	int rc;
	struct tldap_mod *mods;
	int num_mods;
	bool ok;

	ld = pdb_samba_dsdb_ld(state);
	if (ld == NULL) {
		return NT_STATUS_LDAP(TLDAP_SERVER_DOWN);
	}

	sidstr = sid_binstring(talloc_tos(), sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	rc = pdb_samba_dsdb_search_fmt(state, state->domaindn, TLDAP_SCOPE_SUB,
				attrs, ARRAY_SIZE(attrs), 0, talloc_tos(),
				&msg, "(&(objectSid=%s)(objectclass=group)"
				"(|(grouptype=%d)(grouptype=%d)))",
				sidstr, GTYPE_SECURITY_BUILTIN_LOCAL_GROUP,
				GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	TALLOC_FREE(sidstr)
	if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldap_search failed %s\n",
			   ldb_errstring(state->ldb)));
		return NT_STATUS_LDAP(rc);
	}
	switch talloc_array_length(msg) {
	case 0:
		return NT_STATUS_NO_SUCH_ALIAS;
	case 1:
		break;
	default:
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (!tldap_entry_dn(msg[0], &dn)) {
		TALLOC_FREE(msg);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	mods = NULL;
	num_mods = 0;
	ok = true;

	ok &= tldap_make_mod_fmt(
		msg[0], msg, &num_mods, &mods, "description",
		"%s", info->acct_desc);
	ok &= tldap_make_mod_fmt(
		msg[0], msg, &num_mods, &mods, "samAccountName",
		"%s", info->acct_name);
	if (!ok) {
		TALLOC_FREE(msg);
		return NT_STATUS_NO_MEMORY;
	}
	if (num_mods == 0) {
		/* no change */
		TALLOC_FREE(msg);
		return NT_STATUS_OK;
	}

	rc = tldap_modify(ld, dn, num_mods, mods, NULL, 0, NULL, 0);
	TALLOC_FREE(msg);
	if (rc != LDB_SUCCESS) {
		DEBUG(10, ("ldap_modify failed: %s\n",
			   ldb_errstring(state->ldb)));
		return NT_STATUS_LDAP(rc);
	}
	return NT_STATUS_OK;
}
#endif
static NTSTATUS pdb_samba_dsdb_add_aliasmem(struct pdb_methods *m,
				     const struct dom_sid *alias,
				     const struct dom_sid *member)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	status = pdb_samba_dsdb_mod_groupmem_by_sid(m, frame, alias, member, LDB_FLAG_MOD_ADD);
	talloc_free(frame);
	return status;
}

static NTSTATUS pdb_samba_dsdb_del_aliasmem(struct pdb_methods *m,
				     const struct dom_sid *alias,
				     const struct dom_sid *member)
{
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	status = pdb_samba_dsdb_mod_groupmem_by_sid(m, frame, alias, member, LDB_FLAG_MOD_DELETE);
	talloc_free(frame);
	return status;
}

static NTSTATUS pdb_samba_dsdb_enum_aliasmem(struct pdb_methods *m,
				      const struct dom_sid *alias,
				      TALLOC_CTX *mem_ctx,
				      struct dom_sid **pmembers,
				      size_t *pnum_members)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct ldb_dn *dn;
	unsigned int num_members;
	NTSTATUS status;
	struct dom_sid_buf buf;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(
		tmp_ctx,
		state->ldb,
		"<SID=%s>",
		dom_sid_str_buf(alias, &buf));
	if (!dn || !ldb_dn_validate(dn)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dsdb_enum_group_mem(state->ldb, mem_ctx, dn, pmembers, &num_members);
	if (NT_STATUS_IS_OK(status)) {
		*pnum_members = num_members;
	}
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_enum_alias_memberships(struct pdb_methods *m,
					       TALLOC_CTX *mem_ctx,
					       const struct dom_sid *domain_sid,
					       const struct dom_sid *members,
					       size_t num_members,
					       uint32_t **palias_rids,
					       size_t *pnum_alias_rids)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	uint32_t *alias_rids = NULL;
	size_t num_alias_rids = 0;
	int i;
	struct dom_sid *groupSIDs = NULL;
	unsigned int num_groupSIDs = 0;
	char *filter;
	NTSTATUS status;
	const char *sid_dn;
	DATA_BLOB sid_blob;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);
	/*
	 * TODO: Get the filter right so that we only get the aliases from
	 * either the SAM or BUILTIN
	 */

	filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=%u))",
				 GROUP_TYPE_BUILTIN_LOCAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_members; i++) {
		struct dom_sid_buf buf;

		sid_dn = talloc_asprintf(
			tmp_ctx,
			"<SID=%s>",
			dom_sid_str_buf(&members[i], &buf));
		if (sid_dn == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		sid_blob = data_blob_string_const(sid_dn);

		status = dsdb_expand_nested_groups(state->ldb, &sid_blob, true, filter,
						   tmp_ctx, &groupSIDs, &num_groupSIDs);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return status;
		}
	}

	alias_rids = talloc_array(mem_ctx, uint32_t, num_groupSIDs);
	if (alias_rids == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_groupSIDs; i++) {
		if (sid_peek_check_rid(domain_sid, &groupSIDs[i],
				       &alias_rids[num_alias_rids])) {
			num_alias_rids++;;
		}
	}

	*palias_rids = alias_rids;
	*pnum_alias_rids = num_alias_rids;
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_lookup_rids(struct pdb_methods *m,
				    const struct dom_sid *domain_sid,
				    int num_rids,
				    uint32_t *rids,
				    const char **names,
				    enum lsa_SidType *lsa_attrs)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	NTSTATUS status;

	TALLOC_CTX *tmp_ctx;

	if (num_rids == 0) {
		return NT_STATUS_NONE_MAPPED;
	}

	tmp_ctx = talloc_stackframe();
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	status = dsdb_lookup_rids(state->ldb, tmp_ctx, domain_sid, num_rids, rids, names, lsa_attrs);
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_lookup_names(struct pdb_methods *m,
				     const struct dom_sid *domain_sid,
				     int num_names,
				     const char **pp_names,
				     uint32_t *rids,
				     enum lsa_SidType *attrs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_get_account_policy(struct pdb_methods *m,
					   enum pdb_policy_type type,
					   uint32_t *value)
{
	return account_policy_get(type, value)
		? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_samba_dsdb_set_account_policy(struct pdb_methods *m,
					   enum pdb_policy_type type,
					   uint32_t value)
{
	return account_policy_set(type, value)
		? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS pdb_samba_dsdb_get_seq_num(struct pdb_methods *m,
				    time_t *seq_num_out)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	uint64_t seq_num;
	int ret = ldb_sequence_number(state->ldb, LDB_SEQ_HIGHEST_SEQ, &seq_num);
	if (ret == LDB_SUCCESS) {
		*seq_num_out = seq_num;
		return NT_STATUS_OK;
	} else {
		return NT_STATUS_UNSUCCESSFUL;
	}
}

struct pdb_samba_dsdb_search_state {
	uint32_t acct_flags;
	struct samr_displayentry *entries;
	uint32_t num_entries;
	ssize_t array_size;
	uint32_t current;
};

static bool pdb_samba_dsdb_next_entry(struct pdb_search *search,
			       struct samr_displayentry *entry)
{
	struct pdb_samba_dsdb_search_state *state = talloc_get_type_abort(
		search->private_data, struct pdb_samba_dsdb_search_state);

	if (state->current == state->num_entries) {
		return false;
	}

	entry->idx = state->entries[state->current].idx;
	entry->rid = state->entries[state->current].rid;
	entry->acct_flags = state->entries[state->current].acct_flags;

	entry->account_name = talloc_strdup(
		search, state->entries[state->current].account_name);
	entry->fullname = talloc_strdup(
		search, state->entries[state->current].fullname);
	entry->description = talloc_strdup(
		search, state->entries[state->current].description);

	state->current += 1;
	return true;
}

static void pdb_samba_dsdb_search_end(struct pdb_search *search)
{
	struct pdb_samba_dsdb_search_state *state = talloc_get_type_abort(
		search->private_data, struct pdb_samba_dsdb_search_state);
	talloc_free(state);
}

static bool pdb_samba_dsdb_search_filter(struct pdb_methods *m,
					 struct pdb_search *search,
					 struct pdb_samba_dsdb_search_state **pstate,
					 const char *exp_fmt, ...)
					 PRINTF_ATTRIBUTE(4, 5);

static bool pdb_samba_dsdb_search_filter(struct pdb_methods *m,
				     struct pdb_search *search,
				     struct pdb_samba_dsdb_search_state **pstate,
				     const char *exp_fmt, ...)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct pdb_samba_dsdb_search_state *sstate;
	const char * attrs[] = { "objectSid", "sAMAccountName", "displayName",
				 "userAccountControl", "description", NULL };
	struct ldb_result *res;
	int i, rc, num_users;

	va_list ap;
	char *expression = NULL;

	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (!tmp_ctx) {
		return false;
	}

	va_start(ap, exp_fmt);
	expression = talloc_vasprintf(tmp_ctx, exp_fmt, ap);
	va_end(ap);

	if (!expression) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	sstate = talloc_zero(tmp_ctx, struct pdb_samba_dsdb_search_state);
	if (sstate == NULL) {
		talloc_free(tmp_ctx);
		return false;
	}

	rc = dsdb_search(state->ldb, tmp_ctx, &res, ldb_get_default_basedn(state->ldb), LDB_SCOPE_SUBTREE, attrs, 0, "%s", expression);
	if (rc != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		DEBUG(10, ("dsdb_search failed: %s\n",
			   ldb_errstring(state->ldb)));
		return false;
	}

	num_users = res->count;

	sstate->entries = talloc_array(sstate, struct samr_displayentry,
				       num_users);
	if (sstate->entries == NULL) {
		talloc_free(tmp_ctx);
		DEBUG(10, ("talloc failed\n"));
		return false;
	}

	sstate->num_entries = 0;

	for (i=0; i<num_users; i++) {
		struct samr_displayentry *e;
		struct dom_sid *sid;

		e = &sstate->entries[sstate->num_entries];

		e->idx = sstate->num_entries;
		sid = samdb_result_dom_sid(tmp_ctx, res->msgs[i], "objectSid");
		if (!sid) {
			talloc_free(tmp_ctx);
			DEBUG(10, ("Could not pull SID\n"));
			return false;
		}
		sid_peek_rid(sid, &e->rid);

		e->acct_flags = samdb_result_acct_flags(res->msgs[i], "userAccountControl");
		e->account_name = ldb_msg_find_attr_as_string(
			res->msgs[i], "samAccountName", NULL);
		if (e->account_name == NULL) {
			talloc_free(tmp_ctx);
			return false;
		}
		e->fullname = ldb_msg_find_attr_as_string(
                        res->msgs[i], "displayName", "");
		e->description = ldb_msg_find_attr_as_string(
                        res->msgs[i], "description", "");

		sstate->num_entries += 1;
		if (sstate->num_entries >= num_users) {
			break;
		}
	}
	talloc_steal(sstate->entries, res->msgs);
	search->private_data = talloc_steal(search, sstate);
	search->next_entry = pdb_samba_dsdb_next_entry;
	search->search_end = pdb_samba_dsdb_search_end;
	*pstate = sstate;
	talloc_free(tmp_ctx);
	return true;
}

static bool pdb_samba_dsdb_search_users(struct pdb_methods *m,
				 struct pdb_search *search,
				 uint32_t acct_flags)
{
	struct pdb_samba_dsdb_search_state *sstate;
	bool ret;

	ret = pdb_samba_dsdb_search_filter(m, search, &sstate, "(objectclass=user)");
	if (!ret) {
		return false;
	}
	sstate->acct_flags = acct_flags;
	return true;
}

static bool pdb_samba_dsdb_search_groups(struct pdb_methods *m,
				  struct pdb_search *search)
{
	struct pdb_samba_dsdb_search_state *sstate;
	bool ret;

	ret = pdb_samba_dsdb_search_filter(m, search, &sstate,
				       "(&(grouptype=%d)(objectclass=group))",
				       GTYPE_SECURITY_GLOBAL_GROUP);
	if (!ret) {
		return false;
	}
	sstate->acct_flags = 0;
	return true;
}

static bool pdb_samba_dsdb_search_aliases(struct pdb_methods *m,
				   struct pdb_search *search,
				   const struct dom_sid *sid)
{
	struct pdb_samba_dsdb_search_state *sstate;
	bool ret;

	ret = pdb_samba_dsdb_search_filter(m, search, &sstate,
				       "(&(grouptype=%d)(objectclass=group))",
				       sid_check_is_builtin(sid)
				       ? GTYPE_SECURITY_BUILTIN_LOCAL_GROUP
				       : GTYPE_SECURITY_DOMAIN_LOCAL_GROUP);
	if (!ret) {
		return false;
	}
	sstate->acct_flags = 0;
	return true;
}

/* 
 * Instead of taking a gid or uid, this function takes a pointer to a 
 * unixid. 
 *
 * This acts as an in-out variable so that the idmap functions can correctly
 * receive ID_TYPE_BOTH, and this function ensures cache details are filled
 * correctly rather than forcing the cache to store ID_TYPE_UID or ID_TYPE_GID. 
 */
static bool pdb_samba_dsdb_id_to_sid(struct pdb_methods *m, struct unixid *id,
				     struct dom_sid *sid)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	NTSTATUS status;
	struct id_map id_map;
	struct id_map *id_maps[2];
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (!tmp_ctx) {
		return false;
	}

	id_map.xid = *id;
	id_maps[0] = &id_map;
	id_maps[1] = NULL;

	status = idmap_xids_to_sids(state->idmap_ctx, tmp_ctx, id_maps);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return false;
	}

	if (id_map.xid.type != ID_TYPE_NOT_SPECIFIED) {
		id->type = id_map.xid.type;
	}
	*sid = *id_map.sid;
	talloc_free(tmp_ctx);
	return true;
}

static bool pdb_samba_dsdb_sid_to_id(struct pdb_methods *m, const struct dom_sid *sid,
				 struct unixid *id)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct id_map id_map;
	struct id_map *id_maps[2];
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	if (!tmp_ctx) {
		return false;
	}

	ZERO_STRUCT(id_map);
	id_map.sid = discard_const_p(struct dom_sid, sid);
	id_maps[0] = &id_map;
	id_maps[1] = NULL;

	status = idmap_sids_to_xids(state->idmap_ctx, tmp_ctx, id_maps);
	talloc_free(tmp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}
	if (id_map.xid.type != ID_TYPE_NOT_SPECIFIED) {
		*id = id_map.xid;
		return true;
	}
	return false;
}

static uint32_t pdb_samba_dsdb_capabilities(struct pdb_methods *m)
{
	return PDB_CAP_STORE_RIDS | PDB_CAP_ADS | PDB_CAP_TRUSTED_DOMAINS_EX;
}

static bool pdb_samba_dsdb_new_rid(struct pdb_methods *m, uint32_t *rid)
{
	return false;
}

static bool pdb_samba_dsdb_get_trusteddom_pw(struct pdb_methods *m,
				      const char *domain, char** pwd,
				      struct dom_sid *sid,
				      time_t *pass_last_set_time)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAuthOutgoing",
		"whenCreated",
		"msDS-SupportedEncryptionTypes",
		"trustAttributes",
		"trustDirection",
		"trustType",
		NULL
	};
	struct ldb_message *msg;
	const struct ldb_val *password_val;
	int trust_direction_flags;
	int trust_type;
	int i;
	DATA_BLOB password_utf16;
	struct trustAuthInOutBlob password_blob;
	struct AuthenticationInformationArray *auth_array;
	char *password_talloc;
	size_t password_len;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	const char *netbios_domain = NULL;
	const struct dom_sid *domain_sid = NULL;

	status = dsdb_trust_search_tdo(state->ldb, domain, NULL,
				       attrs, tmp_ctx, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * This can be called to work out of a domain is
		 * trusted, rather than just to get the password
		 */
		DEBUG(2, ("Failed to get trusted domain password for %s - %s.  "
			  "It may not be a trusted domain.\n", domain,
			  nt_errstr(status)));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	netbios_domain = ldb_msg_find_attr_as_string(msg, "flatName", NULL);
	if (netbios_domain == NULL) {
		DEBUG(2, ("Trusted domain %s has to flatName defined.\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	domain_sid = samdb_result_dom_sid(tmp_ctx, msg, "securityIdentifier");
	if (domain_sid == NULL) {
		DEBUG(2, ("Trusted domain %s has no securityIdentifier defined.\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	trust_direction_flags = ldb_msg_find_attr_as_int(msg, "trustDirection", 0);
	if (!(trust_direction_flags & LSA_TRUST_DIRECTION_OUTBOUND)) {
		DBG_WARNING("Trusted domain %s is not an outbound trust.\n",
			    domain);
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	trust_type = ldb_msg_find_attr_as_int(msg, "trustType", 0);
	if (trust_type == LSA_TRUST_TYPE_MIT) {
		DBG_WARNING("Trusted domain %s is not an AD trust "
			    "(trustType == LSA_TRUST_TYPE_MIT).\n", domain);
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	password_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	if (password_val == NULL) {
		DEBUG(2, ("Failed to get trusted domain password for %s, "
			  "attribute trustAuthOutgoing not returned.\n", domain));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	ndr_err = ndr_pull_struct_blob(password_val, tmp_ctx, &password_blob,
				(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to get trusted domain password for %s, "
			  "attribute trustAuthOutgoing could not be parsed %s.\n",
			  domain,
			  ndr_map_error2string(ndr_err)));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	auth_array = &password_blob.current;

	for (i=0; i < auth_array->count; i++) {
		if (auth_array->array[i].AuthType == TRUST_AUTH_TYPE_CLEAR) {
			break;
		}
	}

	if (i == auth_array->count) {
		DEBUG(0, ("Trusted domain %s does not have a "
			  "clear-text password stored\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	password_utf16 = data_blob_const(auth_array->array[i].AuthInfo.clear.password,
					 auth_array->array[i].AuthInfo.clear.size);

	/*
	 * In the future, make this function return a
	 * cli_credentials that can store a MD4 hash with cli_credential_set_nt_hash()
	 * but for now convert to UTF8 and fail if the string can not be converted.
	 *
	 * We can't safely convert the random strings windows uses into
	 * utf8.
	 */
	if (!convert_string_talloc(tmp_ctx,
				   CH_UTF16MUNGED, CH_UTF8,
				   password_utf16.data, password_utf16.length,
				   (void *)&password_talloc,
				   &password_len)) {
		DEBUG(0, ("FIXME: Could not convert password for trusted domain %s"
			  " to UTF8. This may be a password set from Windows.\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return false;
	}
	*pwd = SMB_STRNDUP(password_talloc, password_len);
	if (pass_last_set_time) {
		*pass_last_set_time = nt_time_to_unix(auth_array->array[i].LastUpdateTime);
	}

	if (sid != NULL) {
		sid_copy(sid, domain_sid);
	}

	TALLOC_FREE(tmp_ctx);
	return true;
}

static NTSTATUS pdb_samba_dsdb_get_trusteddom_creds(struct pdb_methods *m,
						    const char *domain,
						    TALLOC_CTX *mem_ctx,
						    struct cli_credentials **_creds)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAuthOutgoing",
		"whenCreated",
		"msDS-SupportedEncryptionTypes",
		"trustAttributes",
		"trustDirection",
		"trustType",
		NULL
	};
	struct ldb_message *msg;
	const struct ldb_val *password_val;
	int trust_direction_flags;
	int trust_type;
	int i;
	DATA_BLOB password_utf16 = {};
	struct samr_Password *password_nt = NULL;
	uint32_t password_version = 0;
	DATA_BLOB old_password_utf16 = {};
	struct samr_Password *old_password_nt = NULL;
	struct trustAuthInOutBlob password_blob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	time_t last_set_time = 0;
	struct cli_credentials *creds = NULL;
	bool ok;
	const char *my_netbios_name = NULL;
	const char *my_netbios_domain = NULL;
	const char *my_dns_domain = NULL;
	const char *netbios_domain = NULL;
	char *account_name = NULL;
	char *principal_name = NULL;
	const char *dns_domain = NULL;

	status = dsdb_trust_search_tdo(state->ldb, domain, NULL,
				       attrs, tmp_ctx, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * This can be called to work out of a domain is
		 * trusted, rather than just to get the password
		 */
		DEBUG(2, ("Failed to get trusted domain password for %s - %s "
			  "It may not be a trusted domain.\n", domain,
			  nt_errstr(status)));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	netbios_domain = ldb_msg_find_attr_as_string(msg, "flatName", NULL);
	if (netbios_domain == NULL) {
		DEBUG(2, ("Trusted domain %s has to flatName defined.\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	dns_domain = ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);

	trust_direction_flags = ldb_msg_find_attr_as_int(msg, "trustDirection", 0);
	if (!(trust_direction_flags & LSA_TRUST_DIRECTION_OUTBOUND)) {
		DBG_WARNING("Trusted domain %s is not an outbound trust.\n",
			    domain);
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	trust_type = ldb_msg_find_attr_as_int(msg, "trustType", 0);
	if (trust_type == LSA_TRUST_TYPE_MIT) {
		DBG_WARNING("Trusted domain %s is not an AD trust "
			    "(trustType == LSA_TRUST_TYPE_MIT).\n", domain);
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	password_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	if (password_val == NULL) {
		DEBUG(2, ("Failed to get trusted domain password for %s, "
			  "attribute trustAuthOutgoing not returned.\n", domain));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ndr_err = ndr_pull_struct_blob(password_val, tmp_ctx, &password_blob,
				(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to get trusted domain password for %s, "
			  "attribute trustAuthOutgoing could not be parsed %s.\n",
			  domain,
			  ndr_map_error2string(ndr_err)));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	for (i=0; i < password_blob.current.count; i++) {
		struct AuthenticationInformation *a =
			&password_blob.current.array[i];

		switch (a->AuthType) {
		case TRUST_AUTH_TYPE_NONE:
			break;

		case TRUST_AUTH_TYPE_VERSION:
			password_version = a->AuthInfo.version.version;
			break;

		case TRUST_AUTH_TYPE_CLEAR:
			last_set_time = nt_time_to_unix(a->LastUpdateTime);

			password_utf16 = data_blob_const(a->AuthInfo.clear.password,
							 a->AuthInfo.clear.size);
			password_nt = NULL;
			break;

		case TRUST_AUTH_TYPE_NT4OWF:
			if (password_utf16.length != 0) {
				break;
			}

			last_set_time = nt_time_to_unix(a->LastUpdateTime);

			password_nt = &a->AuthInfo.nt4owf.password;
			break;
		}
	}

	for (i=0; i < password_blob.previous.count; i++) {
		struct AuthenticationInformation *a = &password_blob.previous.array[i];

		switch (a->AuthType) {
		case TRUST_AUTH_TYPE_NONE:
			break;

		case TRUST_AUTH_TYPE_VERSION:
			break;

		case TRUST_AUTH_TYPE_CLEAR:
			old_password_utf16 = data_blob_const(a->AuthInfo.clear.password,
							 a->AuthInfo.clear.size);
			old_password_nt = NULL;
			break;

		case TRUST_AUTH_TYPE_NT4OWF:
			if (old_password_utf16.length != 0) {
				break;
			}

			old_password_nt = &a->AuthInfo.nt4owf.password;
			break;
		}
	}

	if (password_utf16.length == 0 && password_nt == NULL) {
		DEBUG(0, ("Trusted domain %s does not have a "
			  "clear-text nor nt password stored\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	my_netbios_name = lpcfg_netbios_name(state->lp_ctx);
	my_netbios_domain = lpcfg_workgroup(state->lp_ctx);
	my_dns_domain = lpcfg_dnsdomain(state->lp_ctx);

	creds = cli_credentials_init(tmp_ctx);
	if (creds == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ok = cli_credentials_set_workstation(creds, my_netbios_name, CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	ok = cli_credentials_set_domain(creds, netbios_domain, CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ok = cli_credentials_set_realm(creds, dns_domain, CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	if (my_dns_domain != NULL && dns_domain != NULL) {
		cli_credentials_set_secure_channel_type(creds, SEC_CHAN_DNS_DOMAIN);
		account_name = talloc_asprintf(tmp_ctx, "%s.", my_dns_domain);
		if (account_name == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		principal_name = talloc_asprintf(tmp_ctx, "%s$@%s", my_netbios_domain,
						 cli_credentials_get_realm(creds));
		if (principal_name == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		cli_credentials_set_secure_channel_type(creds, SEC_CHAN_DOMAIN);
		account_name = talloc_asprintf(tmp_ctx, "%s$", my_netbios_domain);
		if (account_name == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		principal_name = NULL;
	}

	ok = cli_credentials_set_username(creds, account_name, CRED_SPECIFIED);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	if (principal_name != NULL) {
		ok = cli_credentials_set_principal(creds, principal_name,
						   CRED_SPECIFIED);
		if (!ok) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (old_password_nt != NULL) {
		ok = cli_credentials_set_old_nt_hash(creds, old_password_nt);
		if (!ok) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (old_password_utf16.length > 0) {
		ok = cli_credentials_set_old_utf16_password(creds,
							    &old_password_utf16);
		if (!ok) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (password_nt != NULL) {
		ok = cli_credentials_set_nt_hash(creds, password_nt,
						 CRED_SPECIFIED);
		if (!ok) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (password_utf16.length > 0) {
		ok = cli_credentials_set_utf16_password(creds,
							&password_utf16,
							CRED_SPECIFIED);
		if (!ok) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	cli_credentials_set_password_last_changed_time(creds, last_set_time);
	cli_credentials_set_kvno(creds, password_version);

	if (password_utf16.length > 0 && dns_domain != NULL) {
		/*
		 * Force kerberos if this is an active directory domain
		 */
		cli_credentials_set_kerberos_state(creds,
						   CRED_MUST_USE_KERBEROS);
	} else  {
		/*
		 * TODO: we should allow krb5 with the raw nt hash.
		 */
		cli_credentials_set_kerberos_state(creds,
						   CRED_DONT_USE_KERBEROS);
	}

	*_creds = talloc_move(mem_ctx, &creds);
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static bool pdb_samba_dsdb_set_trusteddom_pw(struct pdb_methods *m,
				      const char* domain, const char* pwd,
				      const struct dom_sid *sid)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"trustAuthOutgoing",
		"trustDirection",
		"trustType",
		NULL
	};
	struct ldb_message *msg = NULL;
	int trust_direction_flags;
	int trust_type;
	uint32_t i; /* The same type as old_blob.current.count */
	const struct ldb_val *old_val = NULL;
	struct trustAuthInOutBlob old_blob = {};
	uint32_t old_version = 0;
	uint32_t new_version = 0;
	DATA_BLOB new_utf16 = {};
	struct trustAuthInOutBlob new_blob = {};
	struct ldb_val new_val = {};
	struct timeval tv = timeval_current();
	NTTIME now = timeval_to_nttime(&tv);
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ok;
	int ret;

	ret = ldb_transaction_start(state->ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(2, ("Failed to start transaction.\n"));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	ok = samdb_is_pdc(state->ldb);
	if (!ok) {
		DEBUG(2, ("Password changes for domain %s are only allowed on a PDC.\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	status = dsdb_trust_search_tdo(state->ldb, domain, NULL,
				       attrs, tmp_ctx, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		/*
		 * This can be called to work out of a domain is
		 * trusted, rather than just to get the password
		 */
		DEBUG(2, ("Failed to get trusted domain password for %s - %s.  "
			  "It may not be a trusted domain.\n", domain,
			  nt_errstr(status)));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	trust_direction_flags = ldb_msg_find_attr_as_int(msg, "trustDirection", 0);
	if (!(trust_direction_flags & LSA_TRUST_DIRECTION_OUTBOUND)) {
		DBG_WARNING("Trusted domain %s is not an outbound trust, can't set a password.\n",
			    domain);
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	trust_type = ldb_msg_find_attr_as_int(msg, "trustType", 0);
	switch (trust_type) {
	case LSA_TRUST_TYPE_DOWNLEVEL:
	case LSA_TRUST_TYPE_UPLEVEL:
		break;
	default:
		DEBUG(0, ("Trusted domain %s is of type 0x%X - "
			  "password changes are not supported\n",
			  domain, (unsigned)trust_type));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	old_val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	if (old_val != NULL) {
		ndr_err = ndr_pull_struct_blob(old_val, tmp_ctx, &old_blob,
				(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to get trusted domain password for %s, "
				  "attribute trustAuthOutgoing could not be parsed %s.\n",
				  domain,
				  ndr_map_error2string(ndr_err)));
			TALLOC_FREE(tmp_ctx);
			ldb_transaction_cancel(state->ldb);
			return false;
		}
	}

	for (i=0; i < old_blob.current.count; i++) {
		struct AuthenticationInformation *a =
			&old_blob.current.array[i];

		switch (a->AuthType) {
		case TRUST_AUTH_TYPE_NONE:
			break;

		case TRUST_AUTH_TYPE_VERSION:
			old_version = a->AuthInfo.version.version;
			break;

		case TRUST_AUTH_TYPE_CLEAR:
			break;

		case TRUST_AUTH_TYPE_NT4OWF:
			break;
		}
	}

	new_version = old_version + 1;
	ok = convert_string_talloc(tmp_ctx,
				   CH_UNIX, CH_UTF16,
				   pwd, strlen(pwd),
			           (void *)&new_utf16.data,
			           &new_utf16.length);
	if (!ok) {
		DEBUG(0, ("Failed to generate new_utf16 password for  domain %s\n",
			  domain));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	if (new_utf16.length < 28) {
		DEBUG(0, ("new_utf16[%zu] version[%u] for domain %s to short.\n",
			  new_utf16.length,
			  (unsigned)new_version,
			  domain));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}
	if (new_utf16.length > 498) {
		DEBUG(0, ("new_utf16[%zu] version[%u] for domain %s to long.\n",
			  new_utf16.length,
			  (unsigned)new_version,
			  domain));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	new_blob.count = MAX(old_blob.current.count, 2);
	new_blob.current.array = talloc_zero_array(tmp_ctx,
					struct AuthenticationInformation,
					new_blob.count);
	if (new_blob.current.array == NULL) {
		DEBUG(0, ("talloc_zero_array(%u) failed\n",
			  (unsigned)new_blob.count));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}
	new_blob.previous.array = talloc_zero_array(tmp_ctx,
					struct AuthenticationInformation,
					new_blob.count);
	if (new_blob.current.array == NULL) {
		DEBUG(0, ("talloc_zero_array(%u) failed\n",
			  (unsigned)new_blob.count));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	for (i = 0; i < old_blob.current.count; i++) {
		struct AuthenticationInformation *o =
			&old_blob.current.array[i];
		struct AuthenticationInformation *p =
			&new_blob.previous.array[i];

		*p = *o;
		new_blob.previous.count++;
	}
	for (; i < new_blob.count; i++) {
		struct AuthenticationInformation *pi =
			&new_blob.previous.array[i];

		if (i == 0) {
			/*
			 * new_blob.previous is still empty so
			 * we'll do new_blob.previous = new_blob.current
			 * below.
			 */
			break;
		}

		pi->LastUpdateTime = now;
		pi->AuthType = TRUST_AUTH_TYPE_NONE;
		new_blob.previous.count++;
	}

	for (i = 0; i < new_blob.count; i++) {
		struct AuthenticationInformation *ci =
			&new_blob.current.array[i];

		ci->LastUpdateTime = now;
		switch (i) {
		case 0:
			ci->AuthType = TRUST_AUTH_TYPE_CLEAR;
			ci->AuthInfo.clear.size = new_utf16.length;
			ci->AuthInfo.clear.password = new_utf16.data;
			break;
		case 1:
			ci->AuthType = TRUST_AUTH_TYPE_VERSION;
			ci->AuthInfo.version.version = new_version;
			break;
		default:
			ci->AuthType = TRUST_AUTH_TYPE_NONE;
			break;
		}

		new_blob.current.count++;
	}

	if (new_blob.previous.count == 0) {
		TALLOC_FREE(new_blob.previous.array);
		new_blob.previous = new_blob.current;
	}

	ndr_err = ndr_push_struct_blob(&new_val, tmp_ctx, &new_blob,
			(ndr_push_flags_fn_t)ndr_push_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(0, ("Failed to generate trustAuthOutgoing for "
			  "trusted domain password for %s: %s.\n",
			  domain, ndr_map_error2string(ndr_err)));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	msg->num_elements = 0;
	ret = ldb_msg_add_empty(msg, "trustAuthOutgoing",
				LDB_FLAG_MOD_REPLACE, NULL);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("ldb_msg_add_empty() failed\n"));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}
	ret = ldb_msg_add_value(msg, "trustAuthOutgoing",
				&new_val, NULL);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("ldb_msg_add_value() failed\n"));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	ret = ldb_modify(state->ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to replace trustAuthOutgoing for "
			  "trusted domain password for %s: %s - %s\n",
			  domain, ldb_strerror(ret), ldb_errstring(state->ldb)));
		TALLOC_FREE(tmp_ctx);
		ldb_transaction_cancel(state->ldb);
		return false;
	}

	ret = ldb_transaction_commit(state->ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to commit trustAuthOutgoing for "
			  "trusted domain password for %s: %s - %s\n",
			  domain, ldb_strerror(ret), ldb_errstring(state->ldb)));
		TALLOC_FREE(tmp_ctx);
		return false;
	}

	DEBUG(1, ("Added new_version[%u] to trustAuthOutgoing for "
		  "trusted domain password for %s.\n",
		  (unsigned)new_version, domain));
	TALLOC_FREE(tmp_ctx);
	return true;
}

static bool pdb_samba_dsdb_del_trusteddom_pw(struct pdb_methods *m,
				      const char *domain)
{
	return false;
}

static NTSTATUS pdb_samba_dsdb_enum_trusteddoms(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx,
					 uint32_t *_num_domains,
					 struct trustdom_info ***_domains)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustDirection",
		NULL
	};
	struct ldb_result *res = NULL;
	unsigned int i;
	struct trustdom_info **domains = NULL;
	NTSTATUS status;
	uint32_t di = 0;

	*_num_domains = 0;
	*_domains = NULL;

	status = dsdb_trust_search_tdos(state->ldb, NULL,
					attrs, tmp_ctx, &res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdos() - %s ", nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (res->count == 0) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}

	domains = talloc_zero_array(tmp_ctx, struct trustdom_info *,
				    res->count);
	if (domains == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct trustdom_info *d = NULL;
		const char *name = NULL;
		struct dom_sid *sid = NULL;
		uint32_t direction;

		d = talloc_zero(domains, struct trustdom_info);
		if (d == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		name = ldb_msg_find_attr_as_string(msg, "flatName", NULL);
		if (name == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		sid = samdb_result_dom_sid(msg, msg, "securityIdentifier");
		if (sid == NULL) {
			continue;
		}

		direction = ldb_msg_find_attr_as_uint(msg, "trustDirection", 0);
		if (!(direction & LSA_TRUST_DIRECTION_OUTBOUND)) {
			continue;
		}

		d->name = talloc_strdup(d, name);
		if (d->name == NULL) {
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		d->sid = *sid;

		domains[di++] = d;
	}

	domains = talloc_realloc(domains, domains, struct trustdom_info *, di);
	*_domains = talloc_move(mem_ctx, &domains);
	*_num_domains = di;
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_msg_to_trusted_domain(const struct ldb_message *msg,
						TALLOC_CTX *mem_ctx,
						struct pdb_trusted_domain **_d)
{
	struct pdb_trusted_domain *d = NULL;
	const char *str = NULL;
	struct dom_sid *sid = NULL;
	const struct ldb_val *val = NULL;
	uint64_t val64;

	*_d = NULL;

	d = talloc_zero(mem_ctx, struct pdb_trusted_domain);
	if (d == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "flatName", NULL);
	if (str == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	d->netbios_name = talloc_strdup(d, str);
	if (d->netbios_name == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);
	if (str != NULL) {
		d->domain_name = talloc_strdup(d, str);
		if (d->domain_name == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
	}

	sid = samdb_result_dom_sid(d, msg, "securityIdentifier");
	if (sid != NULL) {
		d->security_identifier = *sid;
		TALLOC_FREE(sid);
	}

	val = ldb_msg_find_ldb_val(msg, "trustAuthOutgoing");
	if (val != NULL) {
		d->trust_auth_outgoing = data_blob_dup_talloc(d, *val);
		if (d->trust_auth_outgoing.data == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
	}
	val = ldb_msg_find_ldb_val(msg, "trustAuthIncoming");
	if (val != NULL) {
		d->trust_auth_incoming = data_blob_dup_talloc(d, *val);
		if (d->trust_auth_incoming.data == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
	}

	d->trust_direction = ldb_msg_find_attr_as_uint(msg, "trustDirection", 0);
	d->trust_type = ldb_msg_find_attr_as_uint(msg, "trustType", 0);
	d->trust_attributes = ldb_msg_find_attr_as_uint(msg, "trustAttributes", 0);

	val64 = ldb_msg_find_attr_as_uint64(msg, "trustPosixOffset", UINT64_MAX);
	if (val64 != UINT64_MAX) {
		d->trust_posix_offset = talloc(d, uint32_t);
		if (d->trust_posix_offset == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
		*d->trust_posix_offset = (uint32_t)val64;
	}

	val64 = ldb_msg_find_attr_as_uint64(msg, "msDS-SupportedEncryptionTypes", UINT64_MAX);
	if (val64 != UINT64_MAX) {
		d->supported_enc_type = talloc(d, uint32_t);
		if (d->supported_enc_type == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
		*d->supported_enc_type = (uint32_t)val64;
	}

	val = ldb_msg_find_ldb_val(msg, "msDS-TrustForestTrustInfo");
	if (val != NULL) {
		d->trust_forest_trust_info = data_blob_dup_talloc(d, *val);
		if (d->trust_forest_trust_info.data == NULL) {
			TALLOC_FREE(d);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_d = d;
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_get_trusted_domain(struct pdb_methods *m,
						  TALLOC_CTX *mem_ctx,
						  const char *domain,
						  struct pdb_trusted_domain **td)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAuthOutgoing",
		"trustAuthIncoming",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"trustPosixOffset",
		"msDS-SupportedEncryptionTypes",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_message *msg = NULL;
	struct pdb_trusted_domain *d = NULL;
	NTSTATUS status;

	status = dsdb_trust_search_tdo(state->ldb, domain, NULL,
				       attrs, tmp_ctx, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdo(%s) - %s ",
			domain, nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	status = pdb_samba_dsdb_msg_to_trusted_domain(msg, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("pdb_samba_dsdb_msg_to_trusted_domain(%s) - %s ",
			domain, nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	*td = d;
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_get_trusted_domain_by_sid(struct pdb_methods *m,
							 TALLOC_CTX *mem_ctx,
							 struct dom_sid *sid,
							 struct pdb_trusted_domain **td)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAuthOutgoing",
		"trustAuthIncoming",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"trustPosixOffset",
		"msDS-SupportedEncryptionTypes",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_message *msg = NULL;
	struct pdb_trusted_domain *d = NULL;
	struct dom_sid_buf buf;
	NTSTATUS status;

	status = dsdb_trust_search_tdo_by_sid(state->ldb, sid,
					      attrs, tmp_ctx, &msg);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdo_by_sid(%s) - %s ",
			dom_sid_str_buf(sid, &buf),
			nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	status = pdb_samba_dsdb_msg_to_trusted_domain(msg, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("pdb_samba_dsdb_msg_to_trusted_domain(%s) - %s ",
			dom_sid_str_buf(sid, &buf),
			nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	*td = d;
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static NTSTATUS add_trust_user(TALLOC_CTX *mem_ctx,
			       struct ldb_context *sam_ldb,
			       struct ldb_dn *base_dn,
			       const char *netbios_name,
			       struct trustAuthInOutBlob *taiob)
{
	struct ldb_request *req = NULL;
	struct ldb_message *msg = NULL;
	struct ldb_dn *dn = NULL;
	uint32_t i;
	int ret;
	bool ok;

	dn = ldb_dn_copy(mem_ctx, base_dn);
	if (dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ok = ldb_dn_add_child_fmt(dn, "cn=%s$,cn=users", netbios_name);
	if (!ok) {
		return NT_STATUS_NO_MEMORY;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = dn;

	ret = ldb_msg_add_string(msg, "objectClass", "user");
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_msg_add_fmt(msg, "samAccountName", "%s$", netbios_name);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_msg_add_uint(sam_ldb, msg, msg, "userAccountControl",
				 UF_INTERDOMAIN_TRUST_ACCOUNT);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < taiob->count; i++) {
		struct AuthenticationInformation *auth_info =
			&taiob->current.array[i];
		const char *attribute = NULL;
		struct ldb_val v;

		switch (taiob->current.array[i].AuthType) {
		case TRUST_AUTH_TYPE_NT4OWF:
			attribute = "unicodePwd";
			v.data = (uint8_t *)&auth_info->AuthInfo.nt4owf.password;
			v.length = 16;
			break;

		case TRUST_AUTH_TYPE_CLEAR:
			attribute = "clearTextPassword";
			v.data = auth_info->AuthInfo.clear.password;
			v.length = auth_info->AuthInfo.clear.size;
			break;

		default:
			continue;
		}

		ret = ldb_msg_add_value(msg, attribute, &v, NULL);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* create the trusted_domain user account */
	ret = ldb_build_add_req(&req, sam_ldb, mem_ctx, msg, NULL, NULL,
				ldb_op_default_callback, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = ldb_request_add_control(
		req, DSDB_CONTROL_PERMIT_INTERDOMAIN_TRUST_UAC_OID,
		false, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_autotransaction_request(sam_ldb, req);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create user record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn),
			 ldb_errstring(sam_ldb)));

		switch (ret) {
		case LDB_ERR_ENTRY_ALREADY_EXISTS:
			return NT_STATUS_DOMAIN_EXISTS;
		case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
			return NT_STATUS_ACCESS_DENIED;
		default:
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_set_trusted_domain(struct pdb_methods *methods,
						  const char* domain,
						  const struct pdb_trusted_domain *td)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		methods->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	bool in_txn = false;
	struct ldb_dn *base_dn = NULL;
	struct ldb_message *msg = NULL;
	const char *attrs[] = {
		NULL
	};
	char *netbios_encoded = NULL;
	char *dns_encoded = NULL;
	char *sid_encoded = NULL;
	int ret;
	struct trustAuthInOutBlob taiob;
	enum ndr_err_code ndr_err;
	NTSTATUS status;
	bool ok;

	base_dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->ldb));
	if (base_dn == NULL) {
		TALLOC_FREE(tmp_ctx);
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	/*
	 * We expect S-1-5-21-A-B-C, but we don't
	 * allow S-1-5-21-0-0-0 as this is used
	 * for claims and compound identities.
	 */
	ok = dom_sid_is_valid_account_domain(&td->security_identifier);
	if (!ok) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	if (strequal(td->netbios_name, "BUILTIN")) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}
	if (strequal(td->domain_name, "BUILTIN")) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	dns_encoded = ldb_binary_encode_string(tmp_ctx, td->domain_name);
	if (dns_encoded == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	netbios_encoded = ldb_binary_encode_string(tmp_ctx, td->netbios_name);
	if (netbios_encoded == NULL) {
		status =NT_STATUS_NO_MEMORY;
		goto out;
	}
	sid_encoded = ldap_encode_ndr_dom_sid(tmp_ctx, &td->security_identifier);
	if (sid_encoded == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ok = samdb_is_pdc(state->ldb);
	if (!ok) {
		DBG_ERR("Adding TDO is only allowed on a PDC.\n");
		TALLOC_FREE(tmp_ctx);
		status = NT_STATUS_INVALID_DOMAIN_ROLE;
		goto out;
	}

	status = dsdb_trust_search_tdo(state->ldb,
				       td->netbios_name,
				       td->domain_name,
				       attrs,
				       tmp_ctx,
				       &msg);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DBG_ERR("dsdb_trust_search_tdo returned %s\n",
			nt_errstr(status));
		status = NT_STATUS_INVALID_DOMAIN_STATE;
		goto out;
	}

	ret = ldb_transaction_start(state->ldb);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}
	in_txn = true;

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	msg->dn = ldb_dn_copy(tmp_ctx, base_dn);

	ok = ldb_dn_add_child_fmt(msg->dn, "cn=%s,cn=System", td->domain_name);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_msg_add_string(msg, "objectClass", "trustedDomain");
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_msg_add_string(msg, "flatname", td->netbios_name);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_msg_add_string(msg, "trustPartner", td->domain_name);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = samdb_msg_add_dom_sid(state->ldb,
				    tmp_ctx,
				    msg,
				    "securityIdentifier",
				    &td->security_identifier);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = samdb_msg_add_int(state->ldb,
				tmp_ctx,
				msg,
				"trustType",
				td->trust_type);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = samdb_msg_add_int(state->ldb,
				tmp_ctx,
				msg,
				"trustAttributes",
				td->trust_attributes);
	if (ret != LDB_SUCCESS) {
		status =NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = samdb_msg_add_int(state->ldb,
				tmp_ctx,
				msg,
				"trustDirection",
				td->trust_direction);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (td->trust_auth_incoming.data != NULL) {
		ret = ldb_msg_add_value(msg,
					"trustAuthIncoming",
					&td->trust_auth_incoming,
					NULL);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}
	if (td->trust_auth_outgoing.data != NULL) {
		ret = ldb_msg_add_value(msg,
					"trustAuthOutgoing",
					&td->trust_auth_outgoing,
					NULL);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	/* create the trusted_domain */
	ret = ldb_add(state->ldb, msg);
	switch (ret) {
	case  LDB_SUCCESS:
		break;

	case  LDB_ERR_ENTRY_ALREADY_EXISTS:
		DBG_ERR("Failed to create trusted domain record %s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(state->ldb));
		status = NT_STATUS_DOMAIN_EXISTS;
		goto out;

	case  LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		DBG_ERR("Failed to create trusted domain record %s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(state->ldb));
		status = NT_STATUS_ACCESS_DENIED;
		goto out;

	default:
		DBG_ERR("Failed to create trusted domain record %s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(state->ldb));
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}

	ndr_err = ndr_pull_struct_blob(
		&td->trust_auth_outgoing,
		tmp_ctx,
		&taiob,
		(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		goto out;
	}

	if (td->trust_direction == LSA_TRUST_DIRECTION_INBOUND) {
		status = add_trust_user(tmp_ctx,
					state->ldb,
					base_dn,
					td->netbios_name,
					&taiob);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	ret = ldb_transaction_commit(state->ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	in_txn = false;

	/*
	 * TODO: Notify winbindd that we have a new trust
	 */

	status = NT_STATUS_OK;

out:
	if (in_txn) {
		ldb_transaction_cancel(state->ldb);
	}
	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS delete_trust_user(TALLOC_CTX *mem_ctx,
				  struct pdb_samba_dsdb_state *state,
				  const char *trust_user)
{
	const char *attrs[] = { "userAccountControl", NULL };
	struct ldb_message **msgs;
	uint32_t uac;
	int ret;

	ret = gendb_search(state->ldb,
			   mem_ctx,
			   ldb_get_default_basedn(state->ldb),
			   &msgs,
			   attrs,
			   "samAccountName=%s$",
			   trust_user);
	if (ret > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (ret == 0) {
		return NT_STATUS_OK;
	}

	uac = ldb_msg_find_attr_as_uint(msgs[0],
					"userAccountControl",
					0);
	if (!(uac & UF_INTERDOMAIN_TRUST_ACCOUNT)) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	ret = ldb_delete(state->ldb, msgs[0]->dn);
	switch (ret) {
	case LDB_SUCCESS:
		break;
	case LDB_ERR_INSUFFICIENT_ACCESS_RIGHTS:
		return NT_STATUS_ACCESS_DENIED;
	default:
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}

static NTSTATUS pdb_samba_dsdb_del_trusted_domain(struct pdb_methods *methods,
						  const char *domain)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		methods->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct pdb_trusted_domain *td = NULL;
	struct ldb_dn *tdo_dn = NULL;
	bool in_txn = false;
	NTSTATUS status;
	int ret;
	bool ok;

	status = pdb_samba_dsdb_get_trusted_domain(methods,
						   tmp_ctx,
						   domain,
						   &td);
	if (!NT_STATUS_IS_OK(status)) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			DBG_ERR("Searching TDO for %s returned %s\n",
				domain, nt_errstr(status));
			return status;
		}
		DBG_NOTICE("No TDO object for %s\n", domain);
		return NT_STATUS_OK;
	}

	tdo_dn = ldb_dn_copy(tmp_ctx, ldb_get_default_basedn(state->ldb));
	if (tdo_dn == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ok = ldb_dn_add_child_fmt(tdo_dn, "cn=%s,cn=System", domain);
	if (!ok) {
		TALLOC_FREE(tmp_ctx);
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	ret = ldb_transaction_start(state->ldb);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}
	in_txn = true;

	ret = ldb_delete(state->ldb, tdo_dn);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INVALID_HANDLE;
		goto out;
	}

	if (td->trust_direction == LSA_TRUST_DIRECTION_INBOUND) {
		status = delete_trust_user(tmp_ctx, state, domain);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	ret = ldb_transaction_commit(state->ldb);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto out;
	}
	in_txn = false;

	status = NT_STATUS_OK;

out:
	if (in_txn) {
		ldb_transaction_cancel(state->ldb);
	}
	TALLOC_FREE(tmp_ctx);

	return status;
}

static NTSTATUS pdb_samba_dsdb_enum_trusted_domains(struct pdb_methods *m,
						    TALLOC_CTX *mem_ctx,
						    uint32_t *_num_domains,
						    struct pdb_trusted_domain ***_domains)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	const char * const attrs[] = {
		"securityIdentifier",
		"flatName",
		"trustPartner",
		"trustAuthOutgoing",
		"trustAuthIncoming",
		"trustAttributes",
		"trustDirection",
		"trustType",
		"trustPosixOffset",
		"msDS-SupportedEncryptionTypes",
		"msDS-TrustForestTrustInfo",
		NULL
	};
	struct ldb_result *res = NULL;
	unsigned int i;
	struct pdb_trusted_domain **domains = NULL;
	NTSTATUS status;
	uint32_t di = 0;

	*_num_domains = 0;
	*_domains = NULL;

	status = dsdb_trust_search_tdos(state->ldb, NULL,
					attrs, tmp_ctx, &res);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("dsdb_trust_search_tdos() - %s ", nt_errstr(status));
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (res->count == 0) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}

	domains = talloc_zero_array(tmp_ctx, struct pdb_trusted_domain *,
				    res->count);
	if (domains == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct pdb_trusted_domain *d = NULL;

		status = pdb_samba_dsdb_msg_to_trusted_domain(msg, domains, &d);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("pdb_samba_dsdb_msg_to_trusted_domain() - %s ",
				nt_errstr(status));
			TALLOC_FREE(tmp_ctx);
			return status;
		}

		domains[di++] = d;
	}

	domains = talloc_realloc(domains, domains, struct pdb_trusted_domain *,
				 di);
	*_domains = talloc_move(mem_ctx, &domains);
	*_num_domains = di;
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

static bool pdb_samba_dsdb_is_responsible_for_wellknown(struct pdb_methods *m)
{
	return true;
}

static bool pdb_samba_dsdb_is_responsible_for_everything_else(struct pdb_methods *m)
{
	return true;
}

static void pdb_samba_dsdb_init_methods(struct pdb_methods *m)
{
	m->name = "samba_dsdb";
	m->get_domain_info = pdb_samba_dsdb_get_domain_info;
	m->getsampwnam = pdb_samba_dsdb_getsampwnam;
	m->getsampwsid = pdb_samba_dsdb_getsampwsid;
	m->create_user = pdb_samba_dsdb_create_user;
	m->delete_user = pdb_samba_dsdb_delete_user;
	m->add_sam_account = pdb_samba_dsdb_add_sam_account;
	m->update_sam_account = pdb_samba_dsdb_update_sam_account;
	m->delete_sam_account = pdb_samba_dsdb_delete_sam_account;
	m->rename_sam_account = pdb_samba_dsdb_rename_sam_account;
	m->update_login_attempts = pdb_samba_dsdb_update_login_attempts;
	m->getgrsid = pdb_samba_dsdb_getgrsid;
	m->getgrgid = pdb_samba_dsdb_getgrgid;
	m->getgrnam = pdb_samba_dsdb_getgrnam;
	m->create_dom_group = pdb_samba_dsdb_create_dom_group;
	m->delete_dom_group = pdb_samba_dsdb_delete_dom_group;
	m->add_group_mapping_entry = pdb_samba_dsdb_add_group_mapping_entry;
	m->update_group_mapping_entry = pdb_samba_dsdb_update_group_mapping_entry;
	m->delete_group_mapping_entry =	pdb_samba_dsdb_delete_group_mapping_entry;
	m->enum_group_mapping = pdb_samba_dsdb_enum_group_mapping;
	m->enum_group_members = pdb_samba_dsdb_enum_group_members;
	m->enum_group_memberships = pdb_samba_dsdb_enum_group_memberships;
	m->set_unix_primary_group = pdb_samba_dsdb_set_unix_primary_group;
	m->add_groupmem = pdb_samba_dsdb_add_groupmem;
	m->del_groupmem = pdb_samba_dsdb_del_groupmem;
	m->create_alias = pdb_samba_dsdb_create_alias;
	m->delete_alias = pdb_samba_dsdb_delete_alias;
	m->get_aliasinfo = pdb_default_get_aliasinfo;
	m->add_aliasmem = pdb_samba_dsdb_add_aliasmem;
	m->del_aliasmem = pdb_samba_dsdb_del_aliasmem;
	m->enum_aliasmem = pdb_samba_dsdb_enum_aliasmem;
	m->enum_alias_memberships = pdb_samba_dsdb_enum_alias_memberships;
	m->lookup_rids = pdb_samba_dsdb_lookup_rids;
	m->lookup_names = pdb_samba_dsdb_lookup_names;
	m->get_account_policy = pdb_samba_dsdb_get_account_policy;
	m->set_account_policy = pdb_samba_dsdb_set_account_policy;
	m->get_seq_num = pdb_samba_dsdb_get_seq_num;
	m->search_users = pdb_samba_dsdb_search_users;
	m->search_groups = pdb_samba_dsdb_search_groups;
	m->search_aliases = pdb_samba_dsdb_search_aliases;
	m->id_to_sid = pdb_samba_dsdb_id_to_sid;
	m->sid_to_id = pdb_samba_dsdb_sid_to_id;
	m->capabilities = pdb_samba_dsdb_capabilities;
	m->new_rid = pdb_samba_dsdb_new_rid;
	m->get_trusteddom_pw = pdb_samba_dsdb_get_trusteddom_pw;
	m->get_trusteddom_creds = pdb_samba_dsdb_get_trusteddom_creds;
	m->set_trusteddom_pw = pdb_samba_dsdb_set_trusteddom_pw;
	m->del_trusteddom_pw = pdb_samba_dsdb_del_trusteddom_pw;
	m->enum_trusteddoms = pdb_samba_dsdb_enum_trusteddoms;
	m->get_trusted_domain = pdb_samba_dsdb_get_trusted_domain;
	m->get_trusted_domain_by_sid = pdb_samba_dsdb_get_trusted_domain_by_sid;
	m->set_trusted_domain = pdb_samba_dsdb_set_trusted_domain;
	m->del_trusted_domain = pdb_samba_dsdb_del_trusted_domain;
	m->enum_trusted_domains = pdb_samba_dsdb_enum_trusted_domains;
	m->is_responsible_for_wellknown =
				pdb_samba_dsdb_is_responsible_for_wellknown;
	m->is_responsible_for_everything_else =
				pdb_samba_dsdb_is_responsible_for_everything_else;
}

static void free_private_data(void **vp)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		*vp, struct pdb_samba_dsdb_state);
	talloc_unlink(state, state->ldb);
	return;
}

static NTSTATUS pdb_samba_dsdb_init_secrets(struct pdb_methods *m)
{
	struct pdb_domain_info *dom_info;
	struct dom_sid stored_sid;
	struct GUID stored_guid;
	bool sid_exists_and_matches = false;
	bool guid_exists_and_matches = false;
	bool ret;

	dom_info = pdb_samba_dsdb_get_domain_info(m, m);
	if (!dom_info) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = secrets_fetch_domain_sid(dom_info->name, &stored_sid);
	if (ret) {
		if (dom_sid_equal(&stored_sid, &dom_info->sid)) {
			sid_exists_and_matches = true;
		}
	}

	if (sid_exists_and_matches == false) {
		secrets_clear_domain_protection(dom_info->name);
		ret = secrets_store_domain_sid(dom_info->name,
					       &dom_info->sid);
		ret &= secrets_mark_domain_protected(dom_info->name);
		if (!ret) {
			goto done;
		}
	}

	ret = secrets_fetch_domain_guid(dom_info->name, &stored_guid);
	if (ret) {
		if (GUID_equal(&stored_guid, &dom_info->guid)) {
			guid_exists_and_matches = true;
		}
	}

	if (guid_exists_and_matches == false) {
		secrets_clear_domain_protection(dom_info->name);
		ret = secrets_store_domain_guid(dom_info->name,
					       &dom_info->guid);
		ret &= secrets_mark_domain_protected(dom_info->name);
		if (!ret) {
			goto done;
		}
	}

done:
	TALLOC_FREE(dom_info);
	if (!ret) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	return NT_STATUS_OK;
}

static NTSTATUS pdb_init_samba_dsdb(struct pdb_methods **pdb_method,
			     const char *location)
{
	struct pdb_methods *m;
	struct pdb_samba_dsdb_state *state;
	NTSTATUS status;
	char *errstring = NULL;
	int ret;

	if ( !NT_STATUS_IS_OK(status = make_pdb_method( &m )) ) {
		return status;
	}

	state = talloc_zero(m, struct pdb_samba_dsdb_state);
	if (state == NULL) {
		goto nomem;
	}
	m->private_data = state;
	m->free_private_data = free_private_data;
	pdb_samba_dsdb_init_methods(m);

	state->ev = s4_event_context_init(state);
	if (!state->ev) {
		DEBUG(0, ("s4_event_context_init failed\n"));
		goto nomem;
	}

	state->lp_ctx = loadparm_init_s3(state, loadparm_s3_helpers());
	if (state->lp_ctx == NULL) {
		DEBUG(0, ("loadparm_init_s3 failed\n"));
		goto nomem;
	}

	if (location == NULL) {
		location = "sam.ldb";
	}

	ret = samdb_connect_url(state,
				state->ev,
				state->lp_ctx,
				system_session(state->lp_ctx),
				0,
				location,
				NULL,
				&state->ldb,
				&errstring);

	if (!state->ldb) {
		DEBUG(0, ("samdb_connect failed: %s: %s\n",
			  errstring, ldb_strerror(ret)));
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	state->idmap_ctx = idmap_init(state, state->ev,
				      state->lp_ctx);
	if (!state->idmap_ctx) {
		DEBUG(0, ("idmap failed\n"));
		status = NT_STATUS_INTERNAL_ERROR;
		goto fail;
	}

	status = pdb_samba_dsdb_init_secrets(m);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("pdb_samba_dsdb_init_secrets failed!\n"));
		goto fail;
	}

	*pdb_method = m;
	return NT_STATUS_OK;
nomem:
	status = NT_STATUS_NO_MEMORY;
fail:
	TALLOC_FREE(m);
	return status;
}

NTSTATUS pdb_samba_dsdb_init(TALLOC_CTX *);
NTSTATUS pdb_samba_dsdb_init(TALLOC_CTX *ctx)
{
	NTSTATUS status = smb_register_passdb(PASSDB_INTERFACE_VERSION, "samba_dsdb",
					      pdb_init_samba_dsdb);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "samba4",
				   pdb_init_samba_dsdb);
}
