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
#include "libds/common/flag_mapping.h"
#include "source4/lib/events/events.h"
#include "source4/auth/session.h"
#include "source4/auth/system_session_proto.h"
#include "lib/param/param.h"
#include "source4/dsdb/common/util.h"
#include "source3/include/secrets.h"

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
	char *sidstr, *filter;
	NTSTATUS status;

	msg = (struct ldb_message *)
		pdb_get_backend_private_data(sam, m);

	if (msg != NULL) {
		return talloc_get_type_abort(msg, struct ldb_message);
	}

	sidstr = dom_sid_string(talloc_tos(), pdb_get_user_sid(sam));
	if (sidstr == NULL) {
		return NULL;
	}

	filter = talloc_asprintf(
		talloc_tos(), "(&(objectsid=%s)(objectclass=user))", sidstr);
	TALLOC_FREE(sidstr);
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

	str = ldb_msg_find_attr_as_string(msg, "userParameters",
					    NULL);
	if (str != NULL) {
		pdb_set_munged_dial(sam, str, PDB_SET);
	}

	sid = samdb_result_dom_sid(talloc_tos(), msg, "objectSid");
	if (!sid) {
		DEBUG(10, ("Could not pull SID\n"));
		goto fail;
	}
	pdb_set_user_sid(sam, sid, PDB_SET);

	n = ldb_msg_find_attr_as_uint(msg, "userAccountControl", 0);
	if (n == 0) {
		DEBUG(10, ("Could not pull userAccountControl\n"));
		goto fail;
	}
	pdb_set_acct_ctrl(sam, ds_uf2acb(n), PDB_SET);

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
		dsdb_flags = DSDB_PASSWORD_BYPASS_LAST_SET;

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
				static const uint8_t zeros[16];
				/* Parse the history into the correct format */
				for (i = 0; i < current_hist_len; i++) {
					if (memcmp(&history[i*PW_HISTORY_ENTRY_LEN], zeros, 16) != 0) {
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
			dsdb_flags = DSDB_BYPASS_PASSWORD_HASH;
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
		ret |= ldb_msg_add_string(msg, "userParameters",
					  pdb_get_munged_dial(sam));
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
		"primaryGroupID", "userAccountControl", "logonHours",
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
					  const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(4, 5)
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
	char *sidstr;

	sidstr = dom_sid_string(talloc_tos(), sid);
	NT_STATUS_HAVE_NO_MEMORY(sidstr);

	status = pdb_samba_dsdb_getsampwfilter(m, state, sam_acct,
					   "(&(objectsid=%s)(objectclass=user))",
					   sidstr);
	talloc_free(sidstr);
	return status;
}

static NTSTATUS pdb_samba_dsdb_create_user(struct pdb_methods *m,
				    TALLOC_CTX *mem_ctx,
				    const char *name, uint32 acct_flags,
				    uint32 *rid)
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
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(tmp_ctx, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, pdb_get_user_sid(sam)));
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
 * be careful around the creation of arbitary SIDs (ie, we must ensrue
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

/* This is not implemented, as this module is exptected to be used
 * with auth_samba_dsdb, and this is responible for login counters etc
 *
 */
static NTSTATUS pdb_samba_dsdb_update_login_attempts(struct pdb_methods *m,
					      struct samu *sam_acct,
					      bool success)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS pdb_samba_dsdb_getgrfilter(struct pdb_methods *m, GROUP_MAP *map,
				    const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(4, 5)
{
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	const char *attrs[] = { "objectSid", "description", "samAccountName", "groupType",
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

		map->sid_name_use = SID_NAME_DOM_GRP;

		ZERO_STRUCT(id_map);
		id_map.sid = sid;
		id_maps[0] = &id_map;
		id_maps[1] = NULL;

		status = idmap_sids_to_xids(state->idmap_ctx, tmp_ctx, id_maps);
		talloc_free(tmp_ctx);
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

	filter = talloc_asprintf(talloc_tos(),
				 "(&(objectsid=%s)(objectclass=group))",
				 sid_string_talloc(talloc_tos(), &sid));
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pdb_samba_dsdb_getgrfilter(m, map, filter);
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

	status = pdb_samba_dsdb_getgrfilter(m, map, filter);
	TALLOC_FREE(filter);
	return status;
}

static NTSTATUS pdb_samba_dsdb_create_dom_group(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx, const char *name,
					 uint32 *rid)
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
					 TALLOC_CTX *mem_ctx, uint32 rid)
{
	const char *attrs[] = { NULL };
	struct pdb_samba_dsdb_state *state = talloc_get_type_abort(
		m->private_data, struct pdb_samba_dsdb_state);
	struct dom_sid sid;
	struct ldb_message *msg;
	struct ldb_dn *dn;
	int rc;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	sid_compose(&sid, samdb_domain_sid(state->ldb), rid);

	if (ldb_transaction_start(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Unable to start transaction in pdb_samba_dsdb_delete_dom_group()\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	dn = ldb_dn_new_fmt(tmp_ctx, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, &sid));
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

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(tmp_ctx, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, group));
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
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(*pmembers, tmp_ctx);
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
	struct dom_sid *group_sids;
	gid_t *gids;
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
			DEBUG(1, (__location__
				  "Group %s, of which %s is a member, could not be converted to a GID\n",
				  dom_sid_string(tmp_ctx, &group_sids[0]),
				  dom_sid_string(tmp_ctx, &user->user_sid)));
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
			DEBUG(1, (__location__
				  "Group %s, of which %s is a member, could not be converted to a GID\n",
				  dom_sid_string(tmp_ctx, &group_sids[num_groups]),
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
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);
	msg = ldb_msg_new(tmp_ctx);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(msg, tmp_ctx);

	msg->dn = ldb_dn_new_fmt(msg, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, groupsid));
	if (!msg->dn || !ldb_dn_validate(msg->dn)) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	ret = ldb_msg_add_fmt(msg, "member", "<SID=%s>", dom_sid_string(tmp_ctx, membersid));
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
				     uint32 grouprid, uint32 memberrid,
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
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(groupsid, tmp_ctx);
	membersid = dom_sid_add_rid(tmp_ctx, dom_sid, memberrid);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(membersid, tmp_ctx);
	status = pdb_samba_dsdb_mod_groupmem_by_sid(m, tmp_ctx, groupsid, membersid, mod_op);
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS pdb_samba_dsdb_add_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32 group_rid, uint32 member_rid)
{
	return pdb_samba_dsdb_mod_groupmem(m, mem_ctx, group_rid, member_rid,
				    LDB_FLAG_MOD_ADD);
}

static NTSTATUS pdb_samba_dsdb_del_groupmem(struct pdb_methods *m,
				     TALLOC_CTX *mem_ctx,
				     uint32 group_rid, uint32 member_rid)
{
	return pdb_samba_dsdb_mod_groupmem(m, mem_ctx, group_rid, member_rid,
				       LDB_FLAG_MOD_DELETE);
}

static NTSTATUS pdb_samba_dsdb_create_alias(struct pdb_methods *m,
				     const char *name, uint32 *rid)
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
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(tmp_ctx, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, sid));
	if (!dn || !ldb_dn_validate(dn)) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	if (ldb_transaction_start(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to start transaction in dsdb_add_domain_alias(): %s\n", ldb_errstring(state->ldb)));
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
		return NT_STATUS_LDAP(rc);
	}

	if (ldb_transaction_commit(state->ldb) != LDB_SUCCESS) {
		DEBUG(0, ("Failed to commit transaction in pdb_samba_dsdb_delete_alias(): %s\n",
			  ldb_errstring(state->ldb)));
		return NT_STATUS_INTERNAL_ERROR;
	}

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
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	dn = ldb_dn_new_fmt(tmp_ctx, state->ldb, "<SID=%s>", dom_sid_string(tmp_ctx, alias));
	if (!dn || !ldb_dn_validate(dn)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dsdb_enum_group_mem(state->ldb, mem_ctx, dn, pmembers, &num_members);
	*pnum_members = num_members;
	if (NT_STATUS_IS_OK(status)) {
		talloc_steal(mem_ctx, pmembers);
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
	const char *sid_string;
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
		sid_string = dom_sid_string(tmp_ctx, &members[i]);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(sid_string, tmp_ctx);

		sid_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", sid_string);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(sid_dn, tmp_ctx);

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
				    uint32 *rids,
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
				     uint32 *rids,
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
				     const char *exp_fmt, ...) _PRINTF_ATTRIBUTE(4, 5)
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

		e->acct_flags = samdb_result_acct_flags(state->ldb, tmp_ctx,
							res->msgs[i],
							ldb_get_default_basedn(state->ldb));
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
				 uint32 acct_flags)
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

static bool pdb_samba_dsdb_uid_to_sid(struct pdb_methods *m, uid_t uid,
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

	id_map.xid.id = uid;
	id_map.xid.type = ID_TYPE_UID;
	id_maps[0] = &id_map;
	id_maps[1] = NULL;

	status = idmap_xids_to_sids(state->idmap_ctx, tmp_ctx, id_maps);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return false;
	}
	*sid = *id_map.sid;
	talloc_free(tmp_ctx);
	return true;
}

static bool pdb_samba_dsdb_gid_to_sid(struct pdb_methods *m, gid_t gid,
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

	id_map.xid.id = gid;
	id_map.xid.type = ID_TYPE_GID;
	id_maps[0] = &id_map;
	id_maps[1] = NULL;

	status = idmap_xids_to_sids(state->idmap_ctx, tmp_ctx, id_maps);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
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
	id_map.sid = sid;
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
	return PDB_CAP_STORE_RIDS | PDB_CAP_ADS;
}

static bool pdb_samba_dsdb_new_rid(struct pdb_methods *m, uint32 *rid)
{
	return false;
}

static bool pdb_samba_dsdb_get_trusteddom_pw(struct pdb_methods *m,
				      const char *domain, char** pwd,
				      struct dom_sid *sid,
				      time_t *pass_last_set_time)
{
	return false;
}

static bool pdb_samba_dsdb_set_trusteddom_pw(struct pdb_methods *m,
				      const char* domain, const char* pwd,
				      const struct dom_sid *sid)
{
	return false;
}

static bool pdb_samba_dsdb_del_trusteddom_pw(struct pdb_methods *m,
				      const char *domain)
{
	return false;
}

static NTSTATUS pdb_samba_dsdb_enum_trusteddoms(struct pdb_methods *m,
					 TALLOC_CTX *mem_ctx,
					 uint32 *num_domains,
					 struct trustdom_info ***domains)
{
	*num_domains = 0;
	*domains = NULL;
	return NT_STATUS_OK;
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
	m->uid_to_sid = pdb_samba_dsdb_uid_to_sid;
	m->gid_to_sid = pdb_samba_dsdb_gid_to_sid;
	m->sid_to_id = pdb_samba_dsdb_sid_to_id;
	m->capabilities = pdb_samba_dsdb_capabilities;
	m->new_rid = pdb_samba_dsdb_new_rid;
	m->get_trusteddom_pw = pdb_samba_dsdb_get_trusteddom_pw;
	m->set_trusteddom_pw = pdb_samba_dsdb_set_trusteddom_pw;
	m->del_trusteddom_pw = pdb_samba_dsdb_del_trusteddom_pw;
	m->enum_trusteddoms = pdb_samba_dsdb_enum_trusteddoms;
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
	bool ret;

	dom_info = pdb_samba_dsdb_get_domain_info(m, m);
	if (!dom_info) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	secrets_clear_domain_protection(dom_info->name);
	ret = secrets_store_domain_sid(dom_info->name,
				       &dom_info->sid);
	if (!ret) {
		goto done;
	}
	ret = secrets_store_domain_guid(dom_info->name,
				        &dom_info->guid);
	if (!ret) {
		goto done;
	}
	ret = secrets_mark_domain_protected(dom_info->name);
	if (!ret) {
		goto done;
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

	if (location) {
		state->ldb = samdb_connect_url(state,
				   state->ev,
				   state->lp_ctx,
				   system_session(state->lp_ctx),
				   0, location);
	} else {
		state->ldb = samdb_connect(state,
				   state->ev,
				   state->lp_ctx,
				   system_session(state->lp_ctx), 0);
	}

	if (!state->ldb) {
		DEBUG(0, ("samdb_connect failed\n"));
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

NTSTATUS pdb_samba_dsdb_init(void);
NTSTATUS pdb_samba_dsdb_init(void)
{
	NTSTATUS status = smb_register_passdb(PASSDB_INTERFACE_VERSION, "samba_dsdb",
					      pdb_init_samba_dsdb);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "samba4",
				   pdb_init_samba_dsdb);
}
