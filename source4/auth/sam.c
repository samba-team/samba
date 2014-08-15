/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2010
   Copyright (C) Gerald Carter                             2003
   Copyright (C) Stefan Metzmacher                         2005
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

#include "includes.h"
#include "system/time.h"
#include "auth/auth.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "auth/auth_sam.h"
#include "dsdb/common/util.h"
#include "libcli/ldap/ldap_ndr.h"
#include "param/param.h"

#define KRBTGT_ATTRS \
	/* required for the krb5 kdc */		\
	"objectClass",				\
	"sAMAccountName",			\
	"userPrincipalName",			\
	"servicePrincipalName",			\
	"msDS-KeyVersionNumber",		\
	"msDS-SecondaryKrbTgtNumber",		\
	"msDS-SupportedEncryptionTypes",	\
	"supplementalCredentials",		\
	"msDS-AllowedToDelegateTo",		\
						\
	/* passwords */				\
	"dBCSPwd",				\
	"unicodePwd",				\
						\
	"userAccountControl",	                \
	"msDS-User-Account-Control-Computed",	\
	"objectSid",				\
						\
	"pwdLastSet",				\
	"accountExpires"

const char *krbtgt_attrs[] = {
	KRBTGT_ATTRS, NULL
};

const char *server_attrs[] = {
	KRBTGT_ATTRS, NULL
};

const char *user_attrs[] = {
	KRBTGT_ATTRS,

	"logonHours",

	/*
	 * To allow us to zero the badPwdCount and lockoutTime on
	 * successful logon, without database churn
	 */
	"lockoutTime",

	/* check 'allowed workstations' */
	"userWorkstations",
		       
	/* required for user_info_dc, not access control: */
	"displayName",
	"scriptPath",
	"profilePath",
	"homeDirectory",
	"homeDrive",
	"lastLogon",
	"lastLogoff",
	"accountExpires",
	"badPwdCount",
	"logonCount",
	"primaryGroupID",
	"memberOf",
	"badPasswordTime",
	"lmPwdHistory",
	"ntPwdHistory",
	NULL,
};

/****************************************************************************
 Check if a user is allowed to logon at this time. Note this is the
 servers local time, as logon hours are just specified as a weekly
 bitmask.
****************************************************************************/
                                                                                                              
static bool logon_hours_ok(struct ldb_message *msg, const char *name_for_logs)
{
	/* In logon hours first bit is Sunday from 12AM to 1AM */
	const struct ldb_val *hours;
	struct tm *utctime;
	time_t lasttime;
	const char *asct;
	uint8_t bitmask, bitpos;

	hours = ldb_msg_find_ldb_val(msg, "logonHours");
	if (!hours) {
		DEBUG(5,("logon_hours_ok: No hours restrictions for user %s\n", name_for_logs));
		return true;
	}

	if (hours->length != 168/8) {
		DEBUG(5,("logon_hours_ok: malformed logon hours restrictions for user %s\n", name_for_logs));
		return true;		
	}

	lasttime = time(NULL);
	utctime = gmtime(&lasttime);
	if (!utctime) {
		DEBUG(1, ("logon_hours_ok: failed to get gmtime. Failing logon for user %s\n",
			name_for_logs));
		return false;
	}

	/* find the corresponding byte and bit */
	bitpos = (utctime->tm_wday * 24 + utctime->tm_hour) % 168;
	bitmask = 1 << (bitpos % 8);

	if (! (hours->data[bitpos/8] & bitmask)) {
		struct tm *t = localtime(&lasttime);
		if (!t) {
			asct = "INVALID TIME";
		} else {
			asct = asctime(t);
			if (!asct) {
				asct = "INVALID TIME";
			}
		}
		
		DEBUG(1, ("logon_hours_ok: Account for user %s not allowed to "
			  "logon at this time (%s).\n",
			  name_for_logs, asct ));
		return false;
	}

	asct = asctime(utctime);
	DEBUG(5,("logon_hours_ok: user %s allowed to logon at this time (%s)\n",
		name_for_logs, asct ? asct : "UNKNOWN TIME" ));

	return true;
}

/****************************************************************************
 Do a specific test for a SAM_ACCOUNT being valid for this connection
 (ie not disabled, expired and the like).
****************************************************************************/
_PUBLIC_ NTSTATUS authsam_account_ok(TALLOC_CTX *mem_ctx,
				     struct ldb_context *sam_ctx,
				     uint32_t logon_parameters,
				     struct ldb_dn *domain_dn,
				     struct ldb_message *msg,
				     const char *logon_workstation,
				     const char *name_for_logs,
				     bool allow_domain_trust,
				     bool password_change)
{
	uint16_t acct_flags;
	const char *workstation_list;
	NTTIME acct_expiry;
	NTTIME must_change_time;
	struct timeval tv_now = timeval_current();
	NTTIME now = timeval_to_nttime(&tv_now);

	DEBUG(4,("authsam_account_ok: Checking SMB password for user %s\n", name_for_logs));

	acct_flags = samdb_result_acct_flags(msg, "msDS-User-Account-Control-Computed");
	
	acct_expiry = samdb_result_account_expires(msg);

	/* Check for when we must change this password, taking the
	 * userAccountControl flags into account */
	must_change_time = samdb_result_force_password_change(sam_ctx, mem_ctx, 
							      domain_dn, msg);

	workstation_list = ldb_msg_find_attr_as_string(msg, "userWorkstations", NULL);

	/* Quit if the account was disabled. */
	if (acct_flags & ACB_DISABLED) {
		DEBUG(2,("authsam_account_ok: Account for user '%s' was disabled.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(2,("authsam_account_ok: Account for user %s was locked out.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* Test account expire time */
	if (now > acct_expiry) {
		DEBUG(2,("authsam_account_ok: Account for user '%s' has expired.\n", name_for_logs));
		DEBUG(3,("authsam_account_ok: Account expired at '%s'.\n", 
			 nt_time_string(mem_ctx, acct_expiry)));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	/* check for immediate expiry "must change at next logon" (but not if this is a password change request) */
	if ((must_change_time == 0) && !password_change) {
		DEBUG(2,("sam_account_ok: Account for user '%s' password must change!.\n",
			 name_for_logs));
		return NT_STATUS_PASSWORD_MUST_CHANGE;
	}

	/* check for expired password (but not if this is a password change request) */
	if ((must_change_time < now) && !password_change) {
		DEBUG(2,("sam_account_ok: Account for user '%s' password expired!.\n",
			 name_for_logs));
		DEBUG(2,("sam_account_ok: Password expired at '%s' unix time.\n",
			 nt_time_string(mem_ctx, must_change_time)));
		return NT_STATUS_PASSWORD_EXPIRED;
	}

	/* Test workstation. Workstation list is comma separated. */
	if (logon_workstation && workstation_list && *workstation_list) {
		bool invalid_ws = true;
		int i;
		char **workstations = str_list_make(mem_ctx, workstation_list, ",");

		for (i = 0; workstations && workstations[i]; i++) {
			DEBUG(10,("sam_account_ok: checking for workstation match '%s' and '%s'\n",
				  workstations[i], logon_workstation));

			if (strequal(workstations[i], logon_workstation)) {
				invalid_ws = false;
				break;
			}
		}

		talloc_free(workstations);

		if (invalid_ws) {
			return NT_STATUS_INVALID_WORKSTATION;
		}
	}
	
	if (!logon_hours_ok(msg, name_for_logs)) {
		return NT_STATUS_INVALID_LOGON_HOURS;
	}
	
	if (!allow_domain_trust) {
		if (acct_flags & ACB_DOMTRUST) {
			DEBUG(2,("sam_account_ok: Domain trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
		}
	}
	if (!(logon_parameters & MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT)) {
		if (acct_flags & ACB_SVRTRUST) {
			DEBUG(2,("sam_account_ok: Server trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
		}
	}
	if (!(logon_parameters & MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT)) {
		/* TODO: this fails with current solaris client. We
		   need to work with Gordon to work out why */
		if (acct_flags & ACB_WSTRUST) {
			DEBUG(4,("sam_account_ok: Wksta trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
		}
	}

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS authsam_make_user_info_dc(TALLOC_CTX *mem_ctx,
					   struct ldb_context *sam_ctx,
					   const char *netbios_name,
					   const char *domain_name,
					   struct ldb_dn *domain_dn, 
					   struct ldb_message *msg,
					   DATA_BLOB user_sess_key,
					   DATA_BLOB lm_sess_key,
					   struct auth_user_info_dc **_user_info_dc)
{
	NTSTATUS status;
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;
	const char *str, *filter;
	/* SIDs for the account and his primary group */
	struct dom_sid *account_sid;
	const char *primary_group_string;
	const char *primary_group_dn;
	DATA_BLOB primary_group_blob;
	/* SID structures for the expanded group memberships */
	struct dom_sid *sids = NULL;
	unsigned int num_sids = 0, i;
	struct dom_sid *domain_sid;
	TALLOC_CTX *tmp_ctx;
	struct ldb_message_element *el;

	user_info_dc = talloc(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	tmp_ctx = talloc_new(user_info_dc);
	if (user_info_dc == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_array(user_info_dc, struct dom_sid, 2);
	if (sids == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	num_sids = 2;

	account_sid = samdb_result_dom_sid(user_info_dc, msg, "objectSid");
	if (account_sid == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	status = dom_sid_split_rid(tmp_ctx, account_sid, &domain_sid, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(user_info_dc);
		return status;
	}

	sids[PRIMARY_USER_SID_INDEX] = *account_sid;
	sids[PRIMARY_GROUP_SID_INDEX] = *domain_sid;
	sid_append_rid(&sids[PRIMARY_GROUP_SID_INDEX], ldb_msg_find_attr_as_uint(msg, "primaryGroupID", ~0));

	/* Filter out builtin groups from this token.  We will search
	 * for builtin groups later, and not include them in the PAC
	 * on SamLogon validation info */
	filter = talloc_asprintf(tmp_ctx, "(&(objectClass=group)(!(groupType:1.2.840.113556.1.4.803:=%u))(groupType:1.2.840.113556.1.4.803:=%u))", GROUP_TYPE_BUILTIN_LOCAL_GROUP, GROUP_TYPE_SECURITY_ENABLED);
	if (filter == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	primary_group_string = dom_sid_string(tmp_ctx, &sids[PRIMARY_GROUP_SID_INDEX]);
	if (primary_group_string == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	primary_group_dn = talloc_asprintf(tmp_ctx, "<SID=%s>", primary_group_string);
	if (primary_group_dn == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	primary_group_blob = data_blob_string_const(primary_group_dn);

	/* Expands the primary group - this function takes in
	 * memberOf-like values, so we fake one up with the
	 * <SID=S-...> format of DN and then let it expand
	 * them, as long as they meet the filter - so only
	 * domain groups, not builtin groups
	 *
	 * The primary group is still treated specially, so we set the
	 * 'only childs' flag to true
	 */
	status = dsdb_expand_nested_groups(sam_ctx, &primary_group_blob, true, filter,
					   user_info_dc, &sids, &num_sids);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(user_info_dc);
		return status;
	}

	/* Expands the additional groups */
	el = ldb_msg_find_element(msg, "memberOf");
	for (i = 0; el && i < el->num_values; i++) {
		/* This function takes in memberOf values and expands
		 * them, as long as they meet the filter - so only
		 * domain groups, not builtin groups */
		status = dsdb_expand_nested_groups(sam_ctx, &el->values[i], false, filter,
						   user_info_dc, &sids, &num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(user_info_dc);
			return status;
		}
	}

	user_info_dc->sids = sids;
	user_info_dc->num_sids = num_sids;

	user_info_dc->info = info = talloc_zero(user_info_dc, struct auth_user_info);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc->info);

	info->account_name = talloc_steal(info,
		ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL));

	info->domain_name = talloc_strdup(info, domain_name);
	if (info->domain_name == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "displayName", "");
	info->full_name = talloc_strdup(info, str);
	if (info->full_name == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "scriptPath", "");
	info->logon_script = talloc_strdup(info, str);
	if (info->logon_script == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "profilePath", "");
	info->profile_path = talloc_strdup(info, str);
	if (info->profile_path == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "homeDirectory", "");
	info->home_directory = talloc_strdup(info, str);
	if (info->home_directory == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "homeDrive", "");
	info->home_drive = talloc_strdup(info, str);
	if (info->home_drive == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	info->logon_server = talloc_strdup(info, netbios_name);
	if (info->logon_server == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	info->last_logon = samdb_result_nttime(msg, "lastLogon", 0);
	info->last_logoff = samdb_result_last_logoff(msg);
	info->acct_expiry = samdb_result_account_expires(msg);
	info->last_password_change = samdb_result_nttime(msg,
		"pwdLastSet", 0);
	info->allow_password_change
		= samdb_result_allow_password_change(sam_ctx, mem_ctx, 
			domain_dn, msg, "pwdLastSet");
	info->force_password_change
		= samdb_result_force_password_change(sam_ctx, mem_ctx,
			domain_dn, msg);
	info->logon_count = ldb_msg_find_attr_as_uint(msg, "logonCount", 0);
	info->bad_password_count = ldb_msg_find_attr_as_uint(msg, "badPwdCount",
		0);

	info->acct_flags = samdb_result_acct_flags(msg, "msDS-User-Account-Control-Computed");

	user_info_dc->user_session_key = data_blob_talloc(user_info_dc,
							 user_sess_key.data,
							 user_sess_key.length);
	if (user_sess_key.data) {
		if (user_info_dc->user_session_key.data == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}
	user_info_dc->lm_session_key = data_blob_talloc(user_info_dc,
						       lm_sess_key.data,
						       lm_sess_key.length);
	if (lm_sess_key.data) {
		if (user_info_dc->lm_session_key.data == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (info->acct_flags & ACB_SVRTRUST) {
		/* the SID_NT_ENTERPRISE_DCS SID gets added into the
		   PAC */
		user_info_dc->sids = talloc_realloc(user_info_dc,
						   user_info_dc->sids,
						   struct dom_sid,
						   user_info_dc->num_sids+1);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
		user_info_dc->sids[user_info_dc->num_sids] = global_sid_Enterprise_DCs;
		user_info_dc->num_sids++;
	}

	if ((info->acct_flags & (ACB_PARTIAL_SECRETS_ACCOUNT | ACB_WSTRUST)) ==
	    (ACB_PARTIAL_SECRETS_ACCOUNT | ACB_WSTRUST)) {
		/* the DOMAIN_RID_ENTERPRISE_READONLY_DCS PAC */
		user_info_dc->sids = talloc_realloc(user_info_dc,
						   user_info_dc->sids,
						   struct dom_sid,
						   user_info_dc->num_sids+1);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
		user_info_dc->sids[user_info_dc->num_sids] = *domain_sid;
		sid_append_rid(&user_info_dc->sids[user_info_dc->num_sids],
			    DOMAIN_RID_ENTERPRISE_READONLY_DCS);
		user_info_dc->num_sids++;
	}

	info->authenticated = true;

	talloc_free(tmp_ctx);
	*_user_info_dc = user_info_dc;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_results_principal(struct ldb_context *sam_ctx,
				   TALLOC_CTX *mem_ctx, const char *principal,
				   const char **attrs,
				   struct ldb_dn **domain_dn,
				   struct ldb_message **msg)
{			   
	struct ldb_dn *user_dn;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int ret;

	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = crack_user_principal_name(sam_ctx, tmp_ctx, principal, 
					      &user_dn, domain_dn);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}
	
	/* pull the user attributes */
	ret = dsdb_search_one(sam_ctx, tmp_ctx, msg, user_dn,
			      LDB_SCOPE_BASE, attrs,
			      DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
			      "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, *msg);
	talloc_steal(mem_ctx, *domain_dn);
	talloc_free(tmp_ctx);
	
	return NT_STATUS_OK;
}

NTSTATUS sam_get_results_trust(struct ldb_context *sam_ctx,
			       TALLOC_CTX *mem_ctx, const char *domain,
			       const char *realm, const char * const *attrs,
			       struct ldb_message **msg)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int lret;
	struct ldb_dn *system_dn;
	char *filter;
	struct ldb_result *res = NULL;
	char *domain_encoded;

	system_dn = ldb_dn_copy(frame, ldb_get_default_basedn(sam_ctx));
	if (system_dn == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (!ldb_dn_add_child_fmt(system_dn, "CN=System")) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	domain_encoded = ldb_binary_encode_string(mem_ctx, domain);
	if (!domain_encoded) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}
	if (realm == NULL) {
		filter = talloc_asprintf(mem_ctx,
				"(&(objectClass=trustedDomain)(flatname=%s))",
				domain_encoded);
		if (!filter) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		char *realm_encoded = ldb_binary_encode_string(mem_ctx, realm);
		if (!realm_encoded) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}

		filter = talloc_asprintf(mem_ctx,
				"(&(objectClass=trustedDomain)"
				  "(|(trustPartner=%s)(flatname=%s))"
				")",
				realm_encoded, domain_encoded);
		if (!filter) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	lret = dsdb_search(sam_ctx, frame, &res,
			   system_dn,
			   LDB_SCOPE_ONELEVEL, attrs,
			   DSDB_SEARCH_NO_GLOBAL_CATALOG|DSDB_SEARCH_ONE_ONLY,
			   "%s", filter);
	if (lret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(3, ("Failed to find result for %s: %s\n", filter, ldb_errstring(sam_ctx)));
		TALLOC_FREE(frame);
		return NT_STATUS_NOT_FOUND;
	} else if (lret != LDB_SUCCESS) {
		DEBUG(3, ("Failed to search for %s: %s\n", filter, ldb_errstring(sam_ctx)));
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, res->msgs);
	*msg = res->msgs[0];
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/* Used in the gensec_gssapi and gensec_krb5 server-side code, where the PAC isn't available, and for tokenGroups in the DSDB stack.

 Supply either a principal or a DN
*/
NTSTATUS authsam_get_user_info_dc_principal(TALLOC_CTX *mem_ctx,
					   struct loadparm_context *lp_ctx,
					   struct ldb_context *sam_ctx,
					   const char *principal,
					   struct ldb_dn *user_dn,
					   struct auth_user_info_dc **user_info_dc)
{
	NTSTATUS nt_status;
	DATA_BLOB user_sess_key = data_blob(NULL, 0);
	DATA_BLOB lm_sess_key = data_blob(NULL, 0);

	struct ldb_message *msg;
	struct ldb_dn *domain_dn;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	if (principal) {
		nt_status = sam_get_results_principal(sam_ctx, tmp_ctx, principal,
						      user_attrs, &domain_dn, &msg);
		if (!NT_STATUS_IS_OK(nt_status)) {
			talloc_free(tmp_ctx);
			return nt_status;
		}
	} else if (user_dn) {
		struct dom_sid *user_sid, *domain_sid;
		int ret;
		/* pull the user attributes */
		ret = dsdb_search_one(sam_ctx, tmp_ctx, &msg, user_dn,
				      LDB_SCOPE_BASE, user_attrs,
				      DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
				      "(objectClass=*)");
		if (ret == LDB_ERR_NO_SUCH_OBJECT) {
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_SUCH_USER;
		} else if (ret != LDB_SUCCESS) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		user_sid = samdb_result_dom_sid(msg, msg, "objectSid");

		nt_status = dom_sid_split_rid(tmp_ctx, user_sid, &domain_sid, NULL);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}

		domain_dn = samdb_search_dn(sam_ctx, mem_ctx, NULL,
					  "(&(objectSid=%s)(objectClass=domain))",
					    ldap_encode_ndr_dom_sid(tmp_ctx, domain_sid));
		if (!domain_dn) {
			DEBUG(3, ("authsam_get_user_info_dc_principal: Failed to find domain with: SID %s\n",
				  dom_sid_string(tmp_ctx, domain_sid)));
			return NT_STATUS_NO_SUCH_USER;
		}

	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	nt_status = authsam_make_user_info_dc(tmp_ctx, sam_ctx,
					     lpcfg_netbios_name(lp_ctx),
					     lpcfg_workgroup(lp_ctx),
					     domain_dn,
					     msg,
					     user_sess_key, lm_sess_key,
					     user_info_dc);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_steal(mem_ctx, *user_info_dc);
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

NTSTATUS authsam_update_bad_pwd_count(struct ldb_context *sam_ctx,
				      struct ldb_message *msg,
				      struct ldb_dn *domain_dn)
{
	const char *attrs[] = { "lockoutThreshold",
				"lockOutObservationWindow",
				"lockoutDuration",
				"pwdProperties",
				NULL };
	int ret;
	NTSTATUS status;
	struct ldb_result *domain_res;
	struct ldb_message *msg_mod = NULL;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(msg);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_search_dn(sam_ctx, mem_ctx, &domain_res, domain_dn, attrs, 0);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = dsdb_update_bad_pwd_count(mem_ctx, sam_ctx,
					   msg, domain_res->msgs[0], &msg_mod);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(mem_ctx);
		return status;
	}

	if (msg_mod != NULL) {
		ret = dsdb_modify(sam_ctx, msg_mod, 0);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Failed to update badPwdCount, badPasswordTime or set lockoutTime on %s: %s\n",
				  ldb_dn_get_linearized(msg_mod->dn), ldb_errstring(sam_ctx)));
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}

NTSTATUS authsam_zero_bad_pwd_count(struct ldb_context *sam_ctx,
				    const struct ldb_message *msg)
{
	int ret;
	int badPwdCount;
	int64_t lockoutTime;
	struct ldb_message *msg_mod;
	TALLOC_CTX *mem_ctx;

	lockoutTime = ldb_msg_find_attr_as_int64(msg, "lockoutTime", 0);
	badPwdCount = ldb_msg_find_attr_as_int(msg, "badPwdCount", 0);
	if (lockoutTime == 0 && badPwdCount == 0) {
		return NT_STATUS_OK;
	}

	mem_ctx = talloc_new(msg);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	msg_mod = ldb_msg_new(mem_ctx);
	if (msg_mod == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	msg_mod->dn = msg->dn;

	if (lockoutTime != 0) {
		/*
		 * This implies "badPwdCount" = 0, see samldb_lockout_time()
		 */
		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod, "lockoutTime", 0);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod, "badPwdCount", 0);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	ret = dsdb_replace(sam_ctx, msg_mod, 0);
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to set badPwdCount and lockoutTime to 0 on %s: %s\n",
			  ldb_dn_get_linearized(msg_mod->dn), ldb_errstring(sam_ctx)));
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}
