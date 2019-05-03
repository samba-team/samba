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
#include "librpc/gen_ndr/ndr_winbind_c.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

#define KRBTGT_ATTRS				\
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
	"msDS-UserPasswordExpiryTimeComputed",	\
	"accountExpires"

const char *krbtgt_attrs[] = {
	KRBTGT_ATTRS, NULL
};

const char *server_attrs[] = {
	KRBTGT_ATTRS, NULL
};

const char *user_attrs[] = {
	/*
	 * This ordering (having msDS-ResultantPSO first) is
	 * important.  By processing this attribute first it is
	 * available in the operational module for the other PSO
	 * attribute calcuations to use.
	 */
	"msDS-ResultantPSO",

	KRBTGT_ATTRS,

	"logonHours",

	/*
	 * To allow us to zero the badPwdCount and lockoutTime on
	 * successful logon, without database churn
	 */
	"lockoutTime",

	/*
	 * Needed for SendToSAM requests
	 */
	"objectGUID",

	/* check 'allowed workstations' */
	"userWorkstations",

	/* required for user_info_dc, not access control: */
	"displayName",
	"scriptPath",
	"profilePath",
	"homeDirectory",
	"homeDrive",
	"lastLogon",
	"lastLogonTimestamp",
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
	must_change_time = samdb_result_nttime(msg,
			"msDS-UserPasswordExpiryTimeComputed", 0);

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

static NTSTATUS authsam_domain_group_filter(TALLOC_CTX *mem_ctx,
					    char **_filter)
{
	char *filter = NULL;

	*_filter = NULL;

	filter = talloc_strdup(mem_ctx, "(&(objectClass=group)");
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Skip all builtin groups, they're added later.
	 */
	filter = talloc_asprintf_append_buffer(filter,
				"(!(groupType:1.2.840.113556.1.4.803:=%u))",
				GROUP_TYPE_BUILTIN_LOCAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	/*
	 * Only include security groups.
	 */
	filter = talloc_asprintf_append_buffer(filter,
				"(groupType:1.2.840.113556.1.4.803:=%u))",
				GROUP_TYPE_SECURITY_ENABLED);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*_filter = filter;
	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS authsam_make_user_info_dc(TALLOC_CTX *mem_ctx,
					   struct ldb_context *sam_ctx,
					   const char *netbios_name,
					   const char *domain_name,
					   const char *dns_domain_name,
					   struct ldb_dn *domain_dn, 
					   struct ldb_message *msg,
					   DATA_BLOB user_sess_key,
					   DATA_BLOB lm_sess_key,
					   struct auth_user_info_dc **_user_info_dc)
{
	NTSTATUS status;
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;
	const char *str = NULL;
	char *filter = NULL;
	/* SIDs for the account and his primary group */
	struct dom_sid *account_sid;
	struct dom_sid_buf buf;
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
	if (tmp_ctx == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_array(user_info_dc, struct dom_sid, 2);
	if (sids == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	num_sids = 2;

	account_sid = samdb_result_dom_sid(tmp_ctx, msg, "objectSid");
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

	/*
	 * Filter out builtin groups from this token. We will search
	 * for builtin groups later, and not include them in the PAC
	 * or SamLogon validation info.
	 */
	status = authsam_domain_group_filter(tmp_ctx, &filter);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(user_info_dc);
		return status;
	}

	primary_group_dn = talloc_asprintf(
		tmp_ctx,
		"<SID=%s>",
		dom_sid_str_buf(&sids[PRIMARY_GROUP_SID_INDEX], &buf));
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

	info->user_principal_name = talloc_steal(info,
		ldb_msg_find_attr_as_string(msg, "userPrincipalName", NULL));
	if (info->user_principal_name == NULL && dns_domain_name != NULL) {
		info->user_principal_name = talloc_asprintf(info, "%s@%s",
					info->account_name,
					dns_domain_name);
		if (info->user_principal_name == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
		info->user_principal_constructed = true;
	}

	info->domain_name = talloc_strdup(info, domain_name);
	if (info->domain_name == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	if (dns_domain_name != NULL) {
		info->dns_domain_name = talloc_strdup(info, dns_domain_name);
		if (info->dns_domain_name == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
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
	info->force_password_change = samdb_result_nttime(msg,
		"msDS-UserPasswordExpiryTimeComputed", 0);
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

_PUBLIC_ NTSTATUS authsam_update_user_info_dc(TALLOC_CTX *mem_ctx,
			struct ldb_context *sam_ctx,
			struct auth_user_info_dc *user_info_dc)
{
	char *filter = NULL;
	NTSTATUS status;
	uint32_t i;
	uint32_t n = 0;

	/*
	 * This function exists to expand group memberships
	 * in the local domain (forest), as the token
	 * may come from a different domain.
	 */

	/*
	 * Filter out builtin groups from this token. We will search
	 * for builtin groups later.
	 */
	status = authsam_domain_group_filter(mem_ctx, &filter);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(user_info_dc);
		return status;
	}

	/*
	 * We loop only over the existing number of
	 * sids.
	 */
	n = user_info_dc->num_sids;
	for (i = 0; i < n; i++) {
		struct dom_sid *sid = &user_info_dc->sids[i];
		struct dom_sid_buf sid_buf;
		char dn_str[sizeof(sid_buf.buf)*2];
		DATA_BLOB dn_blob = data_blob_null;

		snprintf(dn_str,
			sizeof(dn_str),
			"<SID=%s>",
			dom_sid_str_buf(sid, &sid_buf));
		dn_blob = data_blob_string_const(dn_str);

		/*
		 * We already have the SID in the token, so set
		 * 'only childs' flag to true and add all
		 * groups which match the filter.
		 */
		status = dsdb_expand_nested_groups(sam_ctx, &dn_blob,
						   true, filter,
						   user_info_dc,
						   &user_info_dc->sids,
						   &user_info_dc->num_sids);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

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
			struct dom_sid_buf buf;
			DEBUG(3, ("authsam_get_user_info_dc_principal: Failed to find domain with: SID %s\n",
				  dom_sid_str_buf(domain_sid, &buf)));
			return NT_STATUS_NO_SUCH_USER;
		}

	} else {
		return NT_STATUS_INVALID_PARAMETER;
	}

	nt_status = authsam_make_user_info_dc(tmp_ctx, sam_ctx,
					     lpcfg_netbios_name(lp_ctx),
					     lpcfg_sam_name(lp_ctx),
					     lpcfg_sam_dnsname(lp_ctx),
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

/*
 * Returns the details for the Password Settings Object (PSO), if one applies
 * the user.
 */
static int authsam_get_user_pso(struct ldb_context *sam_ctx,
				TALLOC_CTX *mem_ctx,
				struct ldb_message *user_msg,
				struct ldb_message **pso_msg)
{
	const char *attrs[] = { "msDS-LockoutThreshold",
				"msDS-LockoutObservationWindow",
				NULL };
	struct ldb_dn *pso_dn = NULL;
	struct ldb_result *res = NULL;
	int ret;

	/* check if the user has a PSO that applies to it */
	pso_dn = ldb_msg_find_attr_as_dn(sam_ctx, mem_ctx, user_msg,
					 "msDS-ResultantPSO");

	if (pso_dn != NULL) {
		ret = dsdb_search_dn(sam_ctx, mem_ctx, &res, pso_dn, attrs, 0);
		if (ret != LDB_SUCCESS) {
			return ret;
		}

		*pso_msg = res->msgs[0];
	}

	return LDB_SUCCESS;
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
	struct ldb_message *pso_msg = NULL;
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

	ret = authsam_get_user_pso(sam_ctx, mem_ctx, msg, &pso_msg);
	if (ret != LDB_SUCCESS) {

		/*
		 * fallback to using the domain defaults so that we still
		 * record the bad password attempt
		 */
		DBG_ERR("Error (%d) checking PSO for %s",
			ret, ldb_dn_get_linearized(msg->dn));
	}

	status = dsdb_update_bad_pwd_count(mem_ctx, sam_ctx,
					   msg, domain_res->msgs[0], pso_msg,
					   &msg_mod);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(mem_ctx);
		return status;
	}

	if (msg_mod != NULL) {
		struct ldb_request *req;

		ret = ldb_build_mod_req(&req, sam_ctx, sam_ctx,
					msg_mod,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
		if (ret != LDB_SUCCESS) {
			goto done;
		}

		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			goto done;
		}

		ret = dsdb_autotransaction_request(sam_ctx, req);
		talloc_free(req);
	}

done:
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Failed to update badPwdCount, badPasswordTime or "
			"set lockoutTime on %s: %s\n",
			ldb_dn_get_linearized(msg->dn),
			ldb_errstring(sam_ctx));
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}


static NTSTATUS authsam_update_lastlogon_timestamp(struct ldb_context *sam_ctx,
					    struct ldb_message *msg_mod,
					    struct ldb_dn *domain_dn,
					    NTTIME old_timestamp,
					    NTTIME now)
{
	/*
	 * We only set lastLogonTimestamp if the current value is older than
	 * now - msDS-LogonTimeSyncInterval days.
	 *
	 * msDS-LogonTimeSyncInterval is an int32_t number of days, while
	 * lastLogonTimestamp is in the 64 bit 100ns NTTIME format.
	 *
	 * The docs say: "the initial update, after the domain functional
	 * level is raised to DS_BEHAVIOR_WIN2003 or higher, is calculated as
	 * 14 days minus a random percentage of 5 days", but we aren't doing
	 * that. The blogosphere seems to think that this randomised update
	 * happens everytime, but [MS-ADA1] doesn't agree.
	 *
	 * Dochelp referred us to the following blog post:
	 * http://blogs.technet.com/b/askds/archive/2009/04/15/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works.aspx
	 *
	 * en msDS-LogonTimeSyncInterval is zero, the lastLogonTimestamp is
	 * not changed.
	 */
	static const char *attrs[] = { "msDS-LogonTimeSyncInterval",
					NULL };
	int ret;
	struct ldb_result *domain_res = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	int32_t sync_interval;
	NTTIME sync_interval_nt;

	mem_ctx = talloc_new(msg_mod);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dsdb_search_dn(sam_ctx, mem_ctx, &domain_res, domain_dn, attrs,
			     0);
	if (ret != LDB_SUCCESS || domain_res->count != 1) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	sync_interval = ldb_msg_find_attr_as_int(domain_res->msgs[0],
						 "msDS-LogonTimeSyncInterval",
						 14);
	DEBUG(5, ("sync interval is %d\n", sync_interval));
	if (sync_interval == 0){
		/*
		 * Setting msDS-LogonTimeSyncInterval to zero is how you ask
		 * that nothing happens here.
		 */
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_OK;
	}
	else if (sync_interval >= 5){
		/*
		 * Subtract "a random percentage of 5" days. Presumably this
		 * percentage is between 0 and 100, and modulus is accurate
		 * enough.
		 */
		uint32_t r = generate_random() % 6;
		sync_interval -= r;
		DEBUG(5, ("randomised sync interval is %d (-%d)\n", sync_interval, r));
	}
	/* In the case where sync_interval < 5 there is no randomisation */

	sync_interval_nt = sync_interval * 24LL * 3600LL * 10000000LL;

	DEBUG(5, ("old timestamp is %lld, threshold %lld, diff %lld\n",
		  (long long int)old_timestamp,
		  (long long int)(now - sync_interval_nt),
		  (long long int)(old_timestamp - now + sync_interval_nt)));

	if (old_timestamp > now){
		DEBUG(0, ("lastLogonTimestamp is in the future! (%lld > %lld)\n",
			  (long long int)old_timestamp, (long long int)now));
		/* then what? */

	} else if (old_timestamp < now - sync_interval_nt){
		DEBUG(5, ("updating lastLogonTimestamp to %lld\n",
			  (long long int)now));

		/* The time has come to update lastLogonTimestamp */
		ret = samdb_msg_add_int64(sam_ctx, msg_mod, msg_mod,
					  "lastLogonTimestamp", now);

		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}
	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}

/****************************************************************************
 Look for the specified user in the sam, return ldb result structures
****************************************************************************/

NTSTATUS authsam_search_account(TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx,
					 const char *account_name,
					 struct ldb_dn *domain_dn,
					 struct ldb_message **ret_msg)
{
	int ret;

	/* pull the user attributes */
	ret = dsdb_search_one(sam_ctx, mem_ctx, ret_msg, domain_dn, LDB_SCOPE_SUBTREE,
			      user_attrs,
			      DSDB_SEARCH_SHOW_EXTENDED_DN,
			      "(&(sAMAccountName=%s)(objectclass=user))",
			      ldb_binary_encode_string(mem_ctx, account_name));
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(3,("sam_search_user: Couldn't find user [%s] in samdb, under %s\n",
			 account_name, ldb_dn_get_linearized(domain_dn)));
		return NT_STATUS_NO_SUCH_USER;
	}
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}


/* Reset the badPwdCount to zero and update the lastLogon time. */
NTSTATUS authsam_logon_success_accounting(struct ldb_context *sam_ctx,
					  const struct ldb_message *msg,
					  struct ldb_dn *domain_dn,
					  bool interactive_or_kerberos,
					  struct netr_SendToSamBase **send_to_sam)
{
	int ret;
	NTSTATUS status;
	int badPwdCount;
	int dbBadPwdCount;
	int64_t lockoutTime;
	struct ldb_message *msg_mod;
	TALLOC_CTX *mem_ctx;
	struct timeval tv_now;
	NTTIME now;
	NTTIME lastLogonTimestamp;
	bool am_rodc = false;

	mem_ctx = talloc_new(msg);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	lockoutTime = ldb_msg_find_attr_as_int64(msg, "lockoutTime", 0);
	dbBadPwdCount = ldb_msg_find_attr_as_int(msg, "badPwdCount", 0);
	if (interactive_or_kerberos) {
		badPwdCount = dbBadPwdCount;
	} else {
		badPwdCount = samdb_result_effective_badPwdCount(sam_ctx, mem_ctx,
								 domain_dn, msg);
	}
	lastLogonTimestamp =
		ldb_msg_find_attr_as_int64(msg, "lastLogonTimestamp", 0);

	DEBUG(5, ("lastLogonTimestamp is %lld\n",
		  (long long int)lastLogonTimestamp));

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
	} else if (badPwdCount != 0) {
		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod, "badPwdCount", 0);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	tv_now = timeval_current();
	now = timeval_to_nttime(&tv_now);

	if (interactive_or_kerberos ||
	    (badPwdCount != 0 && lockoutTime == 0)) {
		ret = samdb_msg_add_int64(sam_ctx, msg_mod, msg_mod,
					  "lastLogon", now);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (interactive_or_kerberos) {
		int logonCount;

		logonCount = ldb_msg_find_attr_as_int(msg, "logonCount", 0);

		logonCount += 1;

		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod,
					"logonCount", logonCount);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/* Set an unset logonCount to 0 on first successful login */
		if (ldb_msg_find_ldb_val(msg, "logonCount") == NULL) {
			ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod,
						"logonCount", 0);
			if (ret != LDB_SUCCESS) {
				TALLOC_FREE(mem_ctx);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}

	ret = samdb_rodc(sam_ctx, &am_rodc);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (!am_rodc) {
		status = authsam_update_lastlogon_timestamp(sam_ctx, msg_mod, domain_dn,
							    lastLogonTimestamp, now);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(mem_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		/* Perform the (async) SendToSAM calls for MS-SAMS */
		if (dbBadPwdCount != 0 && send_to_sam != NULL) {
			struct netr_SendToSamBase *base_msg;
			struct GUID guid = samdb_result_guid(msg, "objectGUID");
			base_msg = talloc_zero(msg, struct netr_SendToSamBase);

			base_msg->message_type = SendToSamResetBadPasswordCount;
			base_msg->message_size = 16;
			base_msg->message.reset_bad_password.guid = guid;
			*send_to_sam = base_msg;
		}
	}

	if (msg_mod->num_elements > 0) {
		unsigned int i;
		struct ldb_request *req;

		/* mark all the message elements as LDB_FLAG_MOD_REPLACE */
		for (i=0;i<msg_mod->num_elements;i++) {
			msg_mod->elements[i].flags = LDB_FLAG_MOD_REPLACE;
		}

		ret = ldb_build_mod_req(&req, sam_ctx, sam_ctx,
					msg_mod,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
		if (ret != LDB_SUCCESS) {
			goto done;
		}

		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			goto done;
		}

		ret = dsdb_autotransaction_request(sam_ctx, req);
		talloc_free(req);
	}

done:
	if (ret != LDB_SUCCESS) {
		DEBUG(0, ("Failed to set badPwdCount and lockoutTime "
			  "to 0 and/or  lastlogon to now (%lld) "
			  "%s: %s\n", (long long int)now,
			  ldb_dn_get_linearized(msg_mod->dn),
			  ldb_errstring(sam_ctx)));
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}
