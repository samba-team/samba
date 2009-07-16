/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2004
   Copyright (C) Gerald Carter                             2003
   Copyright (C) Stefan Metzmacher                         2005
   
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
#include "../lib/util/util_ldb.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/security.h"
#include "libcli/ldap/ldap.h"
#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "param/param.h"
#include "auth/auth_sam.h"

#define KRBTGT_ATTRS \
	/* required for the krb5 kdc */		\
	"objectClass",				\
	"sAMAccountName",			\
	"userPrincipalName",			\
	"servicePrincipalName",			\
	"msDS-KeyVersionNumber",		\
	"supplementalCredentials",		\
						\
	/* passwords */				\
	"dBCSPwd",				\
	"unicodePwd",				\
						\
	"userAccountControl",			\
	"objectSid",				\
						\
	"pwdLastSet",				\
	"accountExpires"			

const char *krbtgt_attrs[] = {
	KRBTGT_ATTRS
};

const char *server_attrs[] = {
	KRBTGT_ATTRS
};

const char *user_attrs[] = {
	KRBTGT_ATTRS,

	"logonHours",

	/* check 'allowed workstations' */
	"userWorkstations",
		       
	/* required for server_info, not access control: */
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
 Do a specific test for a SAM_ACCOUNT being vaild for this connection 
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

	NTTIME now;
	DEBUG(4,("authsam_account_ok: Checking SMB password for user %s\n", name_for_logs));

	acct_flags = samdb_result_acct_flags(sam_ctx, mem_ctx, msg, domain_dn);
	
	acct_expiry = samdb_result_account_expires(msg);

	/* Check for when we must change this password, taking the
	 * userAccountControl flags into account */
	must_change_time = samdb_result_force_password_change(sam_ctx, mem_ctx, 
							      domain_dn, msg);

	workstation_list = samdb_result_string(msg, "userWorkstations", NULL);

	/* Quit if the account was disabled. */
	if (acct_flags & ACB_DISABLED) {
		DEBUG(1,("authsam_account_ok: Account for user '%s' was disabled.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(1,("authsam_account_ok: Account for user %s was locked out.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* Test account expire time */
	unix_to_nt_time(&now, time(NULL));
	if (now > acct_expiry) {
		DEBUG(1,("authsam_account_ok: Account for user '%s' has expired.\n", name_for_logs));
		DEBUG(3,("authsam_account_ok: Account expired at '%s'.\n", 
			 nt_time_string(mem_ctx, acct_expiry)));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	/* check for immediate expiry "must change at next logon" (but not if this is a password change request) */
	if ((must_change_time == 0) && !password_change) {
		DEBUG(1,("sam_account_ok: Account for user '%s' password must change!.\n", 
			 name_for_logs));
		return NT_STATUS_PASSWORD_MUST_CHANGE;
	}

	/* check for expired password (but not if this is a password change request) */
	if ((must_change_time < now) && !password_change) {
		DEBUG(1,("sam_account_ok: Account for user '%s' password expired!.\n", 
			 name_for_logs));
		DEBUG(1,("sam_account_ok: Password expired at '%s' unix time.\n", 
			 nt_time_string(mem_ctx, must_change_time)));
		return NT_STATUS_PASSWORD_EXPIRED;
	}

	/* Test workstation. Workstation list is comma separated. */
	if (logon_workstation && workstation_list && *workstation_list) {
		bool invalid_ws = true;
		int i;
		const char **workstations = (const char **)str_list_make(mem_ctx, workstation_list, ",");
		
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
		if (acct_flags & ACB_WSTRUST) {
			DEBUG(4,("sam_account_ok: Wksta trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
		}
	}

	return NT_STATUS_OK;
}

_PUBLIC_ NTSTATUS authsam_make_server_info(TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx,
					   const char *netbios_name,
					   const char *domain_name,
					   struct ldb_dn *domain_dn, 
					   struct ldb_message *msg,
					   DATA_BLOB user_sess_key, DATA_BLOB lm_sess_key,
					   struct auth_serversupplied_info **_server_info)
{
	struct auth_serversupplied_info *server_info;
	int group_ret = 0;
	/* find list of sids */
	struct dom_sid **groupSIDs = NULL;
	struct dom_sid *account_sid;
	struct dom_sid *primary_group_sid;
	const char *str;
	int i;
	uint_t rid;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);	
	struct ldb_message_element *el;

	server_info = talloc(tmp_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info, tmp_ctx);
	
	el = ldb_msg_find_element(msg, "memberOf");
	if (el != NULL) {
		group_ret = el->num_values;
		groupSIDs = talloc_array(server_info, struct dom_sid *, group_ret);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(groupSIDs, tmp_ctx);
	}

	/* TODO Note: this is incomplete. We need to unroll some
	 * nested groups, but not aliases */
	for (i = 0; i < group_ret; i++) {
		struct ldb_dn *dn;
		const struct ldb_val *v;
		enum ndr_err_code ndr_err;

		dn = ldb_dn_from_ldb_val(tmp_ctx, sam_ctx, &el->values[i]);
		if (dn == NULL) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		v = ldb_dn_get_extended_component(dn, "SID");
		groupSIDs[i] = talloc(groupSIDs, struct dom_sid);
		NT_STATUS_HAVE_NO_MEMORY_AND_FREE(groupSIDs[i], tmp_ctx);

		ndr_err = ndr_pull_struct_blob(v, groupSIDs[i], NULL, groupSIDs[i], 
					       (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	account_sid = samdb_result_dom_sid(server_info, msg, "objectSid");
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(account_sid, tmp_ctx);

	primary_group_sid = dom_sid_dup(server_info, account_sid);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(primary_group_sid, tmp_ctx);

	rid = samdb_result_uint(msg, "primaryGroupID", ~0);
	if (rid == ~0) {
		if (group_ret > 0) {
			primary_group_sid = groupSIDs[0];
		} else {
			primary_group_sid = NULL;
		}
	} else {
		primary_group_sid->sub_auths[primary_group_sid->num_auths-1] = rid;
	}

	server_info->account_sid = account_sid;
	server_info->primary_group_sid = primary_group_sid;
	
	server_info->n_domain_groups = group_ret;
	server_info->domain_groups = groupSIDs;

	server_info->account_name = talloc_steal(server_info, samdb_result_string(msg, "sAMAccountName", NULL));

	server_info->domain_name = talloc_strdup(server_info, domain_name);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->domain_name, tmp_ctx);

	str = samdb_result_string(msg, "displayName", "");
	server_info->full_name = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->full_name, tmp_ctx);

	str = samdb_result_string(msg, "scriptPath", "");
	server_info->logon_script = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->logon_script, tmp_ctx);

	str = samdb_result_string(msg, "profilePath", "");
	server_info->profile_path = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->profile_path, tmp_ctx);

	str = samdb_result_string(msg, "homeDirectory", "");
	server_info->home_directory = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->home_directory, tmp_ctx);

	str = samdb_result_string(msg, "homeDrive", "");
	server_info->home_drive = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->home_drive, tmp_ctx);

	server_info->logon_server = talloc_strdup(server_info, netbios_name);
	NT_STATUS_HAVE_NO_MEMORY_AND_FREE(server_info->logon_server, tmp_ctx);

	server_info->last_logon = samdb_result_nttime(msg, "lastLogon", 0);
	server_info->last_logoff = samdb_result_nttime(msg, "lastLogoff", 0);
	server_info->acct_expiry = samdb_result_account_expires(msg);
	server_info->last_password_change = samdb_result_nttime(msg, "pwdLastSet", 0);

	server_info->allow_password_change
		= samdb_result_allow_password_change(sam_ctx, mem_ctx, 
						     domain_dn, msg, "pwdLastSet");
	server_info->force_password_change
		= samdb_result_force_password_change(sam_ctx, mem_ctx, 
						     domain_dn, msg);
	
	server_info->logon_count = samdb_result_uint(msg, "logonCount", 0);
	server_info->bad_password_count = samdb_result_uint(msg, "badPwdCount", 0);

	server_info->acct_flags = samdb_result_acct_flags(sam_ctx, mem_ctx, 
							  msg, domain_dn);

	server_info->user_session_key = user_sess_key;
	server_info->lm_session_key = lm_sess_key;

	server_info->authenticated = true;

	*_server_info = talloc_steal(mem_ctx, server_info);

	return NT_STATUS_OK;
}

NTSTATUS sam_get_results_principal(struct ldb_context *sam_ctx,
				   TALLOC_CTX *mem_ctx, const char *principal,
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

	nt_status = crack_user_principal_name(sam_ctx, tmp_ctx, principal, &user_dn, domain_dn);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}
	
	/* pull the user attributes */
	ret = gendb_search_single_extended_dn(sam_ctx, tmp_ctx, user_dn, LDB_SCOPE_BASE,
					      msg, user_attrs, "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, *msg);
	talloc_steal(mem_ctx, *domain_dn);
	talloc_free(tmp_ctx);
	
	return NT_STATUS_OK;
}
