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
#include "param/param.h"
#include "auth/auth_sam.h"

const char *user_attrs[] = {
	/* required for the krb5 kdc */
	"objectClass",
	"sAMAccountName",
	"userPrincipalName",
	"servicePrincipalName",
	"msDS-KeyVersionNumber",
	"supplementalCredentials",

	/* passwords */
	"dBCSPwd", 
	"unicodePwd",

	"userAccountControl",

	"pwdLastSet",
	"accountExpires",
	"logonHours",
	"objectSid",

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
	NULL,
};

const char *domain_ref_attrs[] =  {"nETBIOSName", "nCName", 
				   "dnsRoot", "objectClass", NULL};

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
			    struct ldb_message *msg,
			    struct ldb_message *msg_domain_ref,
			    const char *logon_workstation,
			    const char *name_for_logs,
			    bool allow_domain_trust)
{
	uint16_t acct_flags;
	const char *workstation_list;
	NTTIME acct_expiry;
	NTTIME must_change_time;

	struct ldb_dn *domain_dn = samdb_result_dn(sam_ctx, mem_ctx, msg_domain_ref, "nCName", ldb_dn_new(mem_ctx, sam_ctx, NULL));

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

	/* check for immediate expiry "must change at next logon" */
	if (must_change_time == 0) {
		DEBUG(1,("sam_account_ok: Account for user '%s' password must change!.\n", 
			 name_for_logs));
		return NT_STATUS_PASSWORD_MUST_CHANGE;
	}

	/* check for expired password */
	if (must_change_time < now) {
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
					   struct ldb_message *msg,
					   struct ldb_message *msg_domain_ref,
					   DATA_BLOB user_sess_key, DATA_BLOB lm_sess_key,
					   struct auth_serversupplied_info **_server_info)
{
	struct auth_serversupplied_info *server_info;
	struct ldb_message **group_msgs;
	int group_ret;
	const char *group_attrs[3] = { "sAMAccountType", "objectSid", NULL }; 
	/* find list of sids */
	struct dom_sid **groupSIDs = NULL;
	struct dom_sid *account_sid;
	struct dom_sid *primary_group_sid;
	struct ldb_dn *domain_dn;
	const char *str;
	struct ldb_dn *ncname;
	int i;
	uint_t rid;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	group_ret = gendb_search(sam_ctx,
				 tmp_ctx, NULL, &group_msgs, group_attrs,
				 "(&(member=%s)(sAMAccountType=*))", 
				 ldb_dn_get_linearized(msg->dn));
	if (group_ret == -1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);
	
	if (group_ret > 0) {
		groupSIDs = talloc_array(server_info, struct dom_sid *, group_ret);
		NT_STATUS_HAVE_NO_MEMORY(groupSIDs);
	}

	/* Need to unroll some nested groups, but not aliases */
	for (i = 0; i < group_ret; i++) {
		groupSIDs[i] = samdb_result_dom_sid(groupSIDs, 
						    group_msgs[i], "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(groupSIDs[i]);
	}

	talloc_free(tmp_ctx);

	account_sid = samdb_result_dom_sid(server_info, msg, "objectSid");
	NT_STATUS_HAVE_NO_MEMORY(account_sid);

	primary_group_sid = dom_sid_dup(server_info, account_sid);
	NT_STATUS_HAVE_NO_MEMORY(primary_group_sid);

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

	server_info->domain_name = talloc_steal(server_info, samdb_result_string(msg_domain_ref, "nETBIOSName", NULL));

	str = samdb_result_string(msg, "displayName", "");
	server_info->full_name = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->full_name);

	str = samdb_result_string(msg, "scriptPath", "");
	server_info->logon_script = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_script);

	str = samdb_result_string(msg, "profilePath", "");
	server_info->profile_path = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->profile_path);

	str = samdb_result_string(msg, "homeDirectory", "");
	server_info->home_directory = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_directory);

	str = samdb_result_string(msg, "homeDrive", "");
	server_info->home_drive = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_drive);

	server_info->logon_server = talloc_strdup(server_info, netbios_name);
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_server);

	server_info->last_logon = samdb_result_nttime(msg, "lastLogon", 0);
	server_info->last_logoff = samdb_result_nttime(msg, "lastLogoff", 0);
	server_info->acct_expiry = samdb_result_account_expires(msg);
	server_info->last_password_change = samdb_result_nttime(msg, "pwdLastSet", 0);

	ncname = samdb_result_dn(sam_ctx, mem_ctx, msg_domain_ref, "nCName", NULL);
	if (!ncname) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	server_info->allow_password_change
		= samdb_result_allow_password_change(sam_ctx, mem_ctx, 
						     ncname, msg, "pwdLastSet");
	server_info->force_password_change
		= samdb_result_force_password_change(sam_ctx, mem_ctx, 
						     ncname, msg);
	
	server_info->logon_count = samdb_result_uint(msg, "logonCount", 0);
	server_info->bad_password_count = samdb_result_uint(msg, "badPwdCount", 0);

	domain_dn = samdb_result_dn(sam_ctx, mem_ctx, msg_domain_ref, "nCName", NULL);

	server_info->acct_flags = samdb_result_acct_flags(sam_ctx, mem_ctx, 
							  msg, domain_dn);

	server_info->user_session_key = user_sess_key;
	server_info->lm_session_key = lm_sess_key;

	server_info->authenticated = true;

	*_server_info = server_info;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_results_principal(struct ldb_context *sam_ctx,
				   TALLOC_CTX *mem_ctx, const char *principal,
				   struct ldb_message ***msgs,
				   struct ldb_message ***msgs_domain_ref)
{			   
	struct ldb_dn *user_dn, *domain_dn;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int ret;
	struct ldb_dn *partitions_basedn = samdb_partitions_dn(sam_ctx, mem_ctx);

	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = crack_user_principal_name(sam_ctx, tmp_ctx, principal, &user_dn, &domain_dn);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}
	
	/* grab domain info from the reference */
	ret = gendb_search(sam_ctx, tmp_ctx, partitions_basedn, msgs_domain_ref, domain_ref_attrs,
			   "(ncName=%s)", ldb_dn_get_linearized(domain_dn));

	if (ret != 1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	/* pull the user attributes */
	ret = gendb_search_dn(sam_ctx, tmp_ctx, user_dn, msgs, user_attrs);
	if (ret != 1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, *msgs);
	talloc_steal(mem_ctx, *msgs_domain_ref);
	talloc_free(tmp_ctx);
	
	return NT_STATUS_OK;
}
