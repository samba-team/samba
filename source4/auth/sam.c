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
#include "lib/dbwrap/dbwrap.h"
#include "cluster/cluster.h"

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
	"msDS-AllowedToActOnBehalfOfOtherIdentity", \
						\
	/* passwords */				\
	"unicodePwd",				\
						\
	"userAccountControl",	                \
	"msDS-User-Account-Control-Computed",	\
	"objectSid",				\
						\
	"pwdLastSet",				\
	"msDS-UserPasswordExpiryTimeComputed",	\
	"accountExpires",			\
						\
	/* Needed for RODC rule processing */	\
	"msDS-KrbTgtLinkBL",			\
						\
	/* Required for Group Managed Service Accounts. */ \
	"msDS-ManagedPasswordId",		\
	"msDS-ManagedPasswordInterval",		\
	"whenCreated",				\
	/* Required for Key Trust authentication */\
	"msDS-CustomKeyInformation"

#define AUTHN_POLICY_ATTRS                     \
	/* Required for authentication policies / silos */ \
	"msDS-AssignedAuthNPolicy",             \
	"msDS-AssignedAuthNPolicySilo"

const char *krbtgt_attrs[] = {
	/*
	 * Authentication policies will not be enforced on the TGS
	 * account. Don’t include the relevant attributes in the account search.
	 */
	KRBTGT_ATTRS, NULL
};

const char *server_attrs[] = {
	KRBTGT_ATTRS,
	AUTHN_POLICY_ATTRS,
	NULL
};

const char *user_attrs[] = {
	/*
	 * This ordering (having msDS-ResultantPSO first) is
	 * important.  By processing this attribute first it is
	 * available in the operational module for the other PSO
	 * attribute calculations to use.
	 */
	"msDS-ResultantPSO",

	KRBTGT_ATTRS,
	AUTHN_POLICY_ATTRS,

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
				     NTTIME now,
				     uint32_t logon_parameters,
				     struct ldb_dn *domain_dn,
				     struct ldb_message *msg,
				     const char *logon_workstation,
				     const char *name_for_logs,
				     bool allow_domain_trust,
				     bool password_change)
{
	uint32_t acct_flags;
	const char *workstation_list;
	NTTIME acct_expiry;
	NTTIME must_change_time;

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
	if ((acct_flags & ACB_PW_EXPIRED) && !password_change) {
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
	talloc_asprintf_addbuf(&filter,
			       "(!(groupType:"LDB_OID_COMPARATOR_AND":=%u))",
			       GROUP_TYPE_BUILTIN_LOCAL_GROUP);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	/*
	 * Only include security groups.
	 */
	talloc_asprintf_addbuf(&filter,
			       "(groupType:"LDB_OID_COMPARATOR_AND":=%u))",
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
					   const struct ldb_message *msg,
					   DATA_BLOB user_sess_key,
					   DATA_BLOB lm_sess_key,
					   struct auth_user_info_dc **_user_info_dc)
{
	NTSTATUS status;
	int ret;
	struct auth_user_info_dc *user_info_dc;
	struct auth_user_info *info;
	const char *str = NULL;
	char *filter = NULL;
	/* SIDs for the account and his primary group */
	struct dom_sid *account_sid;
	struct dom_sid_buf buf;
	const char *primary_group_dn_str = NULL;
	DATA_BLOB primary_group_blob;
	struct ldb_dn *primary_group_dn = NULL;
	struct ldb_message *primary_group_msg = NULL;
	unsigned primary_group_type;
	/* SID structures for the expanded group memberships */
	struct auth_SidAttr *sids = NULL;
	uint32_t num_sids = 0;
	unsigned int i;
	struct dom_sid *domain_sid;
	uint32_t group_rid;
	struct dom_sid groupsid = {};
	TALLOC_CTX *tmp_ctx;
	struct ldb_message_element *el;
	static const char * const group_type_attrs[] = { "groupType", NULL };

	if (msg == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	NT_STATUS_HAVE_NO_MEMORY(user_info_dc);

	tmp_ctx = talloc_new(user_info_dc);
	if (tmp_ctx == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * We'll typically store three SIDs: the SID of the user, the SID of the
	 * primary group, and a copy of the latter if it's not a resource
	 * group. Allocate enough memory for these three SIDs.
	 */
	sids = talloc_zero_array(user_info_dc, struct auth_SidAttr, 3);
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

	group_rid = ldb_msg_find_attr_as_uint(msg, "primaryGroupID", ~0);
	groupsid = *domain_sid;
	sid_append_rid(&groupsid, group_rid);

	sids[PRIMARY_USER_SID_INDEX] = (struct auth_SidAttr) {
		.sid = *account_sid,
		.attrs = SE_GROUP_DEFAULT_FLAGS,
	};

	sids[PRIMARY_GROUP_SID_INDEX] = (struct auth_SidAttr) {
		.sid = groupsid,
		.attrs = SE_GROUP_DEFAULT_FLAGS,
	};

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

	primary_group_dn_str = talloc_asprintf(
		tmp_ctx,
		"<SID=%s>",
		dom_sid_str_buf(&sids[PRIMARY_GROUP_SID_INDEX].sid, &buf));
	if (primary_group_dn_str == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	/* Get the DN of the primary group. */
	primary_group_dn = ldb_dn_new(tmp_ctx, sam_ctx, primary_group_dn_str);
	if (primary_group_dn == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Do a search for the primary group, for the purpose of checking
	 * whether it's a resource group.
	 */
	ret = dsdb_search_one(sam_ctx, tmp_ctx,
			      &primary_group_msg,
			      primary_group_dn,
			      LDB_SCOPE_BASE,
			      group_type_attrs,
			      0,
			      NULL);
	if (ret != LDB_SUCCESS) {
		talloc_free(user_info_dc);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* Check the type of the primary group. */
	primary_group_type = ldb_msg_find_attr_as_uint(primary_group_msg, "groupType", 0);
	if (primary_group_type & GROUP_TYPE_RESOURCE_GROUP) {
		/*
		 * If it's a resource group, we might as well indicate that in
		 * its attributes. At any rate, the primary group's attributes
		 * are unlikely to be used in the code, as there's nowhere to
		 * store them.
		 */
		sids[PRIMARY_GROUP_SID_INDEX].attrs |= SE_GROUP_RESOURCE;
	} else {
		/*
		 * The primary group is not a resource group. Make a copy of its
		 * SID to ensure it is added to the Base SIDs in the PAC.
		 */
		sids[REMAINING_SIDS_INDEX] = sids[PRIMARY_GROUP_SID_INDEX];
		++num_sids;
	}

	primary_group_blob = data_blob_string_const(primary_group_dn_str);

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
	if (user_info_dc->info == NULL) {
		talloc_free(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "sAMAccountName", NULL);
	info->account_name = talloc_strdup(info, str);
	if (info->account_name == NULL) {
		TALLOC_FREE(user_info_dc);
		return NT_STATUS_NO_MEMORY;
	}

	str = ldb_msg_find_attr_as_string(msg, "userPrincipalName", NULL);
	if (str == NULL && dns_domain_name != NULL) {
		info->user_principal_name = talloc_asprintf(info, "%s@%s",
					info->account_name,
					dns_domain_name);
		if (info->user_principal_name == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
		info->user_principal_constructed = true;
	} else if (str != NULL) {
		info->user_principal_name = talloc_strdup(info, str);
		if (info->user_principal_name == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}
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
						   struct auth_SidAttr,
						   user_info_dc->num_sids+1);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		user_info_dc->sids[user_info_dc->num_sids] = (struct auth_SidAttr) {
			.sid = global_sid_Enterprise_DCs,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		user_info_dc->num_sids++;
	}

	if ((info->acct_flags & (ACB_PARTIAL_SECRETS_ACCOUNT | ACB_WSTRUST)) ==
	    (ACB_PARTIAL_SECRETS_ACCOUNT | ACB_WSTRUST)) {
		struct dom_sid rodcsid = {};

		/* the DOMAIN_RID_ENTERPRISE_READONLY_DCS PAC */
		user_info_dc->sids = talloc_realloc(user_info_dc,
						   user_info_dc->sids,
						   struct auth_SidAttr,
						   user_info_dc->num_sids+1);
		if (user_info_dc->sids == NULL) {
			TALLOC_FREE(user_info_dc);
			return NT_STATUS_NO_MEMORY;
		}

		rodcsid = *domain_sid;
		sid_append_rid(&rodcsid, DOMAIN_RID_ENTERPRISE_READONLY_DCS);

		user_info_dc->sids[user_info_dc->num_sids] = (struct auth_SidAttr) {
			.sid = rodcsid,
			.attrs = SE_GROUP_DEFAULT_FLAGS,
		};
		user_info_dc->num_sids++;
	}

	info->user_flags = 0;

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
		return status;
	}

	/*
	 * We loop only over the existing number of
	 * sids.
	 */
	n = user_info_dc->num_sids;
	for (i = 0; i < n; i++) {
		struct dom_sid *sid = &user_info_dc->sids[i].sid;
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
			talloc_free(filter);
			return status;
		}
	}

	talloc_free(filter);
	return NT_STATUS_OK;
}

/*
 * Make a shallow copy of a talloc-allocated user_info_dc structure, holding a
 * reference to each of the original fields.
 */
NTSTATUS authsam_shallow_copy_user_info_dc(TALLOC_CTX *mem_ctx,
					   const struct auth_user_info_dc *user_info_dc_in,
					   struct auth_user_info_dc **user_info_dc_out)
{
	struct auth_user_info_dc *user_info_dc = NULL;
	NTSTATUS status = NT_STATUS_OK;

	if (user_info_dc_in == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (user_info_dc_out == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	user_info_dc = talloc_zero(mem_ctx, struct auth_user_info_dc);
	if (user_info_dc == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	*user_info_dc = *user_info_dc_in;

	if (user_info_dc->info != NULL) {
		if (talloc_reference(user_info_dc, user_info_dc->info) == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (user_info_dc->user_session_key.data != NULL) {
		if (talloc_reference(user_info_dc, user_info_dc->user_session_key.data) == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (user_info_dc->lm_session_key.data != NULL) {
		if (talloc_reference(user_info_dc, user_info_dc->lm_session_key.data) == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (user_info_dc->sids != NULL) {
		/*
		 * Because we want to modify the SIDs in the user_info_dc
		 * structure, adding various well-known SIDs such as Asserted
		 * Identity or Claims Valid, make a copy of the SID array to
		 * guard against modification of the original.
		 *
		 * It’s better not to make a reference, because anything that
		 * tries to call talloc_realloc() on the original or the copy
		 * will fail when called for any referenced talloc context.
		 */
		user_info_dc->sids = talloc_memdup(user_info_dc,
						   user_info_dc->sids,
						   talloc_get_size(user_info_dc->sids));
		if (user_info_dc->sids == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	*user_info_dc_out = user_info_dc;
	user_info_dc = NULL;

out:
	talloc_free(user_info_dc);
	return status;
}

NTSTATUS sam_get_results_principal(struct ldb_context *sam_ctx,
				   TALLOC_CTX *mem_ctx, const char *principal,
				   const char **attrs,
				   const uint32_t dsdb_flags,
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
			      dsdb_flags | DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG,
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
						      user_attrs, DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS, &domain_dn, &msg);
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
				      DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_NO_GLOBAL_CATALOG | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
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
			talloc_free(tmp_ctx);
			return nt_status;
		}

		domain_dn = samdb_search_dn(sam_ctx, mem_ctx, NULL,
					  "(&(objectSid=%s)(objectClass=domain))",
					    ldap_encode_ndr_dom_sid(tmp_ctx, domain_sid));
		if (!domain_dn) {
			struct dom_sid_buf buf;
			DEBUG(3, ("authsam_get_user_info_dc_principal: Failed to find domain with: SID %s\n",
				  dom_sid_str_buf(domain_sid, &buf)));
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_SUCH_USER;
		}

	} else {
		talloc_free(tmp_ctx);
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

/*
 * Re-read the bad password and successful logon data for a user.
 *
 * The DN in the passed user record should contain the "objectGUID" in case the
 * object DN has changed.
 */
NTSTATUS authsam_reread_user_logon_data(
	struct ldb_context *sam_ctx,
	TALLOC_CTX *mem_ctx,
	const struct ldb_message *user_msg,
	struct ldb_message **current)
{
	TALLOC_CTX *tmp_ctx = NULL;
	const struct ldb_val *v = NULL;
	struct ldb_result *res = NULL;
	uint32_t acct_flags = 0;
	const char *attr_name = "msDS-User-Account-Control-Computed";
	NTSTATUS status = NT_STATUS_OK;
	int ret;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/*
	 * Re-read the account details, using the GUID in case the DN
	 * is being changed (this is automatic in LDB because the
	 * original search also used DSDB_SEARCH_SHOW_EXTENDED_DN)
	 *
	 * We re read all the attributes in user_attrs, rather than using a
	 * subset to ensure that we can reuse existing validation code.
	 */
	ret = dsdb_search_dn(sam_ctx,
			     tmp_ctx,
			     &res,
			     user_msg->dn,
			     user_attrs,
			     DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Unable to re-read account control data for %s\n",
			ldb_dn_get_linearized(user_msg->dn));
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	/*
	 * Ensure the account has not been locked out by another request
	 */
	v = ldb_msg_find_ldb_val(res->msgs[0], attr_name);
	if (v == NULL || v->data == NULL) {
		DBG_ERR("No %s attribute for %s\n",
			attr_name,
			ldb_dn_get_linearized(user_msg->dn));
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}
	acct_flags = samdb_result_acct_flags(res->msgs[0], attr_name);
	if (acct_flags & ACB_AUTOLOCK) {
		DBG_WARNING(
			"Account for user %s was locked out.\n",
			ldb_dn_get_linearized(user_msg->dn));
		status = NT_STATUS_ACCOUNT_LOCKED_OUT;
		goto out;
	}
	*current = talloc_steal(mem_ctx, res->msgs[0]);
out:
	TALLOC_FREE(tmp_ctx);
	return status;
}

static struct db_context *authsam_get_bad_password_db(
	TALLOC_CTX *mem_ctx,
	struct ldb_context *sam_ctx)
{
	struct loadparm_context *lp_ctx = NULL;
	const char *db_name = "bad_password";
	struct db_context *db_ctx =  NULL;

	lp_ctx = ldb_get_opaque(sam_ctx, "loadparm");
	if (lp_ctx == NULL) {
		DBG_ERR("Unable to get loadparm_context\n");
		return NULL;
	}

	db_ctx = cluster_db_tmp_open(mem_ctx, lp_ctx, db_name, TDB_DEFAULT);
	if (db_ctx == NULL) {
		DBG_ERR("Unable to open bad password attempts database\n");
		return NULL;
	}
	return db_ctx;
}

static NTSTATUS get_object_sid_as_tdb_data(
	TALLOC_CTX *mem_ctx,
	const struct ldb_message *msg,
	struct dom_sid_buf *buf,
	TDB_DATA *key)
{
	struct dom_sid *objectsid = NULL;

	/*
	 * Convert the objectSID to a human readable form to
	 * make debugging easier
	 */
	objectsid = samdb_result_dom_sid(mem_ctx, msg, "objectSID");
	if (objectsid == NULL) {
		DBG_ERR("Unable to extract objectSID\n");
		return NT_STATUS_INTERNAL_ERROR;
	}
	dom_sid_str_buf(objectsid, buf);
	key->dptr = (unsigned char *)buf->buf;
	key->dsize = strlen(buf->buf);

	talloc_free(objectsid);

	return NT_STATUS_OK;
}

/*
 * Add the users objectSID to the bad password attempt database
 * to indicate that last authentication failed due to a bad password
 */
static NTSTATUS authsam_set_bad_password_indicator(
	struct ldb_context *sam_ctx,
	TALLOC_CTX *mem_ctx,
	const struct ldb_message *msg)
{
	NTSTATUS status = NT_STATUS_OK;
	struct dom_sid_buf buf;
	TDB_DATA key = {0};
	TDB_DATA value = {0};
	struct db_context *db = NULL;

	TALLOC_CTX *ctx = talloc_new(mem_ctx);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db = authsam_get_bad_password_db(ctx, sam_ctx);
	if (db == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto exit;
	}

	status = get_object_sid_as_tdb_data(ctx, msg, &buf, &key);
	if (!NT_STATUS_IS_OK(status)) {
		goto exit;
	}

	status = dbwrap_store(db, key, value, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Unable to store bad password indicator\n");
	}
exit:
	talloc_free(ctx);
	return status;
}

/*
 * see if the users objectSID is in the bad password attempt database
 */
static NTSTATUS authsam_check_bad_password_indicator(
	struct ldb_context *sam_ctx,
	TALLOC_CTX *mem_ctx,
	bool *exists,
	const struct ldb_message *msg)
{
	NTSTATUS status = NT_STATUS_OK;
	struct dom_sid_buf buf;
	TDB_DATA key = {0};
	struct db_context *db = NULL;

	TALLOC_CTX *ctx = talloc_new(mem_ctx);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db = authsam_get_bad_password_db(ctx, sam_ctx);
	if (db == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto exit;
	}

	status = get_object_sid_as_tdb_data(ctx, msg, &buf, &key);
	if (!NT_STATUS_IS_OK(status)) {
		goto exit;
	}

	*exists = dbwrap_exists(db, key);
exit:
	talloc_free(ctx);
	return status;
}

/*
 * Remove the users objectSID to the bad password attempt database
 * to indicate that last authentication succeeded.
 */
static NTSTATUS authsam_clear_bad_password_indicator(
	struct ldb_context *sam_ctx,
	TALLOC_CTX *mem_ctx,
	const struct ldb_message *msg)
{
	NTSTATUS status = NT_STATUS_OK;
	struct dom_sid_buf buf;
	TDB_DATA key = {0};
	struct db_context *db = NULL;

	TALLOC_CTX *ctx = talloc_new(mem_ctx);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	db = authsam_get_bad_password_db(ctx, sam_ctx);
	if (db == NULL) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto exit;
	}

	status = get_object_sid_as_tdb_data(ctx, msg, &buf, &key);
	if (!NT_STATUS_IS_OK(status)) {
		goto exit;
	}

	status = dbwrap_delete(db, key);
	if (NT_STATUS_EQUAL(NT_STATUS_NOT_FOUND, status)) {
		/*
		 * Ok there was no bad password indicator this is expected
		 */
		status = NT_STATUS_OK;
	}
	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("Unable to delete bad password indicator, %s %s\n",
			nt_errstr(status),
			get_friendly_nt_error_msg(status));
	}
exit:
	talloc_free(ctx);
	return status;
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
	struct ldb_message *current = NULL;
	struct ldb_message *pso_msg = NULL;
	bool txn_active = false;
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
		DBG_ERR("Error (%d) checking PSO for %s\n",
			ret, ldb_dn_get_linearized(msg->dn));
	}

	/*
	 * To ensure that the bad password count is updated atomically,
	 * we need to:
	 *    begin a transaction
	 *       re-read the account details,
	 *         using the <GUID= part of the DN
	 *       update the bad password count
	 *    commit the transaction.
	 */

	/*
	 * Start a new transaction
	 */
	ret = ldb_transaction_start(sam_ctx);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}
	txn_active = true;

	/*
	 * Re-read the account details, using the GUID in case the DN
	 * is being changed.
	 */
	status = authsam_reread_user_logon_data(
		sam_ctx, mem_ctx, msg, &current);
	if (!NT_STATUS_IS_OK(status)) {
		/* The re-read can return account locked out, as well
		 * as an internal error
		 */
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
			/*
			 * For NT_STATUS_ACCOUNT_LOCKED_OUT we want to commit
			 * the transaction. Again to avoid cluttering the
			 * audit logs with spurious errors
			 */
			goto exit;
		}
		goto error;
	}

	/*
	 * Update the bad password count and if required lock the account
	 */
	status = dsdb_update_bad_pwd_count(
		mem_ctx,
		sam_ctx,
		current,
		domain_res->msgs[0],
		pso_msg,
		&msg_mod);
	if (!NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}

	/*
	 * Write the data back to disk if required.
	 */
	if (msg_mod != NULL) {
		struct ldb_request *req;

		ret = ldb_build_mod_req(&req, sam_ctx, sam_ctx,
					msg_mod,
					NULL,
					NULL,
					ldb_op_default_callback,
					NULL);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(msg_mod);
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}

		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			talloc_free(req);
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}

		/*
		 * As we're in a transaction, make the ldb request directly
		 * to avoid the nested transaction that would result if we
		 * called dsdb_autotransaction_request
		 */
		ret = ldb_request(sam_ctx, req);
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		}
		talloc_free(req);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}
		status = authsam_set_bad_password_indicator(
			sam_ctx, mem_ctx, msg);
		if (!NT_STATUS_IS_OK(status)) {
			goto error;
		}
	}
	/*
	 * Note that we may not have updated the user record, but
	 * committing the transaction in that case is still the correct
	 * thing to do.
	 * If the transaction was cancelled, this would be logged by
	 * the dsdb audit log as a failure. When in fact it is expected
	 * behaviour.
	 */
exit:
	TALLOC_FREE(mem_ctx);
	ret = ldb_transaction_commit(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Error (%d) %s, committing transaction,"
			" while updating bad password count"
			" for (%s)\n",
			ret,
			ldb_errstring(sam_ctx),
			ldb_dn_get_linearized(msg->dn));
		return NT_STATUS_INTERNAL_ERROR;
	}
	return status;

error:
	DBG_ERR("Failed to update badPwdCount, badPasswordTime or "
		"set lockoutTime on %s: %s\n",
		ldb_dn_get_linearized(msg->dn),
		ldb_errstring(sam_ctx) != NULL ?
			ldb_errstring(sam_ctx) :nt_errstr(status));
	if (txn_active) {
		ret = ldb_transaction_cancel(sam_ctx);
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Error rolling back transaction,"
				" while updating bad password count"
				" on %s: %s\n",
				ldb_dn_get_linearized(msg->dn),
				ldb_errstring(sam_ctx));
		}
	}
	TALLOC_FREE(mem_ctx);
	return status;

}

/*
 * msDS-LogonTimeSyncInterval is an int32_t number of days.
 *
 * The docs say: "the initial update, after the domain functional
 * level is raised to DS_BEHAVIOR_WIN2003 or higher, is calculated as
 * 14 days minus a random percentage of 5 days", but we aren't doing
 * that. The blogosphere seems to think that this randomised update
 * happens every time, but [MS-ADA1] doesn't agree.
 *
 * Dochelp referred us to the following blog post:
 * http://blogs.technet.com/b/askds/archive/2009/04/15/the-lastlogontimestamp-attribute-what-it-was-designed-for-and-how-it-works.aspx
 *
 * when msDS-LogonTimeSyncInterval is zero, the lastLogonTimestamp is
 * not changed.
 */

static NTSTATUS authsam_calculate_lastlogon_sync_interval(
	struct ldb_context *sam_ctx,
	TALLOC_CTX *ctx,
	struct ldb_dn *domain_dn,
	NTTIME *sync_interval_nt)
{
	static const char *attrs[] = { "msDS-LogonTimeSyncInterval",
					NULL };
	int ret;
	struct ldb_result *domain_res = NULL;
	TALLOC_CTX *mem_ctx = NULL;
	uint32_t sync_interval;

	mem_ctx = talloc_new(ctx);
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
	if (sync_interval >= 5){
		/*
		 * Subtract "a random percentage of 5" days. Presumably this
		 * percentage is between 0 and 100, and modulus is accurate
		 * enough.
		 */
		uint32_t r = generate_random() % 6;
		sync_interval -= r;
		DBG_INFO("randomised sync interval is %d (-%d)\n", sync_interval, r);
	}
	/* In the case where sync_interval < 5 there is no randomisation */

	/*
	 * msDS-LogonTimeSyncInterval is an int32_t number of days,
	 * while lastLogonTimestamp (to be updated) is in the 64 bit
	 * 100ns NTTIME format so we must convert.
	 */
	*sync_interval_nt = sync_interval * 24LL * 3600LL * 10000000LL;
	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}


/*
 * We only set lastLogonTimestamp if the current value is older than
 * now - msDS-LogonTimeSyncInterval days.
 *
 * lastLogonTimestamp is in the 64 bit 100ns NTTIME format
 */
static NTSTATUS authsam_update_lastlogon_timestamp(struct ldb_context *sam_ctx,
						   struct ldb_message *msg_mod,
						   struct ldb_dn *domain_dn,
						   NTTIME old_timestamp,
						   NTTIME now,
						   NTTIME sync_interval_nt)
{
	int ret;
	DEBUG(5, ("old timestamp is %lld, threshold %lld, diff %lld\n",
		  (long long int)old_timestamp,
		  (long long int)(now - sync_interval_nt),
		  (long long int)(old_timestamp - now + sync_interval_nt)));

	if (sync_interval_nt == 0){
		/*
		 * Setting msDS-LogonTimeSyncInterval to zero is how you ask
		 * that nothing happens here.
		 */
		return NT_STATUS_OK;
	}
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
			return NT_STATUS_NO_MEMORY;
		}
	}
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
	char *account_name_encoded = NULL;

	account_name_encoded = ldb_binary_encode_string(mem_ctx, account_name);
	if (account_name_encoded == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* pull the user attributes */
	ret = dsdb_search_one(sam_ctx, mem_ctx, ret_msg, domain_dn, LDB_SCOPE_SUBTREE,
			      user_attrs,
			      DSDB_SEARCH_SHOW_EXTENDED_DN | DSDB_SEARCH_UPDATE_MANAGED_PASSWORDS,
			      "(&(sAMAccountName=%s)(objectclass=user))",
			      account_name_encoded);
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		DEBUG(3,("authsam_search_account: Couldn't find user [%s] in samdb, under %s\n",
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
					  TALLOC_CTX *send_to_sam_mem_ctx,
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
	int64_t lockOutObservationWindow;
	NTTIME sync_interval_nt = 0;
	bool am_rodc = false;
	bool txn_active = false;
	bool need_db_reread = false;

	mem_ctx = talloc_new(msg);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Any update of the last logon data, needs to be done inside a
	 * transaction.
	 * And the user data needs to be re-read, and the account re-checked
	 * for lockout.
	 *
	 * However we have long-running transactions like replication
	 * that could otherwise grind the system to a halt so we first
	 * determine if *this* account has seen a bad password,
	 * otherwise we only start a transaction if there was a need
	 * (because a change was to be made).
	 */

	status = authsam_check_bad_password_indicator(
		sam_ctx, mem_ctx, &need_db_reread, msg);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(mem_ctx);
		return status;
	}

	if (interactive_or_kerberos == false) {
		/*
		 * Avoid calculating this twice, it reads the PSO.  A
		 * race on this is unimportant.
		 */
		lockOutObservationWindow
			= samdb_result_msds_LockoutObservationWindow(
				sam_ctx, mem_ctx, domain_dn, msg);
	}

	ret = samdb_rodc(sam_ctx, &am_rodc);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto error;
	}

	if (!am_rodc) {
		/*
		 * Avoid reading the main domain DN twice.  A race on
		 * this is unimportant.
		 */
		status = authsam_calculate_lastlogon_sync_interval(
			sam_ctx, mem_ctx, domain_dn, &sync_interval_nt);

		if (!NT_STATUS_IS_OK(status)) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}
	}

get_transaction:

	if (need_db_reread) {
		struct ldb_message *current = NULL;

		/*
		 * Start a new transaction
		 */
		ret = ldb_transaction_start(sam_ctx);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}

		txn_active = true;

		/*
		 * Re-read the account details, using the GUID
		 * embedded in DN so this is safe against a race where
		 * it is being renamed.
		 */
		status = authsam_reread_user_logon_data(
			sam_ctx, mem_ctx, msg, &current);
		if (!NT_STATUS_IS_OK(status)) {
			/*
			 * The re-read can return account locked out, as well
			 * as an internal error
			 */
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCOUNT_LOCKED_OUT)) {
				/*
				 * For NT_STATUS_ACCOUNT_LOCKED_OUT we want to commit
				 * the transaction. Again to avoid cluttering the
				 * audit logs with spurious errors
				 */
				goto exit;
			}
			goto error;
		}
		msg = current;
	}

	lockoutTime = ldb_msg_find_attr_as_int64(msg, "lockoutTime", 0);
	dbBadPwdCount = ldb_msg_find_attr_as_int(msg, "badPwdCount", 0);
	tv_now = timeval_current();
	now = timeval_to_nttime(&tv_now);

	if (interactive_or_kerberos) {
		badPwdCount = dbBadPwdCount;
	} else {
		/*
		 * We get lockOutObservationWindow above, before the
		 * transaction
		 */
		badPwdCount = dsdb_effective_badPwdCount(
			msg, lockOutObservationWindow, now);
	}
	lastLogonTimestamp =
		ldb_msg_find_attr_as_int64(msg, "lastLogonTimestamp", 0);

	DEBUG(5, ("lastLogonTimestamp is %lld\n",
		  (long long int)lastLogonTimestamp));

	msg_mod = ldb_msg_new(mem_ctx);
	if (msg_mod == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto error;
	}

	/*
	 * By using the DN from msg->dn directly, we allow LDB to
	 * prefer the embedded GUID form, so this is actually quite
	 * safe even in the case where DN has been changed
	 */
	msg_mod->dn = msg->dn;

	if (lockoutTime != 0) {
		/*
		 * This implies "badPwdCount" = 0, see samldb_lockout_time()
		 */
		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod, "lockoutTime", 0);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
	} else if (badPwdCount != 0) {
		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod, "badPwdCount", 0);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
	}

	if (interactive_or_kerberos ||
	    (badPwdCount != 0 && lockoutTime == 0)) {
		ret = samdb_msg_add_int64(sam_ctx, msg_mod, msg_mod,
					  "lastLogon", now);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
	}

	if (interactive_or_kerberos) {
		int logonCount;

		logonCount = ldb_msg_find_attr_as_int(msg, "logonCount", 0);

		logonCount += 1;

		ret = samdb_msg_add_int(sam_ctx, msg_mod, msg_mod,
					"logonCount", logonCount);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
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

	if (!am_rodc) {
		status = authsam_update_lastlogon_timestamp(
			sam_ctx,
			msg_mod,
			domain_dn,
			lastLogonTimestamp,
			now,
			sync_interval_nt);
		if (!NT_STATUS_IS_OK(status)) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}
	} else {
		/* Perform the (async) SendToSAM calls for MS-SAMS */
		if (dbBadPwdCount != 0 && send_to_sam != NULL) {
			struct netr_SendToSamBase *base_msg;
			struct GUID guid = samdb_result_guid(msg, "objectGUID");

			base_msg = talloc_zero(send_to_sam_mem_ctx,
					       struct netr_SendToSamBase);
			if (base_msg == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto error;
			}

			base_msg->message_type = SendToSamResetBadPasswordCount;
			base_msg->message_size = 16;
			base_msg->message.reset_bad_password.guid = guid;
			*send_to_sam = base_msg;
		}
	}

	if (msg_mod->num_elements > 0) {
		unsigned int i;
		struct ldb_request *req;

		/*
		 * If it turns out we are going to update the DB, go
		 * back to the start, get a transaction and the
		 * current DB state and try again
		 */
		if (txn_active == false) {
			need_db_reread = true;
			goto get_transaction;
		}

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
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}

		ret = ldb_request_add_control(req,
					      DSDB_CONTROL_FORCE_RODC_LOCAL_CHANGE,
					      false, NULL);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(req);
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}
		/*
		 * As we're in a transaction, make the ldb request directly
		 * to avoid the nested transaction that would result if we
		 * called dsdb_autotransaction_request
		 */
		ret = ldb_request(sam_ctx, req);
		if (ret == LDB_SUCCESS) {
			ret = ldb_wait(req->handle, LDB_WAIT_ALL);
		}
		TALLOC_FREE(req);
		if (ret != LDB_SUCCESS) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto error;
		}
	}
	status = authsam_clear_bad_password_indicator(sam_ctx, mem_ctx, msg);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	/*
	 * Note that we may not have updated the user record, but
	 * committing the transaction in that case is still the correct
	 * thing to do.
	 * If the transaction was cancelled, this would be logged by
	 * the dsdb audit log as a failure. When in fact it is expected
	 * behaviour.
	 *
	 * Thankfully both TDB and LMDB seem to optimise for the empty
	 * transaction case
	 */
exit:
	TALLOC_FREE(mem_ctx);

	if (txn_active == false) {
		return status;
	}

	ret = ldb_transaction_commit(sam_ctx);
	if (ret != LDB_SUCCESS) {
		DBG_ERR("Error (%d) %s, committing transaction,"
			" while updating successful logon accounting"
			" for (%s)\n",
			ret,
			ldb_errstring(sam_ctx),
			ldb_dn_get_linearized(msg->dn));
		return NT_STATUS_INTERNAL_ERROR;
	}
	return status;

error:
	DBG_ERR("Failed to update badPwdCount, badPasswordTime or "
		"set lockoutTime on %s: %s\n",
		ldb_dn_get_linearized(msg->dn),
		ldb_errstring(sam_ctx) != NULL ?
			ldb_errstring(sam_ctx) :nt_errstr(status));
	if (txn_active) {
		ret = ldb_transaction_cancel(sam_ctx);
		if (ret != LDB_SUCCESS) {
			DBG_ERR("Error rolling back transaction,"
				" while updating bad password count"
				" on %s: %s\n",
				ldb_dn_get_linearized(msg->dn),
				ldb_errstring(sam_ctx));
		}
	}
	TALLOC_FREE(mem_ctx);
	return status;
}
