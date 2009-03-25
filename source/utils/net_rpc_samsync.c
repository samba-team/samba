/*
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Tim Potter 2001,2002
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2005
   Modified by Volker Lendecke 2002
   Copyright (C) Jeremy Allison 2005.
   Copyright (C) Guenther Deschner 2008.

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
#include "utils/net.h"

/* uid's and gid's for writing deltas to ldif */
static uint32 ldif_gid = 999;
static uint32 ldif_uid = 999;
/* Keep track of ldap initialization */
static int init_ldap = 1;

static void display_group_mem_info(uint32_t rid,
				   struct netr_DELTA_GROUP_MEMBER *r)
{
	int i;
	d_printf("Group mem %u: ", rid);
	for (i=0; i< r->num_rids; i++) {
		d_printf("%u ", r->rids[i]);
	}
	d_printf("\n");
}

static void display_alias_info(uint32_t rid,
			       struct netr_DELTA_ALIAS *r)
{
	d_printf("Alias '%s' ", r->alias_name.string);
	d_printf("desc='%s' rid=%u\n", r->description.string, r->rid);
}

static void display_alias_mem(uint32_t rid,
			      struct netr_DELTA_ALIAS_MEMBER *r)
{
	int i;
	d_printf("Alias rid %u: ", rid);
	for (i=0; i< r->sids.num_sids; i++) {
		d_printf("%s ", sid_string_tos(r->sids.sids[i].sid));
	}
	d_printf("\n");
}

static void display_account_info(uint32_t rid,
				 struct netr_DELTA_USER *r)
{
	fstring hex_nt_passwd, hex_lm_passwd;
	uchar zero_buf[16];

	memset(zero_buf, '\0', sizeof(zero_buf));
	/* Decode hashes from password hash (if they are not NULL) */

	if (memcmp(r->lmpassword.hash, zero_buf, 16) != 0) {
		pdb_sethexpwd(hex_lm_passwd, r->lmpassword.hash, r->acct_flags);
	} else {
		pdb_sethexpwd(hex_lm_passwd, NULL, 0);
	}

	if (memcmp(r->ntpassword.hash, zero_buf, 16) != 0) {
		pdb_sethexpwd(hex_nt_passwd, r->ntpassword.hash, r->acct_flags);
	} else {
		pdb_sethexpwd(hex_nt_passwd, NULL, 0);
	}

	printf("%s:%d:%s:%s:%s:LCT-0\n",
		r->account_name.string,
		r->rid, hex_lm_passwd, hex_nt_passwd,
		pdb_encode_acct_ctrl(r->acct_flags, NEW_PW_FORMAT_SPACE_PADDED_LEN));
}

static time_t uint64s_nt_time_to_unix_abs(const uint64 *src)
{
	NTTIME nttime;
	nttime = *src;
	return nt_time_to_unix_abs(&nttime);
}

static NTSTATUS pull_netr_AcctLockStr(TALLOC_CTX *mem_ctx,
				      struct lsa_BinaryString *r,
				      struct netr_AcctLockStr **str_p)
{
	struct netr_AcctLockStr *str;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	if (!mem_ctx || !r || !str_p) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*str_p = NULL;

	str = TALLOC_ZERO_P(mem_ctx, struct netr_AcctLockStr);
	if (!str) {
		return NT_STATUS_NO_MEMORY;
	}

	blob = data_blob_const(r->array, r->length);

	ndr_err = ndr_pull_struct_blob(&blob, mem_ctx, str,
		       (ndr_pull_flags_fn_t)ndr_pull_netr_AcctLockStr);
	data_blob_free(&blob);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return ndr_map_error2ntstatus(ndr_err);
	}

	*str_p = str;

	return NT_STATUS_OK;
}

static void display_domain_info(struct netr_DELTA_DOMAIN *r)
{
	time_t u_logout;
	struct netr_AcctLockStr *lockstr = NULL;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_tos();

	status = pull_netr_AcctLockStr(mem_ctx, &r->account_lockout,
				       &lockstr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to pull account lockout string: %s\n",
			nt_errstr(status));
	}

	u_logout = uint64s_nt_time_to_unix_abs((const uint64 *)&r->force_logoff_time);

	d_printf("Domain name: %s\n", r->domain_name.string);

	d_printf("Minimal Password Length: %d\n", r->min_password_length);
	d_printf("Password History Length: %d\n", r->password_history_length);

	d_printf("Force Logoff: %d\n", (int)u_logout);

	d_printf("Max Password Age: %s\n", display_time(r->max_password_age));
	d_printf("Min Password Age: %s\n", display_time(r->min_password_age));

	if (lockstr) {
		d_printf("Lockout Time: %s\n", display_time((NTTIME)lockstr->lockout_duration));
		d_printf("Lockout Reset Time: %s\n", display_time((NTTIME)lockstr->reset_count));
		d_printf("Bad Attempt Lockout: %d\n", lockstr->bad_attempt_lockout);
	}

	d_printf("User must logon to change password: %d\n", r->logon_to_chgpass);
}

static void display_group_info(uint32_t rid, struct netr_DELTA_GROUP *r)
{
	d_printf("Group '%s' ", r->group_name.string);
	d_printf("desc='%s', rid=%u\n", r->description.string, rid);
}

static void display_sam_entry(struct netr_DELTA_ENUM *r)
{
	union netr_DELTA_UNION u = r->delta_union;
	union netr_DELTA_ID_UNION id = r->delta_id_union;

	switch (r->delta_type) {
	case NETR_DELTA_DOMAIN:
		display_domain_info(u.domain);
		break;
	case NETR_DELTA_GROUP:
		display_group_info(id.rid, u.group);
		break;
#if 0
	case NETR_DELTA_DELETE_GROUP:
		printf("Delete Group: %d\n",
			u.delete_account.unknown);
		break;
	case NETR_DELTA_RENAME_GROUP:
		printf("Rename Group: %s -> %s\n",
			u.rename_group->OldName.string,
			u.rename_group->NewName.string);
		break;
#endif
	case NETR_DELTA_USER:
		display_account_info(id.rid, u.user);
		break;
#if 0
	case NETR_DELTA_DELETE_USER:
		printf("Delete User: %d\n",
			id.rid);
		break;
	case NETR_DELTA_RENAME_USER:
		printf("Rename user: %s -> %s\n",
			u.rename_user->OldName.string,
			u.rename_user->NewName.string);
		break;
#endif
	case NETR_DELTA_GROUP_MEMBER:
		display_group_mem_info(id.rid, u.group_member);
		break;
	case NETR_DELTA_ALIAS:
		display_alias_info(id.rid, u.alias);
		break;
#if 0
	case NETR_DELTA_DELETE_ALIAS:
		printf("Delete Alias: %d\n",
			id.rid);
		break;
	case NETR_DELTA_RENAME_ALIAS:
		printf("Rename alias: %s -> %s\n",
			u.rename_alias->OldName.string,
			u.rename_alias->NewName.string);
		break;
#endif
	case NETR_DELTA_ALIAS_MEMBER:
		display_alias_mem(id.rid, u.alias_member);
		break;
#if 0
	case NETR_DELTA_POLICY:
		printf("Policy\n");
		break;
	case NETR_DELTA_TRUSTED_DOMAIN:
		printf("Trusted Domain: %s\n",
			u.trusted_domain->domain_name.string);
		break;
	case NETR_DELTA_DELETE_TRUST:
		printf("Delete Trust: %d\n",
			u.delete_trust.unknown);
		break;
	case NETR_DELTA_ACCOUNT:
		printf("Account\n");
		break;
	case NETR_DELTA_DELETE_ACCOUNT:
		printf("Delete Account: %d\n",
			u.delete_account.unknown);
		break;
	case NETR_DELTA_SECRET:
		printf("Secret\n");
		break;
	case NETR_DELTA_DELETE_SECRET:
		printf("Delete Secret: %d\n",
			u.delete_secret.unknown);
		break;
	case NETR_DELTA_DELETE_GROUP2:
		printf("Delete Group2: %s\n",
			u.delete_group->account_name);
		break;
	case NETR_DELTA_DELETE_USER2:
		printf("Delete User2: %s\n",
			u.delete_user->account_name);
		break;
	case NETR_DELTA_MODIFY_COUNT:
		printf("sam sequence update: 0x%016llx\n",
			(unsigned long long) *u.modified_count);
		break;
#endif
	/* The following types are recognised but not handled */
	case NETR_DELTA_RENAME_GROUP:
		d_printf("NETR_DELTA_RENAME_GROUP not handled\n");
		break;
	case NETR_DELTA_RENAME_USER:
		d_printf("NETR_DELTA_RENAME_USER not handled\n");
		break;
	case NETR_DELTA_RENAME_ALIAS:
		d_printf("NETR_DELTA_RENAME_ALIAS not handled\n");
		break;
	case NETR_DELTA_POLICY:
		d_printf("NETR_DELTA_POLICY not handled\n");
		break;
	case NETR_DELTA_TRUSTED_DOMAIN:
		d_printf("NETR_DELTA_TRUSTED_DOMAIN not handled\n");
		break;
	case NETR_DELTA_ACCOUNT:
		d_printf("NETR_DELTA_ACCOUNT not handled\n");
		break;
	case NETR_DELTA_SECRET:
		d_printf("NETR_DELTA_SECRET not handled\n");
		break;
	case NETR_DELTA_DELETE_GROUP:
		d_printf("NETR_DELTA_DELETE_GROUP not handled\n");
		break;
	case NETR_DELTA_DELETE_USER:
		d_printf("NETR_DELTA_DELETE_USER not handled\n");
		break;
	case NETR_DELTA_MODIFY_COUNT:
		d_printf("NETR_DELTA_MODIFY_COUNT not handled\n");
		break;
	case NETR_DELTA_DELETE_ALIAS:
		d_printf("NETR_DELTA_DELETE_ALIAS not handled\n");
		break;
	case NETR_DELTA_DELETE_TRUST:
		d_printf("NETR_DELTA_DELETE_TRUST not handled\n");
		break;
	case NETR_DELTA_DELETE_ACCOUNT:
		d_printf("NETR_DELTA_DELETE_ACCOUNT not handled\n");
		break;
	case NETR_DELTA_DELETE_SECRET:
		d_printf("NETR_DELTA_DELETE_SECRET not handled\n");
		break;
	case NETR_DELTA_DELETE_GROUP2:
		d_printf("NETR_DELTA_DELETE_GROUP2 not handled\n");
		break;
	case NETR_DELTA_DELETE_USER2:
		d_printf("NETR_DELTA_DELETE_USER2 not handled\n");
		break;
	default:
		printf("unknown delta type 0x%02x\n",
			r->delta_type);
		break;
	}
}

static void dump_database(struct rpc_pipe_client *pipe_hnd,
			  enum netr_SamDatabaseID database_id)
{
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
	const char *logon_server = pipe_hnd->cli->desthost;
	const char *computername = global_myname();
	struct netr_Authenticator credential;
	struct netr_Authenticator return_authenticator;
	uint16_t restart_state = 0;
	uint32_t sync_context = 0;
	DATA_BLOB session_key;

	ZERO_STRUCT(return_authenticator);

	if (!(mem_ctx = talloc_init("dump_database"))) {
		return;
	}

	switch(database_id) {
	case SAM_DATABASE_DOMAIN:
		d_printf("Dumping DOMAIN database\n");
		break;
	case SAM_DATABASE_BUILTIN:
		d_printf("Dumping BUILTIN database\n");
		break;
	case SAM_DATABASE_PRIVS:
		d_printf("Dumping PRIVS databases\n");
		break;
	default:
		d_printf("Dumping unknown database type %u\n",
			database_id);
		break;
	}

	do {
		struct netr_DELTA_ENUM_ARRAY *delta_enum_array = NULL;

		netlogon_creds_client_step(pipe_hnd->dc, &credential);

		result = rpccli_netr_DatabaseSync2(pipe_hnd, mem_ctx,
						   logon_server,
						   computername,
						   &credential,
						   &return_authenticator,
						   database_id,
						   restart_state,
						   &sync_context,
						   &delta_enum_array,
						   0xffff);

		/* Check returned credentials. */
		if (!netlogon_creds_client_check(pipe_hnd->dc,
						 &return_authenticator.cred)) {
			DEBUG(0,("credentials chain check failed\n"));
			return;
		}

		if (NT_STATUS_IS_ERR(result)) {
			break;
		}

		session_key = data_blob_const(pipe_hnd->dc->sess_key, 16);

		samsync_fix_delta_array(mem_ctx,
					&session_key,
					database_id,
					delta_enum_array);

		/* Display results */
		for (i = 0; i < delta_enum_array->num_deltas; i++) {
			display_sam_entry(&delta_enum_array->delta_enum[i]);
                }

		TALLOC_FREE(delta_enum_array);

	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);
}

/* dump sam database via samsync rpc calls */
NTSTATUS rpc_samdump_internals(const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
#if 0
	/* net_rpc.c now always tries to create an schannel pipe.. */

	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	uchar trust_password[16];
	uint32_t neg_flags = NETLOGON_NEG_AUTH2_ADS_FLAGS;
	uint32 sec_channel_type = 0;

	if (!secrets_fetch_trust_account_password(domain_name,
						  trust_password,
						  NULL, &sec_channel_type)) {
		DEBUG(0,("Could not fetch trust account password\n"));
		goto fail;
	}

	nt_status = rpccli_netlogon_setup_creds(pipe_hnd,
						cli->desthost,
						domain_name,
                                                global_myname(),
                                                trust_password,
                                                sec_channel_type,
                                                &neg_flags);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0,("Error connecting to NETLOGON pipe\n"));
		goto fail;
	}
#endif

	dump_database(pipe_hnd, SAM_DATABASE_DOMAIN);
	dump_database(pipe_hnd, SAM_DATABASE_BUILTIN);
	dump_database(pipe_hnd, SAM_DATABASE_PRIVS);

	return NT_STATUS_OK;
}

/* Convert a struct samu_DELTA to a struct samu. */
#define STRING_CHANGED (old_string && !new_string) ||\
		    (!old_string && new_string) ||\
		(old_string && new_string && (strcmp(old_string, new_string) != 0))

#define STRING_CHANGED_NC(s1,s2) ((s1) && !(s2)) ||\
		    (!(s1) && (s2)) ||\
		((s1) && (s2) && (strcmp((s1), (s2)) != 0))

static NTSTATUS sam_account_from_delta(struct samu *account,
				       struct netr_DELTA_USER *r)
{
	const char *old_string, *new_string;
	time_t unix_time, stored_time;
	uchar zero_buf[16];

	memset(zero_buf, '\0', sizeof(zero_buf));

	/* Username, fullname, home dir, dir drive, logon script, acct
	   desc, workstations, profile. */

	if (r->account_name.string) {
		old_string = pdb_get_nt_username(account);
		new_string = r->account_name.string;

		if (STRING_CHANGED) {
			pdb_set_nt_username(account, new_string, PDB_CHANGED);
		}

		/* Unix username is the same - for sanity */
		old_string = pdb_get_username( account );
		if (STRING_CHANGED) {
			pdb_set_username(account, new_string, PDB_CHANGED);
		}
	}

	if (r->full_name.string) {
		old_string = pdb_get_fullname(account);
		new_string = r->full_name.string;

		if (STRING_CHANGED)
			pdb_set_fullname(account, new_string, PDB_CHANGED);
	}

	if (r->home_directory.string) {
		old_string = pdb_get_homedir(account);
		new_string = r->home_directory.string;

		if (STRING_CHANGED)
			pdb_set_homedir(account, new_string, PDB_CHANGED);
	}

	if (r->home_drive.string) {
		old_string = pdb_get_dir_drive(account);
		new_string = r->home_drive.string;

		if (STRING_CHANGED)
			pdb_set_dir_drive(account, new_string, PDB_CHANGED);
	}

	if (r->logon_script.string) {
		old_string = pdb_get_logon_script(account);
		new_string = r->logon_script.string;

		if (STRING_CHANGED)
			pdb_set_logon_script(account, new_string, PDB_CHANGED);
	}

	if (r->description.string) {
		old_string = pdb_get_acct_desc(account);
		new_string = r->description.string;

		if (STRING_CHANGED)
			pdb_set_acct_desc(account, new_string, PDB_CHANGED);
	}

	if (r->workstations.string) {
		old_string = pdb_get_workstations(account);
		new_string = r->workstations.string;

		if (STRING_CHANGED)
			pdb_set_workstations(account, new_string, PDB_CHANGED);
	}

	if (r->profile_path.string) {
		old_string = pdb_get_profile_path(account);
		new_string = r->profile_path.string;

		if (STRING_CHANGED)
			pdb_set_profile_path(account, new_string, PDB_CHANGED);
	}

	if (r->parameters.string) {
		DATA_BLOB mung;
		char *newstr;
		old_string = pdb_get_munged_dial(account);
		mung.length = r->parameters.length;
		mung.data = (uint8 *) r->parameters.string;
		newstr = (mung.length == 0) ? NULL :
			base64_encode_data_blob(talloc_tos(), mung);

		if (STRING_CHANGED_NC(old_string, newstr))
			pdb_set_munged_dial(account, newstr, PDB_CHANGED);
		TALLOC_FREE(newstr);
	}

	/* User and group sid */
	if (pdb_get_user_rid(account) != r->rid)
		pdb_set_user_sid_from_rid(account, r->rid, PDB_CHANGED);
	if (pdb_get_group_rid(account) != r->primary_gid)
		pdb_set_group_sid_from_rid(account, r->primary_gid, PDB_CHANGED);

	/* Logon and password information */
	if (!nt_time_is_zero(&r->last_logon)) {
		unix_time = nt_time_to_unix(r->last_logon);
		stored_time = pdb_get_logon_time(account);
		if (stored_time != unix_time)
			pdb_set_logon_time(account, unix_time, PDB_CHANGED);
	}

	if (!nt_time_is_zero(&r->last_logoff)) {
		unix_time = nt_time_to_unix(r->last_logoff);
		stored_time = pdb_get_logoff_time(account);
		if (stored_time != unix_time)
			pdb_set_logoff_time(account, unix_time,PDB_CHANGED);
	}

	/* Logon Divs */
	if (pdb_get_logon_divs(account) != r->logon_hours.units_per_week)
		pdb_set_logon_divs(account, r->logon_hours.units_per_week, PDB_CHANGED);

#if 0
	/* no idea what to do with this one - gd */
	/* Max Logon Hours */
	if (delta->unknown1 != pdb_get_unknown_6(account)) {
		pdb_set_unknown_6(account, delta->unknown1, PDB_CHANGED);
	}
#endif
	/* Logon Hours Len */
	if (r->logon_hours.units_per_week/8 != pdb_get_hours_len(account)) {
		pdb_set_hours_len(account, r->logon_hours.units_per_week/8, PDB_CHANGED);
	}

	/* Logon Hours */
	if (r->logon_hours.bits) {
		char oldstr[44], newstr[44];
		pdb_sethexhours(oldstr, pdb_get_hours(account));
		pdb_sethexhours(newstr, r->logon_hours.bits);
		if (!strequal(oldstr, newstr))
			pdb_set_hours(account, r->logon_hours.bits, PDB_CHANGED);
	}

	if (pdb_get_bad_password_count(account) != r->bad_password_count)
		pdb_set_bad_password_count(account, r->bad_password_count, PDB_CHANGED);

	if (pdb_get_logon_count(account) != r->logon_count)
		pdb_set_logon_count(account, r->logon_count, PDB_CHANGED);

	if (!nt_time_is_zero(&r->last_password_change)) {
		unix_time = nt_time_to_unix(r->last_password_change);
		stored_time = pdb_get_pass_last_set_time(account);
		if (stored_time != unix_time)
			pdb_set_pass_last_set_time(account, unix_time, PDB_CHANGED);
	} else {
		/* no last set time, make it now */
		pdb_set_pass_last_set_time(account, time(NULL), PDB_CHANGED);
	}

	if (!nt_time_is_zero(&r->acct_expiry)) {
		unix_time = nt_time_to_unix(r->acct_expiry);
		stored_time = pdb_get_kickoff_time(account);
		if (stored_time != unix_time)
			pdb_set_kickoff_time(account, unix_time, PDB_CHANGED);
	}

	/* Decode hashes from password hash
	   Note that win2000 may send us all zeros for the hashes if it doesn't
	   think this channel is secure enough - don't set the passwords at all
	   in that case
	*/
	if (memcmp(r->lmpassword.hash, zero_buf, 16) != 0) {
		pdb_set_lanman_passwd(account, r->lmpassword.hash, PDB_CHANGED);
	}

	if (memcmp(r->ntpassword.hash, zero_buf, 16) != 0) {
		pdb_set_nt_passwd(account, r->ntpassword.hash, PDB_CHANGED);
	}

	/* TODO: account expiry time */

	pdb_set_acct_ctrl(account, r->acct_flags, PDB_CHANGED);

	pdb_set_domain(account, lp_workgroup(), PDB_CHANGED);

	return NT_STATUS_OK;
}

static NTSTATUS fetch_account_info(uint32_t rid,
				   struct netr_DELTA_USER *r)
{

	NTSTATUS nt_ret = NT_STATUS_UNSUCCESSFUL;
	fstring account;
	char *add_script = NULL;
	struct samu *sam_account=NULL;
	GROUP_MAP map;
	struct group *grp;
	DOM_SID user_sid;
	DOM_SID group_sid;
	struct passwd *passwd;
	fstring sid_string;

	fstrcpy(account, r->account_name.string);
	d_printf("Creating account: %s\n", account);

	if ( !(sam_account = samu_new( NULL )) ) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!(passwd = Get_Pwnam_alloc(sam_account, account))) {
		/* Create appropriate user */
		if (r->acct_flags & ACB_NORMAL) {
			add_script = talloc_strdup(sam_account,
					lp_adduser_script());
		} else if ( (r->acct_flags & ACB_WSTRUST) ||
			    (r->acct_flags & ACB_SVRTRUST) ||
			    (r->acct_flags & ACB_DOMTRUST) ) {
			add_script = talloc_strdup(sam_account,
					lp_addmachine_script());
		} else {
			DEBUG(1, ("Unknown user type: %s\n",
				  pdb_encode_acct_ctrl(r->acct_flags, NEW_PW_FORMAT_SPACE_PADDED_LEN)));
			nt_ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		if (!add_script) {
			nt_ret = NT_STATUS_NO_MEMORY;
			goto done;
		}
		if (*add_script) {
			int add_ret;
			add_script = talloc_all_string_sub(sam_account,
					add_script,
					"%u",
					account);
			if (!add_script) {
				nt_ret = NT_STATUS_NO_MEMORY;
				goto done;
			}
			add_ret = smbrun(add_script,NULL);
			DEBUG(add_ret ? 0 : 1,("fetch_account: Running the command `%s' "
				 "gave %d\n", add_script, add_ret));
			if (add_ret == 0) {
				smb_nscd_flush_user_cache();
			}
		}

		/* try and find the possible unix account again */
		if ( !(passwd = Get_Pwnam_alloc(sam_account, account)) ) {
			d_fprintf(stderr, "Could not create posix account info for '%s'\n", account);
			nt_ret = NT_STATUS_NO_SUCH_USER;
			goto done;
		}
	}

	sid_copy(&user_sid, get_global_sam_sid());
	sid_append_rid(&user_sid, r->rid);

	DEBUG(3, ("Attempting to find SID %s for user %s in the passdb\n",
		  sid_to_fstring(sid_string, &user_sid), account));
	if (!pdb_getsampwsid(sam_account, &user_sid)) {
		sam_account_from_delta(sam_account, r);
		DEBUG(3, ("Attempting to add user SID %s for user %s in the passdb\n",
			  sid_to_fstring(sid_string, &user_sid),
			  pdb_get_username(sam_account)));
		if (!NT_STATUS_IS_OK(pdb_add_sam_account(sam_account))) {
			DEBUG(1, ("SAM Account for %s failed to be added to the passdb!\n",
				  account));
			return NT_STATUS_ACCESS_DENIED;
		}
	} else {
		sam_account_from_delta(sam_account, r);
		DEBUG(3, ("Attempting to update user SID %s for user %s in the passdb\n",
			  sid_to_fstring(sid_string, &user_sid),
			  pdb_get_username(sam_account)));
		if (!NT_STATUS_IS_OK(pdb_update_sam_account(sam_account))) {
			DEBUG(1, ("SAM Account for %s failed to be updated in the passdb!\n",
				  account));
			TALLOC_FREE(sam_account);
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (pdb_get_group_sid(sam_account) == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	group_sid = *pdb_get_group_sid(sam_account);

	if (!pdb_getgrsid(&map, group_sid)) {
		DEBUG(0, ("Primary group of %s has no mapping!\n",
			  pdb_get_username(sam_account)));
	} else {
		if (map.gid != passwd->pw_gid) {
			if (!(grp = getgrgid(map.gid))) {
				DEBUG(0, ("Could not find unix group %lu for user %s (group SID=%s)\n",
					  (unsigned long)map.gid, pdb_get_username(sam_account), sid_string_tos(&group_sid)));
			} else {
				smb_set_primary_group(grp->gr_name, pdb_get_username(sam_account));
			}
		}
	}

	if ( !passwd ) {
		DEBUG(1, ("No unix user for this account (%s), cannot adjust mappings\n",
			pdb_get_username(sam_account)));
	}

 done:
	TALLOC_FREE(sam_account);
	return nt_ret;
}

static NTSTATUS fetch_group_info(uint32_t rid,
				 struct netr_DELTA_GROUP *r)
{
	fstring name;
	fstring comment;
	struct group *grp = NULL;
	DOM_SID group_sid;
	fstring sid_string;
	GROUP_MAP map;
	bool insert = True;

	fstrcpy(name, r->group_name.string);
	fstrcpy(comment, r->description.string);

	/* add the group to the mapping table */
	sid_copy(&group_sid, get_global_sam_sid());
	sid_append_rid(&group_sid, rid);
	sid_to_fstring(sid_string, &group_sid);

	if (pdb_getgrsid(&map, group_sid)) {
		if ( map.gid != -1 )
			grp = getgrgid(map.gid);
		insert = False;
	}

	if (grp == NULL) {
		gid_t gid;

		/* No group found from mapping, find it from its name. */
		if ((grp = getgrnam(name)) == NULL) {

			/* No appropriate group found, create one */

			d_printf("Creating unix group: '%s'\n", name);

			if (smb_create_group(name, &gid) != 0)
				return NT_STATUS_ACCESS_DENIED;

			if ((grp = getgrnam(name)) == NULL)
				return NT_STATUS_ACCESS_DENIED;
		}
	}

	map.gid = grp->gr_gid;
	map.sid = group_sid;
	map.sid_name_use = SID_NAME_DOM_GRP;
	fstrcpy(map.nt_name, name);
	if (r->description.string) {
		fstrcpy(map.comment, comment);
	} else {
		fstrcpy(map.comment, "");
	}

	if (insert)
		pdb_add_group_mapping_entry(&map);
	else
		pdb_update_group_mapping_entry(&map);

	return NT_STATUS_OK;
}

static NTSTATUS fetch_group_mem_info(uint32_t rid,
				     struct netr_DELTA_GROUP_MEMBER *r)
{
	int i;
	TALLOC_CTX *t = NULL;
	char **nt_members = NULL;
	char **unix_members;
	DOM_SID group_sid;
	GROUP_MAP map;
	struct group *grp;

	if (r->num_rids == 0) {
		return NT_STATUS_OK;
	}

	sid_copy(&group_sid, get_global_sam_sid());
	sid_append_rid(&group_sid, rid);

	if (!get_domain_group_from_sid(group_sid, &map)) {
		DEBUG(0, ("Could not find global group %d\n", rid));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	if (!(grp = getgrgid(map.gid))) {
		DEBUG(0, ("Could not find unix group %lu\n", (unsigned long)map.gid));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	d_printf("Group members of %s: ", grp->gr_name);

	if (!(t = talloc_init("fetch_group_mem_info"))) {
		DEBUG(0, ("could not talloc_init\n"));
		return NT_STATUS_NO_MEMORY;
	}

	if (r->num_rids) {
		if ((nt_members = TALLOC_ZERO_ARRAY(t, char *, r->num_rids)) == NULL) {
			DEBUG(0, ("talloc failed\n"));
			talloc_free(t);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		nt_members = NULL;
	}

	for (i=0; i < r->num_rids; i++) {
		struct samu *member = NULL;
		DOM_SID member_sid;

		if ( !(member = samu_new(t)) ) {
			talloc_destroy(t);
			return NT_STATUS_NO_MEMORY;
		}

		sid_copy(&member_sid, get_global_sam_sid());
		sid_append_rid(&member_sid, r->rids[i]);

		if (!pdb_getsampwsid(member, &member_sid)) {
			DEBUG(1, ("Found bogus group member: %d (member_sid=%s group=%s)\n",
				  r->rids[i], sid_string_tos(&member_sid), grp->gr_name));
			TALLOC_FREE(member);
			continue;
		}

		if (pdb_get_group_rid(member) == rid) {
			d_printf("%s(primary),", pdb_get_username(member));
			TALLOC_FREE(member);
			continue;
		}

		d_printf("%s,", pdb_get_username(member));
		nt_members[i] = talloc_strdup(t, pdb_get_username(member));
		TALLOC_FREE(member);
	}

	d_printf("\n");

	unix_members = grp->gr_mem;

	while (*unix_members) {
		bool is_nt_member = False;
		for (i=0; i < r->num_rids; i++) {
			if (nt_members[i] == NULL) {
				/* This was a primary group */
				continue;
			}

			if (strcmp(*unix_members, nt_members[i]) == 0) {
				is_nt_member = True;
				break;
			}
		}
		if (!is_nt_member) {
			/* We look at a unix group member that is not
			   an nt group member. So, remove it. NT is
			   boss here. */
			smb_delete_user_group(grp->gr_name, *unix_members);
		}
		unix_members += 1;
	}

	for (i=0; i < r->num_rids; i++) {
		bool is_unix_member = False;

		if (nt_members[i] == NULL) {
			/* This was the primary group */
			continue;
		}

		unix_members = grp->gr_mem;

		while (*unix_members) {
			if (strcmp(*unix_members, nt_members[i]) == 0) {
				is_unix_member = True;
				break;
			}
			unix_members += 1;
		}

		if (!is_unix_member) {
			/* We look at a nt group member that is not a
                           unix group member currently. So, add the nt
                           group member. */
			smb_add_user_group(grp->gr_name, nt_members[i]);
		}
	}

	talloc_destroy(t);
	return NT_STATUS_OK;
}

static NTSTATUS fetch_alias_info(uint32_t rid,
				 struct netr_DELTA_ALIAS *r,
				 DOM_SID dom_sid)
{
	fstring name;
	fstring comment;
	struct group *grp = NULL;
	DOM_SID alias_sid;
	fstring sid_string;
	GROUP_MAP map;
	bool insert = True;

	fstrcpy(name, r->alias_name.string);
	fstrcpy(comment, r->description.string);

	/* Find out whether the group is already mapped */
	sid_copy(&alias_sid, &dom_sid);
	sid_append_rid(&alias_sid, rid);
	sid_to_fstring(sid_string, &alias_sid);

	if (pdb_getgrsid(&map, alias_sid)) {
		grp = getgrgid(map.gid);
		insert = False;
	}

	if (grp == NULL) {
		gid_t gid;

		/* No group found from mapping, find it from its name. */
		if ((grp = getgrnam(name)) == NULL) {
			/* No appropriate group found, create one */
			d_printf("Creating unix group: '%s'\n", name);
			if (smb_create_group(name, &gid) != 0)
				return NT_STATUS_ACCESS_DENIED;
			if ((grp = getgrgid(gid)) == NULL)
				return NT_STATUS_ACCESS_DENIED;
		}
	}

	map.gid = grp->gr_gid;
	map.sid = alias_sid;

	if (sid_equal(&dom_sid, &global_sid_Builtin))
		map.sid_name_use = SID_NAME_WKN_GRP;
	else
		map.sid_name_use = SID_NAME_ALIAS;

	fstrcpy(map.nt_name, name);
	fstrcpy(map.comment, comment);

	if (insert)
		pdb_add_group_mapping_entry(&map);
	else
		pdb_update_group_mapping_entry(&map);

	return NT_STATUS_OK;
}

static NTSTATUS fetch_alias_mem(uint32_t rid,
				struct netr_DELTA_ALIAS_MEMBER *r,
				DOM_SID dom_sid)
{
	return NT_STATUS_OK;
}

static NTSTATUS fetch_domain_info(uint32_t rid,
				  struct netr_DELTA_DOMAIN *r)
{
	time_t u_max_age, u_min_age, u_logout;
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	const char *domname;
	struct netr_AcctLockStr *lockstr = NULL;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_tos();

	status = pull_netr_AcctLockStr(mem_ctx, &r->account_lockout,
				       &lockstr);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("failed to pull account lockout string: %s\n",
			nt_errstr(status));
	}

	u_max_age = uint64s_nt_time_to_unix_abs((uint64 *)&r->max_password_age);
	u_min_age = uint64s_nt_time_to_unix_abs((uint64 *)&r->min_password_age);
	u_logout = uint64s_nt_time_to_unix_abs((uint64 *)&r->force_logoff_time);

	domname = r->domain_name.string;
	if (!domname) {
		return NT_STATUS_NO_MEMORY;
	}

	/* we don't handle BUILTIN account policies */
	if (!strequal(domname, get_global_sam_name())) {
		printf("skipping SAM_DOMAIN_INFO delta for '%s' (is not my domain)\n", domname);
		return NT_STATUS_OK;
	}


	if (!pdb_set_account_policy(AP_PASSWORD_HISTORY,
				    r->password_history_length))
		return nt_status;

	if (!pdb_set_account_policy(AP_MIN_PASSWORD_LEN,
				    r->min_password_length))
		return nt_status;

	if (!pdb_set_account_policy(AP_MAX_PASSWORD_AGE, (uint32)u_max_age))
		return nt_status;

	if (!pdb_set_account_policy(AP_MIN_PASSWORD_AGE, (uint32)u_min_age))
		return nt_status;

	if (!pdb_set_account_policy(AP_TIME_TO_LOGOUT, (uint32)u_logout))
		return nt_status;

	if (lockstr) {
		time_t u_lockoutreset, u_lockouttime;

		u_lockoutreset = uint64s_nt_time_to_unix_abs(&lockstr->reset_count);
		u_lockouttime = uint64s_nt_time_to_unix_abs((uint64_t *)&lockstr->lockout_duration);

		if (!pdb_set_account_policy(AP_BAD_ATTEMPT_LOCKOUT,
					    lockstr->bad_attempt_lockout))
			return nt_status;

		if (!pdb_set_account_policy(AP_RESET_COUNT_TIME, (uint32_t)u_lockoutreset/60))
			return nt_status;

		if (u_lockouttime != -1)
			u_lockouttime /= 60;

		if (!pdb_set_account_policy(AP_LOCK_ACCOUNT_DURATION, (uint32_t)u_lockouttime))
			return nt_status;
	}

	if (!pdb_set_account_policy(AP_USER_MUST_LOGON_TO_CHG_PASS,
				    r->logon_to_chgpass))
		return nt_status;

	return NT_STATUS_OK;
}

static void fetch_sam_entry(struct netr_DELTA_ENUM *r, DOM_SID dom_sid)
{
	switch(r->delta_type) {
	case NETR_DELTA_USER:
		fetch_account_info(r->delta_id_union.rid,
				   r->delta_union.user);
		break;
	case NETR_DELTA_GROUP:
		fetch_group_info(r->delta_id_union.rid,
				 r->delta_union.group);
		break;
	case NETR_DELTA_GROUP_MEMBER:
		fetch_group_mem_info(r->delta_id_union.rid,
				     r->delta_union.group_member);
		break;
	case NETR_DELTA_ALIAS:
		fetch_alias_info(r->delta_id_union.rid,
				 r->delta_union.alias,
				 dom_sid);
		break;
	case NETR_DELTA_ALIAS_MEMBER:
		fetch_alias_mem(r->delta_id_union.rid,
				r->delta_union.alias_member,
				dom_sid);
		break;
	case NETR_DELTA_DOMAIN:
		fetch_domain_info(r->delta_id_union.rid,
				  r->delta_union.domain);
		break;
	/* The following types are recognised but not handled */
	case NETR_DELTA_RENAME_GROUP:
		d_printf("NETR_DELTA_RENAME_GROUP not handled\n");
		break;
	case NETR_DELTA_RENAME_USER:
		d_printf("NETR_DELTA_RENAME_USER not handled\n");
		break;
	case NETR_DELTA_RENAME_ALIAS:
		d_printf("NETR_DELTA_RENAME_ALIAS not handled\n");
		break;
	case NETR_DELTA_POLICY:
		d_printf("NETR_DELTA_POLICY not handled\n");
		break;
	case NETR_DELTA_TRUSTED_DOMAIN:
		d_printf("NETR_DELTA_TRUSTED_DOMAIN not handled\n");
		break;
	case NETR_DELTA_ACCOUNT:
		d_printf("NETR_DELTA_ACCOUNT not handled\n");
		break;
	case NETR_DELTA_SECRET:
		d_printf("NETR_DELTA_SECRET not handled\n");
		break;
	case NETR_DELTA_DELETE_GROUP:
		d_printf("NETR_DELTA_DELETE_GROUP not handled\n");
		break;
	case NETR_DELTA_DELETE_USER:
		d_printf("NETR_DELTA_DELETE_USER not handled\n");
		break;
	case NETR_DELTA_MODIFY_COUNT:
		d_printf("NETR_DELTA_MODIFY_COUNT not handled\n");
		break;
	case NETR_DELTA_DELETE_ALIAS:
		d_printf("NETR_DELTA_DELETE_ALIAS not handled\n");
		break;
	case NETR_DELTA_DELETE_TRUST:
		d_printf("NETR_DELTA_DELETE_TRUST not handled\n");
		break;
	case NETR_DELTA_DELETE_ACCOUNT:
		d_printf("NETR_DELTA_DELETE_ACCOUNT not handled\n");
		break;
	case NETR_DELTA_DELETE_SECRET:
		d_printf("NETR_DELTA_DELETE_SECRET not handled\n");
		break;
	case NETR_DELTA_DELETE_GROUP2:
		d_printf("NETR_DELTA_DELETE_GROUP2 not handled\n");
		break;
	case NETR_DELTA_DELETE_USER2:
		d_printf("NETR_DELTA_DELETE_USER2 not handled\n");
		break;
	default:
		d_printf("Unknown delta record type %d\n", r->delta_type);
		break;
	}
}

static NTSTATUS fetch_database(struct rpc_pipe_client *pipe_hnd, uint32 db_type, DOM_SID dom_sid)
{
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
	const char *logon_server = pipe_hnd->cli->desthost;
	const char *computername = global_myname();
	struct netr_Authenticator credential;
	struct netr_Authenticator return_authenticator;
	enum netr_SamDatabaseID database_id = db_type;
	uint16_t restart_state = 0;
	uint32_t sync_context = 0;
	DATA_BLOB session_key;

	if (!(mem_ctx = talloc_init("fetch_database")))
		return NT_STATUS_NO_MEMORY;

	switch( db_type ) {
	case SAM_DATABASE_DOMAIN:
		d_printf("Fetching DOMAIN database\n");
		break;
	case SAM_DATABASE_BUILTIN:
		d_printf("Fetching BUILTIN database\n");
		break;
	case SAM_DATABASE_PRIVS:
		d_printf("Fetching PRIVS databases\n");
		break;
	default:
		d_printf("Fetching unknown database type %u\n", db_type );
		break;
	}

	do {
		struct netr_DELTA_ENUM_ARRAY *delta_enum_array = NULL;

		netlogon_creds_client_step(pipe_hnd->dc, &credential);

		result = rpccli_netr_DatabaseSync2(pipe_hnd, mem_ctx,
						   logon_server,
						   computername,
						   &credential,
						   &return_authenticator,
						   database_id,
						   restart_state,
						   &sync_context,
						   &delta_enum_array,
						   0xffff);

		/* Check returned credentials. */
		if (!netlogon_creds_client_check(pipe_hnd->dc,
						 &return_authenticator.cred)) {
			DEBUG(0,("credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		if (NT_STATUS_IS_ERR(result)) {
			break;
		}

		session_key = data_blob_const(pipe_hnd->dc->sess_key, 16);

		samsync_fix_delta_array(mem_ctx,
					&session_key,
					database_id,
					delta_enum_array);

		for (i = 0; i < delta_enum_array->num_deltas; i++) {
			fetch_sam_entry(&delta_enum_array->delta_enum[i], dom_sid);
		}

	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);

	return result;
}

static NTSTATUS populate_ldap_for_ldif(fstring sid, const char *suffix, const char
		       *builtin_sid, FILE *add_fd)
{
	const char *user_suffix, *group_suffix, *machine_suffix, *idmap_suffix;
	char *user_attr=NULL, *group_attr=NULL;
	char *suffix_attr;
	int len;

	/* Get the suffix attribute */
	suffix_attr = sstring_sub(suffix, '=', ',');
	if (suffix_attr == NULL) {
		len = strlen(suffix);
		suffix_attr = (char*)SMB_MALLOC(len+1);
		memcpy(suffix_attr, suffix, len);
		suffix_attr[len] = '\0';
	}

	/* Write the base */
	fprintf(add_fd, "# %s\n", suffix);
	fprintf(add_fd, "dn: %s\n", suffix);
	fprintf(add_fd, "objectClass: dcObject\n");
	fprintf(add_fd, "objectClass: organization\n");
	fprintf(add_fd, "o: %s\n", suffix_attr);
	fprintf(add_fd, "dc: %s\n", suffix_attr);
	fprintf(add_fd, "\n");
	fflush(add_fd);

	user_suffix = lp_ldap_user_suffix();
	if (user_suffix == NULL) {
		SAFE_FREE(suffix_attr);
		return NT_STATUS_NO_MEMORY;
	}
	/* If it exists and is distinct from other containers,
	   Write the Users entity */
	if (*user_suffix && strcmp(user_suffix, suffix)) {
		user_attr = sstring_sub(lp_ldap_user_suffix(), '=', ',');
		fprintf(add_fd, "# %s\n", user_suffix);
		fprintf(add_fd, "dn: %s\n", user_suffix);
		fprintf(add_fd, "objectClass: organizationalUnit\n");
		fprintf(add_fd, "ou: %s\n", user_attr);
		fprintf(add_fd, "\n");
		fflush(add_fd);
	}


	group_suffix = lp_ldap_group_suffix();
	if (group_suffix == NULL) {
		SAFE_FREE(suffix_attr);
		SAFE_FREE(user_attr);
		return NT_STATUS_NO_MEMORY;
	}
	/* If it exists and is distinct from other containers,
	   Write the Groups entity */
	if (*group_suffix && strcmp(group_suffix, suffix)) {
		group_attr = sstring_sub(lp_ldap_group_suffix(), '=', ',');
		fprintf(add_fd, "# %s\n", group_suffix);
		fprintf(add_fd, "dn: %s\n", group_suffix);
		fprintf(add_fd, "objectClass: organizationalUnit\n");
		fprintf(add_fd, "ou: %s\n", group_attr);
		fprintf(add_fd, "\n");
		fflush(add_fd);
	}

	/* If it exists and is distinct from other containers,
	   Write the Computers entity */
	machine_suffix = lp_ldap_machine_suffix();
	if (machine_suffix == NULL) {
		SAFE_FREE(suffix_attr);
		SAFE_FREE(user_attr);
		SAFE_FREE(group_attr);
		return NT_STATUS_NO_MEMORY;
	}
	if (*machine_suffix && strcmp(machine_suffix, user_suffix) &&
	    strcmp(machine_suffix, suffix)) {
		char *machine_ou = NULL;
		fprintf(add_fd, "# %s\n", machine_suffix);
		fprintf(add_fd, "dn: %s\n", machine_suffix);
		fprintf(add_fd, "objectClass: organizationalUnit\n");
		/* this isn't totally correct as it assumes that
		   there _must_ be an ou. just fixing memleak now. jmcd */
		machine_ou = sstring_sub(lp_ldap_machine_suffix(), '=', ',');
		fprintf(add_fd, "ou: %s\n", machine_ou);
		SAFE_FREE(machine_ou);
		fprintf(add_fd, "\n");
		fflush(add_fd);
	}

	/* If it exists and is distinct from other containers,
	   Write the IdMap entity */
	idmap_suffix = lp_ldap_idmap_suffix();
	if (idmap_suffix == NULL) {
		SAFE_FREE(suffix_attr);
		SAFE_FREE(user_attr);
		SAFE_FREE(group_attr);
		return NT_STATUS_NO_MEMORY;
	}
	if (*idmap_suffix &&
	    strcmp(idmap_suffix, user_suffix) &&
	    strcmp(idmap_suffix, suffix)) {
		char *s;
		fprintf(add_fd, "# %s\n", idmap_suffix);
		fprintf(add_fd, "dn: %s\n", idmap_suffix);
		fprintf(add_fd, "ObjectClass: organizationalUnit\n");
		s = sstring_sub(lp_ldap_idmap_suffix(), '=', ',');
		fprintf(add_fd, "ou: %s\n", s);
		SAFE_FREE(s);
		fprintf(add_fd, "\n");
		fflush(add_fd);
	}

	/* Write the domain entity */
	fprintf(add_fd, "# %s, %s\n", lp_workgroup(), suffix);
	fprintf(add_fd, "dn: sambaDomainName=%s,%s\n", lp_workgroup(),
		suffix);
	fprintf(add_fd, "objectClass: sambaDomain\n");
	fprintf(add_fd, "objectClass: sambaUnixIdPool\n");
	fprintf(add_fd, "sambaDomainName: %s\n", lp_workgroup());
	fprintf(add_fd, "sambaSID: %s\n", sid);
	fprintf(add_fd, "uidNumber: %d\n", ++ldif_uid);
	fprintf(add_fd, "gidNumber: %d\n", ++ldif_gid);
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Domain Admins entity */
	fprintf(add_fd, "# Domain Admins, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Domain Admins,ou=%s,%s\n", group_attr,
		suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "cn: Domain Admins\n");
	fprintf(add_fd, "memberUid: Administrator\n");
	fprintf(add_fd, "description: Netbios Domain Administrators\n");
	fprintf(add_fd, "gidNumber: 512\n");
	fprintf(add_fd, "sambaSID: %s-512\n", sid);
	fprintf(add_fd, "sambaGroupType: 2\n");
	fprintf(add_fd, "displayName: Domain Admins\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Domain Users entity */
	fprintf(add_fd, "# Domain Users, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Domain Users,ou=%s,%s\n", group_attr,
		suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "cn: Domain Users\n");
	fprintf(add_fd, "description: Netbios Domain Users\n");
	fprintf(add_fd, "gidNumber: 513\n");
	fprintf(add_fd, "sambaSID: %s-513\n", sid);
	fprintf(add_fd, "sambaGroupType: 2\n");
	fprintf(add_fd, "displayName: Domain Users\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Domain Guests entity */
	fprintf(add_fd, "# Domain Guests, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Domain Guests,ou=%s,%s\n", group_attr,
		suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "cn: Domain Guests\n");
	fprintf(add_fd, "description: Netbios Domain Guests\n");
	fprintf(add_fd, "gidNumber: 514\n");
	fprintf(add_fd, "sambaSID: %s-514\n", sid);
	fprintf(add_fd, "sambaGroupType: 2\n");
	fprintf(add_fd, "displayName: Domain Guests\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Domain Computers entity */
	fprintf(add_fd, "# Domain Computers, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Domain Computers,ou=%s,%s\n",
		group_attr, suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "gidNumber: 515\n");
	fprintf(add_fd, "cn: Domain Computers\n");
	fprintf(add_fd, "description: Netbios Domain Computers accounts\n");
	fprintf(add_fd, "sambaSID: %s-515\n", sid);
	fprintf(add_fd, "sambaGroupType: 2\n");
	fprintf(add_fd, "displayName: Domain Computers\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Admininistrators Groups entity */
	fprintf(add_fd, "# Administrators, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Administrators,ou=%s,%s\n", group_attr,
		suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "gidNumber: 544\n");
	fprintf(add_fd, "cn: Administrators\n");
	fprintf(add_fd, "description: Netbios Domain Members can fully administer the computer/sambaDomainName\n");
	fprintf(add_fd, "sambaSID: %s-544\n", builtin_sid);
	fprintf(add_fd, "sambaGroupType: 5\n");
	fprintf(add_fd, "displayName: Administrators\n");
	fprintf(add_fd, "\n");

	/* Write the Print Operator entity */
	fprintf(add_fd, "# Print Operators, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Print Operators,ou=%s,%s\n",
		group_attr, suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "gidNumber: 550\n");
	fprintf(add_fd, "cn: Print Operators\n");
	fprintf(add_fd, "description: Netbios Domain Print Operators\n");
	fprintf(add_fd, "sambaSID: %s-550\n", builtin_sid);
	fprintf(add_fd, "sambaGroupType: 5\n");
	fprintf(add_fd, "displayName: Print Operators\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Backup Operators entity */
	fprintf(add_fd, "# Backup Operators, %s, %s\n", group_attr,
		suffix);
	fprintf(add_fd, "dn: cn=Backup Operators,ou=%s,%s\n",
		group_attr, suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "gidNumber: 551\n");
	fprintf(add_fd, "cn: Backup Operators\n");
	fprintf(add_fd, "description: Netbios Domain Members can bypass file security to back up files\n");
	fprintf(add_fd, "sambaSID: %s-551\n", builtin_sid);
	fprintf(add_fd, "sambaGroupType: 5\n");
	fprintf(add_fd, "displayName: Backup Operators\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Write the Replicators entity */
	fprintf(add_fd, "# Replicators, %s, %s\n", group_attr, suffix);
	fprintf(add_fd, "dn: cn=Replicators,ou=%s,%s\n", group_attr,
		suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "gidNumber: 552\n");
	fprintf(add_fd, "cn: Replicators\n");
	fprintf(add_fd, "description: Netbios Domain Supports file replication in a sambaDomainName\n");
	fprintf(add_fd, "sambaSID: %s-552\n", builtin_sid);
	fprintf(add_fd, "sambaGroupType: 5\n");
	fprintf(add_fd, "displayName: Replicators\n");
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Deallocate memory, and return */
	SAFE_FREE(suffix_attr);
	SAFE_FREE(user_attr);
	SAFE_FREE(group_attr);
	return NT_STATUS_OK;
}

static NTSTATUS map_populate_groups(GROUPMAP *groupmap, ACCOUNTMAP *accountmap, fstring sid,
		    const char *suffix, const char *builtin_sid)
{
	char *group_attr = sstring_sub(lp_ldap_group_suffix(), '=', ',');

	/* Map the groups created by populate_ldap_for_ldif */
	groupmap[0].rid = 512;
	groupmap[0].gidNumber = 512;
	snprintf(groupmap[0].sambaSID, sizeof(groupmap[0].sambaSID),
			"%s-512", sid);
	snprintf(groupmap[0].group_dn, sizeof(groupmap[0].group_dn),
			"cn=Domain Admins,ou=%s,%s",
			group_attr, suffix);
	accountmap[0].rid = 512;
	snprintf(accountmap[0].cn, sizeof(accountmap[0].cn),
			"%s", "Domain Admins");

	groupmap[1].rid = 513;
	groupmap[1].gidNumber = 513;
	snprintf(groupmap[1].sambaSID, sizeof(groupmap[1].sambaSID),
			"%s-513", sid);
	snprintf(groupmap[1].group_dn, sizeof(groupmap[1].group_dn),
			"cn=Domain Users,ou=%s,%s",
			group_attr, suffix);
	accountmap[1].rid = 513;
	snprintf(accountmap[1].cn, sizeof(accountmap[1].cn),
			"%s", "Domain Users");

	groupmap[2].rid = 514;
	groupmap[2].gidNumber = 514;
	snprintf(groupmap[2].sambaSID, sizeof(groupmap[2].sambaSID),
			"%s-514", sid);
	snprintf(groupmap[2].group_dn, sizeof(groupmap[2].group_dn),
			"cn=Domain Guests,ou=%s,%s",
			group_attr, suffix);
	accountmap[2].rid = 514;
	snprintf(accountmap[2].cn, sizeof(accountmap[2].cn),
			"%s", "Domain Guests");

	groupmap[3].rid = 515;
	groupmap[3].gidNumber = 515;
	snprintf(groupmap[3].sambaSID, sizeof(groupmap[3].sambaSID),
			"%s-515", sid);
	snprintf(groupmap[3].group_dn, sizeof(groupmap[3].group_dn),
			"cn=Domain Computers,ou=%s,%s",
			group_attr, suffix);
	accountmap[3].rid = 515;
	snprintf(accountmap[3].cn, sizeof(accountmap[3].cn),
			"%s", "Domain Computers");

	groupmap[4].rid = 544;
	groupmap[4].gidNumber = 544;
	snprintf(groupmap[4].sambaSID, sizeof(groupmap[4].sambaSID),
			"%s-544", builtin_sid);
	snprintf(groupmap[4].group_dn, sizeof(groupmap[4].group_dn),
			"cn=Administrators,ou=%s,%s",
			group_attr, suffix);
	accountmap[4].rid = 515;
	snprintf(accountmap[4].cn, sizeof(accountmap[4].cn),
			"%s", "Administrators");

	groupmap[5].rid = 550;
	groupmap[5].gidNumber = 550;
	snprintf(groupmap[5].sambaSID, sizeof(groupmap[5].sambaSID),
			"%s-550", builtin_sid);
	snprintf(groupmap[5].group_dn, sizeof(groupmap[5].group_dn),
			"cn=Print Operators,ou=%s,%s",
			group_attr, suffix);
	accountmap[5].rid = 550;
	snprintf(accountmap[5].cn, sizeof(accountmap[5].cn),
			"%s", "Print Operators");

	groupmap[6].rid = 551;
	groupmap[6].gidNumber = 551;
	snprintf(groupmap[6].sambaSID, sizeof(groupmap[6].sambaSID),
			"%s-551", builtin_sid);
	snprintf(groupmap[6].group_dn, sizeof(groupmap[6].group_dn),
			"cn=Backup Operators,ou=%s,%s",
			group_attr, suffix);
	accountmap[6].rid = 551;
	snprintf(accountmap[6].cn, sizeof(accountmap[6].cn),
			"%s", "Backup Operators");

	groupmap[7].rid = 552;
	groupmap[7].gidNumber = 552;
	snprintf(groupmap[7].sambaSID, sizeof(groupmap[7].sambaSID),
			"%s-552", builtin_sid);
	snprintf(groupmap[7].group_dn, sizeof(groupmap[7].group_dn),
			"cn=Replicators,ou=%s,%s",
			group_attr, suffix);
	accountmap[7].rid = 551;
	snprintf(accountmap[7].cn, sizeof(accountmap[7].cn),
			"%s", "Replicators");
	SAFE_FREE(group_attr);
	return NT_STATUS_OK;
}

/*
 * This is a crap routine, but I think it's the quickest way to solve the
 * UTF8->base64 problem.
 */

static int fprintf_attr(FILE *add_fd, const char *attr_name,
			const char *fmt, ...)
{
	va_list ap;
	char *value, *p, *base64;
	DATA_BLOB base64_blob;
	bool do_base64 = False;
	int res;

	va_start(ap, fmt);
	value = talloc_vasprintf(NULL, fmt, ap);
	va_end(ap);

	SMB_ASSERT(value != NULL);

	for (p=value; *p; p++) {
		if (*p & 0x80) {
			do_base64 = True;
			break;
		}
	}

	if (!do_base64) {
		bool only_whitespace = True;
		for (p=value; *p; p++) {
			/*
			 * I know that this not multibyte safe, but we break
			 * on the first non-whitespace character anyway.
			 */
			if (!isspace(*p)) {
				only_whitespace = False;
				break;
			}
		}
		if (only_whitespace) {
			do_base64 = True;
		}
	}

	if (!do_base64) {
		res = fprintf(add_fd, "%s: %s\n", attr_name, value);
		TALLOC_FREE(value);
		return res;
	}

	base64_blob.data = (unsigned char *)value;
	base64_blob.length = strlen(value);

	base64 = base64_encode_data_blob(value, base64_blob);
	SMB_ASSERT(base64 != NULL);

	res = fprintf(add_fd, "%s:: %s\n", attr_name, base64);
	TALLOC_FREE(value);
	return res;
}

static NTSTATUS fetch_group_info_to_ldif(struct netr_DELTA_GROUP *r, GROUPMAP *groupmap,
			 FILE *add_fd, fstring sid, char *suffix)
{
	fstring groupname;
	uint32 grouptype = 0, g_rid = 0;
	char *group_attr = sstring_sub(lp_ldap_group_suffix(), '=', ',');

	/* Get the group name */
	fstrcpy(groupname, r->group_name.string);

	/* Set up the group type (always 2 for group info) */
	grouptype = 2;

	/* These groups are entered by populate_ldap_for_ldif */
	if (strcmp(groupname, "Domain Admins") == 0 ||
            strcmp(groupname, "Domain Users") == 0 ||
	    strcmp(groupname, "Domain Guests") == 0 ||
	    strcmp(groupname, "Domain Computers") == 0 ||
	    strcmp(groupname, "Administrators") == 0 ||
	    strcmp(groupname, "Print Operators") == 0 ||
	    strcmp(groupname, "Backup Operators") == 0 ||
	    strcmp(groupname, "Replicators") == 0) {
		SAFE_FREE(group_attr);
		return NT_STATUS_OK;
	} else {
		/* Increment the gid for the new group */
	        ldif_gid++;
	}

	/* Map the group rid, gid, and dn */
	g_rid = r->rid;
	groupmap->rid = g_rid;
	groupmap->gidNumber = ldif_gid;
	snprintf(groupmap->sambaSID, sizeof(groupmap->sambaSID),
			"%s-%d", sid, g_rid);
	snprintf(groupmap->group_dn, sizeof(groupmap->group_dn),
		     "cn=%s,ou=%s,%s", groupname, group_attr, suffix);

	/* Write the data to the temporary add ldif file */
	fprintf(add_fd, "# %s, %s, %s\n", groupname, group_attr,
		suffix);
	fprintf_attr(add_fd, "dn", "cn=%s,ou=%s,%s", groupname, group_attr,
		     suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf_attr(add_fd, "cn", "%s", groupname);
	fprintf(add_fd, "gidNumber: %d\n", ldif_gid);
	fprintf(add_fd, "sambaSID: %s\n", groupmap->sambaSID);
	fprintf(add_fd, "sambaGroupType: %d\n", grouptype);
	fprintf_attr(add_fd, "displayName", "%s", groupname);
	fprintf(add_fd, "\n");
	fflush(add_fd);

	SAFE_FREE(group_attr);
	/* Return */
	return NT_STATUS_OK;
}

static NTSTATUS fetch_account_info_to_ldif(struct netr_DELTA_USER *r,
					   GROUPMAP *groupmap,
					   ACCOUNTMAP *accountmap,
					   FILE *add_fd,
					   fstring sid, char *suffix,
					   int alloced)
{
	fstring username, logonscript, homedrive, homepath = "", homedir = "";
	fstring hex_nt_passwd, hex_lm_passwd;
	fstring description, profilepath, fullname, sambaSID;
	char *flags, *user_rdn;
	const char *ou;
	const char* nopasswd = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
	uchar zero_buf[16];
	uint32 rid = 0, group_rid = 0, gidNumber = 0;
	time_t unix_time;
	int i;

	memset(zero_buf, '\0', sizeof(zero_buf));

	/* Get the username */
	fstrcpy(username, r->account_name.string);

	/* Get the rid */
	rid = r->rid;

	/* Map the rid and username for group member info later */
	accountmap->rid = rid;
	snprintf(accountmap->cn, sizeof(accountmap->cn), "%s", username);

	/* Get the home directory */
	if (r->acct_flags & ACB_NORMAL) {
		fstrcpy(homedir, r->home_directory.string);
		if (!*homedir) {
			snprintf(homedir, sizeof(homedir), "/home/%s", username);
		} else {
			snprintf(homedir, sizeof(homedir), "/nobodyshomedir");
		}
		ou = lp_ldap_user_suffix();
	} else {
		ou = lp_ldap_machine_suffix();
		snprintf(homedir, sizeof(homedir), "/machinehomedir");
	}

        /* Get the logon script */
	fstrcpy(logonscript, r->logon_script.string);

        /* Get the home drive */
	fstrcpy(homedrive, r->home_drive.string);

        /* Get the home path */
	fstrcpy(homepath, r->home_directory.string);

	/* Get the description */
	fstrcpy(description, r->description.string);

	/* Get the display name */
	fstrcpy(fullname, r->full_name.string);

	/* Get the profile path */
	fstrcpy(profilepath, r->profile_path.string);

	/* Get lm and nt password data */
	if (memcmp(r->lmpassword.hash, zero_buf, 16) != 0) {
		pdb_sethexpwd(hex_lm_passwd, r->lmpassword.hash, r->acct_flags);
	} else {
		pdb_sethexpwd(hex_lm_passwd, NULL, 0);
	}
	if (memcmp(r->ntpassword.hash, zero_buf, 16) != 0) {
		pdb_sethexpwd(hex_nt_passwd, r->ntpassword.hash, r->acct_flags);
	} else {
		pdb_sethexpwd(hex_nt_passwd, NULL, 0);
	}
	unix_time = nt_time_to_unix(r->last_password_change);

	/* Increment the uid for the new user */
	ldif_uid++;

	/* Set up group id and sambaSID for the user */
	group_rid = r->primary_gid;
	for (i=0; i<alloced; i++) {
		if (groupmap[i].rid == group_rid) break;
	}
	if (i == alloced){
		DEBUG(1, ("Could not find rid %d in groupmap array\n",
			  group_rid));
		return NT_STATUS_UNSUCCESSFUL;
	}
	gidNumber = groupmap[i].gidNumber;
	snprintf(sambaSID, sizeof(sambaSID), groupmap[i].sambaSID);

	/* Set up sambaAcctFlags */
	flags = pdb_encode_acct_ctrl(r->acct_flags,
				     NEW_PW_FORMAT_SPACE_PADDED_LEN);

	/* Add the user to the temporary add ldif file */
	/* this isn't quite right...we can't assume there's just OU=. jmcd */
	user_rdn = sstring_sub(ou, '=', ',');
	fprintf(add_fd, "# %s, %s, %s\n", username, user_rdn, suffix);
	fprintf_attr(add_fd, "dn", "uid=%s,ou=%s,%s", username, user_rdn,
		     suffix);
	SAFE_FREE(user_rdn);
	fprintf(add_fd, "ObjectClass: top\n");
	fprintf(add_fd, "objectClass: inetOrgPerson\n");
	fprintf(add_fd, "objectClass: posixAccount\n");
	fprintf(add_fd, "objectClass: shadowAccount\n");
	fprintf(add_fd, "objectClass: sambaSamAccount\n");
	fprintf_attr(add_fd, "cn", "%s", username);
	fprintf_attr(add_fd, "sn", "%s", username);
	fprintf_attr(add_fd, "uid", "%s", username);
	fprintf(add_fd, "uidNumber: %d\n", ldif_uid);
	fprintf(add_fd, "gidNumber: %d\n", gidNumber);
	fprintf_attr(add_fd, "homeDirectory", "%s", homedir);
	if (*homepath)
		fprintf_attr(add_fd, "sambaHomePath", "%s", homepath);
        if (*homedrive)
                fprintf_attr(add_fd, "sambaHomeDrive", "%s", homedrive);
        if (*logonscript)
                fprintf_attr(add_fd, "sambaLogonScript", "%s", logonscript);
	fprintf(add_fd, "loginShell: %s\n",
		((r->acct_flags & ACB_NORMAL) ?
		 "/bin/bash" : "/bin/false"));
	fprintf(add_fd, "gecos: System User\n");
	if (*description)
		fprintf_attr(add_fd, "description", "%s", description);
	fprintf(add_fd, "sambaSID: %s-%d\n", sid, rid);
	fprintf(add_fd, "sambaPrimaryGroupSID: %s\n", sambaSID);
	if(*fullname)
		fprintf_attr(add_fd, "displayName", "%s", fullname);
	if(*profilepath)
		fprintf_attr(add_fd, "sambaProfilePath", "%s", profilepath);
	if (strcmp(nopasswd, hex_lm_passwd) != 0)
		fprintf(add_fd, "sambaLMPassword: %s\n", hex_lm_passwd);
	if (strcmp(nopasswd, hex_nt_passwd) != 0)
		fprintf(add_fd, "sambaNTPassword: %s\n", hex_nt_passwd);
	fprintf(add_fd, "sambaPwdLastSet: %d\n", (int)unix_time);
	fprintf(add_fd, "sambaAcctFlags: %s\n", flags);
	fprintf(add_fd, "\n");
	fflush(add_fd);

	/* Return */
	return NT_STATUS_OK;
}

static NTSTATUS fetch_alias_info_to_ldif(struct netr_DELTA_ALIAS *r,
					 GROUPMAP *groupmap,
					 FILE *add_fd, fstring sid,
					 char *suffix,
					 unsigned db_type)
{
	fstring aliasname, description;
	uint32 grouptype = 0, g_rid = 0;
	char *group_attr = sstring_sub(lp_ldap_group_suffix(), '=', ',');

	/* Get the alias name */
	fstrcpy(aliasname, r->alias_name.string);

	/* Get the alias description */
	fstrcpy(description, r->description.string);

	/* Set up the group type */
	switch (db_type) {
	case SAM_DATABASE_DOMAIN:
		grouptype = 4;
		break;
	case SAM_DATABASE_BUILTIN:
		grouptype = 5;
		break;
	default:
		grouptype = 4;
		break;
	}

	/*
	  These groups are entered by populate_ldap_for_ldif
	  Note that populate creates a group called Relicators,
	  but NT returns a group called Replicator
	*/
	if (strcmp(aliasname, "Domain Admins") == 0 ||
	    strcmp(aliasname, "Domain Users") == 0 ||
	    strcmp(aliasname, "Domain Guests") == 0 ||
	    strcmp(aliasname, "Domain Computers") == 0 ||
	    strcmp(aliasname, "Administrators") == 0 ||
	    strcmp(aliasname, "Print Operators") == 0 ||
	    strcmp(aliasname, "Backup Operators") == 0 ||
	    strcmp(aliasname, "Replicator") == 0) {
		SAFE_FREE(group_attr);
		return NT_STATUS_OK;
	} else {
		/* Increment the gid for the new group */
		ldif_gid++;
	}

	/* Map the group rid and gid */
	g_rid = r->rid;
	groupmap->gidNumber = ldif_gid;
	snprintf(groupmap->sambaSID, sizeof(groupmap->sambaSID),
			"%s-%d", sid, g_rid);

	/* Write the data to the temporary add ldif file */
	fprintf(add_fd, "# %s, %s, %s\n", aliasname, group_attr,
		suffix);
	fprintf_attr(add_fd, "dn", "cn=%s,ou=%s,%s", aliasname, group_attr,
		     suffix);
	fprintf(add_fd, "objectClass: posixGroup\n");
	fprintf(add_fd, "objectClass: sambaGroupMapping\n");
	fprintf(add_fd, "cn: %s\n", aliasname);
	fprintf(add_fd, "gidNumber: %d\n", ldif_gid);
	fprintf(add_fd, "sambaSID: %s\n", groupmap->sambaSID);
	fprintf(add_fd, "sambaGroupType: %d\n", grouptype);
	fprintf_attr(add_fd, "displayName", "%s", aliasname);
	if (description[0])
		fprintf_attr(add_fd, "description", "%s", description);
	fprintf(add_fd, "\n");
	fflush(add_fd);

	SAFE_FREE(group_attr);
	/* Return */
	return NT_STATUS_OK;
}

static NTSTATUS fetch_groupmem_info_to_ldif(struct netr_DELTA_GROUP_MEMBER *r,
					    uint32_t id_rid,
					    GROUPMAP *groupmap,
					    ACCOUNTMAP *accountmap,
					    FILE *mod_fd, int alloced)
{
	fstring group_dn;
	uint32 group_rid = 0, rid = 0;
	int i, j, k;

	/* Get the dn for the group */
	if (r->num_rids > 0) {
		group_rid = id_rid;
		for (j=0; j<alloced; j++) {
			if (groupmap[j].rid == group_rid) break;
		}
		if (j == alloced){
			DEBUG(1, ("Could not find rid %d in groupmap array\n",
				  group_rid));
			return NT_STATUS_UNSUCCESSFUL;
		}
		snprintf(group_dn, sizeof(group_dn), "%s", groupmap[j].group_dn);
		fprintf(mod_fd, "dn: %s\n", group_dn);

		/* Get the cn for each member */
		for (i=0; i < r->num_rids; i++) {
			rid = r->rids[i];
			for (k=0; k<alloced; k++) {
				if (accountmap[k].rid == rid) break;
			}
			if (k == alloced){
				DEBUG(1, ("Could not find rid %d in "
					  "accountmap array\n", rid));
				return NT_STATUS_UNSUCCESSFUL;
			}
			fprintf(mod_fd, "memberUid: %s\n", accountmap[k].cn);
		}
		fprintf(mod_fd, "\n");
	}
	fflush(mod_fd);

	/* Return */
	return NT_STATUS_OK;
}

static NTSTATUS fetch_database_to_ldif(struct rpc_pipe_client *pipe_hnd,
				       uint32 db_type,
				       DOM_SID dom_sid,
				       const char *user_file)
{
	char *suffix;
	const char *builtin_sid = "S-1-5-32";
	char *add_name = NULL, *mod_filename = NULL;
	const char *add_template = "/tmp/add.ldif.XXXXXX";
	const char *mod_template = "/tmp/mod.ldif.XXXXXX";
	fstring sid, domainname;
	NTSTATUS ret = NT_STATUS_OK, result;
	int k;
	TALLOC_CTX *mem_ctx;
	uint32 num_deltas;
	FILE *add_file = NULL, *mod_file = NULL, *ldif_file = NULL;
	int num_alloced = 0, g_index = 0, a_index = 0;
	const char *logon_server = pipe_hnd->cli->desthost;
	const char *computername = global_myname();
	struct netr_Authenticator credential;
	struct netr_Authenticator return_authenticator;
	enum netr_SamDatabaseID database_id = db_type;
	uint16_t restart_state = 0;
	uint32_t sync_context = 0;
	DATA_BLOB session_key;

	/* Set up array for mapping accounts to groups */
	/* Array element is the group rid */
	GROUPMAP *groupmap = NULL;

	/* Set up array for mapping account rid's to cn's */
	/* Array element is the account rid */
	ACCOUNTMAP *accountmap = NULL;

	if (!(mem_ctx = talloc_init("fetch_database"))) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Ensure we have an output file */
	if (user_file)
		ldif_file = fopen(user_file, "a");
	else
		ldif_file = stdout;

	if (!ldif_file) {
		fprintf(stderr, "Could not open %s\n", user_file);
		DEBUG(1, ("Could not open %s\n", user_file));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	add_name = talloc_strdup(mem_ctx, add_template);
	mod_filename = talloc_strdup(mem_ctx, mod_template);
	if (!add_name || !mod_filename) {
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	/* Open the add and mod ldif files */
	if (!(add_file = fdopen(smb_mkstemp(add_name),"w"))) {
		DEBUG(1, ("Could not open %s\n", add_name));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	if (!(mod_file = fdopen(smb_mkstemp(mod_filename),"w"))) {
		DEBUG(1, ("Could not open %s\n", mod_filename));
		ret = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Get the sid */
	sid_to_fstring(sid, &dom_sid);

	/* Get the ldap suffix */
	suffix = lp_ldap_suffix();
	if (suffix == NULL || strcmp(suffix, "") == 0) {
		DEBUG(0,("ldap suffix missing from smb.conf--exiting\n"));
		exit(1);
	}

	/* Get other smb.conf data */
	if (!(lp_workgroup()) || !*(lp_workgroup())) {
		DEBUG(0,("workgroup missing from smb.conf--exiting\n"));
		exit(1);
	}

	/* Allocate initial memory for groupmap and accountmap arrays */
	if (init_ldap == 1) {
		groupmap = SMB_MALLOC_ARRAY(GROUPMAP, 8);
		accountmap = SMB_MALLOC_ARRAY(ACCOUNTMAP, 8);
		if (groupmap == NULL || accountmap == NULL) {
			DEBUG(1,("GROUPMAP malloc failed\n"));
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}

		/* Initialize the arrays */
		memset(groupmap, 0, sizeof(GROUPMAP)*8);
		memset(accountmap, 0, sizeof(ACCOUNTMAP)*8);

		/* Remember how many we malloced */
		num_alloced = 8;

		/* Initial database population */
		populate_ldap_for_ldif(sid, suffix, builtin_sid, add_file);
		map_populate_groups(groupmap, accountmap, sid, suffix,
				    builtin_sid);

		/* Don't do this again */
		init_ldap = 0;
	}

	/* Announce what we are doing */
	switch( db_type ) {
	case SAM_DATABASE_DOMAIN:
		d_fprintf(stderr, "Fetching DOMAIN database\n");
		break;
	case SAM_DATABASE_BUILTIN:
		d_fprintf(stderr, "Fetching BUILTIN database\n");
		break;
	case SAM_DATABASE_PRIVS:
		d_fprintf(stderr, "Fetching PRIVS databases\n");
		break;
	default:
		d_fprintf(stderr,
			  "Fetching unknown database type %u\n",
			  db_type );
		break;
	}

	do {
		struct netr_DELTA_ENUM_ARRAY *delta_enum_array = NULL;

		netlogon_creds_client_step(pipe_hnd->dc, &credential);

		result = rpccli_netr_DatabaseSync2(pipe_hnd, mem_ctx,
						   logon_server,
						   computername,
						   &credential,
						   &return_authenticator,
						   database_id,
						   restart_state,
						   &sync_context,
						   &delta_enum_array,
						   0xffff);

		/* Check returned credentials. */
		if (!netlogon_creds_client_check(pipe_hnd->dc,
						 &return_authenticator.cred)) {
			DEBUG(0,("credentials chain check failed\n"));
			return NT_STATUS_ACCESS_DENIED;
		}

		if (NT_STATUS_IS_ERR(result)) {
			break;
		}

		session_key = data_blob_const(pipe_hnd->dc->sess_key, 16);

		samsync_fix_delta_array(mem_ctx,
					&session_key,
					database_id,
					delta_enum_array);

		num_deltas = delta_enum_array->num_deltas;

		/* Re-allocate memory for groupmap and accountmap arrays */
		groupmap = SMB_REALLOC_ARRAY(groupmap, GROUPMAP,
					     num_deltas+num_alloced);
		accountmap = SMB_REALLOC_ARRAY(accountmap, ACCOUNTMAP,
					       num_deltas+num_alloced);
		if (groupmap == NULL || accountmap == NULL) {
			DEBUG(1,("GROUPMAP malloc failed\n"));
			ret = NT_STATUS_NO_MEMORY;
			goto done;
		}

		/* Initialize the new records */
		memset(&groupmap[num_alloced], 0,
		       sizeof(GROUPMAP)*num_deltas);
		memset(&accountmap[num_alloced], 0,
		       sizeof(ACCOUNTMAP)*num_deltas);

		/* Remember how many we alloced this time */
		num_alloced += num_deltas;

		/* Loop through the deltas */
		for (k=0; k<num_deltas; k++) {

			union netr_DELTA_UNION u =
				delta_enum_array->delta_enum[k].delta_union;
			union netr_DELTA_ID_UNION id =
				delta_enum_array->delta_enum[k].delta_id_union;

			switch(delta_enum_array->delta_enum[k].delta_type) {
			case NETR_DELTA_DOMAIN:
				/* Is this case needed? */
				fstrcpy(domainname,
					u.domain->domain_name.string);
				break;

			case NETR_DELTA_GROUP:
				fetch_group_info_to_ldif(
					u.group,
					&groupmap[g_index],
					add_file, sid, suffix);
				g_index++;
				break;

			case NETR_DELTA_USER:
				fetch_account_info_to_ldif(
					u.user, groupmap,
					&accountmap[a_index], add_file,
					sid, suffix, num_alloced);
				a_index++;
				break;

			case NETR_DELTA_ALIAS:
				fetch_alias_info_to_ldif(
					u.alias, &groupmap[g_index],
					add_file, sid, suffix, db_type);
				g_index++;
				break;

			case NETR_DELTA_GROUP_MEMBER:
				fetch_groupmem_info_to_ldif(
					u.group_member, id.rid,
					groupmap, accountmap,
					mod_file, num_alloced);
				break;

			case NETR_DELTA_ALIAS_MEMBER:
			case NETR_DELTA_POLICY:
			case NETR_DELTA_ACCOUNT:
			case NETR_DELTA_TRUSTED_DOMAIN:
			case NETR_DELTA_SECRET:
			case NETR_DELTA_RENAME_GROUP:
			case NETR_DELTA_RENAME_USER:
			case NETR_DELTA_RENAME_ALIAS:
			case NETR_DELTA_DELETE_GROUP:
			case NETR_DELTA_DELETE_USER:
			case NETR_DELTA_MODIFY_COUNT:
			default:
				break;
			} /* end of switch */
		} /* end of for loop */

	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	/* Write ldif data to the user's file */
	if (db_type == SAM_DATABASE_DOMAIN) {
		fprintf(ldif_file,
			"# SAM_DATABASE_DOMAIN: ADD ENTITIES\n");
		fprintf(ldif_file,
			"# =================================\n\n");
		fflush(ldif_file);
	} else if (db_type == SAM_DATABASE_BUILTIN) {
		fprintf(ldif_file,
			"# SAM_DATABASE_BUILTIN: ADD ENTITIES\n");
		fprintf(ldif_file,
			"# ==================================\n\n");
		fflush(ldif_file);
	}
	fseek(add_file, 0, SEEK_SET);
	transfer_file(fileno(add_file), fileno(ldif_file), (size_t) -1);

	if (db_type == SAM_DATABASE_DOMAIN) {
		fprintf(ldif_file,
			"# SAM_DATABASE_DOMAIN: MODIFY ENTITIES\n");
		fprintf(ldif_file,
			"# ====================================\n\n");
		fflush(ldif_file);
	} else if (db_type == SAM_DATABASE_BUILTIN) {
		fprintf(ldif_file,
			"# SAM_DATABASE_BUILTIN: MODIFY ENTITIES\n");
		fprintf(ldif_file,
			"# =====================================\n\n");
		fflush(ldif_file);
	}
	fseek(mod_file, 0, SEEK_SET);
	transfer_file(fileno(mod_file), fileno(ldif_file), (size_t) -1);


 done:
	/* Close and delete the ldif files */
	if (add_file) {
		fclose(add_file);
	}

	if ((add_name != NULL) &&
	    strcmp(add_name, add_template) && (unlink(add_name))) {
		DEBUG(1,("unlink(%s) failed, error was (%s)\n",
			 add_name, strerror(errno)));
	}

	if (mod_file) {
		fclose(mod_file);
	}

	if ((mod_filename != NULL) &&
	    strcmp(mod_filename, mod_template) && (unlink(mod_filename))) {
		DEBUG(1,("unlink(%s) failed, error was (%s)\n",
			 mod_filename, strerror(errno)));
	}

	if (ldif_file && (ldif_file != stdout)) {
		fclose(ldif_file);
	}

	/* Deallocate memory for the mapping arrays */
	SAFE_FREE(groupmap);
	SAFE_FREE(accountmap);

	/* Return */
	talloc_destroy(mem_ctx);
	return ret;
}

/**
 * Basic usage function for 'net rpc vampire'
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int rpc_vampire_usage(int argc, const char **argv)
{
	d_printf("net rpc vampire [ldif [<ldif-filename>] [options]\n"
		 "\t to pull accounts from a remote PDC where we are a BDC\n"
		 "\t\t no args puts accounts in local passdb from smb.conf\n"
		 "\t\t ldif - put accounts in ldif format (file defaults to "
		 "/tmp/tmp.ldif\n");

	net_common_flags_usage(argc, argv);
	return -1;
}


/* dump sam database via samsync rpc calls */
NTSTATUS rpc_vampire_internals(const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
        NTSTATUS result;
	fstring my_dom_sid_str;
	fstring rem_dom_sid_str;

	if (!sid_equal(domain_sid, get_global_sam_sid())) {
		d_printf("Cannot import users from %s at this time, "
			 "as the current domain:\n\t%s: %s\nconflicts "
			 "with the remote domain\n\t%s: %s\n"
			 "Perhaps you need to set: \n\n\tsecurity=user\n\t"
			 "workgroup=%s\n\n in your smb.conf?\n",
			 domain_name,
			 get_global_sam_name(),
			 sid_to_fstring(my_dom_sid_str,
					get_global_sam_sid()),
			 domain_name, sid_to_fstring(rem_dom_sid_str,
						     domain_sid),
			 domain_name);
		return NT_STATUS_UNSUCCESSFUL;
	}

        if (argc >= 1 && (strcmp(argv[0], "ldif") == 0)) {
		result = fetch_database_to_ldif(pipe_hnd, SAM_DATABASE_DOMAIN,
						*domain_sid, argv[1]);
        } else {
		result = fetch_database(pipe_hnd, SAM_DATABASE_DOMAIN,
					*domain_sid);
        }

	if (!NT_STATUS_IS_OK(result)) {
		d_fprintf(stderr, "Failed to fetch domain database: %s\n",
			  nt_errstr(result));
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED))
			d_fprintf(stderr, "Perhaps %s is a Windows 2000 "
				  "native mode domain?\n", domain_name);
		goto fail;
	}

        if (argc >= 1 && (strcmp(argv[0], "ldif") == 0)) {
		result = fetch_database_to_ldif(pipe_hnd, SAM_DATABASE_BUILTIN,
						global_sid_Builtin, argv[1]);
        } else {
		result = fetch_database(pipe_hnd, SAM_DATABASE_BUILTIN,
					global_sid_Builtin);
        }

	if (!NT_STATUS_IS_OK(result)) {
		d_fprintf(stderr, "Failed to fetch builtin database: %s\n",
			  nt_errstr(result));
		goto fail;
	}

	/* Currently we crash on PRIVS somewhere in unmarshalling */
	/* Dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds); */

 fail:
	return result;
}
