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
	uchar lm_passwd[16], nt_passwd[16];
	static uchar zero_buf[16];

	/* Decode hashes from password hash (if they are not NULL) */

	if (memcmp(r->lmpassword.hash, zero_buf, 16) != 0) {
		sam_pwd_hash(r->rid, r->lmpassword.hash, lm_passwd, 0);
		pdb_sethexpwd(hex_lm_passwd, lm_passwd, r->acct_flags);
	} else {
		pdb_sethexpwd(hex_lm_passwd, NULL, 0);
	}

	if (memcmp(r->ntpassword.hash, zero_buf, 16) != 0) {
		sam_pwd_hash(r->rid, r->ntpassword.hash, nt_passwd, 0);
		pdb_sethexpwd(hex_nt_passwd, nt_passwd, r->acct_flags);
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

static NTSTATUS display_sam_entry(TALLOC_CTX *mem_ctx,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM *r,
				  NTSTATUS status,
				  struct samsync_context *ctx)
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

	return NT_STATUS_OK;
}

static NTSTATUS display_sam_entries(TALLOC_CTX *mem_ctx,
				    enum netr_SamDatabaseID database_id,
				    struct netr_DELTA_ENUM_ARRAY *r,
				    NTSTATUS status,
				    struct samsync_context *ctx)
{
	int i;

	for (i = 0; i < r->num_deltas; i++) {
		display_sam_entry(mem_ctx, database_id, &r->delta_enum[i], status, ctx);
	}

	return NT_STATUS_OK;
}

/* dump sam database via samsync rpc calls */
NTSTATUS rpc_samdump_internals(struct net_context *c,
				const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
	struct samsync_context *ctx = NULL;
	NTSTATUS status;

	status = samsync_init_context(mem_ctx,
				      domain_sid,
				      NET_SAMSYNC_MODE_DUMP,
				      &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	samsync_process_database(pipe_hnd, SAM_DATABASE_DOMAIN,
				 display_sam_entries, ctx);

	samsync_process_database(pipe_hnd, SAM_DATABASE_BUILTIN,
				 display_sam_entries, ctx);

	samsync_process_database(pipe_hnd, SAM_DATABASE_PRIVS,
				 display_sam_entries, ctx);

	TALLOC_FREE(ctx);

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
	uchar lm_passwd[16], nt_passwd[16];
	static uchar zero_buf[16];

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
	if (memcmp(r->ntpassword.hash, zero_buf, 16) != 0) {
		sam_pwd_hash(r->rid, r->ntpassword.hash, lm_passwd, 0);
		pdb_set_lanman_passwd(account, lm_passwd, PDB_CHANGED);
	}

	if (memcmp(r->lmpassword.hash, zero_buf, 16) != 0) {
		sam_pwd_hash(r->rid, r->lmpassword.hash, nt_passwd, 0);
		pdb_set_nt_passwd(account, nt_passwd, PDB_CHANGED);
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
	bool insert = true;

	fstrcpy(name, r->group_name.string);
	fstrcpy(comment, r->description.string);

	/* add the group to the mapping table */
	sid_copy(&group_sid, get_global_sam_sid());
	sid_append_rid(&group_sid, rid);
	sid_to_fstring(sid_string, &group_sid);

	if (pdb_getgrsid(&map, group_sid)) {
		if ( map.gid != -1 )
			grp = getgrgid(map.gid);
		insert = false;
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
		bool is_nt_member = false;
		for (i=0; i < r->num_rids; i++) {
			if (nt_members[i] == NULL) {
				/* This was a primary group */
				continue;
			}

			if (strcmp(*unix_members, nt_members[i]) == 0) {
				is_nt_member = true;
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
		bool is_unix_member = false;

		if (nt_members[i] == NULL) {
			/* This was the primary group */
			continue;
		}

		unix_members = grp->gr_mem;

		while (*unix_members) {
			if (strcmp(*unix_members, nt_members[i]) == 0) {
				is_unix_member = true;
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
				 const DOM_SID *dom_sid)
{
	fstring name;
	fstring comment;
	struct group *grp = NULL;
	DOM_SID alias_sid;
	fstring sid_string;
	GROUP_MAP map;
	bool insert = true;

	fstrcpy(name, r->alias_name.string);
	fstrcpy(comment, r->description.string);

	/* Find out whether the group is already mapped */
	sid_copy(&alias_sid, dom_sid);
	sid_append_rid(&alias_sid, rid);
	sid_to_fstring(sid_string, &alias_sid);

	if (pdb_getgrsid(&map, alias_sid)) {
		grp = getgrgid(map.gid);
		insert = false;
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

	if (sid_equal(dom_sid, &global_sid_Builtin))
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
				const DOM_SID *dom_sid)
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

static NTSTATUS fetch_sam_entry(TALLOC_CTX *mem_ctx,
				enum netr_SamDatabaseID database_id,
				struct netr_DELTA_ENUM *r,
				struct samsync_context *ctx)
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
				 ctx->domain_sid);
		break;
	case NETR_DELTA_ALIAS_MEMBER:
		fetch_alias_mem(r->delta_id_union.rid,
				r->delta_union.alias_member,
				ctx->domain_sid);
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

	return NT_STATUS_OK;
}

static NTSTATUS fetch_sam_entries(TALLOC_CTX *mem_ctx,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM_ARRAY *r,
				  NTSTATUS status,
				  struct samsync_context *ctx)
{
	int i;

	for (i = 0; i < r->num_deltas; i++) {
		fetch_sam_entry(mem_ctx, database_id, &r->delta_enum[i], ctx);
	}

	return NT_STATUS_OK;
}

/**
 * Basic usage function for 'net rpc vampire'
 *
 * @param c	A net_context structure
 * @param argc  Standard main() style argc
 * @param argc  Standard main() style argv.  Initial components are already
 *              stripped
 **/

int rpc_vampire_usage(struct net_context *c, int argc, const char **argv)
{
	d_printf("net rpc vampire [ldif [<ldif-filename>] [options]\n"
		 "\t to pull accounts from a remote PDC where we are a BDC\n"
		 "\t\t no args puts accounts in local passdb from smb.conf\n"
		 "\t\t ldif - put accounts in ldif format (file defaults to "
		 "/tmp/tmp.ldif\n");

	net_common_flags_usage(c, argc, argv);
	return -1;
}


/* dump sam database via samsync rpc calls */
NTSTATUS rpc_vampire_internals(struct net_context *c,
				const DOM_SID *domain_sid,
				const char *domain_name,
				struct cli_state *cli,
				struct rpc_pipe_client *pipe_hnd,
				TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv)
{
	NTSTATUS result;
	struct samsync_context *ctx = NULL;

	result = samsync_init_context(mem_ctx,
				      domain_sid,
				      NET_SAMSYNC_MODE_FETCH_PASSDB,
				      &ctx);
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	if (!sid_equal(domain_sid, get_global_sam_sid())) {
		d_printf("Cannot import users from %s at this time, "
			 "as the current domain:\n\t%s: %s\nconflicts "
			 "with the remote domain\n\t%s: %s\n"
			 "Perhaps you need to set: \n\n\tsecurity=user\n\t"
			 "workgroup=%s\n\n in your smb.conf?\n",
			 domain_name,
			 get_global_sam_name(),
			 sid_string_dbg(get_global_sam_sid()),
			 domain_name,
			 sid_string_dbg(domain_sid),
			 domain_name);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* fetch domain */
	result = samsync_process_database(pipe_hnd, SAM_DATABASE_DOMAIN,
					  fetch_sam_entries, ctx);
	if (!NT_STATUS_IS_OK(result)) {
		d_fprintf(stderr, "Failed to fetch domain database: %s\n",
			  nt_errstr(result));
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED))
			d_fprintf(stderr, "Perhaps %s is a Windows 2000 "
				  "native mode domain?\n", domain_name);
		goto fail;
	}

	/* fetch builtin */
	ctx->domain_sid = sid_dup_talloc(mem_ctx, &global_sid_Builtin);
	ctx->domain_sid_str = sid_string_talloc(mem_ctx, ctx->domain_sid);
	result = samsync_process_database(pipe_hnd, SAM_DATABASE_BUILTIN,
					  fetch_sam_entries, ctx);
	if (!NT_STATUS_IS_OK(result)) {
		d_fprintf(stderr, "Failed to fetch builtin database: %s\n",
			  nt_errstr(result));
		goto fail;
	}

	TALLOC_FREE(ctx);

 fail:
	return result;
}

NTSTATUS rpc_vampire_ldif_internals(struct net_context *c,
				    const DOM_SID *domain_sid,
				    const char *domain_name,
				    struct cli_state *cli,
				    struct rpc_pipe_client *pipe_hnd,
				    TALLOC_CTX *mem_ctx,
				    int argc,
				    const char **argv)
{
	NTSTATUS status;
	struct samsync_context *ctx = NULL;

	status = samsync_init_context(mem_ctx,
				      domain_sid,
				      NET_SAMSYNC_MODE_FETCH_LDIF,
				      &ctx);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (argc >= 1) {
		ctx->ldif_filename = argv[1];
	}

	/* fetch domain */
	status = samsync_process_database(pipe_hnd, SAM_DATABASE_DOMAIN,
					  fetch_sam_entries_ldif, ctx);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Failed to fetch domain database: %s\n",
			  nt_errstr(status));
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED))
			d_fprintf(stderr, "Perhaps %s is a Windows 2000 "
				  "native mode domain?\n", domain_name);
		goto fail;
	}

	/* fetch builtin */
	ctx->domain_sid = sid_dup_talloc(mem_ctx, &global_sid_Builtin);
	ctx->domain_sid_str = sid_string_talloc(mem_ctx, ctx->domain_sid);
	status = samsync_process_database(pipe_hnd, SAM_DATABASE_BUILTIN,
					  fetch_sam_entries_ldif, ctx);
	if (!NT_STATUS_IS_OK(status)) {
		d_fprintf(stderr, "Failed to fetch builtin database: %s\n",
			  nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(ctx);

 fail:
	return status;
}

int rpc_vampire_ldif(struct net_context *c, int argc, const char **argv)
{
	if (c->display_usage) {
		d_printf("Usage\n"
			 "net rpc vampire ldif\n"
			 "    Dump remote SAM database to LDIF file or stdout\n");
		return 0;
	}

	return run_rpc_command(c, NULL, PI_NETLOGON, 0, rpc_vampire_ldif_internals,
			       argc, argv);
}
