/* 
   Unix SMB/CIFS implementation.
   dump the remote SAM using rpc samsync operations

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Tim Potter 2001,2002
   Modified by Volker Lendecke 2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "../utils/net.h"

extern DOM_SID global_sid_Builtin; 

static void display_group_mem_info(uint32 rid, SAM_GROUP_MEM_INFO *g)
{
	int i;
	d_printf("Group mem %u: ", rid);
	for (i=0;i<g->num_members;i++) {
		d_printf("%u ", g->rids[i]);
	}
	d_printf("\n");
}

static void display_alias_info(uint32 rid, SAM_ALIAS_INFO *a)
{
	d_printf("Alias '%s' ", unistr2_static(&a->uni_als_name));
	d_printf("desc='%s' rid=%u\n", unistr2_static(&a->uni_als_desc), a->als_rid);
}

static void display_alias_mem(uint32 rid, SAM_ALIAS_MEM_INFO *a)
{
	int i;
	d_printf("Alias rid %u: ", rid);
	for (i=0;i<a->num_members;i++) {
		d_printf("%s ", sid_string_static(&a->sids[i].sid));
	}
	d_printf("\n");
}

static void display_account_info(uint32 rid, SAM_ACCOUNT_INFO *a)
{
	fstring hex_nt_passwd, hex_lm_passwd;
	uchar lm_passwd[16], nt_passwd[16];
	static uchar zero_buf[16];

	/* Decode hashes from password hash (if they are not NULL) */
	
	if (memcmp(a->pass.buf_lm_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(a->user_rid, a->pass.buf_lm_pwd, lm_passwd, 0);
		pdb_sethexpwd(hex_lm_passwd, lm_passwd, a->acb_info);
	} else {
		pdb_sethexpwd(hex_lm_passwd, NULL, 0);
	}

	if (memcmp(a->pass.buf_nt_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(a->user_rid, a->pass.buf_nt_pwd, nt_passwd, 0);
		pdb_sethexpwd(hex_nt_passwd, nt_passwd, a->acb_info);
	} else {
		pdb_sethexpwd(hex_nt_passwd, NULL, 0);
	}
	
	printf("%s:%d:%s:%s:%s:LCT-0\n", unistr2_static(&a->uni_acct_name),
	       a->user_rid, hex_lm_passwd, hex_nt_passwd,
	       pdb_encode_acct_ctrl(a->acb_info, NEW_PW_FORMAT_SPACE_PADDED_LEN));
}

static void display_domain_info(SAM_DOMAIN_INFO *a)
{
	d_printf("Domain name: %s\n", unistr2_static(&a->uni_dom_name));
}

static void display_group_info(uint32 rid, SAM_GROUP_INFO *a)
{
	d_printf("Group '%s' ", unistr2_static(&a->uni_grp_name));
	d_printf("desc='%s', rid=%u\n", unistr2_static(&a->uni_grp_desc), rid);
}

static void display_sam_entry(SAM_DELTA_HDR *hdr_delta, SAM_DELTA_CTR *delta)
{
	switch (hdr_delta->type) {
	case SAM_DELTA_ACCOUNT_INFO:
		display_account_info(hdr_delta->target_rid, &delta->account_info);
		break;
	case SAM_DELTA_GROUP_MEM:
		display_group_mem_info(hdr_delta->target_rid, &delta->grp_mem_info);
		break;
	case SAM_DELTA_ALIAS_INFO:
		display_alias_info(hdr_delta->target_rid, &delta->alias_info);
		break;
	case SAM_DELTA_ALIAS_MEM:
		display_alias_mem(hdr_delta->target_rid, &delta->als_mem_info);
		break;
	case SAM_DELTA_DOMAIN_INFO:
		display_domain_info(&delta->domain_info);
		break;
	case SAM_DELTA_GROUP_INFO:
		display_group_info(hdr_delta->target_rid, &delta->group_info);
		break;
		/* The following types are recognised but not handled */
	case SAM_DELTA_RENAME_GROUP:
		d_printf("SAM_DELTA_RENAME_GROUP not handled\n");
		break;
	case SAM_DELTA_RENAME_USER:
		d_printf("SAM_DELTA_RENAME_USER not handled\n");
		break;
	case SAM_DELTA_RENAME_ALIAS:
		d_printf("SAM_DELTA_RENAME_ALIAS not handled\n");
		break;
	case SAM_DELTA_POLICY_INFO:
		d_printf("SAM_DELTA_POLICY_INFO not handled\n");
		break;
	case SAM_DELTA_TRUST_DOMS:
		d_printf("SAM_DELTA_TRUST_DOMS not handled\n");
		break;
	case SAM_DELTA_PRIVS_INFO:
		d_printf("SAM_DELTA_PRIVS_INFO not handled\n");
		break;
	case SAM_DELTA_SECRET_INFO:
		d_printf("SAM_DELTA_SECRET_INFO not handled\n");
		break;
	case SAM_DELTA_DELETE_GROUP:
		d_printf("SAM_DELTA_DELETE_GROUP not handled\n");
		break;
	case SAM_DELTA_DELETE_USER:
		d_printf("SAM_DELTA_DELETE_USER not handled\n");
		break;
	case SAM_DELTA_MODIFIED_COUNT:
		d_printf("SAM_DELTA_MODIFIED_COUNT not handled\n");
		break;
	default:
		d_printf("Unknown delta record type %d\n", hdr_delta->type);
		break;
	}
}


static void dump_database(struct cli_state *cli, unsigned db_type, DOM_CRED *ret_creds)
{
	unsigned sync_context = 0;
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32 num_deltas;

	if (!(mem_ctx = talloc_init("dump_database"))) {
		return;
	}

	switch( db_type ) {
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
		d_printf("Dumping unknown database type %u\n", db_type );
		break;
	}

	do {
		result = cli_netlogon_sam_sync(cli, mem_ctx, ret_creds, db_type,
					       sync_context,
					       &num_deltas, &hdr_deltas, &deltas);
		if (NT_STATUS_IS_ERR(result))
			break;

		clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), ret_creds);
                for (i = 0; i < num_deltas; i++) {
			display_sam_entry(&hdr_deltas[i], &deltas[i]);
                }
		sync_context += 1;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);
}

/* dump sam database via samsync rpc calls */
NTSTATUS rpc_samdump_internals(const DOM_SID *domain_sid, 
			       const char *domain_name, 
			       struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			       int argc, const char **argv) 
{
	NTSTATUS nt_status = NT_STATUS_UNSUCCESSFUL;
	uchar trust_password[16];
	DOM_CRED ret_creds;
	uint32 sec_channel;

	ZERO_STRUCT(ret_creds);

	fstrcpy(cli->domain, domain_name);

	if (!secrets_fetch_trust_account_password(domain_name,
						  trust_password,
						  NULL, &sec_channel)) {
		DEBUG(0,("Could not fetch trust account password\n"));
		goto fail;
	}

	if (!NT_STATUS_IS_OK(nt_status = cli_nt_establish_netlogon(cli, sec_channel,
								   trust_password))) {
		DEBUG(0,("Error connecting to NETLOGON pipe\n"));
		goto fail;
	}

	dump_database(cli, SAM_DATABASE_DOMAIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_BUILTIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds);

        nt_status = NT_STATUS_OK;

fail:
	cli_nt_session_close(cli);
	return nt_status;
}

/* Convert a SAM_ACCOUNT_DELTA to a SAM_ACCOUNT. */
#define STRING_CHANGED (old_string && !new_string) ||\
		    (!old_string && new_string) ||\
		(old_string && new_string && (strcmp(old_string, new_string) != 0))

static void sam_account_from_delta(SAM_ACCOUNT *account,
				   SAM_ACCOUNT_INFO *delta,
				   const char *unix_name)
{
	const char *old_string, *new_string;
	time_t unix_time, stored_time;
	uchar lm_passwd[16], nt_passwd[16];
	static uchar zero_buf[16];

	/* Username, fullname, home dir, dir drive, logon script, acct
	   desc, workstations, profile. */

	{
		old_string = pdb_get_username(account);
		new_string = unix_name;

		if (STRING_CHANGED) {
			pdb_set_username(account, new_string, PDB_CHANGED);
		}
	}

	if (delta->hdr_full_name.buffer) {
		old_string = pdb_get_fullname(account);
		new_string = unistr2_static(&delta->uni_full_name);

		if (STRING_CHANGED)
			pdb_set_fullname(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_home_dir.buffer) {
		old_string = pdb_get_homedir(account);
		new_string = unistr2_static(&delta->uni_home_dir);

		if (STRING_CHANGED)
			pdb_set_homedir(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_dir_drive.buffer) {
		old_string = pdb_get_dir_drive(account);
		new_string = unistr2_static(&delta->uni_dir_drive);

		if (STRING_CHANGED)
			pdb_set_dir_drive(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_logon_script.buffer) {
		old_string = pdb_get_logon_script(account);
		new_string = unistr2_static(&delta->uni_logon_script);

		if (STRING_CHANGED)
			pdb_set_logon_script(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_acct_desc.buffer) {
		old_string = pdb_get_acct_desc(account);
		new_string = unistr2_static(&delta->uni_acct_desc);

		if (STRING_CHANGED)
			pdb_set_acct_desc(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_workstations.buffer) {
		old_string = pdb_get_workstations(account);
		new_string = unistr2_static(&delta->uni_workstations);

		if (STRING_CHANGED)
			pdb_set_workstations(account, new_string, PDB_CHANGED);
	}

	if (delta->hdr_profile.buffer) {
		old_string = pdb_get_profile_path(account);
		new_string = unistr2_static(&delta->uni_profile);

		if (STRING_CHANGED)
			pdb_set_profile_path(account, new_string, PDB_CHANGED);
	}

	/* Logon and password information */
	if (!nt_time_is_zero(&delta->logon_time)) {
		unix_time = nt_time_to_unix(&delta->logon_time);
		stored_time = pdb_get_logon_time(account);
		if (stored_time != unix_time)
			pdb_set_logon_time(account, unix_time, PDB_CHANGED);
	}

	if (!nt_time_is_zero(&delta->logoff_time)) {
		unix_time = nt_time_to_unix(&delta->logoff_time);
		stored_time = pdb_get_logoff_time(account);
		if (stored_time != unix_time)
			pdb_set_logoff_time(account, unix_time,PDB_CHANGED);
	}

	if (pdb_get_logon_divs(account) != delta->logon_divs)
		pdb_set_logon_divs(account, delta->logon_divs, PDB_CHANGED);

	/* TODO: logon hours */
	/* TODO: bad password count */
	/* TODO: logon count */

	if (!nt_time_is_zero(&delta->pwd_last_set_time)) {
		unix_time = nt_time_to_unix(&delta->pwd_last_set_time);
		stored_time = pdb_get_pass_last_set_time(account);
		if (stored_time != unix_time)
			pdb_set_pass_last_set_time(account, unix_time,
						   PDB_CHANGED);
	}

	/* Decode hashes from password hash 

	   Note that win2000 may send us all zeros for the hashes if it
	   doesn't think this channel is secure enough - don't set the
	   passwords at all in that case
	*/

	if (memcmp(delta->pass.buf_lm_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(delta->user_rid, delta->pass.buf_lm_pwd,
			     lm_passwd, 0);
		pdb_set_lanman_passwd(account, lm_passwd, PDB_CHANGED);
	}

	if (memcmp(delta->pass.buf_nt_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(delta->user_rid, delta->pass.buf_nt_pwd,
			     nt_passwd, 0);
		pdb_set_nt_passwd(account, nt_passwd, PDB_CHANGED);
	}

	/* TODO: account expiry time */

	if (pdb_get_acct_ctrl(account) != delta->acb_info)
		pdb_set_acct_ctrl(account, delta->acb_info, PDB_CHANGED);

	pdb_set_domain(account, lp_workgroup(), PDB_CHANGED);
}

static BOOL fetch_account_info(TALLOC_CTX *mem_ctx, const DOM_SID *dom_sid,
			       uint32 rid, SAM_ACCOUNT_INFO *delta)
{
	fstring name;
	char *unix_name;
	SAM_ACCOUNT *sam_account=NULL;
	DOM_SID user_sid;
	DOM_SID group_sid;
	fstring groupname;
	struct passwd *pwd;
	BOOL is_user;
	int ret;
	unid_t id;
	gid_t gid;
	const char *add_script;

	unistr2_to_ascii(name, &delta->uni_acct_name, sizeof(name)-1);

	sid_copy(&user_sid, dom_sid);
	sid_append_rid(&user_sid, delta->user_rid);

	sid_copy(&group_sid, dom_sid);
	sid_append_rid(&group_sid, delta->group_rid);

	if (nt_to_unix_name(mem_ctx, name, &unix_name, &is_user)) {
		d_printf("Name %s exists, stopping\n", name);
		return False;
	}

	if ((pwd = getpwnam(name)) != NULL) {
		d_printf("User %s exists, trying to invent a new name\n",
			 name);
		unix_name = invent_username(mem_ctx, name);
	} else {
		d_printf("User %s does not exist, trying native name\n",
			 name);
		unix_name = talloc_strdup(mem_ctx, name);
	}

	if (unix_name == NULL) {
		d_printf("No unix name for %s, stopping\n", name);
		return False;
	}

	/* Try to find primary group */

	if (!NT_STATUS_IS_OK(sid_to_gid(&group_sid, &gid))) {
		d_printf("No gid for primary group SID %s\n",
			 sid_string_static(&group_sid));
		return False;
	}

	if (!sid_to_local_dom_grp_name(&group_sid, groupname)) {
		d_printf("Could not find primary group %s for user %s\n",
			 sid_string_static(&group_sid), name);
		return False;
	}

	add_script = ((delta->acb_info & ACB_NORMAL) != 0) ?
		lp_adduser_script() : lp_addmachine_script();

	if ((ret = smb_create_account(add_script, unix_name)) != 0) {
		d_printf("Error creating user %s: %d\n", unix_name, ret);

		unix_name = invent_username(mem_ctx, name);
		d_printf("Retrying with invented name %s\n", unix_name);

		if ((ret = smb_create_account(add_script, unix_name)) != 0) {
			d_printf("Error creating user %s: %d\n", name, ret);
			return False;
		}
	}

	if ((ret = smb_set_primary_group(groupname, unix_name)) != 0) {
		d_printf("Could not set primary group of user %s to %s: %d\n",
			 unix_name, groupname, ret);
		return False;
	}

	if ((pwd = getpwnam(unix_name)) == NULL) {
		d_printf("User %s created, but not there\n", unix_name);
		return False;
	}

	if (pwd->pw_gid != gid) {
		d_printf("Setting primary group id failed for user %s\n",
			 name);
	}

	if (!create_name_mapping(pwd->pw_name, name, True)) {
		d_printf("Could not create name mapping\n");
		return False;
	}

	id.uid = pwd->pw_uid;

	if (!NT_STATUS_IS_OK(idmap_set_mapping(&user_sid, id, ID_USERID))) {
		d_printf("Could not create id mapping\n");
		return False;
	}

	/* Ok, finally get the additional NT attributes right */

	pdb_init_sam(&sam_account);
	sam_account_from_delta(sam_account, delta, pwd->pw_name);

	if (!pdb_add_sam_account(sam_account)) {
		d_printf("Could not add sam account\n");
		return False;
	}

	pdb_free_sam(&sam_account);
	return True;
}

static BOOL fetch_group_info(TALLOC_CTX *mem_ctx, const DOM_SID *dom_sid,
			     uint32 rid, SAM_GROUP_INFO *delta)
{
	fstring name;
	char *unix_name;
	fstring comment;
	DOM_SID group_sid;
	BOOL is_user;
	struct group *grp;
	gid_t gid;
	int ret;
	unid_t id;

	unistr2_to_ascii(name, &delta->uni_grp_name, sizeof(name)-1);
	unistr2_to_ascii(comment, &delta->uni_grp_desc, sizeof(comment)-1);

	sid_copy(&group_sid, dom_sid);
	sid_append_rid(&group_sid, rid);

	if (nt_to_unix_name(mem_ctx, name, &unix_name, &is_user)) {
		d_printf("Name %s exists, stopping\n", name);
		return False;
	}

	if ((grp = getgrnam(name)) != NULL) {
		d_printf("Group %s exists, trying to invent a new name\n",
			 name);
		unix_name = invent_groupname(mem_ctx, name);
	} else {
		d_printf("Group %s does not exist, trying native name\n",
			 name);
		unix_name = talloc_strdup(mem_ctx, name);
	}

	if (unix_name == NULL) {
		d_printf("No unix name for %s, stopping\n", name);
		return False;
	}

	if ((ret = smb_create_group(unix_name, &gid)) != 0) {
		d_printf("Error creating group %s: %d\n", unix_name, ret);

		unix_name = invent_groupname(mem_ctx, name);
		d_printf("Retrying with invented name %s\n", unix_name);

		if ((ret = smb_create_group(unix_name, &gid)) != 0) {
			d_printf("Error creating group %s: %d\n", name, ret);
			return False;
		}
	}

	if ((grp = getgrgid(gid)) == NULL) {
		d_printf("Group created, but not there\n");
		return False;
	}

	if (!create_name_mapping(grp->gr_name, name, False)) {
		d_printf("Could not create name mapping\n");
		return False;
	}

	id.gid = gid;

	if (!NT_STATUS_IS_OK(idmap_set_mapping(&group_sid, id, ID_GROUPID))) {
		d_printf("Could not create id mapping\n");
		return False;
	}

	if (!pdb_set_group_comment(unix_name, comment)) {
		d_printf("Could not set group comment\n");
		return False;
	}

	return True;
}

static BOOL fetch_group_mem_info(TALLOC_CTX *mem_ctx, const DOM_SID *dom_sid,
				 uint32 rid, SAM_GROUP_MEM_INFO *delta)
{
	int i;
	DOM_SID group_sid;
	struct group *grp;
	gid_t gid;

	if (delta->num_members == 0) {
		return True;
	}

	sid_copy(&group_sid, dom_sid);
	sid_append_rid(&group_sid, rid);

	if (!NT_STATUS_IS_OK(sid_to_gid(&group_sid, &gid))) {
		d_printf("Could not find global group %d\n", rid);
		return False;
	}

	if (!(grp = getgrgid(gid))) {
		d_printf("Could not find unix group %d\n", gid);
		return False;
	}

	if ((grp->gr_mem != NULL) && (grp->gr_mem[0] != NULL)) {
		d_printf("Group %s has auxiliary members\n", grp->gr_name);
		return False;
	}

	for (i=0; i<delta->num_members; i++) {
		DOM_SID member_sid;
		uid_t uid;
		struct passwd *pwd;
		int res;

		sid_copy(&member_sid, dom_sid);
		sid_append_rid(&member_sid, delta->rids[i]);

		if (!NT_STATUS_IS_OK(sid_to_uid(&member_sid, &uid))) {
			d_printf("Could not find uid for member SID %s\n",
				 sid_string_static(&member_sid));
			return False;
		}

		if ((pwd = getpwuid(uid)) == NULL) {
			d_printf("Member %d not found in passwd\n", uid);
			return False;
		}

		if (pwd->pw_gid == gid) {
			d_printf("User %s has group %d as primary group\n",
				 pwd->pw_name, gid);
			continue;
		}

		res = smb_add_user_group(grp->gr_name, pwd->pw_name);

		if (res != 0) {
			d_printf("Could not add user %s to group %s\n",
				 pwd->pw_name, pwd->pw_name);
			return False;
		}
	}

	return True;
}

static BOOL fetch_alias_info(TALLOC_CTX *mem_ctx, uint32 rid,
			     SAM_ALIAS_INFO *delta, const DOM_SID *dom_sid)
{
	fstring name;
	fstring comment;
	DOM_SID alias_sid;
	char *unix_name;
	BOOL is_user;

	unistr2_to_ascii(name, &delta->uni_als_name, sizeof(name)-1);
	unistr2_to_ascii(comment, &delta->uni_als_desc, sizeof(comment)-1);

	sid_copy(&alias_sid, dom_sid);
	sid_append_rid(&alias_sid, rid);

	if (nt_to_unix_name(mem_ctx, name, &unix_name, &is_user)) {
		d_printf("Name %s exists, stopping\n", name);
		return False;
	}

	if (!new_alias(name, &alias_sid)) {
		d_printf("Could not create alias %s\n", name);
		return False;
	}

	if (!pdb_set_group_comment(name, comment)) {
		d_printf("Could not set comment of [%s] to [%s]\n",
			 name, comment);
		return False;
	}

	return True;
}

static BOOL fetch_alias_mem(TALLOC_CTX *mem_ctx, uint32 rid,
			    SAM_ALIAS_MEM_INFO *delta, const DOM_SID *dom_sid)
{
	DOM_SID alias_sid;
	int i;

	sid_copy(&alias_sid, dom_sid);
	sid_append_rid(&alias_sid, rid);

	for (i=0; i<delta->num_members; i++) {
		if (!pdb_add_aliasmem(&alias_sid, &delta->sids[i].sid)) {
			d_printf("Could not add member %s to alias %s\n",
				 sid_string_static(&delta->sids[i].sid),
				 sid_string_static(&alias_sid));
			return False;
		}
	}

	return True;
}

static BOOL
fetch_sam_entry(TALLOC_CTX *mem_ctx, SAM_DELTA_HDR *hdr_delta,
		SAM_DELTA_CTR *delta, const DOM_SID *dom_sid)
{
	switch(hdr_delta->type) {
	case SAM_DELTA_ACCOUNT_INFO:
		return fetch_account_info(mem_ctx, dom_sid,
					  hdr_delta->target_rid,
					  &delta->account_info);
		break;
	case SAM_DELTA_GROUP_INFO:
		return fetch_group_info(mem_ctx, dom_sid,
					hdr_delta->target_rid,
					&delta->group_info);
		break;
	case SAM_DELTA_GROUP_MEM:
		return fetch_group_mem_info(mem_ctx, dom_sid,
					    hdr_delta->target_rid,
					    &delta->grp_mem_info);
		break;
	case SAM_DELTA_ALIAS_INFO:
		return fetch_alias_info(mem_ctx, hdr_delta->target_rid,
					&delta->alias_info, dom_sid);
	case SAM_DELTA_ALIAS_MEM:
		return fetch_alias_mem(mem_ctx, hdr_delta->target_rid,
				       &delta->als_mem_info, dom_sid);
		break;
	/* The following types are recognised but not handled */
	case SAM_DELTA_DOMAIN_INFO:
		d_printf("SAM_DELTA_DOMAIN_INFO not handled\n");
		break;
	case SAM_DELTA_RENAME_GROUP:
		d_printf("SAM_DELTA_RENAME_GROUP not handled\n");
		break;
	case SAM_DELTA_RENAME_USER:
		d_printf("SAM_DELTA_RENAME_USER not handled\n");
		break;
	case SAM_DELTA_RENAME_ALIAS:
		d_printf("SAM_DELTA_RENAME_ALIAS not handled\n");
		break;
	case SAM_DELTA_POLICY_INFO:
		d_printf("SAM_DELTA_POLICY_INFO not handled\n");
		break;
	case SAM_DELTA_TRUST_DOMS:
		d_printf("SAM_DELTA_TRUST_DOMS not handled\n");
		break;
	case SAM_DELTA_PRIVS_INFO:
		d_printf("SAM_DELTA_PRIVS_INFO not handled\n");
		break;
	case SAM_DELTA_SECRET_INFO:
		d_printf("SAM_DELTA_SECRET_INFO not handled\n");
		break;
	case SAM_DELTA_DELETE_GROUP:
		d_printf("SAM_DELTA_DELETE_GROUP not handled\n");
		break;
	case SAM_DELTA_DELETE_USER:
		d_printf("SAM_DELTA_DELETE_USER not handled\n");
		break;
	case SAM_DELTA_MODIFIED_COUNT:
		d_printf("SAM_DELTA_MODIFIED_COUNT not handled\n");
		break;
	default:
		d_printf("Unknown delta record type %d\n", hdr_delta->type);
		break;
	}
	return True;
}

static NTSTATUS
fetch_database(struct cli_state *cli, unsigned db_type, DOM_CRED *ret_creds,
	       const DOM_SID *dom_sid)
{
	unsigned sync_context = 0;
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32 num_deltas;

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
		result = cli_netlogon_sam_sync(cli, mem_ctx, ret_creds,
					       db_type, sync_context,
					       &num_deltas,
					       &hdr_deltas, &deltas);

		if (NT_STATUS_IS_OK(result) ||
		    NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {

			clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred),
					     ret_creds);

			for (i = 0; i < num_deltas; i++) {
				if (!fetch_sam_entry(mem_ctx, &hdr_deltas[i],
						     &deltas[i], dom_sid)) {
					result = NT_STATUS_UNSUCCESSFUL;
					break;
				}
			}
		} else
			return result;

		sync_context += 1;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);

	return result;
}

/* dump sam database via samsync rpc calls */
NTSTATUS rpc_vampire_internals(const DOM_SID *domain_sid, 
			       const char *domain_name, 
			       struct cli_state *cli, TALLOC_CTX *mem_ctx, 
			       int argc, const char **argv) 
{
        NTSTATUS result;
	uchar trust_password[16];
	DOM_CRED ret_creds;
	fstring my_dom_sid_str;
	fstring rem_dom_sid_str;
	uint32 sec_channel;

	ZERO_STRUCT(ret_creds);

	if (!idmap_init(lp_idmap_backend())) {
		d_printf("Could not init idmap\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (!sid_equal(domain_sid, get_global_sam_sid())) {
		d_printf("Cannot import users from %s at this time, "
			 "as the current domain:\n\t%s: %s\nconflicts "
			 "with the remote domain\n\t%s: %s\n"
			 "Perhaps you need to set: \n\n\tsecurity=user\n\tworkgroup=%s\n\n in your smb.conf?\n",
			 domain_name,
			 get_global_sam_name(), sid_to_string(my_dom_sid_str, 
							      get_global_sam_sid()),
			 domain_name, sid_to_string(rem_dom_sid_str, domain_sid),
			 domain_name);
		return NT_STATUS_UNSUCCESSFUL;
	}

	fstrcpy(cli->domain, domain_name);

	if (!secrets_fetch_trust_account_password(domain_name,
						  trust_password, NULL,
						  &sec_channel)) {
		result = NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		d_printf("Could not retrieve domain trust secret\n");
		goto fail;
	}
	
	result = cli_nt_establish_netlogon(cli, sec_channel, trust_password);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to setup BDC creds\n");
		goto fail;
	}

	result = fetch_database(cli, SAM_DATABASE_DOMAIN, &ret_creds,
				domain_sid);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to fetch domain database: %s\n",
			 nt_errstr(result));
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED))
			d_printf("Perhaps %s is a Windows 2000 native mode "
				 "domain?\n", domain_name);
		goto fail;
	}

	result = fetch_database(cli, SAM_DATABASE_BUILTIN, &ret_creds, 
				&global_sid_Builtin);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to fetch builtin database: %s\n",
			 nt_errstr(result));
		goto fail;
	}

	/* Currently we crash on PRIVS somewhere in unmarshalling */
	/* Dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds); */

fail:
	return result;
}
