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

static void display_group_mem_info(uint32_t rid, SAM_GROUP_MEM_INFO *g)
{
	int i;
	d_printf("Group mem %u: ", rid);
	for (i=0;i<g->num_members;i++) {
		d_printf("%u ", g->rids[i]);
	}
	d_printf("\n");
}

static void display_alias_info(uint32_t rid, SAM_ALIAS_INFO *a)
{
	d_printf("Alias '%s' ", unistr2_static(&a->uni_als_name));
	d_printf("desc='%s' rid=%u\n", unistr2_static(&a->uni_als_desc), a->als_rid);
}

static void display_alias_mem(uint32_t rid, SAM_ALIAS_MEM_INFO *a)
{
	int i;
	d_printf("Alias rid %u: ", rid);
	for (i=0;i<a->num_members;i++) {
		d_printf("%s ", sid_string_static(&a->sids[i].sid));
	}
	d_printf("\n");
}

static void display_account_info(uint32_t rid, SAM_ACCOUNT_INFO *a)
{
	fstring hex_nt_passwd, hex_lm_passwd;
	uint8_t lm_passwd[16], nt_passwd[16];
	static uint8_t zero_buf[16];

	/* Decode hashes from password hash (if they are not NULL) */
	
	if (memcmp(a->pass.buf_lm_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(a->user_rid, a->pass.buf_lm_pwd, lm_passwd, 0);
		smbpasswd_sethexpwd(hex_lm_passwd, lm_passwd, a->acb_info);
	} else {
		smbpasswd_sethexpwd(hex_lm_passwd, NULL, 0);
	}

	if (memcmp(a->pass.buf_nt_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(a->user_rid, a->pass.buf_nt_pwd, nt_passwd, 0);
		smbpasswd_sethexpwd(hex_nt_passwd, nt_passwd, a->acb_info);
	} else {
		smbpasswd_sethexpwd(hex_nt_passwd, NULL, 0);
	}
	
	printf("%s:%d:%s:%s:%s:LCT-0\n", unistr2_static(&a->uni_acct_name),
	       a->user_rid, hex_lm_passwd, hex_nt_passwd,
	       smbpasswd_encode_acb_info(a->acb_info));
}

static void display_domain_info(SAM_DOMAIN_INFO *a)
{
	d_printf("Domain name: %s\n", unistr2_static(&a->uni_dom_name));
}

static void display_group_info(uint32_t rid, SAM_GROUP_INFO *a)
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
	default:
		d_printf("Unknown delta record type %d\n", hdr_delta->type);
		break;
	}
}


static void dump_database(struct cli_state *cli, uint_t db_type, DOM_CRED *ret_creds)
{
	uint_t sync_context = 0;
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32_t num_deltas;

	if (!(mem_ctx = talloc_init("dump_database"))) {
		return;
	}

	d_printf("Dumping database %u\n", db_type);

	do {
		result = cli_netlogon_sam_sync(cli, mem_ctx, ret_creds, db_type,
					       sync_context,
					       &num_deltas, &hdr_deltas, &deltas);
		clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), ret_creds);
                for (i = 0; i < num_deltas; i++) {
			display_sam_entry(&hdr_deltas[i], &deltas[i]);
                }
		sync_context += 1;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);
}

/* dump sam database via samsync rpc calls */
int rpc_samdump(int argc, const char **argv)
{
        NTSTATUS result;
	struct cli_state *cli = NULL;
	uint8_t trust_password[16];
	DOM_CRED ret_creds;
	uint32_t neg_flags = 0x000001ff;


	ZERO_STRUCT(ret_creds);

	/* Connect to remote machine */
	if (!(cli = net_make_ipc_connection(NET_FLAGS_ANONYMOUS | NET_FLAGS_PDC))) {
		return 1;
	}

	if (!cli_nt_session_open(cli, PI_NETLOGON)) {
		DEBUG(0,("Error connecting to NETLOGON pipe\n"));
		goto fail;
	}

	if (!secrets_fetch_trust_account_password(lp_workgroup(), trust_password, NULL)) {
		d_printf("Could not retrieve domain trust secret\n");
		goto fail;
	}
	
	result = cli_nt_setup_creds(cli, SEC_CHAN_BDC,  trust_password, &neg_flags, 2);
	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to setup BDC creds\n");
		goto fail;
	}

	dump_database(cli, SAM_DATABASE_DOMAIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_BUILTIN, &ret_creds);
	dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds);

	cli_nt_session_close(cli);
        
        return 0;

fail:
	if (cli) {
		cli_nt_session_close(cli);
	}
	return -1;
}

/* Convert a SAM_ACCOUNT_DELTA to a SAM_ACCOUNT. */

static NTSTATUS
sam_account_from_delta(SAM_ACCOUNT *account, SAM_ACCOUNT_INFO *delta)
{
	fstring s;
	uint8_t lm_passwd[16], nt_passwd[16];
	static uint8_t zero_buf[16];

	/* Username, fullname, home dir, dir drive, logon script, acct
	   desc, workstations, profile. */

	unistr2_to_ascii(s, &delta->uni_acct_name, sizeof(s) - 1);
	pdb_set_nt_username(account, s, PDB_CHANGED);

	/* Unix username is the same - for sainity */
	pdb_set_username(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_full_name, sizeof(s) - 1);
	pdb_set_fullname(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_home_dir, sizeof(s) - 1);
	pdb_set_homedir(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_dir_drive, sizeof(s) - 1);
	pdb_set_dir_drive(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_logon_script, sizeof(s) - 1);
	pdb_set_logon_script(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_acct_desc, sizeof(s) - 1);
	pdb_set_acct_desc(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_workstations, sizeof(s) - 1);
	pdb_set_workstations(account, s, PDB_CHANGED);

	unistr2_to_ascii(s, &delta->uni_profile, sizeof(s) - 1);
	pdb_set_profile_path(account, s, PDB_CHANGED);

	/* User and group sid */

	pdb_set_user_sid_from_rid(account, delta->user_rid, PDB_CHANGED);
	pdb_set_group_sid_from_rid(account, delta->group_rid, PDB_CHANGED);

	/* Logon and password information */

	pdb_set_logon_time(account, nt_time_to_unix(&delta->logon_time), PDB_CHANGED);
	pdb_set_logoff_time(account, nt_time_to_unix(&delta->logoff_time),
			    PDB_CHANGED);
	pdb_set_logon_divs(account, delta->logon_divs, PDB_CHANGED);

	/* TODO: logon hours */
	/* TODO: bad password count */
	/* TODO: logon count */

	pdb_set_pass_last_set_time(
		account, nt_time_to_unix(&delta->pwd_last_set_time), PDB_CHANGED);

	pdb_set_kickoff_time(account, get_time_t_max(), PDB_CHANGED);

	/* Decode hashes from password hash 
	   Note that win2000 may send us all zeros for the hashes if it doesn't 
	   think this channel is secure enough - don't set the passwords at all
	   in that case
	 */
	if (memcmp(delta->pass.buf_lm_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(delta->user_rid, delta->pass.buf_lm_pwd, lm_passwd, 0);
		pdb_set_lanman_passwd(account, lm_passwd, PDB_CHANGED);
	}

	if (memcmp(delta->pass.buf_nt_pwd, zero_buf, 16) != 0) {
		sam_pwd_hash(delta->user_rid, delta->pass.buf_nt_pwd, nt_passwd, 0);
		pdb_set_nt_passwd(account, nt_passwd, PDB_CHANGED);
	}

	/* TODO: account expiry time */

	pdb_set_acct_ctrl(account, delta->acb_info, PDB_CHANGED);
	return NT_STATUS_OK;
}

static NTSTATUS
fetch_account_info(uint32_t rid, SAM_ACCOUNT_INFO *delta)
{
	NTSTATUS nt_ret;
	fstring account;
	pstring add_script;
	SAM_ACCOUNT *sam_account=NULL;
	GROUP_MAP map;
	struct group *grp;
	DOM_SID sid;
	BOOL try_add = False;

	fstrcpy(account, unistr2_static(&delta->uni_acct_name));
	d_printf("Creating account: %s\n", account);

	if (!NT_STATUS_IS_OK(nt_ret = pdb_init_sam(&sam_account)))
		return nt_ret;

	if (!pdb_getsampwnam(sam_account, account)) {
		/* Create appropriate user */
		if (delta->acb_info & ACB_NORMAL) {
			pstrcpy(add_script, lp_adduser_script());
		} else if ( (delta->acb_info & ACB_WSTRUST) ||
			    (delta->acb_info & ACB_SVRTRUST) ) {
			pstrcpy(add_script, lp_addmachine_script());
		} else {
			DEBUG(1, ("Unknown user type: %s\n",
				  smbpasswd_encode_acb_info(delta->acb_info)));
			pdb_free_sam(&sam_account);
			return NT_STATUS_NO_SUCH_USER;
		}
		if (*add_script) {
			int add_ret;
			all_string_sub(add_script, "%u", account,
				       sizeof(account));
			add_ret = smbrun(add_script,NULL);
			DEBUG(1,("fetch_account: Running the command `%s' "
				 "gave %d\n", add_script, add_ret));
		}

		try_add = True;
	}

	sam_account_from_delta(sam_account, delta);

	if (try_add) { 
		if (!pdb_add_sam_account(sam_account)) {
			DEBUG(1, ("SAM Account for %s failed to be added to the passdb!\n",
				  account));
		}
	} else {
		if (!pdb_update_sam_account(sam_account)) {
			DEBUG(1, ("SAM Account for %s failed to be updated in the passdb!\n",
				  account));
		}
	}

	sid = *pdb_get_group_sid(sam_account);

	if (!pdb_getgrsid(&map, sid, False)) {
		DEBUG(0, ("Primary group of %s has no mapping!\n",
			  pdb_get_username(sam_account)));
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_SUCH_GROUP;
	}

	if (!(grp = getgrgid(map.gid))) {
		DEBUG(0, ("Could not find unix group %d for user %s (group SID=%s)\n", 
			  map.gid, pdb_get_username(sam_account), sid_string_static(&sid)));
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_SUCH_GROUP;
	}

	smb_set_primary_group(grp->gr_name, pdb_get_username(sam_account));

	pdb_free_sam(&sam_account);
	return NT_STATUS_OK;
}

static NTSTATUS
fetch_group_info(uint32_t rid, SAM_GROUP_INFO *delta)
{
	fstring name;
	fstring comment;
	struct group *grp = NULL;
	DOM_SID group_sid;
	fstring sid_string;
	GROUP_MAP map;
	BOOL insert = True;

	unistr2_to_ascii(name, &delta->uni_grp_name, sizeof(name)-1);
	unistr2_to_ascii(comment, &delta->uni_grp_desc, sizeof(comment)-1);

	/* add the group to the mapping table */
	sid_copy(&group_sid, get_global_sam_sid());
	sid_append_rid(&group_sid, rid);
	sid_to_string(sid_string, &group_sid);

	if (pdb_getgrsid(&map, group_sid, False)) {
		grp = getgrgid(map.gid);
		insert = False;
	}

	if (grp == NULL)
	{
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
	map.sid = group_sid;
	map.sid_name_use = SID_NAME_DOM_GRP;
	fstrcpy(map.nt_name, name);
	fstrcpy(map.comment, comment);

	map.priv_set.count = 0;
	map.priv_set.set = NULL;

	if (insert)
		pdb_add_group_mapping_entry(&map);
	else
		pdb_update_group_mapping_entry(&map);

	return NT_STATUS_OK;
}

static NTSTATUS
fetch_group_mem_info(uint32_t rid, SAM_GROUP_MEM_INFO *delta)
{
	int i;
	TALLOC_CTX *t = NULL;
	char **nt_members = NULL;
	char **unix_members;
	DOM_SID group_sid;
	GROUP_MAP map;
	struct group *grp;

	if (delta->num_members == 0) {
		return NT_STATUS_OK;
	}

	sid_copy(&group_sid, get_global_sam_sid());
	sid_append_rid(&group_sid, rid);

	if (!get_domain_group_from_sid(group_sid, &map, False)) {
		DEBUG(0, ("Could not find global group %d\n", rid));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	if (!(grp = getgrgid(map.gid))) {
		DEBUG(0, ("Could not find unix group %d\n", map.gid));
		return NT_STATUS_NO_SUCH_GROUP;
	}

	d_printf("Group members of %s: ", grp->gr_name);

	if (!(t = talloc_init("fetch_group_mem_info"))) {
		DEBUG(0, ("could not talloc_init\n"));
		return NT_STATUS_NO_MEMORY;
	}

	nt_members = talloc_zero(t, sizeof(char *) * delta->num_members);

	for (i=0; i<delta->num_members; i++) {
		NTSTATUS nt_status;
		SAM_ACCOUNT *member = NULL;
		DOM_SID member_sid;

		if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam_talloc(t, &member))) {
			talloc_destroy(t);
			return nt_status;
		}

		sid_copy(&member_sid, get_global_sam_sid());
		sid_append_rid(&member_sid, delta->rids[i]);

		if (!pdb_getsampwsid(member, &member_sid)) {
			DEBUG(1, ("Found bogus group member: %d (member_sid=%s group=%s)\n",
				  delta->rids[i], sid_string_static(&member_sid), grp->gr_name));
			pdb_free_sam(&member);
			continue;
		}

		if (pdb_get_group_rid(member) == rid) {
			d_printf("%s(primary),", pdb_get_username(member));
			pdb_free_sam(&member);
			continue;
		}
		
		d_printf("%s,", pdb_get_username(member));
		nt_members[i] = talloc_strdup(t, pdb_get_username(member));
		pdb_free_sam(&member);
	}

	d_printf("\n");

	unix_members = grp->gr_mem;

	while (*unix_members) {
		BOOL is_nt_member = False;
		for (i=0; i<delta->num_members; i++) {
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

	for (i=0; i<delta->num_members; i++) {
		BOOL is_unix_member = False;

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

static NTSTATUS fetch_alias_info(uint32_t rid, SAM_ALIAS_INFO *delta,
				 DOM_SID dom_sid)
{
	fstring name;
	fstring comment;
	struct group *grp = NULL;
	DOM_SID alias_sid;
	fstring sid_string;
	GROUP_MAP map;
	BOOL insert = True;

	unistr2_to_ascii(name, &delta->uni_als_name, sizeof(name)-1);
	unistr2_to_ascii(comment, &delta->uni_als_desc, sizeof(comment)-1);

	/* Find out whether the group is already mapped */
	sid_copy(&alias_sid, &dom_sid);
	sid_append_rid(&alias_sid, rid);
	sid_to_string(sid_string, &alias_sid);

	if (pdb_getgrsid(&map, alias_sid, False)) {
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

	map.priv_set.count = 0;
	map.priv_set.set = NULL;

	if (insert)
		pdb_add_group_mapping_entry(&map);
	else
		pdb_update_group_mapping_entry(&map);

	return NT_STATUS_OK;
}

static NTSTATUS
fetch_alias_mem(uint32_t rid, SAM_ALIAS_MEM_INFO *delta, DOM_SID dom_sid)
{
	
	return NT_STATUS_OK;
}

static void
fetch_sam_entry(SAM_DELTA_HDR *hdr_delta, SAM_DELTA_CTR *delta,
		DOM_SID dom_sid)
{
	switch(hdr_delta->type) {
	case SAM_DELTA_ACCOUNT_INFO:
		fetch_account_info(hdr_delta->target_rid,
				   &delta->account_info);
		break;
	case SAM_DELTA_GROUP_INFO:
		fetch_group_info(hdr_delta->target_rid,
				 &delta->group_info);
		break;
	case SAM_DELTA_GROUP_MEM:
		fetch_group_mem_info(hdr_delta->target_rid,
				     &delta->grp_mem_info);
		break;
	case SAM_DELTA_ALIAS_INFO:
		fetch_alias_info(hdr_delta->target_rid,
				 &delta->alias_info, dom_sid);
		break;
	case SAM_DELTA_ALIAS_MEM:
		fetch_alias_mem(hdr_delta->target_rid,
				&delta->als_mem_info, dom_sid);
		break;
	default:
		d_printf("Unknown delta record type %d\n", hdr_delta->type);
		break;
	}
}

static void
fetch_database(struct cli_state *cli, uint_t db_type, DOM_CRED *ret_creds,
	       DOM_SID dom_sid)
{
	uint_t sync_context = 0;
        NTSTATUS result;
	int i;
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32_t num_deltas;

	if (!(mem_ctx = talloc_init("fetch_database"))) {
		return;
	}

	d_printf("Fetching database %u\n", db_type);

	do {
		result = cli_netlogon_sam_sync(cli, mem_ctx, ret_creds,
					       db_type, sync_context,
					       &num_deltas,
					       &hdr_deltas, &deltas);
		clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred),
				     ret_creds);
                for (i = 0; i < num_deltas; i++) {
			fetch_sam_entry(&hdr_deltas[i], &deltas[i], dom_sid);
                }
		sync_context += 1;
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	talloc_destroy(mem_ctx);
}

/* dump sam database via samsync rpc calls */
int rpc_vampire(int argc, const char **argv)
{
        NTSTATUS result;
	struct cli_state *cli = NULL;
	uint8_t trust_password[16];
	DOM_CRED ret_creds;
	uint32_t neg_flags = 0x000001ff;
	DOM_SID dom_sid;

	ZERO_STRUCT(ret_creds);

	/* Connect to remote machine */
	if (!(cli = net_make_ipc_connection(NET_FLAGS_ANONYMOUS |
					    NET_FLAGS_PDC))) {
		return 1;
	}

	if (!cli_nt_session_open(cli, PI_NETLOGON)) {
		DEBUG(0,("Error connecting to NETLOGON pipe\n"));
		goto fail;
	}

	if (!secrets_fetch_trust_account_password(lp_workgroup(),
						  trust_password, NULL)) {
		d_printf("Could not retrieve domain trust secret\n");
		goto fail;
	}
	
	result = cli_nt_setup_creds(cli, SEC_CHAN_BDC,  trust_password,
				    &neg_flags, 2);
	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to setup BDC creds\n");
		goto fail;
	}

	dom_sid = *get_global_sam_sid();
	fetch_database(cli, SAM_DATABASE_DOMAIN, &ret_creds, dom_sid);

	sid_copy(&dom_sid, &global_sid_Builtin);
	fetch_database(cli, SAM_DATABASE_BUILTIN, &ret_creds, dom_sid);

	/* Currently we crash on PRIVS somewhere in unmarshalling */
	/* Dump_database(cli, SAM_DATABASE_PRIVS, &ret_creds); */

	cli_nt_session_close(cli);
        
        return 0;

fail:
	if (cli) {
		cli_nt_session_close(cli);
	}
	return -1;
}
