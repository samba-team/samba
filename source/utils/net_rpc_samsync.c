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

static NTSTATUS
sam_account_from_delta(SAM_ACCOUNT *account, SAM_ACCOUNT_INFO *delta)
{
	const char *old_string, *new_string;
	time_t unix_time, stored_time;
	uchar lm_passwd[16], nt_passwd[16];
	static uchar zero_buf[16];

	/* Username, fullname, home dir, dir drive, logon script, acct
	   desc, workstations, profile. */

	if (delta->hdr_acct_name.buffer) {
		old_string = pdb_get_nt_username(account);
		new_string = unistr2_static(&delta->uni_acct_name);

		if (STRING_CHANGED) {
			pdb_set_nt_username(account, new_string, PDB_CHANGED);
              
		}
         
		/* Unix username is the same - for sanity */
		old_string = pdb_get_username( account );
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

	/* User and group sid */
	if (pdb_get_user_rid(account) != delta->user_rid)
		pdb_set_user_sid_from_rid(account, delta->user_rid, PDB_CHANGED);
	if (pdb_get_group_rid(account) != delta->group_rid)
		pdb_set_group_sid_from_rid(account, delta->group_rid, PDB_CHANGED);

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
			pdb_set_pass_last_set_time(account, unix_time, PDB_CHANGED);
	}

#if 0
/*	No kickoff time in the delta? */
	if (!nt_time_is_zero(&delta->kickoff_time)) {
		unix_time = nt_time_to_unix(&delta->kickoff_time);
		stored_time = pdb_get_kickoff_time(account);
		if (stored_time != unix_time)
			pdb_set_kickoff_time(account, unix_time, PDB_CHANGED);
	}
#endif

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

	if (pdb_get_acct_ctrl(account) != delta->acb_info)
		pdb_set_acct_ctrl(account, delta->acb_info, PDB_CHANGED);

	pdb_set_domain(account, lp_workgroup(), PDB_CHANGED);

	return NT_STATUS_OK;
}

static NTSTATUS fetch_account_info(uint32 rid, SAM_ACCOUNT_INFO *delta)
{
	NTSTATUS nt_ret;
	fstring account;
	pstring add_script;
	SAM_ACCOUNT *sam_account=NULL;
	GROUP_MAP map;
	struct group *grp;
	DOM_SID user_sid;
	DOM_SID group_sid;
	struct passwd *passwd;
	fstring sid_string;

	fstrcpy(account, unistr2_static(&delta->uni_acct_name));
	d_printf("Creating account: %s\n", account);

	if (!NT_STATUS_IS_OK(nt_ret = pdb_init_sam(&sam_account)))
		return nt_ret;

	if (!(passwd = Get_Pwnam(account))) {
		/* Create appropriate user */
		if (delta->acb_info & ACB_NORMAL) {
			pstrcpy(add_script, lp_adduser_script());
		} else if ( (delta->acb_info & ACB_WSTRUST) ||
			    (delta->acb_info & ACB_SVRTRUST) ||
			    (delta->acb_info & ACB_DOMTRUST) ) {
			pstrcpy(add_script, lp_addmachine_script());
		} else {
			DEBUG(1, ("Unknown user type: %s\n",
				  pdb_encode_acct_ctrl(delta->acb_info, NEW_PW_FORMAT_SPACE_PADDED_LEN)));
			nt_ret = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		if (*add_script) {
			int add_ret;
			all_string_sub(add_script, "%u", account,
				       sizeof(account));
			add_ret = smbrun(add_script,NULL);
			DEBUG(1,("fetch_account: Running the command `%s' "
				 "gave %d\n", add_script, add_ret));
		} else {
			DEBUG(8,("fetch_account_info: no add user/machine script.  Asking winbindd\n"));
			
			/* don't need a RID allocated since the user already has a SID */
			if ( !winbind_create_user( account, NULL ) )
				DEBUG(4,("fetch_account_info: winbind_create_user() failed\n"));
		}
		
		/* try and find the possible unix account again */
		if ( !(passwd = Get_Pwnam(account)) ) {
			d_printf("Could not create posix account info for '%s'\n", account);
			nt_ret = NT_STATUS_NO_SUCH_USER;
			goto done;
		}
	}
	
	sid_copy(&user_sid, get_global_sam_sid());
	sid_append_rid(&user_sid, delta->user_rid);

	DEBUG(3, ("Attempting to find SID %s for user %s in the passdb\n", sid_to_string(sid_string, &user_sid), account));
	if (!pdb_getsampwsid(sam_account, &user_sid)) {
		sam_account_from_delta(sam_account, delta);
		DEBUG(3, ("Attempting to add user SID %s for user %s in the passdb\n", 
			  sid_to_string(sid_string, &user_sid), pdb_get_username(sam_account)));
		if (!pdb_add_sam_account(sam_account)) {
			DEBUG(1, ("SAM Account for %s failed to be added to the passdb!\n",
				  account));
			return NT_STATUS_ACCESS_DENIED; 
		}
	} else {
		sam_account_from_delta(sam_account, delta);
		DEBUG(3, ("Attempting to update user SID %s for user %s in the passdb\n", 
			  sid_to_string(sid_string, &user_sid), pdb_get_username(sam_account)));
		if (!pdb_update_sam_account(sam_account)) {
			DEBUG(1, ("SAM Account for %s failed to be updated in the passdb!\n",
				  account));
			pdb_free_sam(&sam_account);
			return NT_STATUS_ACCESS_DENIED; 
		}
	}

	group_sid = *pdb_get_group_sid(sam_account);

	if (!pdb_getgrsid(&map, group_sid)) {
		DEBUG(0, ("Primary group of %s has no mapping!\n",
			  pdb_get_username(sam_account)));
	} else {
		if (map.gid != passwd->pw_gid) {
			if (!(grp = getgrgid(map.gid))) {
				DEBUG(0, ("Could not find unix group %lu for user %s (group SID=%s)\n", 
					  (unsigned long)map.gid, pdb_get_username(sam_account), sid_string_static(&group_sid)));
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
	pdb_free_sam(&sam_account);
	return nt_ret;
}

static NTSTATUS
fetch_group_info(uint32 rid, SAM_GROUP_INFO *delta)
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
	if (delta->hdr_grp_desc.buffer) {
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

static NTSTATUS
fetch_group_mem_info(uint32 rid, SAM_GROUP_MEM_INFO *delta)
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

static NTSTATUS fetch_alias_info(uint32 rid, SAM_ALIAS_INFO *delta,
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

static NTSTATUS
fetch_alias_mem(uint32 rid, SAM_ALIAS_MEM_INFO *delta, DOM_SID dom_sid)
{
#if 0 	/* 
	 * commented out right now after talking to Volker.  Can't
	 * do much with the membership but seemed a shame to waste
	 * somewhat working code.  Needs testing because the membership
	 * that shows up surprises me.  Also can't do much with groups
	 * in groups (e.g. Domain Admins being a member of Adminsitrators).
	 * --jerry
	 */
	
	int i;
	TALLOC_CTX *t = NULL;
	char **nt_members = NULL;
	char **unix_members;
	DOM_SID group_sid;
	GROUP_MAP map;
	struct group *grp;
	enum SID_NAME_USE sid_type;

	if (delta->num_members == 0) {
		return NT_STATUS_OK;
	}

	sid_copy(&group_sid, &dom_sid);
	sid_append_rid(&group_sid, rid);

	if (sid_equal(&dom_sid, &global_sid_Builtin)) {
		sid_type = SID_NAME_WKN_GRP;
		if (!get_builtin_group_from_sid(&group_sid, &map, False)) {
			DEBUG(0, ("Could not find builtin group %s\n", sid_string_static(&group_sid)));
			return NT_STATUS_NO_SUCH_GROUP;
		}
	} else {
		sid_type = SID_NAME_ALIAS;
		if (!get_local_group_from_sid(&group_sid, &map, False)) {
			DEBUG(0, ("Could not find local group %s\n", sid_string_static(&group_sid)));
			return NT_STATUS_NO_SUCH_GROUP;
		}
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

		sid_copy(&member_sid, &delta->sids[i].sid);

		if (!pdb_getsampwsid(member, &member_sid)) {
			DEBUG(1, ("Found bogus group member: (member_sid=%s group=%s)\n",
				  sid_string_static(&member_sid), grp->gr_name));
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

#endif	/* end of fetch_alias_mem() */

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
}

static NTSTATUS
fetch_database(struct cli_state *cli, unsigned db_type, DOM_CRED *ret_creds,
	       DOM_SID dom_sid)
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
				fetch_sam_entry(&hdr_deltas[i], &deltas[i], dom_sid);
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

	result = fetch_database(cli, SAM_DATABASE_DOMAIN, &ret_creds, *domain_sid);

	if (!NT_STATUS_IS_OK(result)) {
		d_printf("Failed to fetch domain database: %s\n",
			 nt_errstr(result));
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_SUPPORTED))
			d_printf("Perhaps %s is a Windows 2000 native mode "
				 "domain?\n", domain_name);
		goto fail;
	}

	result = fetch_database(cli, SAM_DATABASE_BUILTIN, &ret_creds, 
				global_sid_Builtin);

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
