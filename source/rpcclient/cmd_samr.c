/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Andrew Tridgell              1992-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Elrond                            2000,
   Copyright (C) Tim Potter                        2000

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
#include "rpcclient.h"

extern DOM_SID domain_sid;

/****************************************************************************
 display sam_user_info_21 structure
 ****************************************************************************/
static void display_sam_user_info_21(SAM_USER_INFO_21 *usr)
{
	fstring temp;

	unistr2_to_unix(temp, &usr->uni_user_name, sizeof(temp)-1);
	printf("\tUser Name   :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_full_name, sizeof(temp)-1);
	printf("\tFull Name   :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_home_dir, sizeof(temp)-1);
	printf("\tHome Drive  :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_dir_drive, sizeof(temp)-1);
	printf("\tDir Drive   :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_profile_path, sizeof(temp)-1);
	printf("\tProfile Path:\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_logon_script, sizeof(temp)-1);
	printf("\tLogon Script:\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_acct_desc, sizeof(temp)-1);
	printf("\tDescription :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_workstations, sizeof(temp)-1);
	printf("\tWorkstations:\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_unknown_str, sizeof(temp)-1);
	printf("\tUnknown Str :\t%s\n", temp);
	
	unistr2_to_unix(temp, &usr->uni_munged_dial, sizeof(temp)-1);
	printf("\tRemote Dial :\t%s\n", temp);
	
	printf("\tLogon Time               :\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->logon_time)));
	printf("\tLogoff Time              :\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->logoff_time)));
	printf("\tKickoff Time             :\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->kickoff_time)));
	printf("\tPassword last set Time   :\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->pass_last_set_time)));
	printf("\tPassword can change Time :\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->pass_can_change_time)));
	printf("\tPassword must change Time:\t%s\n", 
	       http_timestring(nt_time_to_unix(&usr->pass_must_change_time)));
	
	printf("\tunknown_2[0..31]...\n"); /* user passwords? */
	
	printf("\tuser_rid :\t%x\n"  , usr->user_rid ); /* User ID */
	printf("\tgroup_rid:\t%x\n"  , usr->group_rid); /* Group ID */
	printf("\tacb_info :\t%04x\n", usr->acb_info ); /* Account Control Info */
	
	printf("\tunknown_3:\t%08x\n", usr->unknown_3); /* 0x00ff ffff */
	printf("\tlogon_divs:\t%d\n", usr->logon_divs); /* 0x0000 00a8 which is 168 which is num hrs in a week */
	printf("\tunknown_5:\t%08x\n", usr->unknown_5); /* 0x0002 0000 */
	
	printf("\tpadding1[0..7]...\n");
	
	if (usr->ptr_logon_hrs) {
		printf("\tlogon_hrs[0..%d]...\n", usr->logon_hrs.len);
	}
}

static const char *display_time(NTTIME nttime)
{
	static fstring string;

	float high;
	float low;
	int sec;
	int days, hours, mins, secs;

	if (nttime.high==0 && nttime.low==0)
		return "Now";

	if (nttime.high==0x80000000 && nttime.low==0)
		return "Never";

	high = 65536;	
	high = high/10000;
	high = high*65536;
	high = high/1000;
	high = high * (~nttime.high);

	low = ~nttime.low;	
	low = low/(1000*1000*10);

	sec=high+low;

	days=sec/(60*60*24);
	hours=(sec - (days*60*60*24)) / (60*60);
	mins=(sec - (days*60*60*24) - (hours*60*60) ) / 60;
	secs=sec - (days*60*60*24) - (hours*60*60) - (mins*60);

	snprintf(string, sizeof(string)-1, "%u days, %u hours, %u minutes, %u seconds", days, hours, mins, secs);
	return (string);
}

static void display_sam_unk_info_1(SAM_UNK_INFO_1 *info1)
{
	
	printf("Minimum password length:                     %d\n", info1->min_length_password);
	printf("Password uniqueness (remember x passwords):  %d\n", info1->password_history);
	printf("flag:                                        ");
	if(info1->flag&&2==2) printf("users must open a session to change password ");
	printf("\n");

	printf("password expire in:                          %s\n", display_time(info1->expire));
	printf("Min password age (allow changing in x days): %s\n", display_time(info1->min_passwordage));
}

static void display_sam_unk_info_2(SAM_UNK_INFO_2 *info2)
{
	fstring name;

	unistr2_to_unix(name, &info2->uni_domain, sizeof(name) - 1); 
	printf("Domain:\t%s\n", name);

	unistr2_to_unix(name, &info2->uni_server, sizeof(name) - 1); 
	printf("Server:\t%s\n", name);

	printf("Total Users:\t%d\n", info2->num_domain_usrs);
	printf("Total Groups:\t%d\n", info2->num_domain_grps);
	printf("Total Aliases:\t%d\n", info2->num_local_grps);
	
	printf("Sequence No:\t%d\n", info2->seq_num);
	
	printf("Unknown 0:\t0x%x\n", info2->unknown_0);
	printf("Unknown 1:\t0x%x\n", info2->unknown_1);
	printf("Unknown 2:\t0x%x\n", info2->unknown_2);
	printf("Unknown 3:\t0x%x\n", info2->unknown_3);
	printf("Unknown 4:\t0x%x\n", info2->unknown_4);
	printf("Unknown 5:\t0x%x\n", info2->unknown_5);
	printf("Unknown 6:\t0x%x\n", info2->unknown_6);
}

static void display_sam_info_1(SAM_ENTRY1 *e1, SAM_STR1 *s1)
{
	fstring tmp;

	printf("index: 0x%x ", e1->user_idx);
	printf("RID: 0x%x ", e1->rid_user);
	printf("acb: 0x%x ", e1->acb_info);
	
	unistr2_to_unix(tmp, &s1->uni_acct_name, sizeof(tmp)-1);
	printf("Account: %s\t", tmp);

	unistr2_to_unix(tmp, &s1->uni_full_name, sizeof(tmp)-1);
	printf("Name: %s\t", tmp);

	unistr2_to_unix(tmp, &s1->uni_acct_desc, sizeof(tmp)-1);
	printf("Desc: %s\n", tmp);
}

static void display_sam_info_2(SAM_ENTRY2 *e2, SAM_STR2 *s2)
{
	fstring tmp;

	printf("index: 0x%x ", e2->user_idx);
	printf("RID: 0x%x ", e2->rid_user);
	printf("acb: 0x%x ", e2->acb_info);
	
	unistr2_to_unix(tmp, &s2->uni_srv_name, sizeof(tmp)-1);
	printf("Account: %s\t", tmp);

	unistr2_to_unix(tmp, &s2->uni_srv_desc, sizeof(tmp)-1);
	printf("Name: %s\n", tmp);

}

static void display_sam_info_3(SAM_ENTRY3 *e3, SAM_STR3 *s3)
{
	fstring tmp;

	printf("index: 0x%x ", e3->grp_idx);
	printf("RID: 0x%x ", e3->rid_grp);
	printf("attr: 0x%x ", e3->attr);
	
	unistr2_to_unix(tmp, &s3->uni_grp_name, sizeof(tmp)-1);
	printf("Account: %s\t", tmp);

	unistr2_to_unix(tmp, &s3->uni_grp_desc, sizeof(tmp)-1);
	printf("Name: %s\n", tmp);

}

static void display_sam_info_4(SAM_ENTRY4 *e4, SAM_STR4 *s4)
{
	int i;

	printf("index: %d ", e4->user_idx);
	
	printf("Account: ");
	for (i=0; i<s4->acct_name.str_str_len; i++)
		printf("%c", s4->acct_name.buffer[i]);
	printf("\n");

}

static void display_sam_info_5(SAM_ENTRY5 *e5, SAM_STR5 *s5)
{
	int i;

	printf("index: 0x%x ", e5->grp_idx);
	
	printf("Account: ");
	for (i=0; i<s5->grp_name.str_str_len; i++)
		printf("%c", s5->grp_name.buffer[i]);
	printf("\n");

}

/**********************************************************************
 * Query user information 
 */
static NTSTATUS cmd_samr_query_user(struct cli_state *cli, 
                                    TALLOC_CTX *mem_ctx,
                                    int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 info_level = 21;
	SAM_USERINFO_CTR *user_ctr;
	fstring server;
	uint32 user_rid;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return NT_STATUS_OK;
	}
	
	sscanf(argv[1], "%i", &user_rid);

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
	
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
				    MAXIMUM_ALLOWED_ACCESS,
				    user_rid, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	ZERO_STRUCT(user_ctr);

	result = cli_samr_query_userinfo(cli, mem_ctx, &user_pol, 
					 info_level, &user_ctr);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	display_sam_user_info_21(user_ctr->info.id21);

done:
	return result;
}

/****************************************************************************
 display group info
 ****************************************************************************/
static void display_group_info1(GROUP_INFO1 *info1)
{
	fstring temp;

	unistr2_to_unix(temp, &info1->uni_acct_name, sizeof(temp)-1);
	printf("\tGroup Name:\t%s\n", temp);
	unistr2_to_unix(temp, &info1->uni_acct_desc, sizeof(temp)-1);
	printf("\tDescription:\t%s\n", temp);
	printf("\tunk1:%d\n", info1->unknown_1);
	printf("\tNum Members:%d\n", info1->num_members);
}

/****************************************************************************
 display group info
 ****************************************************************************/
static void display_group_info4(GROUP_INFO4 *info4)
{
	fstring desc;

	unistr2_to_unix(desc, &info4->uni_acct_desc, sizeof(desc)-1);
	printf("\tGroup Description:%s\n", desc);
}

/****************************************************************************
 display sam sync structure
 ****************************************************************************/
static void display_group_info_ctr(GROUP_INFO_CTR *ctr)
{
	switch (ctr->switch_value1) {
	    case 1: {
		    display_group_info1(&ctr->group.info1);
		    break;
	    }
	    case 4: {
		    display_group_info4(&ctr->group.info4);
		    break;
	    }
	}
}

/***********************************************************************
 * Query group information 
 */
static NTSTATUS cmd_samr_query_group(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx,
                                     int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, group_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 info_level = 1;
	GROUP_INFO_CTR *group_ctr;
	fstring			server;	
	uint32 group_rid;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return NT_STATUS_OK;
	}

        sscanf(argv[1], "%i", &group_rid);

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     group_rid, &group_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	result = cli_samr_query_groupinfo(cli, mem_ctx, &group_pol, 
					  info_level, &group_ctr);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	display_group_info_ctr(group_ctr);

done:
	return result;
}

/* Query groups a user is a member of */

static NTSTATUS cmd_samr_query_usergroups(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, char **argv) 
{
	POLICY_HND 		connect_pol, 
				domain_pol, 
				user_pol;
	NTSTATUS		result = NT_STATUS_UNSUCCESSFUL;
	uint32 			num_groups, 
				user_rid;
	DOM_GID 		*user_gids;
	int 			i;
	fstring			server;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return NT_STATUS_OK;
	}

	sscanf(argv[1], "%i", &user_rid);

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
		
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
				    MAXIMUM_ALLOWED_ACCESS,
				    user_rid, &user_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_query_usergroups(cli, mem_ctx, &user_pol,
					   &num_groups, &user_gids);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_groups; i++) {
		printf("\tgroup rid:[0x%x] attr:[0x%x]\n", 
		       user_gids[i].g_rid, user_gids[i].attr);
	}

 done:
	return result;
}

/* Query aliases a user is a member of */

static NTSTATUS cmd_samr_query_useraliases(struct cli_state *cli, 
                                          TALLOC_CTX *mem_ctx,
                                          int argc, char **argv) 
{
	POLICY_HND 		connect_pol, domain_pol;
	NTSTATUS		result = NT_STATUS_UNSUCCESSFUL;
	uint32 			user_rid, num_aliases, *alias_rids;
	int 			i;
	fstring			server;
	DOM_SID			tmp_sid;
	DOM_SID2		sid;
	DOM_SID global_sid_Builtin;

	string_to_sid(&global_sid_Builtin, "S-1-5-32");

	if (argc != 3) {
		printf("Usage: %s builtin|domain rid\n", argv[0]);
		return NT_STATUS_OK;
	}

	sscanf(argv[2], "%i", &user_rid);

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
		
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (StrCaseCmp(argv[1], "domain")==0)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &domain_sid, &domain_pol);
	else if (StrCaseCmp(argv[1], "builtin")==0)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &global_sid_Builtin, &domain_pol);
	else
		return NT_STATUS_OK;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	sid_copy(&tmp_sid, &domain_sid);
	sid_append_rid(&tmp_sid, user_rid);
	init_dom_sid2(&sid, &tmp_sid);

	result = cli_samr_query_useraliases(cli, mem_ctx, &domain_pol, 1, &sid, &num_aliases, &alias_rids);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_aliases; i++) {
		printf("\tgroup rid:[0x%x]\n", alias_rids[i]);
	}

 done:
	return result;
}

/* Query members of a group */

static NTSTATUS cmd_samr_query_groupmem(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx,
                                        int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, group_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 num_members, *group_rids, *group_attrs, group_rid;
	int i;
	fstring			server;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return NT_STATUS_OK;
	}

	sscanf(argv[1], "%i", &group_rid);

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     group_rid, &group_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_query_groupmem(cli, mem_ctx, &group_pol,
					 &num_members, &group_rids,
					 &group_attrs);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_members; i++) {
		printf("\trid:[0x%x] attr:[0x%x]\n", group_rids[i],
		       group_attrs[i]);
	}

 done:
	return result;
}

/* Enumerate domain groups */

static NTSTATUS cmd_samr_enum_dom_groups(struct cli_state *cli, 
                                         TALLOC_CTX *mem_ctx,
                                         int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx, size, num_dom_groups, i;
	struct acct_info *dom_groups;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return NT_STATUS_OK;
	}

	/* Get sam policy handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get domain policy handle */

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Enumerate domain groups */

	start_idx = 0;
	size = 0xffff;

	result = cli_samr_enum_dom_groups(cli, mem_ctx, &domain_pol,
					  &start_idx, size,
					  &dom_groups, &num_dom_groups);

	for (i = 0; i < num_dom_groups; i++)
		printf("group:[%s] rid:[0x%x]\n", dom_groups[i].acct_name,
		       dom_groups[i].rid);

 done:
	return result;
}

/* Enumerate domain groups */

static NTSTATUS cmd_samr_enum_als_groups(struct cli_state *cli, 
                                         TALLOC_CTX *mem_ctx,
                                         int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx, size, num_dom_groups, i;
	struct acct_info *dom_groups;
	DOM_SID global_sid_Builtin;

	string_to_sid(&global_sid_Builtin, "S-1-5-32");

	if (argc != 2) {
		printf("Usage: %s builtin|domain\n", argv[0]);
		return NT_STATUS_OK;
	}

	/* Get sam policy handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get domain policy handle */

	if (StrCaseCmp(argv[1], "domain")==0)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &domain_sid, &domain_pol);
	else if (StrCaseCmp(argv[1], "builtin")==0)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &global_sid_Builtin, &domain_pol);
	else
		return NT_STATUS_OK;
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Enumerate domain groups */

	start_idx = 0;
	size = 0xffff;

	result = cli_samr_enum_als_groups(cli, mem_ctx, &domain_pol,
					  &start_idx, size,
					  &dom_groups, &num_dom_groups);

	for (i = 0; i < num_dom_groups; i++)
		printf("group:[%s] rid:[0x%x]\n", dom_groups[i].acct_name,
		       dom_groups[i].rid);

 done:
	return result;
}

/* Query alias membership */

static NTSTATUS cmd_samr_query_aliasmem(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx,
                                        int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, alias_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 alias_rid, num_members, i;
	DOM_SID *alias_sids;

	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return NT_STATUS_OK;
	}

	sscanf(argv[1], "%i", &alias_rid);

	/* Open SAMR handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Open handle on domain */

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Open handle on alias */

	result = cli_samr_open_alias(cli, mem_ctx, &domain_pol,
				     MAXIMUM_ALLOWED_ACCESS,
				     alias_rid, &alias_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_query_aliasmem(cli, mem_ctx, &alias_pol,
					 &num_members, &alias_sids);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	for (i = 0; i < num_members; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &alias_sids[i]);
		printf("\tsid:[%s]\n", sid_str);
	}

 done:
	return result;
}

/* Query display info */

static NTSTATUS cmd_samr_query_dispinfo(struct cli_state *cli, 
                                        TALLOC_CTX *mem_ctx,
                                        int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 start_idx=0, max_entries=250, max_size = 0xffff, num_entries, i;
	int info_level = 1;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;
	SAM_DISPINFO_2 info2;
	SAM_DISPINFO_3 info3;
	SAM_DISPINFO_4 info4;
	SAM_DISPINFO_5 info5;
	int loop_count = 0;
	BOOL got_params = False; /* Use get_query_dispinfo_params() or not? */

	if (argc > 4) {
		printf("Usage: %s [info level] [start index] [max entries] [max_size]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc >= 2)
                sscanf(argv[1], "%i", &info_level);
        
	if (argc >= 3)
                sscanf(argv[2], "%i", &start_idx);
        
	if (argc >= 4) {
                sscanf(argv[3], "%i", &max_entries);
		got_params = True;
	}

	if (argc >= 5) {
                sscanf(argv[4], "%i", &max_size);
		got_params = True;
	}

	/* Get sam policy handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get domain policy handle */

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS, 
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Query display info */

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(info1);

	switch (info_level) {
	case 1:
		ZERO_STRUCT(info1);
	ctr.sam.info1 = &info1;
		break;
	case 2:
		ZERO_STRUCT(info2);
		ctr.sam.info2 = &info2;
		break;
	case 3:
		ZERO_STRUCT(info3);
		ctr.sam.info3 = &info3;
		break;
	case 4:
		ZERO_STRUCT(info4);
		ctr.sam.info4 = &info4;
		break;
	case 5:
		ZERO_STRUCT(info5);
		ctr.sam.info5 = &info5;
		break;
	}


	do {	

	if (!got_params)
		get_query_dispinfo_params(
			loop_count, &max_entries, &max_size);

	result = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
					 &start_idx, info_level,
					 &num_entries, max_entries, 
					 max_size, &ctr);

	loop_count++;

	for (i = 0; i < num_entries; i++) {
		switch (info_level) {
		case 1:
			display_sam_info_1(&ctr.sam.info1->sam[i], &ctr.sam.info1->str[i]);
			break;
			case 2:
				display_sam_info_2(&ctr.sam.info2->sam[i], &ctr.sam.info2->str[i]);
				break;
			case 3:
				display_sam_info_3(&ctr.sam.info3->sam[i], &ctr.sam.info3->str[i]);
				break;
		case 4:
			display_sam_info_4(&ctr.sam.info4->sam[i], &ctr.sam.info4->str[i]);
			break;
			case 5:
				display_sam_info_5(&ctr.sam.info5->sam[i], &ctr.sam.info5->str[i]);
				break;
		}
	}
	} while (!NT_STATUS_IS_OK(result));
 done:
	return result;
}

/* Query domain info */

static NTSTATUS cmd_samr_query_dominfo(struct cli_state *cli, 
                                       TALLOC_CTX *mem_ctx,
                                       int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	int switch_value = 2;
	SAM_UNK_CTR ctr;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return NT_STATUS_OK;
	}

	if (argc == 2)
                sscanf(argv[1], "%i", &switch_value);

	/* Get sam policy handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get domain policy handle */

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Query domain info */

	result = cli_samr_query_dom_info(cli, mem_ctx, &domain_pol,
					 switch_value, &ctr);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display domain info */

	switch (switch_value) {
	case 1:
		display_sam_unk_info_1(&ctr.info.inf1);
		break;
	case 2:
		display_sam_unk_info_2(&ctr.info.inf2);
		break;
	default:
		printf("cannot display domain info for switch value %d\n",
		       switch_value);
		break;
	}

 done:
 
 	cli_samr_close(cli, mem_ctx, &domain_pol);
 	cli_samr_close(cli, mem_ctx, &connect_pol);
	return result;
}

/* Create domain user */

static NTSTATUS cmd_samr_create_dom_user(struct cli_state *cli, 
                                         TALLOC_CTX *mem_ctx,
                                         int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, user_pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	char *acct_name;
	uint16 acb_info;
	uint32 unknown, user_rid;

	if (argc != 2) {
		printf("Usage: %s username\n", argv[0]);
		return NT_STATUS_OK;
	}

	acct_name = argv[1];

	/* Get sam policy handle */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get domain policy handle */

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Create domain user */

	acb_info = ACB_NORMAL;
	unknown = 0xe005000b; /* No idea what this is - a permission mask? */

	result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					  acct_name, acb_info, unknown,
					  &user_pol, &user_rid);
	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

 done:
	return result;
}

/* Lookup sam names */

static NTSTATUS cmd_samr_lookup_names(struct cli_state *cli, 
                                      TALLOC_CTX *mem_ctx,
                                      int argc, char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol;
	uint32 flags = 0x000003e8; /* Unknown */
	uint32 num_rids, num_names, *name_types, *rids;
	const char **names;
	int i;
	DOM_SID global_sid_Builtin;

	string_to_sid(&global_sid_Builtin, "S-1-5-32");

	if (argc < 3) {
		printf("Usage: %s  domain|builtin name1 [name2 [name3] [...]]\n", argv[0]);
		printf("check on the domain SID: S-1-5-21-x-y-z\n");
		printf("or check on the builtin SID: S-1-5-32\n");
		return NT_STATUS_OK;
	}

	/* Get sam policy and domain handles */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	if (StrCaseCmp(argv[1], "domain")==0)
	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);
	else if (StrCaseCmp(argv[1], "builtin")==0)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &global_sid_Builtin, &domain_pol);
	else
		return NT_STATUS_OK;

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Look up names */

	num_names = argc - 2;
	names = (const char **)talloc(mem_ctx, sizeof(char *) * num_names);

	for (i = 0; i < argc - 2; i++)
		names[i] = argv[i + 2];

	result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
				       flags, num_names, names,
				       &num_rids, &rids, &name_types);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	for (i = 0; i < num_names; i++)
		printf("name %s: 0x%x (%d)\n", names[i], rids[i], 
		       name_types[i]);

 done:
	return result;
}

/* Lookup sam rids */

static NTSTATUS cmd_samr_lookup_rids(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx,
                                     int argc, char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol;
	uint32 flags = 0x000003e8; /* Unknown */
	uint32 num_rids, num_names, *rids, *name_types;
	char **names;
	int i;

	if (argc < 2) {
		printf("Usage: %s rid1 [rid2 [rid3] [...]]\n", argv[0]);
		return NT_STATUS_OK;
	}

	/* Get sam policy and domain handles */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Look up rids */

	num_rids = argc - 1;
	rids = (uint32 *)talloc(mem_ctx, sizeof(uint32) * num_rids);

	for (i = 0; i < argc - 1; i++)
                sscanf(argv[i + 1], "%i", &rids[i]);

	result = cli_samr_lookup_rids(cli, mem_ctx, &domain_pol,
				      flags, num_rids, rids,
				      &num_names, &names, &name_types);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

	for (i = 0; i < num_names; i++)
		printf("rid 0x%x: %s (%d)\n", rids[i], names[i], name_types[i]);

 done:
	return result;
}

/* Delete domain user */

static NTSTATUS cmd_samr_delete_dom_user(struct cli_state *cli, 
                                         TALLOC_CTX *mem_ctx,
                                         int argc, char **argv) 
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol, user_pol;

	if (argc != 2) {
		printf("Usage: %s username\n", argv[0]);
		return NT_STATUS_OK;
	}

	/* Get sam policy and domain handles */

	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
				      MAXIMUM_ALLOWED_ACCESS,
				      &domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Get handle on user */

	{
		uint32 *user_rids, num_rids, *name_types;
		uint32 flags = 0x000003e8; /* Unknown */

		result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
					       flags, 1, (const char **)&argv[1],
					       &num_rids, &user_rids,
					       &name_types);

		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}

		result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					    MAXIMUM_ALLOWED_ACCESS,
					    user_rids[0], &user_pol);

		if (!NT_STATUS_IS_OK(result)) {
			goto done;
		}
	}

	/* Delete user */

	result = cli_samr_delete_dom_user(cli, mem_ctx, &user_pol);

	if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

	/* Display results */

 done:
	return result;
}

/**********************************************************************
 * Query user security object 
 */
static NTSTATUS cmd_samr_query_sec_obj(struct cli_state *cli, 
                                    TALLOC_CTX *mem_ctx,
                                    int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, user_pol, *pol;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 info_level = 4;
	fstring server;
	uint32 user_rid = 0;
	TALLOC_CTX *ctx = NULL;
	SEC_DESC_BUF *sec_desc_buf=NULL;
	BOOL domain = False;

	ctx=talloc_init();
	
	if (argc > 2) {
		printf("Usage: %s [rid|-d]\n", argv[0]);
		printf("\tSpecify rid for security on user, -d for security on domain\n");
		return NT_STATUS_OK;
	}
	
	if (argc == 2) {
		if (strcmp(argv[1], "-d") == 0)
			domain = True;
		else
			sscanf(argv[1], "%i", &user_rid);
	}

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
	result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				  &connect_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	if (domain || user_rid)
		result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					      MAXIMUM_ALLOWED_ACCESS,
					      &domain_sid, &domain_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	if (user_rid)
		result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					    MAXIMUM_ALLOWED_ACCESS,
					    user_rid, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	/* Pick which query pol to use */

	pol = &connect_pol;

	if (domain)
		pol = &domain_pol;

	if (user_rid)
		pol = &user_pol;

	/* Query SAM security object */

	result = cli_samr_query_sec_obj(cli, mem_ctx, pol, info_level, ctx, 
					&sec_desc_buf);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	display_sec_desc(sec_desc_buf->sec);
	
done:
	talloc_destroy(ctx);
	return result;
}

/* List of commands exported by this module */

struct cmd_set samr_commands[] = {

	{ "SAMR" },

	{ "queryuser", 		cmd_samr_query_user, 		PIPE_SAMR,	"Query user info",         "" },
	{ "querygroup", 	cmd_samr_query_group, 		PIPE_SAMR,	"Query group info",        "" },
	{ "queryusergroups", 	cmd_samr_query_usergroups, 	PIPE_SAMR,	"Query user groups",       "" },
	{ "queryuseraliases", 	cmd_samr_query_useraliases, 	PIPE_SAMR,	"Query user aliases",      "" },
	{ "querygroupmem", 	cmd_samr_query_groupmem, 	PIPE_SAMR,	"Query group membership",  "" },
	{ "queryaliasmem", 	cmd_samr_query_aliasmem, 	PIPE_SAMR,	"Query alias membership",  "" },
	{ "querydispinfo", 	cmd_samr_query_dispinfo, 	PIPE_SAMR,	"Query display info",      "" },
	{ "querydominfo", 	cmd_samr_query_dominfo, 	PIPE_SAMR,	"Query domain info",       "" },
	{ "enumdomgroups",      cmd_samr_enum_dom_groups,       PIPE_SAMR,	"Enumerate domain groups", "" },
	{ "enumalsgroups",      cmd_samr_enum_als_groups,       PIPE_SAMR,	"Enumerate alias groups",  "" },

	{ "createdomuser",      cmd_samr_create_dom_user,       PIPE_SAMR,	"Create domain user",      "" },
	{ "samlookupnames",     cmd_samr_lookup_names,          PIPE_SAMR,	"Look up names",           "" },
	{ "samlookuprids",      cmd_samr_lookup_rids,           PIPE_SAMR,	"Look up names",           "" },
	{ "deletedomuser",      cmd_samr_delete_dom_user,       PIPE_SAMR,	"Delete domain user",      "" },
	{ "samquerysecobj",     cmd_samr_query_sec_obj,         PIPE_SAMR, "Query SAMR security object",   "" },

	{ NULL }
};
