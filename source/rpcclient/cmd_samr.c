/* 
   Unix SMB/Netbios implementation.
   Version 2.2
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

extern DOM_SID domain_sid;

/****************************************************************************
 display sam_user_info_21 structure
 ****************************************************************************/
static void display_sam_user_info_21(SAM_USER_INFO_21 *usr)
{
	fstring temp;

	unistr2_to_ascii(temp, &usr->uni_user_name, sizeof(temp)-1);
	printf("\tUser Name   :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_full_name, sizeof(temp)-1);
	printf("\tFull Name   :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_home_dir, sizeof(temp)-1);
	printf("\tHome Drive  :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_dir_drive, sizeof(temp)-1);
	printf("\tDir Drive   :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_profile_path, sizeof(temp)-1);
	printf("\tProfile Path:\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_logon_script, sizeof(temp)-1);
	printf("\tLogon Script:\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_acct_desc, sizeof(temp)-1);
	printf("\tDescription :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_workstations, sizeof(temp)-1);
	printf("\tWorkstations:\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_unknown_str, sizeof(temp)-1);
	printf("\tUnknown Str :\t%s\n", temp);
	
	unistr2_to_ascii(temp, &usr->uni_munged_dial, sizeof(temp)-1);
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

static void display_sam_unk_info_2(SAM_UNK_INFO_2 *info2)
{
	fstring name;

	unistr2_to_ascii(name, &info2->uni_domain, sizeof(name) - 1); 
	printf("Domain:\t%s\n", name);

	unistr2_to_ascii(name, &info2->uni_server, sizeof(name) - 1); 
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

void display_sam_info_1(SAM_ENTRY1 *e1, SAM_STR1 *s1)
{
	fstring tmp;

	printf("RID: 0x%x ", e1->rid_user);
	
	unistr2_to_ascii(tmp, &s1->uni_acct_name, sizeof(tmp)-1);
	printf("Account: %s\t", tmp);

	unistr2_to_ascii(tmp, &s1->uni_full_name, sizeof(tmp)-1);
	printf("Name: %s\t", tmp);

	unistr2_to_ascii(tmp, &s1->uni_acct_desc, sizeof(tmp)-1);
	printf("Desc: %s\n", tmp);
}

/**********************************************************************
 * Query user information 
 */
static uint32 cmd_samr_query_user(struct cli_state *cli, int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, user_pol;
	uint32 	result = NT_STATUS_UNSUCCESSFUL, 
		info_level = 21;
	BOOL 	got_connect_pol = False, 
		got_domain_pol = False,
		got_user_pol = False;
	SAM_USERINFO_CTR *user_ctr;
	fstring			server;
	TALLOC_CTX		*mem_ctx;
	uint32 user_rid;
	
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return 0;
	}
	
	sscanf(argv[1], "%i", &user_rid);

	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("cmd_samr_query_user: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
	
	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					 MAXIMUM_ALLOWED_ACCESS,
					 user_rid, &user_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_user_pol = True;

	ZERO_STRUCT(user_ctr);

	if ((result = cli_samr_query_userinfo(cli, mem_ctx, &user_pol, 
					      info_level, &user_ctr)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	display_sam_user_info_21(user_ctr->info.id21);

done:
	if (got_user_pol) cli_samr_close(cli, mem_ctx, &user_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/****************************************************************************
 display group info
 ****************************************************************************/
static void display_group_info1(GROUP_INFO1 *info1)
{
	fstring temp;

	unistr2_to_ascii(temp, &info1->uni_acct_name, sizeof(temp)-1);
	printf("\tGroup Name:\t%s\n", temp);
	unistr2_to_ascii(temp, &info1->uni_acct_desc, sizeof(temp)-1);
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

	unistr2_to_ascii(desc, &info4->uni_acct_desc, sizeof(desc)-1);
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
static uint32 cmd_samr_query_group(struct cli_state *cli, int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, group_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL, info_level = 1;
	BOOL got_connect_pol = False, got_domain_pol = False,
		got_group_pol = False;
	GROUP_INFO_CTR group_ctr;
	fstring			server;	
	TALLOC_CTX		*mem_ctx;
	uint32 group_rid;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return 0;
	}

	group_rid = atoi(argv[1]);

	if (!(mem_ctx=talloc_init())) {
		DEBUG(0,("cmd_samr_query_group: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
					  MAXIMUM_ALLOWED_ACCESS,
					  group_rid, &group_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_group_pol = True;

	ZERO_STRUCT(group_ctr);

	if ((result = cli_samr_query_groupinfo(cli, mem_ctx, &group_pol, 
					       info_level, &group_ctr)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	display_group_info_ctr(&group_ctr);

done:
	if (got_group_pol) cli_samr_close(cli, mem_ctx, &group_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Query groups a user is a member of */

static uint32 cmd_samr_query_usergroups(struct cli_state *cli, int argc, char **argv) 
{
	POLICY_HND 		connect_pol, 
				domain_pol, 
				user_pol;
	uint32 			result = NT_STATUS_UNSUCCESSFUL;
	BOOL 			got_connect_pol = False, 
				got_domain_pol = False,
				got_user_pol = False;
	uint32 			num_groups, 
				user_rid;
	DOM_GID 		*user_gids;
	int 			i;
	fstring			server;
	TALLOC_CTX		*mem_ctx;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("cmd_samr_query_usergroups: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	sscanf(argv[1], "%i", &user_rid);

	fetch_domain_sid(cli);

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
		
	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					 MAXIMUM_ALLOWED_ACCESS,
					 user_rid, &user_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_user_pol = True;

	if ((result = cli_samr_query_usergroups(cli, mem_ctx, &user_pol,
						&num_groups, &user_gids))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	for (i = 0; i < num_groups; i++) {
		printf("\tgroup rid:[0x%x] attr:[0x%x]\n", 
		       user_gids[i].g_rid, user_gids[i].attr);
	}

 done:
	if (got_user_pol) cli_samr_close(cli, mem_ctx, &user_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Query members of a group */

static uint32 cmd_samr_query_groupmem(struct cli_state *cli, int argc, char **argv) 
{
	POLICY_HND connect_pol, domain_pol, group_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL 	got_connect_pol = False, 
		got_domain_pol = False,
		got_group_pol = False;
	uint32 num_members, *group_rids, *group_attrs, group_rid;
	int i;
	fstring			server;
	TALLOC_CTX		*mem_ctx;
	
	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("cmd_samr_query_groupmem: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	sscanf(argv[1], "%i", &group_rid);

	fetch_domain_sid(cli);

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
					  MAXIMUM_ALLOWED_ACCESS,
					  group_rid, &group_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_group_pol = True;

	if ((result = cli_samr_query_groupmem(cli, mem_ctx, &group_pol,
					      &num_members, &group_rids,
					      &group_attrs))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	for (i = 0; i < num_members; i++) {
		printf("\trid:[0x%x] attr:[0x%x]\n", group_rids[i],
		       group_attrs[i]);
	}

 done:
	if (got_group_pol) cli_samr_close(cli, mem_ctx, &group_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Enumerate domain groups */

static uint32 cmd_samr_enum_dom_groups(struct cli_state *cli, int argc, 
				       char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_connect_pol = False, got_domain_pol = False;
	TALLOC_CTX *mem_ctx;
	uint32 start_idx, size, num_dom_groups, i;
	struct acct_info *dom_groups;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_enum_dom_groups: talloc_init returned "
			  "NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy handle */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	/* Get domain policy handle */

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

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
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Query alias membership */

static uint32 cmd_samr_query_aliasmem(struct cli_state *cli, int argc, 
				      char **argv) 
{
	POLICY_HND connect_pol, domain_pol, alias_pol;
	BOOL got_connect_pol = False, got_domain_pol = False,
		got_alias_pol = False;
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL, alias_rid, num_members, i;
	DOM_SID *alias_sids;

	if (argc != 2) {
		printf("Usage: %s rid\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx=talloc_init())) {
		DEBUG(0,("cmd_samr_query_aliasmem: talloc_init() "
			 "returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	sscanf(argv[1], "%i", &alias_rid);

	/* Initialise RPC connection */

	fetch_domain_sid(cli);

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Open SAMR handle */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) != 
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	/* Open handle on domain */

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Open handle on alias */

	if ((result = cli_samr_open_alias(cli, mem_ctx, &domain_pol,
					  MAXIMUM_ALLOWED_ACCESS,
					  alias_rid, &alias_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_alias_pol = True;

	if ((result = cli_samr_query_aliasmem(cli, mem_ctx, &alias_pol,
					      &num_members, &alias_sids))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	for (i = 0; i < num_members; i++) {
		fstring sid_str;

		sid_to_string(sid_str, &alias_sids[i]);
		printf("\tsid:[%s]\n", sid_str);
	}

 done:
	if (got_alias_pol) cli_samr_close(cli, mem_ctx, &alias_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Query display info */

static uint32 cmd_samr_query_dispinfo(struct cli_state *cli, int argc, 
				      char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_connect_pol = False, got_domain_pol = False;
	TALLOC_CTX *mem_ctx;
	uint32 start_idx, max_entries, num_entries, i;
	uint16 info_level = 1;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;

	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_query_dispinfo: talloc_init returned "
			  "NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy handle */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	/* Get domain policy handle */

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS, 
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Query display info */

	start_idx = 0;
	max_entries = 250;

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(info1);

	ctr.sam.info1 = &info1;

	result = cli_samr_query_dispinfo(cli, mem_ctx, &domain_pol,
					 &start_idx, info_level,
					 &num_entries, max_entries, &ctr);

	for (i = 0; i < num_entries; i++) {
		display_sam_info_1(&ctr.sam.info1->sam[i],
				   &ctr.sam.info1->str[i]);
	}

 done:
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Query domain info */

static uint32 cmd_samr_query_dominfo(struct cli_state *cli, int argc, 
				     char **argv) 
{
	POLICY_HND connect_pol, domain_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_connect_pol = False, got_domain_pol = False;
	TALLOC_CTX *mem_ctx;
	uint16 switch_value = 2;
	SAM_UNK_CTR ctr;

	if (argc > 2) {
		printf("Usage: %s [infolevel\n", argv[0]);
		return 0;
	}

	if (argc == 2)
		switch_value = atoi(argv[1]);

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_query_dispinfo: talloc_init returned "
			  "NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy handle */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	/* Get domain policy handle */

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Query domain info */

	if ((result = cli_samr_query_dom_info(cli, mem_ctx, &domain_pol,
					      switch_value, &ctr))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display domain info */

	switch (switch_value) {
	case 2:
		display_sam_unk_info_2(&ctr.info.inf2);
		break;
	default:
		printf("cannot display domain info for switch value %d\n",
		       switch_value);
		break;
	}

 done:
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Create domain user */

static uint32 cmd_samr_create_dom_user(struct cli_state *cli, int argc, 
				       char **argv) 
{
	POLICY_HND connect_pol, domain_pol, user_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	BOOL got_connect_pol = False, got_domain_pol = False, 
		got_user_pol = False;
	TALLOC_CTX *mem_ctx;
	char *acct_name;
	uint16 acb_info;
	uint32 unknown, user_rid;

	if (argc != 2) {
		printf("Usage: %s username\n", argv[0]);
		return 0;
	}

	acct_name = argv[1];

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_query_dispinfo: talloc_init returned "
			  "NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy handle */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	/* Get domain policy handle */

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Create domain user */

	acb_info = ACB_NORMAL;
	unknown = 0xe005000b; /* No idea what this is - a permission mask? */

	if ((result = cli_samr_create_dom_user(cli, mem_ctx, &domain_pol,
					       acct_name, acb_info, unknown,
					       &user_pol, &user_rid))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_user_pol = True;

 done:
	if (got_user_pol) cli_samr_close(cli, mem_ctx, &user_pol);
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Lookup sam names */

static uint32 cmd_samr_lookup_names(struct cli_state *cli, int argc, 
				    char **argv) 
{
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol;
	BOOL got_connect_pol = False, got_domain_pol = False;
	uint32 flags = 0x000003e8;
	uint32 num_rids, num_names, *name_types, *rids;
	char **names;
	int i;

	if (argc < 2) {
		printf("Usage: %s name1 [name2 [name3] [...]]\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_lookup_names: talloc_init failed\n"));
		return result;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy and domain handles */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Look up names */

	num_names = argc - 1;
	names = (char **)talloc(mem_ctx, sizeof(char *) * num_names);

	for (i = 0; i < argc - 1; i++)
		names[i] = argv[i + 1];

	if ((result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
					    flags, num_names, names,
					    &num_rids, &rids, &name_types))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display results */

	for (i = 0; i < num_names; i++)
		printf("name %s: 0x%x (%d)\n", names[i], rids[i], 
		       name_types[i]);

 done:
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Lookup sam rids */

static uint32 cmd_samr_lookup_rids(struct cli_state *cli, int argc, 
				   char **argv) 
{
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol;
	BOOL got_connect_pol = False, got_domain_pol = False;
	uint32 flags = 0x000003e8;
	uint32 num_rids, num_names, *rids, *name_types;
	char **names;
	int i;

	if (argc < 2) {
		printf("Usage: %s rid1 [rid2 [rid3] [...]]\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_lookup_rids: talloc_init failed\n"));
		return result;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy and domain handles */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	/* Look up rids */

	num_rids = argc - 1;
	rids = (uint32 *)talloc(mem_ctx, sizeof(uint32) * num_rids);

	for (i = 0; i < argc - 1; i++)
		rids[i] = atoi(argv[i + 1]);

	if ((result = cli_samr_lookup_rids(cli, mem_ctx, &domain_pol,
					   flags, num_rids, rids,
					   &num_names, &names, &name_types))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display results */

	for (i = 0; i < num_names; i++)
		printf("rid %x: %s (%d)\n", rids[i], names[i], name_types[i]);

 done:
	if (got_domain_pol) cli_samr_close(cli, mem_ctx, &domain_pol);
	if (got_connect_pol) cli_samr_close(cli, mem_ctx, &connect_pol);

	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* Delete domain user */

static uint32 cmd_samr_delete_dom_user(struct cli_state *cli, int argc, 
				       char **argv) 
{
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND connect_pol, domain_pol, user_pol;

	if (argc != 2) {
		printf("Usage: %s username\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("cmd_samr_delete_dom_user: talloc_init failed\n"));
		return result;
	}

	fetch_domain_sid(cli);

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		DEBUG(0, ("cmd_samr_delete_dom_user: could not open samr pipe!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Get sam policy and domain handles */

	if ((result = cli_samr_connect(cli, mem_ctx, MAXIMUM_ALLOWED_ACCESS, 
				       &connect_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Get handle on user */

	{
		uint32 *user_rids, num_rids, *name_types;
		uint32 flags = 0x000003e8;

		if ((result = cli_samr_lookup_names(cli, mem_ctx, &domain_pol,
						    flags, 1, &argv[1],
						    &num_rids, &user_rids,
						    &name_types))
		    != NT_STATUS_NOPROBLEMO) {
			goto done;
		}

		if ((result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
						 MAXIMUM_ALLOWED_ACCESS,
						 user_rids[0], &user_pol))
		    != NT_STATUS_NOPROBLEMO) {
			goto done;
		}
	}

	/* Delete user */

	if ((result = cli_samr_delete_dom_user(cli, mem_ctx, &user_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display results */

 done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);

	return result;
}

/* List of commands exported by this module */

struct cmd_set samr_commands[] = {
	{ "SAMR", 		NULL,		 		"" },

	{ "queryuser", 		cmd_samr_query_user, 		"Query user info" },
	{ "querygroup", 	cmd_samr_query_group, 		"Query group info" },
	{ "queryusergroups", 	cmd_samr_query_usergroups, 	"Query user groups" },
	{ "querygroupmem", 	cmd_samr_query_groupmem, 	"Query group membership" },
	{ "queryaliasmem", 	cmd_samr_query_aliasmem, 	"Query alias membership" },
	{ "querydispinfo", 	cmd_samr_query_dispinfo, 	"Query display info" },
	{ "querydominfo", 	cmd_samr_query_dominfo, 	"Query domain info" },
	{ "enumdomgroups",      cmd_samr_enum_dom_groups,       "Enumerate domain groups" },

	{ "createdomuser",      cmd_samr_create_dom_user,       "Create domain user" },
	{ "samlookupnames",     cmd_samr_lookup_names,          "Look up names", },
	{ "samlookuprids",      cmd_samr_lookup_rids,           "Look up names", },
	{ "deletedomuser",      cmd_samr_delete_dom_user,       "Delete domain user" },
	{ NULL, NULL, NULL }
};

