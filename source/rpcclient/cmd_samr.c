/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client

   Copyright (C) Andrew Tridgell              1992-2000,
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
   Copyright (C) Elrond                            2000
   Copyright (C) Tim Potter 2000

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
	SAM_USERINFO_CTR user_ctr;
	SAM_USER_INFO_21 info_21;
	fstring			server;
	TALLOC_CTX		*mem_ctx;
	
	
	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}
	
	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("cmd_samr_query_user: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}


	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
	
	if ((result = cli_samr_connect(cli, mem_ctx, server, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;
	fetch_domain_sid(cli);

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_user(cli, mem_ctx, &domain_pol,
					 MAXIMUM_ALLOWED_ACCESS,
					 0x1f4, &user_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_user_pol = True;

	ZERO_STRUCT(user_ctr);
	ZERO_STRUCT(info_21);

	user_ctr.info.id21 = &info_21;

	if ((result = cli_samr_query_userinfo(cli, mem_ctx, &user_pol, info_level,
					      &user_ctr)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	display_sam_user_info_21(&info_21);

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
	
	if (argc != 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx=talloc_init()))
	{
		DEBUG(0,("cmd_samr_query_group: talloc_init returned NULL!\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	if ((result = cli_samr_connect(cli, mem_ctx, server, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;
	fetch_domain_sid(cli);

	if ((result = cli_samr_open_domain(cli, mem_ctx, &connect_pol,
					   MAXIMUM_ALLOWED_ACCESS,
					   &domain_sid, &domain_pol))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_pol = True;

	if ((result = cli_samr_open_group(cli, mem_ctx, &domain_pol,
					  MAXIMUM_ALLOWED_ACCESS,
					  0x202, &group_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_group_pol = True;

	ZERO_STRUCT(group_ctr);

	if ((result = cli_samr_query_groupinfo(cli, mem_ctx, &group_pol, info_level,
					       &group_ctr)) 
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

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);
		
	if ((result = cli_samr_connect(cli, mem_ctx, server, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;
	fetch_domain_sid(cli);

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

	/* Initialise RPC connection */
	if (!cli_nt_session_open (cli, PIPE_SAMR)) {
		fprintf (stderr, "Could not initialize samr pipe!\n");
		return NT_STATUS_UNSUCCESSFUL;
	}

	slprintf (server, sizeof(fstring)-1, "\\\\%s", cli->desthost);
	strupper (server);

	if ((result = cli_samr_connect(cli, mem_ctx, server, MAXIMUM_ALLOWED_ACCESS,
				       &connect_pol)) !=
	    NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_connect_pol = True;
	fetch_domain_sid(cli);

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

/* List of commands exported by this module */

struct cmd_set samr_commands[] = {
	{ "SAMR", 		NULL,		 		"" },
	{ "queryuser", 		cmd_samr_query_user, 		"Query user info" },
	{ "querygroup", 	cmd_samr_query_group, 		"Query group info" },
	{ "queryusergroups", 	cmd_samr_query_usergroups, 	"Query user groups" },
	{ "querygroupmem", 	cmd_samr_query_groupmem, 	"Query group membership" },
	{ NULL, NULL, NULL }
};

