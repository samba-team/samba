/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
#include "ntdomain.h"

extern int DEBUGLEVEL;

/****************************************************************************
 This defines the commands supported by this client
 ****************************************************************************/
struct command_set sam_commands[] = 
{
	/*
	 * sam
	 */

	{
		"lookupdomain",
		cmd_sam_lookup_domain,
		"Obtain SID for a local domain",
		{NULL, NULL}
	},
	{
		"samlookuprids",
		cmd_sam_lookup_rids,
		"[-d <domain>] <rid> [<rid> ...]\n"
		"\tLookup RIDs in SAM",
		{NULL, NULL}
	},
	{
		"samlookupnames",
		cmd_sam_lookup_names,
		"[-d <domain>] <name> [<name> ...]\n"
		"\tLookup Names in SAM",
		{NULL, NULL}
	},
	{
		"enumusers",
		cmd_sam_enum_users,
		"SAM User Database Query (experimental!)",
		{NULL, NULL}
	},
	{
		"addgroupmem",
		cmd_sam_add_groupmem,
		"<group rid> [user] [user] ... SAM Add Domain Group Member",
		{complete_samenum_grp, complete_samenum_usr}
	},

	{
		"addaliasmem",
		cmd_sam_add_aliasmem,
		"<alias rid> [member sid1] [member sid2] ... SAM Add Domain Alias Member",
		{complete_samenum_als, NULL}
	},
	{
		"delgroupmem",
		cmd_sam_del_groupmem,
		"<group rid> [user] [user] ... SAM Delete Domain Group Member",
		{complete_samenum_grp, complete_samenum_usr}
	},
	{
		"delaliasmem",
		cmd_sam_del_aliasmem,
		"<alias rid> [member sid1] [member sid2] ... SAM Delete Domain Alias Member",
		{complete_samenum_als, NULL}
	},
	{
		"creategroup",
		cmd_sam_create_dom_group,
		"SAM Create Domain Group",
		{NULL, NULL}
	},
	{
		"createalias",
		cmd_sam_create_dom_alias,
		"SAM Create Domain Alias",
		{NULL, NULL}
	},
	{
		"createuser",
		cmd_sam_create_dom_user,
		"<username> SAM Create Domain User",
		{NULL, NULL}
	},
	{
		"delgroup",
		cmd_sam_delete_dom_group,
		"SAM Delete Domain Group",
		{complete_samenum_grp, NULL}
	},
	{
		"delalias",
		cmd_sam_delete_dom_alias,
		"SAM Delete Domain Alias",
		{complete_samenum_als, NULL}
	},
	{
		"ntpass",
		cmd_sam_ntchange_pwd,
		"NT SAM Password Change",
		{NULL, NULL}
	},
	{
		"samquerysec",
		cmd_sam_query_sec_obj,
		"<username>",
		{complete_samenum_usr, NULL}
	},
	{
		"samuserset2",
		cmd_sam_set_userinfo2,
		"<username> [-s acb_bits] SAM User Set Info 2 (experimental!)",
		{complete_samenum_usr, NULL}
	},
	{
		"samuserset",
		cmd_sam_set_userinfo,
		"<username> [-p password] SAM User Set Info (experimental!)",
		{complete_samenum_usr, NULL}
	},
	{
		"samuser",
		cmd_sam_query_user,
		"<username> [-g] [-u] [-a] SAM User Query (experimental!)",
		{complete_samenum_usr, NULL}
	},
	{
		"samgroup",
		cmd_sam_query_group,
		"<groupname> SAM Group Query (experimental!)",
		{complete_samenum_grp, NULL}
	},
	{
		"samalias",
		cmd_sam_query_alias,
		"<aliasname> SAM Alias Query",
		{complete_samenum_als, NULL}
	},
	{
		"samaliasmem",
		cmd_sam_query_aliasmem,
		"<aliasname> SAM Alias Members",
		{complete_samenum_als, NULL}
	},
	{
		"samgroupmem",
		cmd_sam_query_groupmem,
		"SAM Group Members",
		{complete_samenum_grp, NULL}
	},
	{
		"samtest",
		cmd_sam_test      ,
		"SAM User Encrypted RPC test (experimental!)",
		{NULL, NULL}
	},
	{
		"enumaliases",
		cmd_sam_enum_aliases,
		"SAM Aliases Database Query (experimental!)",
		{NULL, NULL}
	},
	{
		"enumdomains",
		cmd_sam_enum_domains,
		"SAM Domains Database Query (experimental!)",
		{NULL, NULL}
	},
	{
		"enumgroups",
		cmd_sam_enum_groups,
		"SAM Group Database Query (experimental!)",
		{NULL, NULL}
	},
	{
		"dominfo",
		cmd_sam_query_dominfo,
		"SAM Query Domain Info",
		{NULL, NULL}
	},
	{
		"dispinfo",
		cmd_sam_query_dispinfo,
		"SAM Query Display Info",
		{NULL, NULL}
	},

	/*
	 * oop!
	 */

	{
		"",
		NULL,
		NULL,
		{NULL, NULL}
	}
};

