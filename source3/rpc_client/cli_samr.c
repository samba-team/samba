/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;



/****************************************************************************
do a SAMR create domain alias
****************************************************************************/
BOOL create_samr_domain_alias(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				const char *acct_name, const char *acct_desc,
				uint32 *rid)
{
	POLICY_HND pol_open_alias;
	ALIAS_INFO_CTR ctr;
	BOOL ret = True;

	if (pol_open_domain == NULL || acct_name == NULL || acct_desc == NULL) return False;

	/* send create alias */
	if (!samr_create_dom_alias(cli,
				pol_open_domain,
				acct_name,
				&pol_open_alias, rid))
	{
		return False;
	}

	DEBUG(5,("create_samr_domain_alias: name: %s rid 0x%x\n",
	          acct_name, *rid));

	ctr.switch_value1 = 3;
	make_samr_alias_info3(&ctr.alias.info3, acct_desc);

	/* send set alias info */
	if (!samr_set_aliasinfo(cli,
				&pol_open_alias,
				&ctr))
	{
		DEBUG(5,("create_samr_domain_alias: error in samr_set_aliasinfo\n"));
		ret = False;
	}

	return samr_close(cli, &pol_open_alias) && ret;
}

/****************************************************************************
do a SAMR create domain group
****************************************************************************/
BOOL create_samr_domain_group(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				const char *acct_name, const char *acct_desc,
				uint32 *rid)
{
	POLICY_HND pol_open_group;
	GROUP_INFO_CTR ctr;
	BOOL ret = True;

	if (pol_open_domain == NULL || acct_name == NULL || acct_desc == NULL) return False;

	/* send create group*/
	if (!samr_create_dom_group(cli,
				pol_open_domain,
				acct_name,
				&pol_open_group, rid))
	{
		return False;
	}

	DEBUG(5,("create_samr_domain_group: name: %s rid 0x%x\n",
	          acct_name, *rid));

	ctr.switch_value1 = 4;
	ctr.switch_value2 = 4;
	make_samr_group_info4(&ctr.group.info4, acct_desc);

	/* send user groups query */
	if (!samr_set_groupinfo(cli,
				&pol_open_group,
				&ctr))
	{
		DEBUG(5,("create_samr_domain_group: error in samr_set_groupinfo\n"));
		ret = False;
	}

	return samr_close(cli, &pol_open_group) && ret;
}

/****************************************************************************
do a SAMR query user groups
****************************************************************************/
BOOL get_samr_query_usergroups(struct cli_state *cli, 
				POLICY_HND *pol_open_domain, uint32 user_rid,
				uint32 *num_groups, DOM_GID *gid)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_groups == NULL || gid == NULL) return False;

	/* send open domain (on user sid) */
	if (!samr_open_user(cli,
				pol_open_domain,
				0x02011b, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user groups query */
	if (!samr_query_usergroups(cli,
				&pol_open_user,
				num_groups, gid))
	{
		DEBUG(5,("samr_query_usergroups: error in query user groups\n"));
		ret = False;
	}

	return samr_close(cli, &pol_open_user) && ret;
}

/****************************************************************************
do a SAMR query group members 
****************************************************************************/
BOOL get_samr_query_groupmem(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				uint32 group_rid, uint32 *num_mem,
				uint32 *rid, uint32 *attr)
{
	POLICY_HND pol_open_group;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_mem == NULL || rid == NULL || attr == NULL) return False;

	/* send open domain (on group sid) */
	if (!samr_open_group(cli, pol_open_domain,
				group_rid,
				&pol_open_group))
	{
		return False;
	}

	/* send group info query */
	if (!samr_query_groupmem(cli, &pol_open_group, num_mem, rid, attr))
				
	{
		DEBUG(5,("samr_query_group: error in query group members\n"));
		ret = False;
	}

	return samr_close(cli, &pol_open_group) && ret;
}

/****************************************************************************
do a SAMR query alias members 
****************************************************************************/
BOOL get_samr_query_aliasmem(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				uint32 alias_rid, uint32 *num_mem, DOM_SID2 *sid)
{
	POLICY_HND pol_open_alias;
	BOOL ret = True;

	if (pol_open_domain == NULL || num_mem == NULL || sid == NULL) return False;

	/* send open domain (on alias sid) */
	if (!samr_open_alias(cli, pol_open_domain,
				alias_rid,
				&pol_open_alias))
	{
		return False;
	}

	/* send alias info query */
	if (!samr_query_aliasmem(cli, &pol_open_alias, num_mem, sid))
				
	{
		DEBUG(5,("samr_query_alias: error in query alias members\n"));
		ret = False;
	}

	return samr_close(cli, &pol_open_alias) && ret;
}

/****************************************************************************
do a SAMR query user info
****************************************************************************/
BOOL get_samr_query_userinfo(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 user_rid, SAM_USER_INFO_21 *usr)
{
	POLICY_HND pol_open_user;
	BOOL ret = True;

	if (pol_open_domain == NULL || usr == NULL) return False;

	bzero(usr, sizeof(*usr));

	/* send open domain (on user sid) */
	if (!samr_open_user(cli,
				pol_open_domain,
				0x02011b, user_rid,
				&pol_open_user))
	{
		return False;
	}

	/* send user info query */
	if (!samr_query_userinfo(cli,
				&pol_open_user,
				info_level, (void*)usr))
	{
		DEBUG(5,("samr_query_userinfo: error in query user info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(cli, &pol_open_user) && ret;
}

/****************************************************************************
do a SAMR query group info
****************************************************************************/
BOOL get_samr_query_groupinfo(struct cli_state *cli, 
				POLICY_HND *pol_open_domain,
				uint32 info_level,
				uint32 group_rid, GROUP_INFO_CTR *ctr)
{
	POLICY_HND pol_open_group;
	BOOL ret = True;

	if (pol_open_domain == NULL || ctr == NULL) return False;

	bzero(ctr, sizeof(*ctr));

	/* send open domain (on group sid) */
	if (!samr_open_group(cli,
				pol_open_domain,
				group_rid, &pol_open_group))
	{
		return False;
	}

	/* send group info query */
	if (!samr_query_groupinfo(cli,
				&pol_open_group,
				info_level, ctr))
	{
		DEBUG(5,("samr_query_groupinfo: error in query group info, level 0x%x\n",
		          info_level));
		ret = False;
	}

	return samr_close(cli, &pol_open_group) && ret;
}

/****************************************************************************
do a SAMR change user password command
****************************************************************************/
BOOL samr_chgpasswd_user(struct cli_state *cli,
		char *srv_name, char *user_name,
		char nt_newpass[516], uchar nt_oldhash[16],
		char lm_newpass[516], uchar lm_oldhash[16])
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CHGPASSWD_USER q_e;
	BOOL valid_pwc = False;

	/* create and send a MSRPC command with api SAMR_CHGPASSWD_USER */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Change User Password. server:%s username:%s\n",
	        srv_name, user_name));

	make_samr_q_chgpasswd_user(&q_e, srv_name, user_name,
	                           nt_newpass, nt_oldhash,
	                           lm_newpass, lm_oldhash);

	/* turn parameters into data stream */
	samr_io_q_chgpasswd_user("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_CHGPASSWD_USER, &data, &rdata))
	{
		SAMR_R_CHGPASSWD_USER r_e;
		BOOL p;

		samr_io_r_chgpasswd_user("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_CHGPASSWD_USER: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			valid_pwc = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pwc;
}

/****************************************************************************
do a SAMR unknown 0x38 command
****************************************************************************/
BOOL samr_unknown_38(struct cli_state *cli, char *srv_name)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_UNKNOWN_38 q_e;
	BOOL valid_un8 = False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Unknown 38 server:%s\n", srv_name));

	make_samr_q_unknown_38(&q_e, srv_name);

	/* turn parameters into data stream */
	samr_io_q_unknown_38("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_UNKNOWN_38, &data, &rdata))
	{
		SAMR_R_UNKNOWN_38 r_e;
		BOOL p;

		samr_io_r_unknown_38("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
#if 0
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_UNKNOWN_38: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}
#endif
		if (p)
		{
			valid_un8 = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_un8;
}

/****************************************************************************
do a SAMR unknown 0x8 command
****************************************************************************/
BOOL samr_query_dom_info(struct cli_state *cli, 
				POLICY_HND *domain_pol, uint16 switch_value)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_DOMAIN_INFO q_e;
	BOOL valid_un8 = False;

	DEBUG(4,("SAMR Unknown 8 switch:%d\n", switch_value));

	if (domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_dom_info(&q_e, domain_pol, switch_value);

	/* turn parameters into data stream */
	samr_io_q_query_dom_info("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_DOMAIN_INFO, &data, &rdata))
	{
		SAMR_R_QUERY_DOMAIN_INFO r_e;
		BOOL p;

		samr_io_r_query_dom_info("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_DOMAIN_INFO: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			valid_un8 = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_un8;
}

/****************************************************************************
do a SAMR enumerate groups
****************************************************************************/
BOOL samr_enum_dom_groups(struct cli_state *cli, 
				POLICY_HND *pol, uint32 size,
				struct acct_info **sam,
				int *num_sam_groups)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_GROUPS q_e;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_groups == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_GROUPS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_enum_dom_groups(&q_e, pol, 3, 0, size);

	/* turn parameters into data stream */
	samr_io_q_enum_dom_groups("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_ENUM_DOM_GROUPS, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_GROUPS r_e;
		BOOL p;

		samr_io_r_enum_dom_groups("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_ENUM_DOM_GROUPS: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			int i;
			int name_idx = 0;
			int desc_idx = 0;

			*num_sam_groups = r_e.num_entries2;
			if (*num_sam_groups > MAX_SAM_ENTRIES)
			{
				*num_sam_groups = MAX_SAM_ENTRIES;
				DEBUG(2,("samr_enum_dom_groups: sam user entries limited to %d\n",
				          *num_sam_groups));
			}

			*sam = (struct acct_info*) malloc(sizeof(struct acct_info) * (*num_sam_groups));
				    
			if ((*sam) == NULL)
			{
				*num_sam_groups = 0;
			}

			for (i = 0; i < *num_sam_groups; i++)
			{
				(*sam)[i].rid = r_e.sam[i].rid_grp;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[i].hdr_grp_name.buffer)
				{
					fstrcpy((*sam)[i].acct_name, unistr2_to_str(&r_e.str[name_idx].uni_grp_name));
					name_idx++;
				}
				if (r_e.sam[i].hdr_grp_desc.buffer)
				{
					fstrcpy((*sam)[i].acct_desc, unistr2_to_str(&r_e.str[desc_idx].uni_grp_desc));
					desc_idx++;
				}
				DEBUG(5,("samr_enum_dom_groups: idx: %4d rid: %8x acct: %s desc: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name, (*sam)[i].acct_desc));
			}
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR enumerate aliases
****************************************************************************/
BOOL samr_enum_dom_aliases(struct cli_state *cli, 
				POLICY_HND *pol, uint32 size,
				struct acct_info **sam,
				int *num_sam_aliases)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_ALIASES q_e;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_aliases == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_ALIASES */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_enum_dom_aliases(&q_e, pol, size);

	/* turn parameters into data stream */
	samr_io_q_enum_dom_aliases("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_ENUM_DOM_ALIASES, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_ALIASES r_e;
		BOOL p;

		samr_io_r_enum_dom_aliases("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_ENUM_DOM_ALIASES: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			int i;
			int name_idx = 0;

			*num_sam_aliases = r_e.num_entries2;
			if (*num_sam_aliases > MAX_SAM_ENTRIES)
			{
				*num_sam_aliases = MAX_SAM_ENTRIES;
				DEBUG(2,("samr_enum_dom_aliases: sam user entries limited to %d\n",
				          *num_sam_aliases));
			}

			*sam = (struct acct_info*) malloc(sizeof(struct acct_info) * (*num_sam_aliases));
				    
			if ((*sam) == NULL)
			{
				*num_sam_aliases = 0;
			}

			for (i = 0; i < *num_sam_aliases; i++)
			{
				(*sam)[i].rid = r_e.sam[i].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[i].hdr_name.buffer)
				{
					fstrcpy((*sam)[i].acct_name, unistr2_to_str(&r_e.uni_grp_name[name_idx]));
					name_idx++;
				}
				DEBUG(5,("samr_enum_dom_aliases: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR enumerate users
****************************************************************************/
BOOL samr_enum_dom_users(struct cli_state *cli, 
				POLICY_HND *pol, uint16 num_entries, uint16 unk_0,
				uint16 acb_mask, uint16 unk_1, uint32 size,
				struct acct_info **sam,
				int *num_sam_users)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ENUM_DOM_USERS q_e;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Enum SAM DB max size:%x\n", size));

	if (pol == NULL || num_sam_users == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ENUM_DOM_USERS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_enum_dom_users(&q_e, pol,
	                           num_entries, unk_0,
	                           acb_mask, unk_1, size);

	/* turn parameters into data stream */
	samr_io_q_enum_dom_users("", &q_e, &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_ENUM_DOM_USERS, &data, &rdata))
	{
		SAMR_R_ENUM_DOM_USERS r_e;
		BOOL p;

		samr_io_r_enum_dom_users("", &r_e, &rdata, 0);

		p = rdata.offset != 0;
		if (p && r_e.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_ENUM_DOM_USERS: %s\n", get_nt_error_msg(r_e.status)));
			p = False;
		}

		if (p)
		{
			int i;
			int name_idx = 0;

			*num_sam_users = r_e.num_entries2;
			if (*num_sam_users > MAX_SAM_ENTRIES)
			{
				*num_sam_users = MAX_SAM_ENTRIES;
				DEBUG(2,("samr_enum_dom_users: sam user entries limited to %d\n",
				          *num_sam_users));
			}

			*sam = (struct acct_info*) malloc(sizeof(struct acct_info) * (*num_sam_users));
				    
			if ((*sam) == NULL)
			{
				*num_sam_users = 0;
			}

			for (i = 0; i < *num_sam_users; i++)
			{
				(*sam)[i].rid = r_e.sam[i].rid;
				(*sam)[i].acct_name[0] = 0;
				(*sam)[i].acct_desc[0] = 0;
				if (r_e.sam[i].hdr_name.buffer)
				{
					fstrcpy((*sam)[i].acct_name, unistr2_to_str(&r_e.uni_acct_name[name_idx]));
					name_idx++;
				}
				DEBUG(5,("samr_enum_dom_users: idx: %4d rid: %8x acct: %s\n",
				          i, (*sam)[i].rid, (*sam)[i].acct_name));
			}
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Connect
****************************************************************************/
BOOL samr_connect(struct cli_state *cli, 
				char *srv_name, uint32 unknown_0,
				POLICY_HND *connect_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CONNECT q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open Policy server:%s undoc value:%x\n",
				srv_name, unknown_0));

	if (srv_name == NULL || connect_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CONNECT */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_connect(&q_o, srv_name, unknown_0);

	/* turn parameters into data stream */
	samr_io_q_connect("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_CONNECT, &data, &rdata))
	{
		SAMR_R_CONNECT r_o;
		BOOL p;

		samr_io_r_connect("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_CONNECT: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(connect_pol, &r_o.connect_pol, sizeof(r_o.connect_pol));
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open User
****************************************************************************/
BOOL samr_open_user(struct cli_state *cli, 
				POLICY_HND *pol, uint32 unk_0, uint32 rid, 
				POLICY_HND *user_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_USER q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open User.  unk_0: %08x RID:%x\n",
	          unk_0, rid));

	if (pol == NULL || user_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_USER */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_open_user(&q_o, pol, unk_0, rid);

	/* turn parameters into data stream */
	samr_io_q_open_user("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_OPEN_USER, &data, &rdata))
	{
		SAMR_R_OPEN_USER r_o;
		BOOL p;

		samr_io_r_open_user("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_OPEN_USER: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(user_pol, &r_o.user_pol, sizeof(r_o.user_pol));
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open Alias
****************************************************************************/
BOOL samr_open_alias(struct cli_state *cli, 
				POLICY_HND *domain_pol, uint32 rid,
				POLICY_HND *alias_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_ALIAS q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open Alias. RID:%x\n", rid));

	if (alias_pol == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_ALIAS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_open_alias(&q_o, domain_pol, 0x0008, rid);

	/* turn parameters into data stream */
	samr_io_q_open_alias("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_OPEN_ALIAS, &data, &rdata))
	{
		SAMR_R_OPEN_ALIAS r_o;
		BOOL p;

		samr_io_r_open_alias("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_OPEN_ALIAS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(alias_pol, &r_o.pol, sizeof(r_o.pol));
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Add Alias Member
****************************************************************************/
BOOL samr_add_aliasmem(struct cli_state *cli, 
				POLICY_HND *alias_pol, DOM_SID *sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ADD_ALIASMEM q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || sid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ADD_ALIASMEM */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Add Alias Member.\n"));

	/* store the parameters */
	make_samr_q_add_aliasmem(&q_o, alias_pol, sid);

	/* turn parameters into data stream */
	samr_io_q_add_aliasmem("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_ADD_ALIASMEM, &data, &rdata))
	{
		SAMR_R_ADD_ALIASMEM r_o;
		BOOL p;

		samr_io_r_add_aliasmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_ADD_ALIASMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Create Domain Alias
****************************************************************************/
BOOL samr_create_dom_alias(struct cli_state *cli, 
				POLICY_HND *domain_pol, const char *acct_name,
				POLICY_HND *alias_pol, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CREATE_DOM_ALIAS q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || domain_pol == NULL || acct_name == NULL || rid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CREATE_DOM_ALIAS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Create Domain Alias. Name:%s\n", acct_name));

	/* store the parameters */
	make_samr_q_create_dom_alias(&q_o, domain_pol, acct_name);

	/* turn parameters into data stream */
	samr_io_q_create_dom_alias("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_CREATE_DOM_ALIAS, &data, &rdata))
	{
		SAMR_R_CREATE_DOM_ALIAS r_o;
		BOOL p;

		samr_io_r_create_dom_alias("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_CREATE_DOM_ALIAS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(alias_pol, &r_o.alias_pol, sizeof(r_o.alias_pol));
			*rid = r_o.rid;
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Set Alias Info
****************************************************************************/
BOOL samr_set_aliasinfo(struct cli_state *cli, 
				POLICY_HND *alias_pol, ALIAS_INFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_ALIASINFO q_o;
	BOOL valid_pol = False;

	if (alias_pol == NULL || ctr == NULL) return False;

	/* create and send a MSRPC command with api SAMR_SET_ALIASINFO */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Set Alias Info\n"));

	/* store the parameters */
	make_samr_q_set_aliasinfo(&q_o, alias_pol, ctr);

	/* turn parameters into data stream */
	samr_io_q_set_aliasinfo("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_SET_ALIASINFO, &data, &rdata))
	{
		SAMR_R_SET_ALIASINFO r_o;
		BOOL p;

		samr_io_r_set_aliasinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_SET_ALIASINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open Group
****************************************************************************/
BOOL samr_open_group(struct cli_state *cli, 
				POLICY_HND *domain_pol, uint32 rid,
				POLICY_HND *group_pol)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_GROUP q_o;
	BOOL valid_pol = False;

	DEBUG(4,("SAMR Open Group. RID:%x\n", rid));

	if (group_pol == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_GROUP */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_open_group(&q_o, domain_pol, 0x0001, rid);

	/* turn parameters into data stream */
	samr_io_q_open_group("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_OPEN_GROUP, &data, &rdata))
	{
		SAMR_R_OPEN_GROUP r_o;
		BOOL p;

		samr_io_r_open_group("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_OPEN_GROUP: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(group_pol, &r_o.pol, sizeof(r_o.pol));
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Add Group Member
****************************************************************************/
BOOL samr_add_groupmem(struct cli_state *cli, 
				POLICY_HND *group_pol, uint32 rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_ADD_GROUPMEM q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_ADD_GROUPMEM */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Add Group Member.\n"));

	/* store the parameters */
	make_samr_q_add_groupmem(&q_o, group_pol, rid);

	/* turn parameters into data stream */
	samr_io_q_add_groupmem("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_ADD_GROUPMEM, &data, &rdata))
	{
		SAMR_R_ADD_GROUPMEM r_o;
		BOOL p;

		samr_io_r_add_groupmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_ADD_GROUPMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Create Domain Group
****************************************************************************/
BOOL samr_create_dom_group(struct cli_state *cli, 
				POLICY_HND *domain_pol, const char *acct_name,
				POLICY_HND *group_pol, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CREATE_DOM_GROUP q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL || domain_pol == NULL || acct_name == NULL || rid == NULL) return False;

	/* create and send a MSRPC command with api SAMR_CREATE_DOM_GROUP */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Create Domain Group. Name:%s\n", acct_name));

	/* store the parameters */
	make_samr_q_create_dom_group(&q_o, domain_pol, acct_name);

	/* turn parameters into data stream */
	samr_io_q_create_dom_group("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_CREATE_DOM_GROUP, &data, &rdata))
	{
		SAMR_R_CREATE_DOM_GROUP r_o;
		BOOL p;

		samr_io_r_create_dom_group("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_CREATE_DOM_GROUP: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(group_pol, &r_o.pol, sizeof(r_o.pol));
			*rid = r_o.rid;
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Set Group Info
****************************************************************************/
BOOL samr_set_groupinfo(struct cli_state *cli, 
				POLICY_HND *group_pol, GROUP_INFO_CTR *ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_SET_GROUPINFO q_o;
	BOOL valid_pol = False;

	if (group_pol == NULL || ctr == NULL) return False;

	/* create and send a MSRPC command with api SAMR_SET_GROUPINFO */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Set Group Info\n"));

	/* store the parameters */
	make_samr_q_set_groupinfo(&q_o, group_pol, ctr);

	/* turn parameters into data stream */
	samr_io_q_set_groupinfo("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_SET_GROUPINFO, &data, &rdata))
	{
		SAMR_R_SET_GROUPINFO r_o;
		BOOL p;

		samr_io_r_set_groupinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_SET_GROUPINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Open Domain
****************************************************************************/
BOOL samr_open_domain(struct cli_state *cli, 
				POLICY_HND *connect_pol, uint32 flags, DOM_SID *sid,
				POLICY_HND *domain_pol)
{
	pstring sid_str;
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_OPEN_DOMAIN q_o;
	BOOL valid_pol = False;

	sid_to_string(sid_str, sid);
	DEBUG(4,("SAMR Open Domain.  SID:%s Flags:%x\n", sid_str, flags));

	if (connect_pol == NULL || sid == NULL || domain_pol == NULL) return False;

	/* create and send a MSRPC command with api SAMR_OPEN_DOMAIN */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_open_domain(&q_o, connect_pol, flags, sid);

	/* turn parameters into data stream */
	samr_io_q_open_domain("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_OPEN_DOMAIN, &data, &rdata))
	{
		SAMR_R_OPEN_DOMAIN r_o;
		BOOL p;

		samr_io_r_open_domain("", &r_o, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_OPEN_DOMAIN: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			memcpy(domain_pol, &r_o.domain_pol, sizeof(r_o.domain_pol));
			valid_pol = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_pol;
}

/****************************************************************************
do a SAMR Query Lookup RIDS
****************************************************************************/
BOOL samr_query_lookup_rids(struct cli_state *cli, 
				POLICY_HND *pol, uint32 flags,
				uint32 num_rids, uint32 *rids,
				uint32 *num_names,
				fstring names[MAX_LOOKUP_SIDS],
				uint32  type [MAX_LOOKUP_SIDS])
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_LOOKUP_RIDS q_o;
	BOOL valid_query = False;

	if (pol == NULL || flags == 0 || num_rids == 0 || rids == NULL ||
	    num_names == NULL || names == NULL || type == NULL ) return False;

	/* create and send a MSRPC command with api SAMR_LOOKUP_RIDS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	DEBUG(4,("SAMR Query Lookup RIDs.\n"));

	/* store the parameters */
	make_samr_q_lookup_rids(&q_o, pol, flags, num_rids, rids);

	/* turn parameters into data stream */
	samr_io_q_lookup_rids("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_LOOKUP_RIDS, &data, &rdata))
	{
		SAMR_R_LOOKUP_RIDS r_o;
		BOOL p;

		samr_io_r_lookup_rids("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_LOOKUP_RIDS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p)
		{
			if (r_o.ptr_names != 0 && r_o.ptr_types != 0 &&
			    r_o.num_types1 == r_o.num_names1)
			{
				int i;

				valid_query = True;
				*num_names = r_o.num_names1;

				for (i = 0; i < r_o.num_names1; i++)
				{
					fstrcpy(names[i], unistr2_to_str(&r_o.uni_name[i]));
				}
				for (i = 0; i < r_o.num_types1; i++)
				{
					type[i] = r_o.type[i];
				}
			}
			else if (r_o.ptr_names == 0 && r_o.ptr_types == 0)
			{
				valid_query = True;
				*num_names = 0;
			}
			else
			{
				p = False;
			}
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Alias Members
****************************************************************************/
BOOL samr_query_aliasmem(struct cli_state *cli, 
				POLICY_HND *alias_pol, 
				uint32 *num_mem, DOM_SID2 *sid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_ALIASMEM q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Alias Members.\n"));

	if (alias_pol == NULL || sid == NULL || num_mem == NULL) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_ALIASMEM */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_aliasmem(&q_o, alias_pol);

	/* turn parameters into data stream */
	samr_io_q_query_aliasmem("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_ALIASMEM, &data, &rdata))
	{
		SAMR_R_QUERY_ALIASMEM r_o;
		BOOL p;

		/* get user info */
		r_o.sid = sid;

		samr_io_r_query_aliasmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_ALIASMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
			*num_mem = r_o.num_sids;
		}

	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Aliases
****************************************************************************/
BOOL samr_query_useraliases(struct cli_state *cli, 
				POLICY_HND *pol, DOM_SID *sid,
				uint32 *num_aliases, uint32 *rid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERALIASES q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query User Aliases.\n"));

	if (pol == NULL || sid == NULL || rid == NULL || num_aliases == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERALIASES */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_useraliases(&q_o, pol, sid);

	/* turn parameters into data stream */
	samr_io_q_query_useraliases("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_USERALIASES, &data, &rdata))
	{
		SAMR_R_QUERY_USERALIASES r_o;
		BOOL p;

		/* get user info */
		r_o.rid = rid;

		samr_io_r_query_useraliases("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_USERALIASES: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
			*num_aliases = r_o.num_entries;
		}

	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Group Members
****************************************************************************/
BOOL samr_query_groupmem(struct cli_state *cli, 
				POLICY_HND *group_pol, 
				uint32 *num_mem, uint32 *rid, uint32 *attr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_GROUPMEM q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Group Members.\n"));

	if (group_pol == NULL || rid == NULL || attr == NULL || num_mem == NULL) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_GROUPMEM */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_groupmem(&q_o, group_pol);

	/* turn parameters into data stream */
	samr_io_q_query_groupmem("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_GROUPMEM, &data, &rdata))
	{
		SAMR_R_QUERY_GROUPMEM r_o;
		BOOL p;

		/* get user info */
		r_o.rid  = rid;
		r_o.attr = attr;

		samr_io_r_query_groupmem("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_GROUPMEM: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr != 0 &&
		    r_o.ptr_rids != 0 && r_o.ptr_attrs != 0 &&
		    r_o.num_rids == r_o.num_attrs)
		{
			valid_query = True;
			*num_mem = r_o.num_rids;
		}

	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Groups
****************************************************************************/
BOOL samr_query_usergroups(struct cli_state *cli, 
				POLICY_HND *pol, uint32 *num_groups, DOM_GID *gid)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERGROUPS q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query User Groups.\n"));

	if (pol == NULL || gid == NULL || num_groups == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERGROUPS */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_usergroups(&q_o, pol);

	/* turn parameters into data stream */
	samr_io_q_query_usergroups("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_USERGROUPS, &data, &rdata))
	{
		SAMR_R_QUERY_USERGROUPS r_o;
		BOOL p;

		/* get user info */
		r_o.gid = gid;

		samr_io_r_query_usergroups("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_USERGROUPS: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ptr_0 != 0)
		{
			valid_query = True;
			*num_groups = r_o.num_entries;
		}

	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query Group Info
****************************************************************************/
BOOL samr_query_groupinfo(struct cli_state *cli, 
				POLICY_HND *pol,
				uint16 switch_value, GROUP_INFO_CTR* ctr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_GROUPINFO q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query Group Info.  level: %d\n", switch_value));

	if (pol == NULL || ctr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_GROUPINFO */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_groupinfo(&q_o, pol, switch_value);

	/* turn parameters into data stream */
	samr_io_q_query_groupinfo("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_GROUPINFO, &data, &rdata))
	{
		SAMR_R_QUERY_GROUPINFO r_o;
		BOOL p;

		/* get user info */
		r_o.ctr = ctr;

		samr_io_r_query_groupinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_GROUPINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.ctr->switch_value1 != switch_value)
		{
			DEBUG(0,("SAMR_R_QUERY_GROUPINFO: received incorrect level %d\n",
			          r_o.ctr->switch_value1));
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Query User Info
****************************************************************************/
BOOL samr_query_userinfo(struct cli_state *cli, 
				POLICY_HND *pol, uint16 switch_value, void* usr)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_QUERY_USERINFO q_o;
	BOOL valid_query = False;

	DEBUG(4,("SAMR Query User Info.  level: %d\n", switch_value));

	if (pol == NULL || usr == NULL || switch_value == 0) return False;

	/* create and send a MSRPC command with api SAMR_QUERY_USERINFO */

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* store the parameters */
	make_samr_q_query_userinfo(&q_o, pol, switch_value);

	/* turn parameters into data stream */
	samr_io_q_query_userinfo("", &q_o,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_QUERY_USERINFO, &data, &rdata))
	{
		SAMR_R_QUERY_USERINFO r_o;
		BOOL p;

		/* get user info */
		r_o.info.id = usr;

		samr_io_r_query_userinfo("", &r_o, &rdata, 0);
		p = rdata.offset != 0;
		
		if (p && r_o.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_R_QUERY_USERINFO: %s\n", get_nt_error_msg(r_o.status)));
			p = False;
		}

		if (p && r_o.switch_value != switch_value)
		{
			DEBUG(0,("SAMR_R_QUERY_USERINFO: received incorrect level %d\n",
			          r_o.switch_value));
		}

		if (p && r_o.ptr != 0)
		{
			valid_query = True;
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_query;
}

/****************************************************************************
do a SAMR Close
****************************************************************************/
BOOL samr_close(struct cli_state *cli, POLICY_HND *hnd)
{
	prs_struct data;
	prs_struct rdata;

	SAMR_Q_CLOSE_HND q_c;
	BOOL valid_close = False;

	DEBUG(4,("SAMR Close\n"));

	if (hnd == NULL) return False;

	prs_init(&data , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rdata, 0   , 4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api SAMR_CLOSE_HND */

	/* store the parameters */
	make_samr_q_close_hnd(&q_c, hnd);

	/* turn parameters into data stream */
	samr_io_q_close_hnd("", &q_c,  &data, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, SAMR_CLOSE_HND, &data, &rdata))
	{
		SAMR_R_CLOSE_HND r_c;
		BOOL p;

		samr_io_r_close_hnd("", &r_c, &rdata, 0);
		p = rdata.offset != 0;

		if (p && r_c.status != 0)
		{
			/* report error code */
			DEBUG(0,("SAMR_CLOSE_HND: %s\n", get_nt_error_msg(r_c.status)));
			p = False;
		}

		if (p)
		{
			/* check that the returned policy handle is all zeros */
			int i;
			valid_close = True;

			for (i = 0; i < sizeof(r_c.pol.data); i++)
			{
				if (r_c.pol.data[i] != 0)
				{
					valid_close = False;
					break;
				}
			}	
			if (!valid_close)
			{
				DEBUG(0,("SAMR_CLOSE_HND: non-zero handle returned\n"));
			}
		}
	}

	prs_mem_free(&data   );
	prs_mem_free(&rdata  );

	return valid_close;
}

