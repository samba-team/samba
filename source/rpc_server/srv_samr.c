
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;

extern fstring global_sam_name;
extern pstring global_myname;
extern DOM_SID global_sam_sid;
extern DOM_SID global_sid_S_1_1;
extern DOM_SID global_sid_S_1_5_20;

/*******************************************************************
  This next function should be replaced with something that
  dynamically returns the correct user info..... JRA.
 ********************************************************************/

static BOOL get_sampwd_entries(SAM_USER_INFO_21 *pw_buf,
				int start_idx,
                                int *total_entries, int *num_entries,
                                int max_num_entries,
                                uint16 acb_mask)
{
	void *vp = NULL;
	struct sam_passwd *pwd = NULL;

	(*num_entries) = 0;
	(*total_entries) = 0;

	if (pw_buf == NULL) return False;

	vp = startsmbpwent(False);
	if (!vp)
	{
		DEBUG(0, ("get_sampwd_entries: Unable to open SMB password database.\n"));
		return False;
	}

	while (((pwd = getsam21pwent(vp)) != NULL) && (*num_entries) < max_num_entries)
	{
		int user_name_len;

		if (start_idx > 0)
		{
			/* skip the requested number of entries.
			   not very efficient, but hey...
			 */
			if (acb_mask == 0 || IS_BITS_SET_SOME(pwd->acct_ctrl, acb_mask))
			{
				start_idx--;
			}
			continue;
		}

		user_name_len = strlen(pwd->nt_name);
		make_unistr2(&(pw_buf[(*num_entries)].uni_user_name), pwd->nt_name, user_name_len);
		make_uni_hdr(&(pw_buf[(*num_entries)].hdr_user_name), user_name_len);
		pw_buf[(*num_entries)].user_rid = pwd->user_rid;
		bzero( pw_buf[(*num_entries)].nt_pwd , 16);

		/* Now check if the NT compatible password is available. */
		if (pwd->smb_nt_passwd != NULL)
		{
			memcpy( pw_buf[(*num_entries)].nt_pwd , pwd->smb_nt_passwd, 16);
		}

		pw_buf[(*num_entries)].acb_info = (uint16)pwd->acct_ctrl;

		DEBUG(5, ("entry idx: %d user %s, rid 0x%x, acb %x",
		          (*num_entries), pwd->nt_name,
		          pwd->user_rid, pwd->acct_ctrl));

		if (acb_mask == 0 || IS_BITS_SET_SOME(pwd->acct_ctrl, acb_mask))
		{
			DEBUG(5,(" acb_mask %x accepts\n", acb_mask));
			(*num_entries)++;
		}
		else
		{
			DEBUG(5,(" acb_mask %x rejects\n", acb_mask));
		}

		(*total_entries)++;
	}

	endsmbpwent(vp);

	return (*num_entries) > 0;
}

/*******************************************************************
 api_samr_close_hnd
 ********************************************************************/
static void api_samr_close_hnd( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CLOSE_HND q_u;
	SAMR_R_CLOSE_HND r_u;
	samr_io_q_close_hnd("", &q_u, data, 0);

	r_u.status = _samr_close(&q_u.pol);

	memcpy(&r_u.pol, &q_u.pol, sizeof(q_u.pol));
	samr_io_r_close_hnd("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_open_domain
 ********************************************************************/
static void api_samr_open_domain( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_OPEN_DOMAIN q_u;
	SAMR_R_OPEN_DOMAIN r_u;
	samr_io_q_open_domain("", &q_u, data, 0);

	r_u.status = _samr_open_domain(&q_u.connect_pol, q_u.flags,
	                               &q_u.dom_sid.sid,
	                               &r_u.domain_pol);

	samr_io_r_open_domain("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_unknown_2c
 ********************************************************************/
static void api_samr_unknown_2c( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_UNKNOWN_2C q_u;
	SAMR_R_UNKNOWN_2C r_u;
	samr_io_q_unknown_2c("", &q_u, data, 0);

	r_u.status = _samr_unknown_2c(&q_u.user_pol,
	                              &r_u.unknown_0, &r_u.unknown_1);

	samr_io_r_unknown_2c("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_unknown_3
 ********************************************************************/
static void api_samr_unknown_3( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_UNKNOWN_3 q_u;
	SAMR_R_UNKNOWN_3 r_u;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);

	samr_io_q_unknown_3("", &q_u, data, 0);

	r_u.status = _samr_unknown_3(&q_u.user_pol, &r_u.sid_stuff);

	if (r_u.status == 0)
	{
		r_u.ptr_0 = 1;
		r_u.ptr_1 = 1;
	}
		
	samr_io_r_unknown_3("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_enum_dom_users
 ********************************************************************/
static void api_samr_enum_dom_users( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOM_USERS q_e;
	SAMR_R_ENUM_DOM_USERS r_e;
	uint32 num_entries = 0;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_enum_dom_users("", &q_e, data, 0);

	r_e.status = _samr_enum_dom_users(&q_e.pol, &q_e.start_idx,
	                              q_e.acb_mask, q_e.unknown_1, q_e.max_size,
	                              &r_e.sam, &r_e.uni_acct_name,
	                              &num_entries);

	make_samr_r_enum_dom_users(&r_e, q_e.start_idx, num_entries);

	samr_io_r_enum_dom_users("", &r_e, rdata, 0);

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_acct_name != NULL)
	{
		free(r_e.uni_acct_name);
	}
}

/*******************************************************************
 api_samr_add_groupmem
 ********************************************************************/
static void api_samr_add_groupmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ADD_GROUPMEM q_e;
	SAMR_R_ADD_GROUPMEM r_e;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_add_groupmem("", &q_e, data, 0);

	r_e.status = _samr_add_groupmem(&q_e.pol, q_e.rid, q_e.unknown);

	samr_io_r_add_groupmem("", &r_e, rdata, 0);
}

/*******************************************************************
 api_samr_del_groupmem
 ********************************************************************/
static void api_samr_del_groupmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DEL_GROUPMEM q_e;
	SAMR_R_DEL_GROUPMEM r_e;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_del_groupmem("", &q_e, data, 0);

	r_e.status = _samr_del_groupmem(&q_e.pol, q_e.rid);

	samr_io_r_del_groupmem("", &r_e, rdata, 0);
}

/*******************************************************************
 api_samr_add_aliasmem
 ********************************************************************/
static void api_samr_add_aliasmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ADD_ALIASMEM q_e;
	SAMR_R_ADD_ALIASMEM r_e;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_add_aliasmem("", &q_e, data, 0);

	r_e.status = _samr_add_aliasmem(&q_e.alias_pol, &q_e.sid.sid);

	samr_io_r_add_aliasmem("", &r_e, rdata, 0);
}

/*******************************************************************
 api_samr_del_aliasmem
 ********************************************************************/
static void api_samr_del_aliasmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DEL_ALIASMEM q_e;
	SAMR_R_DEL_ALIASMEM r_e;
	samr_io_q_del_aliasmem("", &q_e, data, 0);

	r_e.status = _samr_del_aliasmem(&q_e.alias_pol, &q_e.sid.sid);

	samr_io_r_del_aliasmem("", &r_e, rdata, 0);
}

/*******************************************************************
 api_samr_enum_domains
 ********************************************************************/
static void api_samr_enum_domains( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOMAINS q_e;
	SAMR_R_ENUM_DOMAINS r_e;
	uint32 num_entries = 0;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_enum_domains("", &q_e, data, 0);

	r_e.status = _samr_enum_domains(&q_e.pol, &q_e.start_idx,
	                              q_e.max_size,
	                              &r_e.sam, &r_e.uni_dom_name,
	                              &num_entries);

	make_samr_r_enum_domains(&r_e, q_e.start_idx, num_entries);

	samr_io_r_enum_domains("", &r_e, rdata, 0);

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_dom_name != NULL)
	{
		free(r_e.uni_dom_name);
	}
}

/*******************************************************************
 samr_reply_enum_dom_groups
 ********************************************************************/
static void samr_reply_enum_dom_groups(SAMR_Q_ENUM_DOM_GROUPS *q_u,
				prs_struct *rdata)
{
	SAMR_R_ENUM_DOM_GROUPS r_e;
	DOMAIN_GRP *grps = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;

	r_e.status = 0x0;
	r_e.num_entries2 = 0;

	/* find the policy handle.  open a policy on it. */
	if (r_e.status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &sid))
	{
		r_e.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_groups: sid %s\n", sid_str));

	if (sid_equal(&sid, &global_sam_sid))
	{
		BOOL ret;

		become_root(True);
		ret = enumdomgroups(&grps, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			r_e.status = 0xC0000000 | NT_STATUS_NO_MEMORY;
		}
	}

	if (r_e.status == 0x0)
	{
		make_samr_r_enum_dom_groups(&r_e,
		          q_u->start_idx + num_entries,
		          num_entries, grps, r_e.status);
	}

	/* store the response in the SMB stream */
	samr_io_r_enum_dom_groups("", &r_e, rdata, 0);

	if (grps != NULL)
	{
		free(grps);
	}

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_grp_name != NULL)
	{
		free(r_e.uni_grp_name);
	}

	DEBUG(5,("samr_enum_dom_groups: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_enum_dom_groups
 ********************************************************************/
static void api_samr_enum_dom_groups( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOM_GROUPS q_e;

	/* grab the samr open */
	samr_io_q_enum_dom_groups("", &q_e, data, 0);

	/* construct reply. */
	samr_reply_enum_dom_groups(&q_e, rdata);
}


/*******************************************************************
 samr_reply_enum_dom_aliases
 ********************************************************************/
static void samr_reply_enum_dom_aliases(SAMR_Q_ENUM_DOM_ALIASES *q_u,
				prs_struct *rdata)
{
	SAMR_R_ENUM_DOM_ALIASES r_e;
	LOCAL_GRP *alss = NULL;
	int num_entries = 0;
	DOM_SID sid;
	fstring sid_str;

	ZERO_STRUCT(r_e);

	r_e.status = 0x0;
	r_e.num_entries2 = 0;

	/* find the policy handle.  open a policy on it. */
	if (r_e.status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &sid))
	{
		r_e.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	sid_to_string(sid_str, &sid);

	DEBUG(5,("samr_reply_enum_dom_aliases: sid %s\n", sid_str));

	/* well-known aliases */
	if (sid_equal(&sid, &global_sid_S_1_5_20))
	{
		BOOL ret;
		/* builtin aliases */

		become_root(True);
		ret = enumdombuiltins(&alss, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			r_e.status = 0xC0000000 | NT_STATUS_NO_MEMORY;
		}
	}
	else if (sid_equal(&sid, &global_sam_sid))
	{
		BOOL ret;
		/* local aliases */

		become_root(True);
		ret = enumdomaliases(&alss, &num_entries);
		unbecome_root(True);
		if (!ret)
		{
			r_e.status = 0xC0000000 | NT_STATUS_NO_MEMORY;
		}
	}
		
	if (r_e.status == 0x0)
	{
		make_samr_r_enum_dom_aliases(&r_e,
		               q_u->start_idx + num_entries,
		               num_entries, alss, r_e.status);
	}

	/* store the response in the SMB stream */
	samr_io_r_enum_dom_aliases("", &r_e, rdata, 0);

	if (alss != NULL)
	{
		free(alss);
	}

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_grp_name != NULL)
	{
		free(r_e.uni_grp_name);
	}

	DEBUG(5,("samr_enum_dom_aliases: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_enum_dom_aliases
 ********************************************************************/
static void api_samr_enum_dom_aliases( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOM_ALIASES q_e;

	/* grab the samr open */
	samr_io_q_enum_dom_aliases("", &q_e, data, 0);

	/* construct reply. */
	samr_reply_enum_dom_aliases(&q_e, rdata);
}


/*******************************************************************
 samr_reply_query_dispinfo
 ********************************************************************/
static void samr_reply_query_dispinfo(SAMR_Q_QUERY_DISPINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_DISPINFO r_e;
	SAM_DISPINFO_CTR ctr;
	SAM_USER_INFO_21 pass[MAX_SAM_ENTRIES];
	DOMAIN_GRP *grps = NULL;
	DOMAIN_GRP *sam_grps = NULL;
	uint32 data_size = 0;
	uint32 status = 0x0;
	uint16 acb_mask = ACB_NORMAL;
	int num_sam_entries = 0;
	int num_entries = 0;
	int total_entries;

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->domain_pol)) == -1)
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
		DEBUG(5,("samr_reply_query_dispinfo: invalid handle\n"));
	}

	if (status == 0x0)
	{
		become_root(True);

		/* Get what we need from the password database */
		switch (q_u->switch_level)
		{
			case 0x2:
			{
				acb_mask = ACB_WSTRUST;
				/* Fall through */
			}
			case 0x1:
			case 0x4:
			{
				get_sampwd_entries(pass, q_u->start_idx,
					      &total_entries, &num_sam_entries,
					      MAX_SAM_ENTRIES, acb_mask);
				break;
			}
			case 0x3:
			case 0x5:
			{
				enumdomgroups(&sam_grps, &num_sam_entries);

				if (q_u->start_idx < num_sam_entries) {
					grps = sam_grps + q_u->start_idx;
					num_sam_entries -= q_u->start_idx;
				} else {
					num_sam_entries = 0;
				}
				break;
			}
		}

		unbecome_root(True);

		num_entries = num_sam_entries;

		if (num_entries > q_u->max_entries)
		{
			num_entries = q_u->max_entries;
		}

		if (num_entries > MAX_SAM_ENTRIES)
		{
			num_entries = MAX_SAM_ENTRIES;
			DEBUG(5,("limiting number of entries to %d\n", 
				 num_entries));
		}

		data_size = q_u->max_size;

		/* Now create reply structure */
		switch (q_u->switch_level)
		{
			case 0x1:
			{
				ctr.sam.info1 = malloc(sizeof(SAM_DISPINFO_1));
				make_sam_dispinfo_1(ctr.sam.info1,
						    &num_entries, &data_size,
						    q_u->start_idx, pass);
				break;
			}
			case 0x2:
			{
				ctr.sam.info2 = malloc(sizeof(SAM_DISPINFO_2));
				make_sam_dispinfo_2(ctr.sam.info2,
						    &num_entries, &data_size,
						    q_u->start_idx, pass);
				break;
			}
			case 0x3:
			{
				ctr.sam.info3 = malloc(sizeof(SAM_DISPINFO_3));
				make_sam_dispinfo_3(ctr.sam.info3,
						    &num_entries, &data_size,
						    q_u->start_idx, grps);
				break;
			}
	  		case 0x4:
			{
				ctr.sam.info4 = malloc(sizeof(SAM_DISPINFO_4));
				make_sam_dispinfo_4(ctr.sam.info4,
						    &num_entries, &data_size,
						    q_u->start_idx, pass);
				break;
			}
			case 0x5:
			{
				ctr.sam.info5 = malloc(sizeof(SAM_DISPINFO_5));
				make_sam_dispinfo_5(ctr.sam.info5,
						    &num_entries, &data_size,
						    q_u->start_idx, grps);
				break;
			}
			default:
			{
				ctr.sam.info = NULL;
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
				break;
			}
		}
	}

	if ((status == 0) && (num_entries < num_sam_entries))
	{
		status = STATUS_MORE_ENTRIES;
	}

	make_samr_r_query_dispinfo(&r_e, num_entries, data_size,
				   q_u->switch_level, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dispinfo("", &r_e, rdata, 0);

	/* free malloc'd areas */
	if (sam_grps != NULL)
	{
		free(sam_grps);
	}

	if (ctr.sam.info != NULL)
	{
		free(ctr.sam.info);
	}

	DEBUG(5,("samr_reply_query_dispinfo: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_query_dispinfo
 ********************************************************************/
static void api_samr_query_dispinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_DISPINFO q_e;

	samr_io_q_query_dispinfo("", &q_e, data, 0);
	samr_reply_query_dispinfo(&q_e, rdata);
}

/*******************************************************************
 samr_reply_delete_dom_group
 ********************************************************************/
static void samr_reply_delete_dom_group(SAMR_Q_DELETE_DOM_GROUP *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	SAMR_R_DELETE_DOM_GROUP r_u;

	DEBUG(5,("samr_delete_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->group_pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid     );
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = del_group_entry(group_rid) ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_GROUP);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	make_samr_r_delete_dom_group(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_delete_dom_group("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_delete_dom_group
 ********************************************************************/
static void api_samr_delete_dom_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DELETE_DOM_GROUP q_u;
	samr_io_q_delete_dom_group("", &q_u, data, 0);
	samr_reply_delete_dom_group(&q_u, rdata);
}


/*******************************************************************
 samr_reply_query_groupmem
 ********************************************************************/
static void samr_reply_query_groupmem(SAMR_Q_QUERY_GROUPMEM *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOMAIN_GRP_MEMBER *mem_grp = NULL;
	uint32 *rid = NULL;
	uint32 *attr = NULL;
	int num_rids = 0;
	DOM_SID group_sid;
	uint32 group_rid;
	fstring group_sid_str;

	SAMR_R_QUERY_GROUPMEM r_u;

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->group_pol, &group_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(group_sid_str, &group_sid     );
		sid_split_rid(&group_sid, &group_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", group_sid_str));

		if (sid_equal(&group_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = getgrouprid(group_rid, &mem_grp, &num_rids) != NULL ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_GROUP);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_GROUP;
		}
	}

	if (status == 0x0 && num_rids > 0)
	{
		rid  = malloc(num_rids * sizeof(uint32));
		attr = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && rid != NULL && attr != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				rid [i] = mem_grp[i].rid;
				attr[i] = mem_grp[i].attr;
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_groupmem(&r_u, num_rids, rid, attr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_groupmem("", &r_u, rdata, 0);

	samr_free_r_query_groupmem(&r_u);

	DEBUG(5,("samr_query_groupmem: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_groupmem
 ********************************************************************/
static void api_samr_query_groupmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_GROUPMEM q_u;
	samr_io_q_query_groupmem("", &q_u, data, 0);
	samr_reply_query_groupmem(&q_u, rdata);
}


/*******************************************************************
 samr_reply_query_groupinfo
 ********************************************************************/
static void samr_reply_query_groupinfo(SAMR_Q_QUERY_GROUPINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_GROUPINFO r_e;
	GROUP_INFO_CTR ctr;
	uint32 status = 0x0;

	r_e.ptr = 0;

	/* find the policy handle.  open a policy on it. */
	if (r_e.status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		r_e.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_query_groupinfo: %d\n", __LINE__));

	if (status == 0x0)
	{
		if (q_u->switch_level == 1)
		{
			r_e.ptr = 1;
			ctr.switch_value1 = 1;
			make_samr_group_info1(&ctr.group.info1,
			                      "fake account name",
			                      "fake account description", 2);
		}
		else if (q_u->switch_level == 4)
		{
			r_e.ptr = 1;
			ctr.switch_value1 = 4;
			make_samr_group_info4(&ctr.group.info4,
			                     "fake account description");
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	make_samr_r_query_groupinfo(&r_e, status == 0 ? &ctr : NULL, status);

	/* store the response in the SMB stream */
	samr_io_r_query_groupinfo("", &r_e, rdata, 0);

	DEBUG(5,("samr_query_groupinfo: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_groupinfo
 ********************************************************************/
static void api_samr_query_groupinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_GROUPINFO q_e;
	samr_io_q_query_groupinfo("", &q_e, data, 0);
	samr_reply_query_groupinfo(&q_e, rdata);
}


/*******************************************************************
 samr_reply_query_aliasinfo
 ********************************************************************/
static void samr_reply_query_aliasinfo(SAMR_Q_QUERY_ALIASINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_ALIASINFO r_e;
	ALIAS_INFO_CTR ctr;
	uint32 status = 0x0;

	r_e.ptr = 0;

	/* find the policy handle.  open a policy on it. */
	if (r_e.status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		r_e.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	DEBUG(5,("samr_reply_query_aliasinfo: %d\n", __LINE__));

	if (status == 0x0)
	{
		if (q_u->switch_level == 3)
		{
			r_e.ptr = 1;
			ctr.switch_value1 = 3;
			make_samr_alias_info3(&ctr.alias.info3, "<fake account description>");
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	make_samr_r_query_aliasinfo(&r_e, status == 0 ? &ctr : NULL, status);

	/* store the response in the SMB stream */
	samr_io_r_query_aliasinfo("", &r_e, rdata, 0);

	DEBUG(5,("samr_query_aliasinfo: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_aliasinfo
 ********************************************************************/
static void api_samr_query_aliasinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_ALIASINFO q_e;
	samr_io_q_query_aliasinfo("", &q_e, data, 0);
	samr_reply_query_aliasinfo(&q_e, rdata);
}


/*******************************************************************
 samr_reply_query_useraliases
 ********************************************************************/
static void samr_reply_query_useraliases(SAMR_Q_QUERY_USERALIASES *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	LOCAL_GRP *mem_grp = NULL;
	uint32 *rid = NULL;
	int num_rids = 0;
	struct sam_passwd *sam_pass;
	DOM_SID usr_sid;
	DOM_SID dom_sid;
	uint32 user_rid;
	fstring sam_sid_str;
	fstring dom_sid_str;
	fstring usr_sid_str;

	SAMR_R_QUERY_USERALIASES r_u;
	ZERO_STRUCT(r_u);

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(dom_sid_str, &dom_sid       );
		sid_to_string(sam_sid_str, &global_sam_sid);
	}

	if (status == 0x0)
	{
		usr_sid = q_u->sid[0].sid;
		sid_split_rid(&usr_sid, &user_rid);
		sid_to_string(usr_sid_str, &usr_sid);

	}

	if (status == 0x0)
	{
		/* find the user account */
		become_root(True);
		sam_pass = getsam21pwrid(user_rid);
		unbecome_root(True);

		if (sam_pass == NULL)
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
			num_rids = 0;
		}
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", dom_sid_str));

		if (sid_equal(&dom_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("lookup on S-1-5-20\n"));

			become_root(True);
			getuserbuiltinntnam(sam_pass->nt_name, &mem_grp, &num_rids);
			unbecome_root(True);
		}
		else if (sid_equal(&dom_sid, &usr_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			getuseraliasntnam(sam_pass->nt_name, &mem_grp, &num_rids);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
		}
	}

	if (status == 0x0 && num_rids > 0)
	{
		rid = malloc(num_rids * sizeof(uint32));
		if (mem_grp != NULL && rid != NULL)
		{
			int i;
			for (i = 0; i < num_rids; i++)
			{
				rid[i] = mem_grp[i].rid;
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_useraliases(&r_u, num_rids, rid, status);

	/* store the response in the SMB stream */
	samr_io_r_query_useraliases("", &r_u, rdata, 0);

	samr_free_r_query_useraliases(&r_u);

	DEBUG(5,("samr_query_useraliases: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_useraliases
 ********************************************************************/
static void api_samr_query_useraliases( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERALIASES q_u;
	ZERO_STRUCT(q_u);
	samr_io_q_query_useraliases("", &q_u, data, 0);
	samr_reply_query_useraliases(&q_u, rdata);
	samr_free_q_query_useraliases(&q_u);
}

/*******************************************************************
 samr_reply_delete_dom_alias
 ********************************************************************/
static void samr_reply_delete_dom_alias(SAMR_Q_DELETE_DOM_ALIAS *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	SAMR_R_DELETE_DOM_ALIAS r_u;

	DEBUG(5,("samr_delete_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid     );
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = del_alias_entry(alias_rid) ? 0x0 : (0xC0000000 | NT_STATUS_NO_SUCH_ALIAS);
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	make_samr_r_delete_dom_alias(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_delete_dom_alias("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_delete_dom_alias
 ********************************************************************/
static void api_samr_delete_dom_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DELETE_DOM_ALIAS q_u;
	samr_io_q_delete_dom_alias("", &q_u, data, 0);
	samr_reply_delete_dom_alias(&q_u, rdata);
}


/*******************************************************************
 samr_reply_query_aliasmem
 ********************************************************************/
static void samr_reply_query_aliasmem(SAMR_Q_QUERY_ALIASMEM *q_u,
				prs_struct *rdata)
{
	uint32 status = 0;

	LOCAL_GRP_MEMBER *mem_grp = NULL;
	DOM_SID2 *sid = NULL;
	int num_sids = 0;
	DOM_SID alias_sid;
	uint32 alias_rid;
	fstring alias_sid_str;

	SAMR_R_QUERY_ALIASMEM r_u;

	DEBUG(5,("samr_query_aliasmem: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->alias_pol, &alias_sid))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}
	else
	{
		sid_to_string(alias_sid_str, &alias_sid     );
		sid_split_rid(&alias_sid, &alias_rid);
	}

	if (status == 0x0)
	{
		DEBUG(10,("sid is %s\n", alias_sid_str));

		if (sid_equal(&alias_sid, &global_sid_S_1_5_20))
		{
			DEBUG(10,("lookup on S-1-5-20\n"));

			become_root(True);
			status = getbuiltinrid(alias_rid, &mem_grp, &num_sids) != NULL ? 0x0 : 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
			unbecome_root(True);
		}
		else if (sid_equal(&alias_sid, &global_sam_sid))
		{
			DEBUG(10,("lookup on Domain SID\n"));

			become_root(True);
			status = getaliasrid(alias_rid, &mem_grp, &num_sids) != NULL ? 0x0 : 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
			unbecome_root(True);
		}
		else
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_ALIAS;
		}
	}

	if (status == 0x0 && num_sids > 0)
	{
		sid = malloc(num_sids * sizeof(DOM_SID));
		if (mem_grp != NULL && sid != NULL)
		{
			int i;
			for (i = 0; i < num_sids; i++)
			{
				make_dom_sid2(&sid[i], &mem_grp[i].sid);
			}
			free(mem_grp);
		}
	}

	make_samr_r_query_aliasmem(&r_u, num_sids, sid, status);

	/* store the response in the SMB stream */
	samr_io_r_query_aliasmem("", &r_u, rdata, 0);

	if (sid != NULL)
	{
		free(sid);
	}

	DEBUG(5,("samr_query_aliasmem: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_aliasmem
 ********************************************************************/
static void api_samr_query_aliasmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_ALIASMEM q_u;
	samr_io_q_query_aliasmem("", &q_u, data, 0);
	samr_reply_query_aliasmem(&q_u, rdata);
}

/*******************************************************************
 samr_reply_lookup_names
 ********************************************************************/
static void samr_reply_lookup_names(const SAMR_Q_LOOKUP_NAMES *q_u,
				prs_struct *rdata)
{
	uint32 rid [MAX_SAM_ENTRIES];
	uint8  type[MAX_SAM_ENTRIES];
	uint32 status     = 0;
	int i;
	int num_rids = q_u->num_names1;
	DOM_SID pol_sid;
	fstring tmp;

	SAMR_R_LOOKUP_NAMES r_u;

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));

	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &pol_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	sid_to_string(tmp, &pol_sid);
	DEBUG(5,("pol_sid: %s\n", tmp));

	if (num_rids > MAX_SAM_ENTRIES)
	{
		num_rids = MAX_SAM_ENTRIES;
		DEBUG(5,("samr_lookup_names: truncating entries to %d\n", num_rids));
	}

	SMB_ASSERT_ARRAY(q_u->uni_name, num_rids);

	for (i = 0; i < num_rids && status == 0; i++)
	{
		DOM_SID sid;
		fstring name;
		unistr2_to_ascii(name, &q_u->uni_name[i], sizeof(name)-1);

		status = lookup_name(name, &sid, &(type[i]));
		if (status == 0x0)
		{
			sid_split_rid(&sid, &rid[i]);
		}
		if ((status != 0x0) || !sid_equal(&pol_sid, &sid))
		{
			rid [i] = 0xffffffff;
			type[i] = SID_NAME_UNKNOWN;
		}

		sid_to_string(tmp, &sid);
		DEBUG(10,("name: %s sid: %s rid: %x type: %d\n",
			name, tmp, rid[i], type[i]));
		
	}

	make_samr_r_lookup_names(&r_u, num_rids, rid, type, status);

	/* store the response in the SMB stream */
	samr_io_r_lookup_names("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_names: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_lookup_names
 ********************************************************************/
static void api_samr_lookup_names( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_NAMES q_u;
	samr_io_q_lookup_names("", &q_u, data, 0);
	samr_reply_lookup_names(&q_u, rdata);
	samr_free_q_lookup_names(&q_u);
}

/*******************************************************************
 samr_reply_chgpasswd_user
 ********************************************************************/
static void samr_reply_chgpasswd_user(SAMR_Q_CHGPASSWD_USER *q_u,
				prs_struct *rdata)
{
	SAMR_R_CHGPASSWD_USER r_u;
	uint32 status = 0x0;
	fstring user_name;
	fstring wks;
	uchar *lm_newpass = NULL;
	uchar *nt_newpass = NULL;
	uchar *lm_oldhash = NULL;
	uchar *nt_oldhash = NULL;

	unistr2_to_ascii(user_name, &q_u->uni_user_name, sizeof(user_name)-1);
	unistr2_to_ascii(wks, &q_u->uni_dest_host, sizeof(wks)-1);

	DEBUG(5,("samr_chgpasswd_user: user: %s wks: %s\n", user_name, wks));

	if (q_u->lm_newpass.ptr)
	{
		lm_newpass = q_u->lm_newpass.pass;
	}
	if (q_u->lm_oldhash.ptr)
	{
		lm_oldhash = q_u->lm_oldhash.hash;
	}
	if (q_u->nt_newpass.ptr)
	{
        	nt_newpass = q_u->nt_newpass.pass;
	}
	if (q_u->nt_oldhash.ptr)
	{
        	nt_oldhash = q_u->nt_oldhash.hash;
        }
	if (!pass_oem_change(user_name,
	                     lm_newpass, lm_oldhash,
	                     nt_newpass, nt_oldhash))
	{
		status = 0xC0000000 | NT_STATUS_WRONG_PASSWORD;
	}

	make_samr_r_chgpasswd_user(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_chgpasswd_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_chgpasswd_user: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_chgpasswd_user
 ********************************************************************/
static void api_samr_chgpasswd_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CHGPASSWD_USER q_u;
	samr_io_q_chgpasswd_user("", &q_u, data, 0);
	samr_reply_chgpasswd_user(&q_u, rdata);
}


/*******************************************************************
 samr_reply_unknown_38
 ********************************************************************/
static void samr_reply_unknown_38(SAMR_Q_UNKNOWN_38 *q_u,
				prs_struct *rdata)
{
	SAMR_R_UNKNOWN_38 r_u;

	DEBUG(5,("samr_unknown_38: %d\n", __LINE__));

	make_samr_r_unknown_38(&r_u);

	/* store the response in the SMB stream */
	samr_io_r_unknown_38("", &r_u, rdata, 0);

	DEBUG(5,("samr_unknown_38: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_unknown_38
 ********************************************************************/
static void api_samr_unknown_38( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_UNKNOWN_38 q_u;
	samr_io_q_unknown_38("", &q_u, data, 0);
	samr_reply_unknown_38(&q_u, rdata);
}


/*******************************************************************
 samr_reply_lookup_rids
 ********************************************************************/
static void samr_reply_lookup_rids(SAMR_Q_LOOKUP_RIDS *q_u,
				prs_struct *rdata)
{
	fstring group_names[MAX_SAM_ENTRIES];
	uint8   types[MAX_SAM_ENTRIES];
	uint32 status     = 0;
	int num_rids = q_u->num_rids1;
	DOM_SID pol_sid;

	SAMR_R_LOOKUP_RIDS r_u;
	ZERO_STRUCT(r_u);

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &pol_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (status == 0x0)
	{
		int i;
		if (num_rids > MAX_SAM_ENTRIES)
		{
			num_rids = MAX_SAM_ENTRIES;
			DEBUG(5,("samr_lookup_rids: truncating entries to %d\n", num_rids));
		}

		for (i = 0; i < num_rids && status == 0; i++)
		{
			DOM_SID sid;
			sid_copy(&sid, &pol_sid);
			sid_append_rid(&sid, q_u->rid[i]);
			status = lookup_sid(&sid, group_names[i], &types[i]);
			if (status != 0)
				types[i] = SID_NAME_UNKNOWN;
		}
	}

	make_samr_r_lookup_rids(&r_u, num_rids, group_names, types, status);

	/* store the response in the SMB stream */
	samr_io_r_lookup_rids("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_rids: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_lookup_rids
 ********************************************************************/
static void api_samr_lookup_rids( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_RIDS q_u;
	ZERO_STRUCT(q_u);
	samr_io_q_lookup_rids("", &q_u, data, 0);
	samr_reply_lookup_rids(&q_u, rdata);
	samr_free_q_lookup_rids(&q_u);
}


/*******************************************************************
 samr_reply_open_user
 ********************************************************************/
static void samr_reply_open_user(SAMR_Q_OPEN_USER *q_u,
				prs_struct *rdata,
				int status)
{
	SAMR_R_OPEN_USER r_u;
	struct sam_passwd *sam_pass;
	BOOL pol_open = False;

	/* set up the SAMR open_user response */
	bzero(r_u.user_pol.data, POL_HND_SIZE);

	r_u.status = 0x0;

	/* find the policy handle.  open a policy on it. */
	if (r_u.status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->domain_pol)) == -1))
	{
		r_u.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(r_u.user_pol))))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	become_root(True);
	sam_pass = getsam21pwrid(q_u->user_rid);
	unbecome_root(True);

	/* check that the RID exists in our domain. */
	if (r_u.status == 0x0 && sam_pass == NULL)
	{
		r_u.status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
	}

	/* associate the RID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &(r_u.user_pol), q_u->user_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (r_u.status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(r_u.user_pol));
	}

	DEBUG(5,("samr_open_user: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_open_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_user: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_open_user
 ********************************************************************/
static void api_samr_open_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_OPEN_USER q_u;
	samr_io_q_open_user("", &q_u, data, 0);
	samr_reply_open_user(&q_u, rdata, 0x0);
}


/*************************************************************************
 get_user_info_10
 *************************************************************************/
static BOOL get_user_info_10(SAM_USER_INFO_10 *id10, uint32 user_rid)
{
	struct sam_passwd *sam_pass;

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		DEBUG(4,("User 0x%x not found\n", user_rid));
		return False;
	}

	DEBUG(3,("User:[%s]\n", sam_pass->nt_name));

	make_sam_user_info10(id10, sam_pass->acct_ctrl); 

	return True;
}

/*************************************************************************
 get_user_info_21
 *************************************************************************/
static BOOL get_user_info_21(SAM_USER_INFO_21 *id21, uint32 user_rid)
{
	struct sam_passwd *sam_pass;
	LOGON_HRS hrs;
	int i;

	become_root(True);
	sam_pass = getsam21pwrid(user_rid);
	unbecome_root(True);

	if (sam_pass == NULL)
	{
		DEBUG(4,("User 0x%x not found\n", user_rid));
		return False;
	}

	DEBUG(3,("User:[%s]\n", sam_pass->nt_name));

	/* create a LOGON_HRS structure */
	hrs.len = sam_pass->hours_len;
	SMB_ASSERT_ARRAY(hrs.hours, hrs.len);
	for (i = 0; i < hrs.len; i++)
	{
		hrs.hours[i] = sam_pass->hours[i];
	}

	make_sam_user_info21(id21,

			   &sam_pass->logon_time,
			   &sam_pass->logoff_time,
			   &sam_pass->kickoff_time,
			   &sam_pass->pass_last_set_time,
			   &sam_pass->pass_can_change_time,
			   &sam_pass->pass_must_change_time,

			   sam_pass->nt_name, /* user_name */
			   sam_pass->full_name, /* full_name */
			   sam_pass->home_dir, /* home_dir */
			   sam_pass->dir_drive, /* dir_drive */
			   sam_pass->logon_script, /* logon_script */
			   sam_pass->profile_path, /* profile_path */
			   sam_pass->acct_desc, /* description */
			   sam_pass->workstations, /* workstations user can log in from */
			   sam_pass->unknown_str, /* don't know, yet */
			   sam_pass->munged_dial, /* dialin info.  contains dialin path and tel no */

			   sam_pass->user_rid, /* RID user_id */
			   sam_pass->group_rid, /* RID group_id */
	                   sam_pass->acct_ctrl,

	                   sam_pass->unknown_3, /* unknown_3 */
	                   sam_pass->logon_divs, /* divisions per week */
	                   &hrs, /* logon hours */
	                   sam_pass->unknown_5,
	                   sam_pass->unknown_6);

	return True;
}

/*******************************************************************
 samr_reply_query_userinfo
 ********************************************************************/
static void samr_reply_query_userinfo(SAMR_Q_QUERY_USERINFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_USERINFO r_u;
#if 0
	SAM_USER_INFO_11 id11;
#endif
	SAM_USER_INFO_10 id10;
	SAM_USER_INFO_21 id21;
	void *info = NULL;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_query_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(q_u->pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_query_userinfo: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0)
	{
		switch (q_u->switch_value)
		{
			case 0x10:
			{
				info = (void*)&id10;
				status = get_user_info_10(&id10, rid) ? 0 : (0xC0000000 | NT_STATUS_NO_SUCH_USER);
				break;
			}
#if 0
/* whoops - got this wrong.  i think.  or don't understand what's happening. */
			case 0x11:
			{
				NTTIME expire;
				info = (void*)&id11;
				
				expire.low  = 0xffffffff;
				expire.high = 0x7fffffff;

				make_sam_user_info11(&id11, &expire, "BROOKFIELDS$", 0x03ef, 0x201, 0x0080);

				break;
			}
#endif
			case 21:
			{
				info = (void*)&id21;
				status = get_user_info_21(&id21, rid) ? 0 : (0xC0000000 | NT_STATUS_NO_SUCH_USER);
				break;
			}

			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_query_userinfo(&r_u, q_u->switch_value, info, status);

	/* store the response in the SMB stream */
	samr_io_r_query_userinfo("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_query_userinfo: %d\n", __LINE__));

}

/*******************************************************************
 set_user_info_24
 ********************************************************************/
static BOOL set_user_info_24(SAM_USER_INFO_24 *id24, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (pwd == NULL)
	{
		return False;
	}

	pwdb_init_sam(&new_pwd);
	copy_sam_passwd(&new_pwd, pwd);

	if (!decode_pw_buffer(id24->pass, (char *)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	new_pwd.smb_passwd    = lm_hash;
	new_pwd.smb_nt_passwd = nt_hash;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 set_user_info_23
 ********************************************************************/
static BOOL set_user_info_23(SAM_USER_INFO_23 *id23, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;
	static uchar nt_hash[16];
	static uchar lm_hash[16];
	UNISTR2 new_pw;
	uint32 len;

	if (id23 == NULL)
	{
		DEBUG(5, ("set_user_info_23: NULL id23\n"));
		return False;
	}
	if (pwd == NULL)
	{
		return False;
	}

	pwdb_init_sam(&new_pwd);
	copy_sam_passwd(&new_pwd, pwd);
	copy_id23_to_sam_passwd(&new_pwd, id23);

	if (!decode_pw_buffer(id23->pass, (char*)new_pw.buffer, 256, &len))
	{
		return False;
	}

	new_pw.uni_max_len = len / 2;
	new_pw.uni_str_len = len / 2;

	nt_lm_owf_genW(&new_pw, nt_hash, lm_hash);

	new_pwd.smb_passwd    = lm_hash;
	new_pwd.smb_nt_passwd = nt_hash;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 set_user_info_16
 ********************************************************************/
static BOOL set_user_info_16(SAM_USER_INFO_16 *id16, uint32 rid)
{
	struct sam_passwd *pwd = getsam21pwrid(rid);
	struct sam_passwd new_pwd;

	if (id16 == NULL)
	{
		DEBUG(5, ("set_user_info_16: NULL id16\n"));
		return False;
	}
	if (pwd == NULL)
	{
		return False;
	}

	copy_sam_passwd(&new_pwd, pwd);

	new_pwd.acct_ctrl = id16->acb_info;

	return mod_sam21pwd_entry(&new_pwd, True);
}

/*******************************************************************
 api_samr_query_userinfo
 ********************************************************************/
static void api_samr_query_userinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERINFO q_u;
	samr_io_q_query_userinfo("", &q_u, data, 0);
	samr_reply_query_userinfo(&q_u, rdata);
}


/*******************************************************************
 samr_reply_set_userinfo2
 ********************************************************************/
static void samr_reply_set_userinfo2(SAMR_Q_SET_USERINFO2 *q_u,
				prs_struct *rdata, uchar user_sess_key[16])
{
	SAMR_R_SET_USERINFO2 r_u;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(q_u->pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_set_userinfo2: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0 && q_u->info.id == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo2: NULL info level\n"));
		status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}

	if (status == 0x0)
	{
		switch (q_u->switch_value)
		{
			case 16:
			{
				SAM_USER_INFO_16 *id16 = q_u->info.id16;
				status = set_user_info_16(id16, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}
			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_set_userinfo2(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_set_userinfo2("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_set_userinfo2: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_set_userinfo2
 ********************************************************************/
static void api_samr_set_userinfo2( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_SET_USERINFO2 q_u;
	user_struct *vuser = get_valid_user_struct(p->vuid);

	if (vuser == NULL)
	{
		return;
	}

	ZERO_STRUCT(q_u);

	samr_io_q_set_userinfo2("", &q_u, data, 0);
	samr_reply_set_userinfo2(&q_u, rdata, vuser->user_sess_key);

	if (q_u.info.id != NULL)
	{
		free(q_u.info.id);
	}
}


/*******************************************************************
 samr_reply_set_userinfo
 ********************************************************************/
static void samr_reply_set_userinfo(SAMR_Q_SET_USERINFO *q_u,
				prs_struct *rdata, uchar user_sess_key[16])
{
	SAMR_R_SET_USERINFO r_u;

	uint32 status = 0x0;
	uint32 rid = 0x0;

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

	/* search for the handle */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(q_u->pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	DEBUG(5,("samr_reply_set_userinfo: rid:0x%x\n", rid));

	/* ok!  user info levels (there are lots: see MSDEV help), off we go... */
	if (status == 0x0 && q_u->info.id == NULL)
	{
		DEBUG(5,("samr_reply_set_userinfo: NULL info level\n"));
		status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}

	if (status == 0x0)
	{
		switch (q_u->switch_value)
		{
			case 24:
			{
				SAM_USER_INFO_24 *id24 = q_u->info.id24;
				SamOEMhash(id24->pass, user_sess_key, True);
				status = set_user_info_24(id24, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}

			case 23:
			{
				SAM_USER_INFO_23 *id23 = q_u->info.id23;
				SamOEMhash(id23->pass, user_sess_key, 1);
#if DEBUG_PASSWORD
				DEBUG(100,("pass buff:\n"));
				dump_data(100, id23->pass, sizeof(id23->pass));
#endif
				dbgflush();

				status = set_user_info_23(id23, rid) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
				break;
			}

			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;

				break;
			}
		}
	}

	make_samr_r_set_userinfo(&r_u, status);

	/* store the response in the SMB stream */
	samr_io_r_set_userinfo("", &r_u, rdata, 0);

	DEBUG(5,("samr_reply_set_userinfo: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_set_userinfo
 ********************************************************************/
static void api_samr_set_userinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_SET_USERINFO q_u;
	user_struct *vuser = get_valid_user_struct(p->vuid);
	ZERO_STRUCT(q_u);

	if (vuser == NULL)
	{
		return;
	}

#ifdef DEBUG_PASSWORD
	DEBUG(100,("set user info: sess_key: "));
	dump_data(100, vuser->user_sess_key, 16);
#endif
	samr_io_q_set_userinfo("", &q_u, data, 0);
	samr_reply_set_userinfo(&q_u, rdata, vuser->user_sess_key);

	if (q_u.info.id != NULL)
	{
		free(q_u.info.id);
	}
}


/*******************************************************************
 samr_reply_query_usergroups
 ********************************************************************/
static void samr_reply_query_usergroups(SAMR_Q_QUERY_USERGROUPS *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_USERGROUPS r_u;
	uint32 status = 0x0;

	struct sam_passwd *sam_pass;
	DOM_GID *gids = NULL;
	int num_groups = 0;
	uint32 rid;

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the user's rid */
	if (status == 0x0 && (rid = get_policy_samr_rid(get_global_hnd_cache(), &(q_u->pol))) == 0xffffffff)
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (status == 0x0)
	{
		become_root(True);
		sam_pass = getsam21pwrid(rid);
		unbecome_root(True);

		if (sam_pass == NULL)
		{
			status = 0xC0000000 | NT_STATUS_NO_SUCH_USER;
		}
	}

	if (status == 0x0)
	{
		DOMAIN_GRP *mem_grp = NULL;

		become_root(True);
		getusergroupsntnam(sam_pass->nt_name, &mem_grp, &num_groups);
		unbecome_root(True);

                gids = NULL;
		num_groups = make_dom_gids(mem_grp, num_groups, &gids);

		if (mem_grp != NULL)
		{
			free(mem_grp);
		}
	}

	/* construct the response */
	make_samr_r_query_usergroups(&r_u, num_groups, gids, status);

	/* store the response in the SMB stream */
	samr_io_r_query_usergroups("", &r_u, rdata, 0);

	if (gids)
	{
		free((char *)gids);
	}

	DEBUG(5,("samr_query_usergroups: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_usergroups
 ********************************************************************/
static void api_samr_query_usergroups( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERGROUPS q_u;
	samr_io_q_query_usergroups("", &q_u, data, 0);
	samr_reply_query_usergroups(&q_u, rdata);
}


/*******************************************************************
 opens a samr alias by rid, returns a policy handle.
 ********************************************************************/
static uint32 open_samr_alias(DOM_SID *sid, POLICY_HND *alias_pol,
				uint32 alias_rid)
{
	BOOL pol_open = False;
	uint32 status = 0x0;

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), alias_pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the alias rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), alias_pol, alias_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, alias_rid);

	/* associate an alias SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), alias_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), alias_pol);
	}

	return status;
}

/*******************************************************************
 samr_reply_create_dom_alias
 ********************************************************************/
static void samr_reply_create_dom_alias(SAMR_Q_CREATE_DOM_ALIAS *q_u,
				prs_struct *rdata)
{
	SAMR_R_CREATE_DOM_ALIAS r_u;
	DOM_SID dom_sid;
	LOCAL_GRP grp;
	POLICY_HND alias_pol;
	uint32 status = 0x0;

	bzero(&alias_pol, sizeof(alias_pol));

	DEBUG(5,("samr_create_dom_alias: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->dom_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->dom_pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &q_u->uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;

		become_root(True);
		status = add_alias_entry(&grp) ? 0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		unbecome_root(True);
	}

	if (status == 0x0)
	{
		status = open_samr_alias(&dom_sid, &alias_pol, grp.rid);
	}

	/* construct the response. */
	make_samr_r_create_dom_alias(&r_u, &alias_pol, grp.rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_dom_alias("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_dom_alias: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_create_dom_alias
 ********************************************************************/
static void api_samr_create_dom_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_DOM_ALIAS q_u;
	samr_io_q_create_dom_alias("", &q_u, data, 0);
	samr_reply_create_dom_alias(&q_u, rdata);
}


/*******************************************************************
 opens a samr group by rid, returns a policy handle.
 ********************************************************************/
static uint32 open_samr_group(DOM_SID *sid, POLICY_HND *group_pol,
				uint32 group_rid)
{
	BOOL pol_open = False;
	uint32 status = 0x0;

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), group_pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the group rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), group_pol, group_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, group_rid);

	/* associate an group SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), group_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), group_pol);
	}

	return status;
}

/*******************************************************************
 samr_reply_create_dom_group
 ********************************************************************/
static void samr_reply_create_dom_group(SAMR_Q_CREATE_DOM_GROUP *q_u,
				prs_struct *rdata)
{
	SAMR_R_CREATE_DOM_GROUP r_u;
	DOM_SID dom_sid;
	DOMAIN_GRP grp;
	POLICY_HND group_pol;
	uint32 status = 0x0;

	bzero(&group_pol, sizeof(group_pol));

	DEBUG(5,("samr_create_dom_group: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &dom_sid))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &q_u->uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;
		grp.attr = 0x07;

		become_root(True);
		status = add_group_entry(&grp) ? 0x0 : (0xC0000000 | NT_STATUS_ACCESS_DENIED);
		unbecome_root(True);
	}

	if (status == 0x0)
	{
		status = open_samr_group(&dom_sid, &group_pol, grp.rid);
	}

	/* construct the response. */
	make_samr_r_create_dom_group(&r_u, &group_pol, grp.rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_dom_group("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_dom_group: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_create_dom_group
 ********************************************************************/
static void api_samr_create_dom_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_DOM_GROUP q_u;
	samr_io_q_create_dom_group("", &q_u, data, 0);
	samr_reply_create_dom_group(&q_u, rdata);
}


/*******************************************************************
 samr_reply_query_dom_info
 ********************************************************************/
static void samr_reply_query_dom_info(SAMR_Q_QUERY_DOMAIN_INFO *q_u,
				prs_struct *rdata)
{
	SAMR_R_QUERY_DOMAIN_INFO r_u;
	SAM_UNK_CTR ctr;
	uint16 switch_value = 0x0;
	uint32 status = 0x0;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(ctr);

	r_u.ctr = &ctr;

	DEBUG(5,("samr_reply_query_dom_info: %d\n", __LINE__));

	/* find the policy handle.  open a policy on it. */
	if (r_u.status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->domain_pol)) == -1))
	{
		r_u.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
		DEBUG(5,("samr_reply_query_dom_info: invalid handle\n"));
	}

	if (status == 0x0)
	{
		switch (q_u->switch_value)
		{
			case 0x07:
			{
				switch_value = 0x7;
				make_unk_info7(&ctr.info.inf7);

				break;
			}
			case 0x06:
			{
				switch_value = 0x6;
				make_unk_info6(&ctr.info.inf6);

				break;
			}
			case 0x03:
			{
				switch_value = 0x3;
				make_unk_info3(&ctr.info.inf3);

				break;
			}
			case 0x02:
			{
				switch_value = 0x2;
				make_unk_info2(&ctr.info.inf2, global_sam_name, global_myname);

				break;
			}
			case 0x01:
			{
				switch_value = 0x1;
				make_unk_info1(&ctr.info.inf1);

				break;
			}
			default:
			{
				status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
				break;
			}
		}
	}

	make_samr_r_query_dom_info(&r_u, switch_value, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dom_info("", &r_u, rdata, 0);

	DEBUG(5,("samr_query_dom_info: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_query_dom_info
 ********************************************************************/
static void api_samr_query_dom_info( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_DOMAIN_INFO q_e;
	samr_io_q_query_dom_info("", &q_e, data, 0);
	samr_reply_query_dom_info(&q_e, rdata);
}



/*******************************************************************
 samr_reply_create_user
 ********************************************************************/
static void samr_reply_create_user(SAMR_Q_CREATE_USER *q_u,
				prs_struct *rdata)
{
	struct sam_passwd *sam_pass;
	fstring user_name;

	SAMR_R_CREATE_USER r_u;
	POLICY_HND pol;
	uint32 status = 0x0;
	uint32 user_rid = 0x0;
	BOOL pol_open = False;
	uint32 unk_0 = 0x30;

	/* find the machine account: tell the caller if it exists.
	   lkclXXXX i have *no* idea if this is a problem or not
	   or even if you are supposed to construct a different
	   reply if the account already exists...
	 */

	/* find the policy handle.  open a policy on it. */
	if (status == 0x0 && (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->domain_pol)) == -1))
	{
		status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &pol)))
	{
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	unistr2_to_ascii(user_name, &q_u->uni_name, sizeof(user_name)-1);

	sam_pass = getsam21pwntnam(user_name);

	if (sam_pass != NULL)
	{
		/* account exists: say so */
		status = 0xC0000000 | NT_STATUS_USER_EXISTS;
	}
	else
	{
		pstring err_str;
		pstring msg_str;

		if (!local_password_change(user_name, True,
		          q_u->acb_info | ACB_DISABLED | ACB_PWNOTREQ, 0xffff,
		          NULL,
		          err_str, sizeof(err_str),
		          msg_str, sizeof(msg_str)))
		{
			DEBUG(0,("%s\n", err_str));
			status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
		}
		else
		{
			sam_pass = getsam21pwntnam(user_name);
			if (sam_pass == NULL)
			{
				/* account doesn't exist: say so */
				status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
			}
			else
			{
				user_rid = sam_pass->user_rid;
				unk_0 = 0x000703ff;
			}
		}
	}

	/* associate the RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &pol, user_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &pol);
	}

	DEBUG(5,("samr_create_user: %d\n", __LINE__));

	make_samr_r_create_user(&r_u, &pol, unk_0, user_rid, status);

	/* store the response in the SMB stream */
	samr_io_r_create_user("", &r_u, rdata, 0);

	DEBUG(5,("samr_create_user: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_create_user
 ********************************************************************/
static void api_samr_create_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_USER q_u;

	/* grab the samr unknown 32 */
	samr_io_q_create_user("", &q_u, data, 0);

	/* construct reply. */
	samr_reply_create_user(&q_u, rdata);
}


/*******************************************************************
 samr_reply_connect_anon
 ********************************************************************/
static void samr_reply_connect_anon(SAMR_Q_CONNECT_ANON *q_u,
				prs_struct *rdata)
{
	SAMR_R_CONNECT_ANON r_u;
	BOOL pol_open = False;

	/* set up the SAMR connect_anon response */

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(r_u.connect_pol))))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_pol_status(get_global_hnd_cache(), &(r_u.connect_pol), q_u->unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (r_u.status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(r_u.connect_pol));
	}

	DEBUG(5,("samr_connect_anon: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_connect_anon("", &r_u, rdata, 0);

	DEBUG(5,("samr_connect_anon: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_connect_anon
 ********************************************************************/
static void api_samr_connect_anon( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CONNECT_ANON q_u;
	samr_io_q_connect_anon("", &q_u, data, 0);
	samr_reply_connect_anon(&q_u, rdata);
}

/*******************************************************************
 samr_reply_connect
 ********************************************************************/
static void samr_reply_connect(SAMR_Q_CONNECT *q_u,
				prs_struct *rdata)
{
	SAMR_R_CONNECT r_u;
	BOOL pol_open = False;

	/* set up the SAMR connect response */

	r_u.status = 0x0;
	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(r_u.connect_pol))))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_pol_status(get_global_hnd_cache(), &(r_u.connect_pol), q_u->unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (r_u.status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(r_u.connect_pol));
	}

	DEBUG(5,("samr_connect: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_connect("", &r_u, rdata, 0);

	DEBUG(5,("samr_connect: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_connect
 ********************************************************************/
static void api_samr_connect( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CONNECT q_u;
	samr_io_q_connect("", &q_u, data, 0);
	samr_reply_connect(&q_u, rdata);
}

/*******************************************************************
 samr_reply_open_alias
 ********************************************************************/
static void samr_reply_open_alias(SAMR_Q_OPEN_ALIAS *q_u,
				prs_struct *rdata)
{
	SAMR_R_OPEN_ALIAS r_u;
	DOM_SID sid;
	BOOL pol_open = False;

	/* set up the SAMR open_alias response */

	r_u.status = 0x0;
	if (r_u.status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->dom_pol, &sid))
	{
		r_u.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (r_u.status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &(r_u.pol))))
	{
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the alias rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), &(r_u.pol), q_u->rid_alias))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(&sid, q_u->rid_alias);

	/* associate an alias SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), &(r_u.pol), &sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = 0xC0000000 | NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (r_u.status != 0 && pol_open)
	{
		close_policy_hnd(get_global_hnd_cache(), &(r_u.pol));
	}

	DEBUG(5,("samr_open_alias: %d\n", __LINE__));

	/* store the response in the SMB stream */
	samr_io_r_open_alias("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_alias: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_open_alias
 ********************************************************************/
static void api_samr_open_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
                                
{
	SAMR_Q_OPEN_ALIAS q_u;
	samr_io_q_open_alias("", &q_u, data, 0);
	samr_reply_open_alias(&q_u, rdata);
}

/*******************************************************************
 samr_reply_open_group
 ********************************************************************/
static void samr_reply_open_group(SAMR_Q_OPEN_GROUP *q_u,
				prs_struct *rdata)
{
	SAMR_R_OPEN_GROUP r_u;
	DOM_SID sid;

	DEBUG(5,("samr_open_group: %d\n", __LINE__));

	r_u.status = 0x0;

	/* find the domain sid associated with the policy handle */
	if (r_u.status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->domain_pol, &sid))
	{
		r_u.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (r_u.status == 0x0 && !sid_equal(&sid, &global_sam_sid))
	{
		r_u.status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	if (r_u.status == 0x0)
	{
		r_u.status = open_samr_group(&sid, &r_u.pol, q_u->rid_group);
	}

	/* store the response in the SMB stream */
	samr_io_r_open_group("", &r_u, rdata, 0);

	DEBUG(5,("samr_open_group: %d\n", __LINE__));

}

/*******************************************************************
 api_samr_open_group
 ********************************************************************/
static void api_samr_open_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
                                
{
	SAMR_Q_OPEN_GROUP q_u;
	samr_io_q_open_group("", &q_u, data, 0);
	samr_reply_open_group(&q_u, rdata);
}

/*******************************************************************
 samr_reply_lookup_domain
 ********************************************************************/
static void samr_reply_lookup_domain(SAMR_Q_LOOKUP_DOMAIN *q_u,
				prs_struct *rdata)
{
	SAMR_R_LOOKUP_DOMAIN r_u;
	fstring domain;

	DEBUG(5,("samr_lookup_domain: %d\n", __LINE__));

	r_u.ptr_sid = 0;
	r_u.status = 0x0;

	/* find the connection policy handle */
	if (find_policy_by_hnd(get_global_hnd_cache(), &(q_u->connect_pol)) == -1)
	{
		r_u.status = 0xC0000000 | NT_STATUS_INVALID_HANDLE;
	}

	if (r_u.status == 0x0)
        {
		unistr2_to_ascii(domain, &(q_u->uni_domain), sizeof(domain));
		DEBUG(5, ("Lookup Domain: %s\n", domain));

		/* check it's one of ours */
		if (strequal(domain, global_sam_name))
		{
			make_dom_sid2(&(r_u.dom_sid), &global_sam_sid);
			r_u.ptr_sid = 1;
		}
		else if (strequal(domain, "BUILTIN"))
		{
			make_dom_sid2(&(r_u.dom_sid), &global_sid_S_1_5_20);
			r_u.ptr_sid = 1;
		}
		else
		{
			r_u.status = 0xC0000000 | NT_STATUS_NO_SUCH_DOMAIN;
		}
	}

	/* store the response in the SMB stream */
	samr_io_r_lookup_domain("", &r_u, rdata, 0);

	DEBUG(5,("samr_lookup_domain: %d\n", __LINE__));
}

/*******************************************************************
 api_samr_lookup_domain
 ********************************************************************/
static void api_samr_lookup_domain( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_DOMAIN q_u;
	samr_io_q_lookup_domain("", &q_u, data, 0);
	samr_reply_lookup_domain(&q_u, rdata);
}

/*******************************************************************
 array of \PIPE\samr operations
 ********************************************************************/
static struct api_struct api_samr_cmds [] =
{
	{ "SAMR_CLOSE_HND"        , SAMR_CLOSE_HND        , api_samr_close_hnd        },
	{ "SAMR_CONNECT"          , SAMR_CONNECT          , api_samr_connect          },
	{ "SAMR_CONNECT_ANON"     , SAMR_CONNECT_ANON     , api_samr_connect_anon     },
	{ "SAMR_ENUM_DOMAINS"     , SAMR_ENUM_DOMAINS     , api_samr_enum_domains     },
	{ "SAMR_ENUM_DOM_USERS"   , SAMR_ENUM_DOM_USERS   , api_samr_enum_dom_users   },
	{ "SAMR_ENUM_DOM_GROUPS"  , SAMR_ENUM_DOM_GROUPS  , api_samr_enum_dom_groups  },
	{ "SAMR_ENUM_DOM_ALIASES" , SAMR_ENUM_DOM_ALIASES , api_samr_enum_dom_aliases },
	{ "SAMR_QUERY_USERALIASES", SAMR_QUERY_USERALIASES, api_samr_query_useraliases},
	{ "SAMR_QUERY_ALIASMEM"   , SAMR_QUERY_ALIASMEM   , api_samr_query_aliasmem   },
	{ "SAMR_QUERY_GROUPMEM"   , SAMR_QUERY_GROUPMEM   , api_samr_query_groupmem   },
	{ "SAMR_ADD_ALIASMEM"     , SAMR_ADD_ALIASMEM     , api_samr_add_aliasmem     },
	{ "SAMR_DEL_ALIASMEM"     , SAMR_DEL_ALIASMEM     , api_samr_del_aliasmem     },
	{ "SAMR_ADD_GROUPMEM"     , SAMR_ADD_GROUPMEM     , api_samr_add_groupmem     },
	{ "SAMR_DEL_GROUPMEM"     , SAMR_DEL_GROUPMEM     , api_samr_del_groupmem     },
	{ "SAMR_DELETE_DOM_GROUP" , SAMR_DELETE_DOM_GROUP , api_samr_delete_dom_group },
	{ "SAMR_DELETE_DOM_ALIAS" , SAMR_DELETE_DOM_ALIAS , api_samr_delete_dom_alias },
	{ "SAMR_CREATE_DOM_GROUP" , SAMR_CREATE_DOM_GROUP , api_samr_create_dom_group },
	{ "SAMR_CREATE_DOM_ALIAS" , SAMR_CREATE_DOM_ALIAS , api_samr_create_dom_alias },
	{ "SAMR_LOOKUP_NAMES"     , SAMR_LOOKUP_NAMES     , api_samr_lookup_names     },
	{ "SAMR_OPEN_USER"        , SAMR_OPEN_USER        , api_samr_open_user        },
	{ "SAMR_QUERY_USERINFO"   , SAMR_QUERY_USERINFO   , api_samr_query_userinfo   },
	{ "SAMR_SET_USERINFO"     , SAMR_SET_USERINFO     , api_samr_set_userinfo     },
	{ "SAMR_SET_USERINFO2"    , SAMR_SET_USERINFO2    , api_samr_set_userinfo2    },
	{ "SAMR_QUERY_DOMAIN_INFO", SAMR_QUERY_DOMAIN_INFO, api_samr_query_dom_info   },
	{ "SAMR_QUERY_USERGROUPS" , SAMR_QUERY_USERGROUPS , api_samr_query_usergroups },
	{ "SAMR_QUERY_DISPINFO"   , SAMR_QUERY_DISPINFO   , api_samr_query_dispinfo   },
	{ "SAMR_QUERY_DISPINFO3"  , SAMR_QUERY_DISPINFO3  , api_samr_query_dispinfo   },
	{ "SAMR_QUERY_DISPINFO4"  , SAMR_QUERY_DISPINFO4  , api_samr_query_dispinfo   },
	{ "SAMR_QUERY_ALIASINFO"  , SAMR_QUERY_ALIASINFO  , api_samr_query_aliasinfo  },
	{ "SAMR_QUERY_GROUPINFO"  , SAMR_QUERY_GROUPINFO  , api_samr_query_groupinfo  },
	{ "SAMR_CREATE_USER"      , SAMR_CREATE_USER      , api_samr_create_user      },
	{ "SAMR_LOOKUP_RIDS"      , SAMR_LOOKUP_RIDS      , api_samr_lookup_rids      },
	{ "SAMR_GET_DOM_PWINFO"   , SAMR_GET_DOM_PWINFO   , api_samr_unknown_38       },
	{ "SAMR_CHGPASSWD_USER"   , SAMR_CHGPASSWD_USER   , api_samr_chgpasswd_user   },
	{ "SAMR_OPEN_ALIAS"       , SAMR_OPEN_ALIAS       , api_samr_open_alias       },
	{ "SAMR_OPEN_GROUP"       , SAMR_OPEN_GROUP       , api_samr_open_group       },
	{ "SAMR_OPEN_DOMAIN"      , SAMR_OPEN_DOMAIN      , api_samr_open_domain      },
	{ "SAMR_LOOKUP_DOMAIN"    , SAMR_LOOKUP_DOMAIN    , api_samr_lookup_domain    },
	{ "SAMR_QUERY_SEC_OBJECT" , SAMR_QUERY_SEC_OBJECT , api_samr_unknown_3        },
	{ "SAMR_GET_USRDOM_PWINFO", SAMR_GET_USRDOM_PWINFO, api_samr_unknown_2c       },
	{ NULL                    , 0                     , NULL                      }
};

/*******************************************************************
 receives a samr pipe and responds.
 ********************************************************************/
BOOL api_samr_rpc(rpcsrv_struct *p)
{
    return api_rpcTNP(p, "api_samr_rpc", api_samr_cmds);
}

