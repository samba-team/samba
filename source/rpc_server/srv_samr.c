
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
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
 api_samr_enum_dom_groups
 ********************************************************************/
static void api_samr_enum_dom_groups( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOM_GROUPS q_e;
	SAMR_R_ENUM_DOM_GROUPS r_e;

	uint32 num_entries = 0;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_enum_dom_groups("", &q_e, data, 0);

	r_e.status = _samr_enum_dom_groups(&q_e.pol, &q_e.start_idx,
	                              q_e.max_size,
	                              &r_e.sam, &r_e.uni_grp_name,
	                              &num_entries);

	make_samr_r_enum_dom_groups(&r_e, q_e.start_idx, num_entries);

	samr_io_r_enum_dom_groups("", &r_e, rdata, 0);

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_grp_name != NULL)
	{
		free(r_e.uni_grp_name);
	}
}

/*******************************************************************
 api_samr_enum_dom_aliases
 ********************************************************************/
static void api_samr_enum_dom_aliases( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_ENUM_DOM_ALIASES q_e;
	SAMR_R_ENUM_DOM_ALIASES r_e;

	uint32 num_entries = 0;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);

	samr_io_q_enum_dom_aliases("", &q_e, data, 0);

	r_e.status = _samr_enum_dom_aliases(&q_e.pol, &q_e.start_idx,
	                              q_e.max_size,
	                              &r_e.sam, &r_e.uni_grp_name,
	                              &num_entries);

	make_samr_r_enum_dom_aliases(&r_e, q_e.start_idx, num_entries);

	samr_io_r_enum_dom_aliases("", &r_e, rdata, 0);

	if (r_e.sam != NULL)
	{
		free(r_e.sam);
	}

	if (r_e.uni_grp_name != NULL)
	{
		free(r_e.uni_grp_name);
	}
}

/*******************************************************************
 api_samr_query_dispinfo
 ********************************************************************/
static void api_samr_query_dispinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_DISPINFO q_e;
	SAMR_R_QUERY_DISPINFO r_e;
	SAM_DISPINFO_CTR ctr;
	uint32 data_size = 0;
	uint32 num_entries = 0;
	uint32 status = 0;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);
	ZERO_STRUCT(ctr);

	samr_io_q_query_dispinfo("", &q_e, data, 0);
	status = _samr_query_dispinfo(&q_e.domain_pol,
				q_e.switch_level,
				q_e.start_idx,
				q_e.max_entries,
				q_e.max_size,
				&data_size,
				&num_entries,
				&ctr);

	make_samr_r_query_dispinfo(&r_e, num_entries, data_size,
				   q_e.switch_level, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dispinfo("", &r_e, rdata, 0);

	if (ctr.sam.info != NULL)
	{
		free(ctr.sam.info);
	}
}

/*******************************************************************
 api_samr_delete_dom_group
 ********************************************************************/
static void api_samr_delete_dom_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DELETE_DOM_GROUP q_u;
	SAMR_R_DELETE_DOM_GROUP r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_delete_dom_group("", &q_u, data, 0);
	r_u.status = _samr_delete_dom_group(&q_u.group_pol);
	samr_io_r_delete_dom_group("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_query_groupmem
 ********************************************************************/
static void api_samr_query_groupmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_GROUPMEM q_u;
	SAMR_R_QUERY_GROUPMEM r_u;

	uint32 *rid = NULL;
	uint32 *attr = NULL;
	int num_rids = 0;
	uint32 status = 0;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_query_groupmem("", &q_u, data, 0);
	status = _samr_query_groupmem(&q_u.group_pol,
	                                   &num_rids, &rid, &attr);
	make_samr_r_query_groupmem(&r_u, num_rids, rid, attr, status);
	samr_io_r_query_groupmem("", &r_u, rdata, 0);
	samr_free_r_query_groupmem(&r_u);
}


/*******************************************************************
 api_samr_query_groupinfo
 ********************************************************************/
static void api_samr_query_groupinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_GROUPINFO q_e;
	SAMR_R_QUERY_GROUPINFO r_e;
	GROUP_INFO_CTR ctr;
	uint32 status;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);
	ZERO_STRUCT(ctr);
	
	samr_io_q_query_groupinfo("", &q_e, data, 0);

	status = _samr_query_groupinfo(&q_e.pol, q_e.switch_level, &ctr);

	make_samr_r_query_groupinfo(&r_e, status == 0 ? &ctr : NULL, status);
	samr_io_r_query_groupinfo("", &r_e, rdata, 0);
}


/*******************************************************************
 api_samr_query_aliasinfo
 ********************************************************************/
static void api_samr_query_aliasinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_ALIASINFO q_e;
	SAMR_R_QUERY_ALIASINFO r_e;
	ALIAS_INFO_CTR ctr;
	uint32 status;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_e);
	ZERO_STRUCT(ctr);
	
	samr_io_q_query_aliasinfo("", &q_e, data, 0);

	status = _samr_query_aliasinfo(&q_e.pol, q_e.switch_level, &ctr);

	make_samr_r_query_aliasinfo(&r_e, status == 0 ? &ctr : NULL, status);
	samr_io_r_query_aliasinfo("", &r_e, rdata, 0);
}


/*******************************************************************
 api_samr_query_useraliases
 ********************************************************************/
static void api_samr_query_useraliases( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERALIASES q_u;
	SAMR_R_QUERY_USERALIASES r_u;

	uint32 status = 0;
	uint32 *rid = NULL;
	int num_rids = 0;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);

	samr_io_q_query_useraliases("", &q_u, data, 0);
	status = _samr_query_useraliases(&q_u.pol, q_u.ptr_sid, q_u.sid,
	                                 &num_rids, &rid);
	samr_free_q_query_useraliases(&q_u);
	make_samr_r_query_useraliases(&r_u, num_rids, rid, status);
	samr_io_r_query_useraliases("", &r_u, rdata, 0);
	samr_free_r_query_useraliases(&r_u);

}


/*******************************************************************
 api_samr_delete_dom_alias
 ********************************************************************/
static void api_samr_delete_dom_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_DELETE_DOM_ALIAS q_u;
	SAMR_R_DELETE_DOM_ALIAS r_u;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);

	samr_io_q_delete_dom_alias("", &q_u, data, 0);
	r_u.status = _samr_delete_dom_alias(&q_u.alias_pol);
	samr_io_r_delete_dom_alias("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_query_aliasmem
 ********************************************************************/
static void api_samr_query_aliasmem( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_ALIASMEM q_u;
	SAMR_R_QUERY_ALIASMEM r_u;
	uint32 status = 0;
	DOM_SID2 *sid = NULL;
	int num_sids = 0;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_query_aliasmem("", &q_u, data, 0);
	status = _samr_query_aliasmem(&q_u.alias_pol, &num_sids, &sid);
	make_samr_r_query_aliasmem(&r_u, num_sids, sid, status);

	/* store the response in the SMB stream */
	samr_io_r_query_aliasmem("", &r_u, rdata, 0);

	if (sid != NULL)
	{
		free(sid);
	}

}

/*******************************************************************
 api_samr_lookup_names
 ********************************************************************/
static void api_samr_lookup_names( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_NAMES q_u;
	SAMR_R_LOOKUP_NAMES r_u;

	uint32 rid [MAX_SAM_ENTRIES];
	uint32 type[MAX_SAM_ENTRIES];
	uint32 num_rids  = 0;
	uint32 num_types = 0;

	uint32 status     = 0;

	samr_io_q_lookup_names("", &q_u, data, 0);
	status = _samr_lookup_names(&q_u.pol, q_u.num_names1,
	                             q_u.flags, q_u.ptr, q_u.uni_name,
	                             &num_rids, rid, &num_types, type);
	samr_free_q_lookup_names(&q_u);
	make_samr_r_lookup_names(&r_u, num_rids, rid, type, status);
	samr_io_r_lookup_names("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_chgpasswd_user
 ********************************************************************/
static void api_samr_chgpasswd_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CHGPASSWD_USER q_u;
	SAMR_R_CHGPASSWD_USER r_u;
	uchar *lm_newpass = NULL;
	uchar *nt_newpass = NULL;
	uchar *lm_oldhash = NULL;
	uchar *nt_oldhash = NULL;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_chgpasswd_user("", &q_u, data, 0);
	if (q_u.lm_newpass.ptr)
	{
		lm_newpass = q_u.lm_newpass.pass;
	}
	if (q_u.lm_oldhash.ptr)
	{
		lm_oldhash = q_u.lm_oldhash.hash;
	}
	if (q_u.nt_newpass.ptr)
	{
        	nt_newpass = q_u.nt_newpass.pass;
	}
	if (q_u.nt_oldhash.ptr)
	{
        	nt_oldhash = q_u.nt_oldhash.hash;
        }
	r_u.status = _samr_chgpasswd_user(&q_u.uni_dest_host,
	                          &q_u.uni_user_name,
	                          lm_newpass, nt_newpass,
	                          lm_oldhash, nt_oldhash);
	samr_io_r_chgpasswd_user("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_unknown_38
 ********************************************************************/
static void api_samr_unknown_38( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_UNKNOWN_38 q_u;
	SAMR_R_UNKNOWN_38 r_u;

	samr_io_q_unknown_38("", &q_u, data, 0);
	r_u.status = _samr_unknown_38(&q_u.uni_srv_name,
	                    &r_u.unk_0,
	                    &r_u.unk_1,
	                    &r_u.unk_2);
	samr_io_r_unknown_38("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_lookup_rids
 ********************************************************************/
static void api_samr_lookup_rids( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_RIDS q_u;
	SAMR_R_LOOKUP_RIDS r_u;
	uint32 status = 0;
	UNIHDR *hdr_names = NULL;
	UNISTR2 *uni_names = NULL;
	uint32 *types = NULL;
	uint32 num_names = 0;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);

	samr_io_q_lookup_rids("", &q_u, data, 0);
	status = _samr_lookup_rids(&q_u.pol, q_u.num_rids1,
		                    q_u.flags, q_u.rid,
	                            &num_names, 
	                            &hdr_names, &uni_names, &types);
	samr_free_q_lookup_rids(&q_u);
	make_samr_r_lookup_rids(&r_u, num_names, hdr_names, uni_names, types);
	samr_io_r_lookup_rids("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_open_user
 ********************************************************************/
static void api_samr_open_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_OPEN_USER q_u;
	SAMR_R_OPEN_USER r_u;
	samr_io_q_open_user("", &q_u, data, 0);
	r_u.status = _samr_open_user(&q_u.domain_pol,
	                                   q_u.unknown_0, q_u.user_rid,
	                                  &r_u.user_pol);
	samr_io_r_open_user("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_query_userinfo
 ********************************************************************/
static void api_samr_query_userinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERINFO q_u;
	SAMR_R_QUERY_USERINFO r_u;
	SAM_USERINFO_CTR ctr;
	uint32 status = 0x0;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);
	ZERO_STRUCT(ctr);

	samr_io_q_query_userinfo("", &q_u, data, 0);
	status = _samr_query_userinfo(&q_u.pol, q_u.switch_value, &ctr);
	make_samr_r_query_userinfo(&r_u, &ctr, status);
	samr_io_r_query_userinfo("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_set_userinfo2
 ********************************************************************/
static void api_samr_set_userinfo2( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_SET_USERINFO2 q_u;
	SAMR_R_SET_USERINFO2 r_u;
	SAM_USERINFO2_CTR ctr;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	q_u.ctr = &ctr;

	samr_io_q_set_userinfo2("", &q_u, data, 0);
	r_u.status = _samr_set_userinfo2(&q_u.pol, q_u.switch_value, &ctr);
	samr_io_r_set_userinfo2("", &r_u, rdata, 0);

	free_samr_q_set_userinfo2(&q_u);
}


/*******************************************************************
 api_samr_set_userinfo
 ********************************************************************/
static void api_samr_set_userinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_SET_USERINFO q_u;
	SAMR_R_SET_USERINFO r_u;
	SAM_USERINFO_CTR ctr;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	q_u.ctr = &ctr;

	samr_io_q_set_userinfo("", &q_u, data, 0);
	r_u.status = _samr_set_userinfo(&q_u.pol, q_u.switch_value, &ctr);
	samr_io_r_set_userinfo("", &r_u, rdata, 0);

	free_samr_q_set_userinfo(&q_u);
}


/*******************************************************************
 api_samr_query_usergroups
 ********************************************************************/
static void api_samr_query_usergroups( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_USERGROUPS q_u;
	SAMR_R_QUERY_USERGROUPS r_u;

	uint32 status = 0x0;
	DOM_GID *gids = NULL;
	int num_groups = 0;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_query_usergroups("", &q_u, data, 0);

	status = _samr_query_usergroups(&q_u.pol, &num_groups, &gids);

	make_samr_r_query_usergroups(&r_u, num_groups, gids, status);
	samr_io_r_query_usergroups("", &r_u, rdata, 0);

	safe_free(gids);
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
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the alias rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), alias_pol, alias_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, alias_rid);

	/* associate an alias SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), alias_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
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
		status = NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->dom_pol, &dom_sid))
	{
		status = NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &q_u->uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;

		become_root(True);
		status = add_alias_entry(&grp) ? 0 : (NT_STATUS_ACCESS_DENIED);
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
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DEBUG(0,("TODO: verify that the group rid exists\n"));

	/* associate a RID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_rid(get_global_hnd_cache(), group_pol, group_rid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	sid_append_rid(sid, group_rid);

	/* associate an group SID with the (unique) handle. */
	if (status == 0x0 && !set_policy_samr_sid(get_global_hnd_cache(), group_pol, sid))
	{
		/* oh, whoops.  don't know what error message to return, here */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
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
		status = NT_STATUS_INVALID_HANDLE;
	}

	/* find the domain sid */
	if (status == 0x0 && !get_policy_samr_sid(get_global_hnd_cache(), &q_u->pol, &dom_sid))
	{
		status = NT_STATUS_OBJECT_TYPE_MISMATCH;
	}

	if (!sid_equal(&dom_sid, &global_sam_sid))
	{
		status = NT_STATUS_ACCESS_DENIED;
	}

	if (status == 0x0)
	{
		unistr2_to_ascii(grp.name, &q_u->uni_acct_desc, sizeof(grp.name)-1);
		fstrcpy(grp.comment, "");
		grp.rid = 0xffffffff;
		grp.attr = 0x07;

		become_root(True);
		status = add_group_entry(&grp) ? 0x0 : (NT_STATUS_ACCESS_DENIED);
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
		r_u.status = NT_STATUS_INVALID_HANDLE;
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
				status = NT_STATUS_INVALID_INFO_CLASS;
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
		status = NT_STATUS_INVALID_HANDLE;
	}

	/* get a (unique) handle.  open a policy on it. */
	if (status == 0x0 && !(pol_open = open_policy_hnd(get_global_hnd_cache(), &pol)))
	{
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	unistr2_to_ascii(user_name, &q_u->uni_name, sizeof(user_name)-1);

	sam_pass = getsam21pwntnam(user_name);

	if (sam_pass != NULL)
	{
		/* account exists: say so */
		status = NT_STATUS_USER_EXISTS;
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
			status = NT_STATUS_ACCESS_DENIED;
		}
		else
		{
			sam_pass = getsam21pwntnam(user_name);
			if (sam_pass == NULL)
			{
				/* account doesn't exist: say so */
				status = NT_STATUS_ACCESS_DENIED;
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
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
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
		r_u.status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* associate the domain SID with the (unique) handle. */
	if (r_u.status == 0x0 && !set_policy_samr_pol_status(get_global_hnd_cache(), &(r_u.connect_pol), q_u->unknown_0))
	{
		/* oh, whoops.  don't know what error message to return, here */
		r_u.status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
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
 api_samr_connect
 ********************************************************************/
static void api_samr_connect( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CONNECT q_u;
	SAMR_R_CONNECT r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_connect("", &q_u, data, 0);
	r_u.status = _samr_connect(&q_u.uni_srv_name,
	                            q_u.unknown_0,
	                           &r_u.connect_pol);

	/* store the response in the SMB stream */
	samr_io_r_connect("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_open_alias
 ********************************************************************/
static void api_samr_open_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
                                
{
	SAMR_Q_OPEN_ALIAS q_u;
	SAMR_R_OPEN_ALIAS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_open_alias("", &q_u, data, 0);
	r_u.status = _samr_open_alias(&q_u.dom_pol,
	                               q_u.unknown_0,
	                               q_u.rid_alias, &r_u.pol);

	/* store the response in the SMB stream */
	samr_io_r_open_alias("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_open_group
 ********************************************************************/
static void api_samr_open_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
                                
{
	SAMR_Q_OPEN_GROUP q_u;
	SAMR_R_OPEN_GROUP r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_open_group("", &q_u, data, 0);
	/* leave flags 0, because it isn't used in _samr_open_group() */
	r_u.status = _samr_open_group(&q_u.domain_pol, 0, q_u.rid_group, &r_u.pol);

	/* store the response in the SMB stream */
	samr_io_r_open_group("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_lookup_domain
 ********************************************************************/
static void api_samr_lookup_domain( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_LOOKUP_DOMAIN q_u;
	SAMR_R_LOOKUP_DOMAIN r_u;
	DOM_SID dom_sid;
	uint32 status;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_lookup_domain("", &q_u, data, 0);
	status = _samr_lookup_domain(&q_u.connect_pol, &q_u.uni_domain, &dom_sid);
	make_samr_r_lookup_domain(&r_u, &dom_sid, status);

	/* store the response in the SMB stream */
	samr_io_r_lookup_domain("", &r_u, rdata, 0);
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

