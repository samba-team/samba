
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
#include "rpc_parse.h"
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
 api_samr_usrdom_pwinfo
 ********************************************************************/
static void api_samr_get_usrdom_pwinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_GET_USRDOM_PWINFO q_u;
	SAMR_R_GET_USRDOM_PWINFO r_u;
	samr_io_q_get_usrdom_pwinfo("", &q_u, data, 0);

	r_u.status = _samr_get_usrdom_pwinfo(&q_u.user_pol,
	                              &r_u.unknown_0, &r_u.unknown_1);

	samr_io_r_get_usrdom_pwinfo("", &r_u, rdata, 0);
}


/*******************************************************************
 api_samr_query_sec_obj
 ********************************************************************/
static void api_samr_query_sec_obj( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_SEC_OBJ q_u;
	SAMR_R_QUERY_SEC_OBJ r_u;

	ZERO_STRUCT(r_u);
	ZERO_STRUCT(q_u);

	samr_io_q_query_sec_obj("", &q_u, data, 0);
	r_u.status = _samr_query_sec_obj(&q_u.user_pol, &r_u.buf);
	r_u.ptr = 1; /* man, we don't have any choice!  NT bombs otherwise! */
	samr_io_r_query_sec_obj("", &r_u, rdata, 0);
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
	memcpy(&r_u.pol, &q_u.group_pol, sizeof(q_u.group_pol));
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
 api_samr_get_dom_pwinfo
 ********************************************************************/
static void api_samr_get_dom_pwinfo( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_GET_DOM_PWINFO q_u;
	SAMR_R_GET_DOM_PWINFO r_u;

	samr_io_q_get_dom_pwinfo("", &q_u, data, 0);
	r_u.status = _samr_get_dom_pwinfo(&q_u.uni_srv_name,
	                    &r_u.unk_0,
	                    &r_u.unk_1,
	                    &r_u.unk_2);
	samr_io_r_get_dom_pwinfo("", &r_u, rdata, 0);
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
	                                   q_u.access_mask, q_u.user_rid,
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

	if (q_u.switch_value == 0x12)
	{
		DEBUG(0,("api_samr_query_userinfo: possible password attack (info level 0x12)\n"));

		status = NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		status = _samr_query_userinfo(&q_u.pol, q_u.switch_value, &ctr);
	}
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
 api_samr_create_dom_alias
 ********************************************************************/
static void api_samr_create_dom_alias( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_DOM_ALIAS q_u;
	SAMR_R_CREATE_DOM_ALIAS r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_create_dom_alias("", &q_u, data, 0);
	r_u.status = _samr_create_dom_alias(&q_u.dom_pol, &q_u.uni_acct_desc,
	                                    q_u.access_mask,
	                                    &r_u.alias_pol, &r_u.rid);
	samr_io_r_create_dom_alias("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_create_dom_group
 ********************************************************************/
static void api_samr_create_dom_group( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_DOM_GROUP q_u;
	SAMR_R_CREATE_DOM_GROUP r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_create_dom_group("", &q_u, data, 0);
	r_u.status = _samr_create_dom_group(&q_u.pol,
	                                    &q_u.uni_acct_desc,
	                                    q_u.access_mask,
	                                    &r_u.pol, &r_u.rid);

	/* store the response in the SMB stream */
	samr_io_r_create_dom_group("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_query_dom_info
 ********************************************************************/
static void api_samr_query_dom_info( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_QUERY_DOMAIN_INFO q_e;
	SAMR_R_QUERY_DOMAIN_INFO r_u;
	SAM_UNK_CTR ctr;
	uint16 switch_value;
	uint32 status;

	ZERO_STRUCT(q_e);
	ZERO_STRUCT(r_u);
	ZERO_STRUCT(ctr);

	samr_io_q_query_dom_info("", &q_e, data, 0);

	switch_value = q_e.switch_value;
	status = _samr_query_dom_info(&q_e.domain_pol, q_e.switch_value, &ctr);
	make_samr_r_query_dom_info(&r_u, switch_value, &ctr, status);

	/* store the response in the SMB stream */
	samr_io_r_query_dom_info("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_create_user
 ********************************************************************/
static void api_samr_create_user( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CREATE_USER q_u;
	SAMR_R_CREATE_USER r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_create_user("", &q_u, data, 0);
	r_u.status = _samr_create_user(&q_u.domain_pol,
	                                   &q_u.uni_name, q_u.acb_info, 
					   q_u.access_mask,
					   &r_u.user_pol,
					   &r_u.unknown_0,
					   &r_u.user_rid);
	samr_io_r_create_user("", &r_u, rdata, 0);
}

/*******************************************************************
 api_samr_connect_anon
 ********************************************************************/
static void api_samr_connect_anon( rpcsrv_struct *p, prs_struct *data, prs_struct *rdata)
{
	SAMR_Q_CONNECT_ANON q_u;
	SAMR_R_CONNECT_ANON r_u;

	ZERO_STRUCT(q_u);
	ZERO_STRUCT(r_u);

	samr_io_q_connect_anon("", &q_u, data, 0);
	r_u.status = _samr_connect_anon(NULL,
	                                q_u.access_mask,
	                                &r_u.connect_pol);
	samr_io_r_connect_anon("", &r_u, rdata, 0);
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
	                           q_u.access_mask,
	                           &r_u.connect_pol);
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

	r_u.status = _samr_open_alias(&q_u.dom_pol, q_u.unknown_0, q_u.rid_alias, &r_u.pol);

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
	r_u.status = _samr_open_group(&q_u.domain_pol, q_u.access_mask,
	                               q_u.rid_group, &r_u.pol);
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
	{ "SAMR_GET_DOM_PWINFO"   , SAMR_GET_DOM_PWINFO   , api_samr_get_dom_pwinfo       },
	{ "SAMR_CHGPASSWD_USER"   , SAMR_CHGPASSWD_USER   , api_samr_chgpasswd_user   },
	{ "SAMR_OPEN_ALIAS"       , SAMR_OPEN_ALIAS       , api_samr_open_alias       },
	{ "SAMR_OPEN_GROUP"       , SAMR_OPEN_GROUP       , api_samr_open_group       },
	{ "SAMR_OPEN_DOMAIN"      , SAMR_OPEN_DOMAIN      , api_samr_open_domain      },
	{ "SAMR_LOOKUP_DOMAIN"    , SAMR_LOOKUP_DOMAIN    , api_samr_lookup_domain    },
	{ "SAMR_QUERY_SEC_OBJECT" , SAMR_QUERY_SEC_OBJECT , api_samr_query_sec_obj    },
	{ "SAMR_GET_USRDOM_PWINFO", SAMR_GET_USRDOM_PWINFO, api_samr_get_usrdom_pwinfo},
	{ NULL                    , 0                     , NULL                      }
};

/*******************************************************************
 receives a samr pipe and responds.
 ********************************************************************/
BOOL api_samr_rpc(rpcsrv_struct *p)
{
    return api_rpcTNP(p, "api_samr_rpc", api_samr_cmds);
}

