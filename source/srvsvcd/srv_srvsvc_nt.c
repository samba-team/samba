/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Main SMB server routines
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Jean-Francois Micouleau      1999-2000
   Copyright (C) Sean Millichamp                   2000
   
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
#include "rpc_parse.h"
#include "nterr.h"

extern pstring global_myname;
extern int DEBUGLEVEL;

/*******************************************************************
time of day
********************************************************************/
uint32 _srv_net_remote_tod(UNISTR2 *srv_name, TIME_OF_DAY_INFO * tod)
{
	struct tm *t;
	time_t unixdate = time(NULL);

	t = gmtime(&unixdate);

	/* set up the */
	make_time_of_day_info(tod,
			      unixdate,
			      0,
			      t->tm_hour,
			      t->tm_min,
			      t->tm_sec,
			      0,
			      TimeDiff(unixdate) / 60,
			      10000,
			      t->tm_mday,
			      t->tm_mon + 1, 1900 + t->tm_year, t->tm_wday);
	return 0x0;
}

/*******************************************************************
 makes a SRV_INFO_101 structure.
 ********************************************************************/
static BOOL make_r_srv_info_101(SRV_INFO_101 * sv101, uint32 platform_id,
				char *name, int32 ver_major, uint32 ver_minor,
				uint32 srv_type, char *comment)
{
	if (sv101 == NULL)
		return False;

	DEBUG(5, ("make_srv_info_101\n"));

	sv101->platform_id = platform_id;
	make_buf_unistr2(&(sv101->uni_name), &(sv101->ptr_name), name);
	sv101->ver_major = ver_major;
	sv101->ver_minor = ver_minor;
	sv101->srv_type = srv_type;
	make_buf_unistr2(&(sv101->uni_comment), &(sv101->ptr_comment),
			 comment);

	return True;
}

/*******************************************************************
 makes a SRV_INFO_102 structure.
 ********************************************************************/
static BOOL make_r_srv_info_102(SRV_INFO_102 * sv102, uint32 platform_id,
				char *name, char *comment, uint32 ver_major,
				uint32 ver_minor, uint32 srv_type,
				uint32 users, uint32 disc, uint32 hidden,
				uint32 announce, uint32 ann_delta,
				uint32 licenses, char *usr_path)
{
	if (sv102 == NULL)
		return False;

	DEBUG(5, ("make_srv_info_102\n"));

	sv102->platform_id = platform_id;
	make_buf_unistr2(&(sv102->uni_name), &(sv102->ptr_name), name);
	sv102->ver_major = ver_major;
	sv102->ver_minor = ver_minor;
	sv102->srv_type = srv_type;
	make_buf_unistr2(&(sv102->uni_comment), &(sv102->ptr_comment),
			 comment);

	/* same as 101 up to here */

	sv102->users = users;
	sv102->disc = disc;
	sv102->hidden = hidden;
	sv102->announce = announce;
	sv102->ann_delta = ann_delta;
	sv102->licenses = licenses;
	make_buf_unistr2(&(sv102->uni_usr_path), &(sv102->ptr_usr_path),
			 usr_path);

	return True;
}


/*******************************************************************
net server get info
********************************************************************/
uint32 _srv_net_srv_get_info(UNISTR2 *srv_name, uint32 switch_value,
			     SRV_INFO_CTR * ctr)
{
	switch (switch_value)
	{
		case 102:
		{
			make_r_srv_info_102(&(ctr->srv.sv102), 500,	/* platform id */
					    global_myname,
					    lp_serverstring(),
					    lp_major_announce_version(),
					    lp_minor_announce_version(),
					    lp_default_server_announce(), 0xffffffff,	/* users */
					    0xf,	/* disc */
					    0,	/* hidden */
					    240,	/* announce */
					    3000,	/* announce delta */
					    100000,	/* licenses */
					    "c:\\");	/* user path */
			break;
		}
		case 101:
		{
			make_r_srv_info_101(&(ctr->srv.sv101), 500,	/* platform id */
					    global_myname,
					    lp_major_announce_version(),
					    lp_minor_announce_version(),
					    lp_default_server_announce(),
					    lp_serverstring());
			break;
		}
		default:
		{
			return (NT_STATUS_INVALID_INFO_CLASS);
			break;
		}
	}
	return 0x0;
}

/*******************************************************************
 fill in a share info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 see ipc.c:fill_share_info()

 ********************************************************************/
static void make_srv_share_1_info(SH_INFO_1 * sh1,
				  SH_INFO_1_STR * str1, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;

	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	make_srv_sh_info1(sh1, net_name, type, remark);
	make_srv_sh_info1_str(str1, net_name, remark);
}

/*******************************************************************
 fill in a share info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_share_info_1(SRV_SHARE_INFO_1 * sh1, uint32 *snum,
				  uint32 *svcs)
{
	uint32 num_entries = 0;
	(*svcs) = lp_numservices();

	if (sh1 == NULL)
	{
		(*snum) = 0;
		return;
	}

	sh1->info_1 = g_new(SH_INFO_1 *, (*svcs));
	sh1->info_1_str = g_new(SH_INFO_1_STR *, (*svcs));

	DEBUG(5, ("make_srv_share_1_sh1\n"));

	for (; (*snum) < (*svcs); (*snum)++)
	{
		if (lp_browseable((*snum)) && lp_snum_ok((*snum)))
		{
			sh1->info_1[num_entries] = g_new(SH_INFO_1, 1);
			sh1->info_1_str[num_entries] =
				g_new(SH_INFO_1_STR, 1);

			make_srv_share_1_info(sh1->info_1[num_entries],
					      sh1->info_1_str[num_entries],
					      (*snum));

			/* move on to creating next share */
			num_entries++;
		}
	}

	sh1->num_entries_read = num_entries;
	sh1->ptr_share_info = num_entries > 0 ? 1 : 0;
	sh1->num_entries_read2 = num_entries;

	if ((*snum) >= (*svcs))
	{
		(*snum) = 0;
	}
}

/*******************************************************************
 fill in a share info level 2 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 see ipc.c:fill_share_info()

 ********************************************************************/
static void make_srv_share_2_info(SH_INFO_2 * sh2,
				  SH_INFO_2_STR * str2, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;
	uint32 perms;
	uint32 max_uses;
	uint32 current_uses;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	pstrcpy(path, lp_pathname(snum));
	pstrcpy(passwd, "");
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;

	/* permissions.  actually, i think delete is modify.  lkclXXXX */
	perms = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	current_uses = 1;
	max_uses = lp_max_connections(snum);
	if (max_uses == 0)
		max_uses = 0xffffffff;

	make_srv_sh_info2(sh2, net_name, type, remark, perms,
			  max_uses, current_uses, path, passwd);
	make_srv_sh_info2_str(str2, net_name, remark, path, passwd);
}

/*******************************************************************
 fill in a share info level 2 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_share_info_2(SRV_SHARE_INFO_2 * sh2, uint32 *snum,
				  uint32 *svcs)
{
	uint32 num_entries = 0;
	(*svcs) = lp_numservices();

	if (sh2 == NULL)
	{
		(*snum) = 0;
		return;
	}

	sh2->info_2 = g_new(SH_INFO_2 *, (*svcs));
	sh2->info_2_str = g_new(SH_INFO_2_STR *, (*svcs));

	DEBUG(5, ("make_srv_share_2_sh1\n"));

	for (; (*snum) < (*svcs); (*snum)++)
	{
		if (lp_browseable((*snum)) && lp_snum_ok((*snum)))
		{
			sh2->info_2[num_entries] = g_new(SH_INFO_2, 1);
			sh2->info_2_str[num_entries] =
				g_new(SH_INFO_2_STR, 1);

			make_srv_share_2_info(sh2->info_2[num_entries],
					      sh2->info_2_str[num_entries],
					      (*snum));

			/* move on to creating next share */
			num_entries++;
		}
	}

	sh2->num_entries_read = num_entries;
	sh2->ptr_share_info = num_entries > 0 ? 1 : 0;
	sh2->num_entries_read2 = num_entries;

	if ((*snum) >= (*svcs))
	{
		(*snum) = 0;
	}
}

/*******************************************************************
 fill in a share info level 2 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 see ipc.c:fill_share_info()

 ********************************************************************/
static void make_srv_share_502_info(SH_INFO_502_HDR * sh502,
				    SH_INFO_502_DATA * str502, int snum)
{
	if (sh502 == NULL || str502 == NULL)
		return;

	make_srv_share_2_info(&(sh502->info2_hdr),
			      &(str502->info2_str), snum);

	/* currently, no SD */
	sh502->sd_size = 0;
	sh502->sd_ptr = 0;
	str502->sd_size2 = 0;
	ZERO_STRUCT(str502->sd);
}

/*******************************************************************
 makes a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/
static uint32 make_srv_share_info_ctr(SRV_SHARE_INFO_CTR * ctr,
				      uint32 switch_value, uint32 *resume_hnd,
				      uint32 *total_entries)
{
	uint32 status = 0x0;
	DEBUG(5, ("make_srv_share_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 1:
		{
			make_srv_share_info_1(&(ctr->share.info1),
					      resume_hnd, total_entries);
			ctr->ptr_share_ctr = 1;
			break;
		}
		case 2:
		{
			make_srv_share_info_2(&(ctr->share.info2),
					      resume_hnd, total_entries);
			ctr->ptr_share_ctr = 2;
			break;
		}
		default:
		{
			DEBUG(5,
			      ("make_srv_share_info_ctr: unsupported switch value %d\n",
			       switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_share_ctr = 0;
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/
static uint32 make_srv_r_net_share_enum(uint32 resume_hnd,
					int switch_value,
					SRV_SHARE_INFO_CTR * ctr,
					uint32 *total_entries,
					ENUM_HND * enum_hnd,
					uint32 share_level)
{
	uint32 status;

	DEBUG(5, ("make_srv_r_net_share_enum: %d\n", __LINE__));

	if (share_level == 0)
	{
		status = (NT_STATUS_INVALID_INFO_CLASS);
	}
	else
	{
		status = make_srv_share_info_ctr(ctr, switch_value,
						 &resume_hnd, total_entries);
	}

	if (status != 0x0)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(enum_hnd, resume_hnd);

	return status;
}

/*******************************************************************
net share enum
********************************************************************/
uint32 _srv_net_share_enum(const UNISTR2 *srv_name,
			   uint32 switch_value, SRV_SHARE_INFO_CTR * ctr,
			   uint32 preferred_len, ENUM_HND * enum_hnd,
			   uint32 *total_entries, uint32 share_level)
{
	uint32 status;

	DEBUG(5, ("_srv_net_srv_share_enum: %d\n", __LINE__));

	status = make_srv_r_net_share_enum(get_enum_hnd(enum_hnd),
					   ctr->switch_value,
					   ctr, total_entries,
					   enum_hnd, share_level);

	DEBUG(5, ("_srv_net_srv_share_enum: %d\n", __LINE__));

	return status;
}


/*******************************************************************
net share add
********************************************************************/
uint32 _srv_net_share_add(const UNISTR2 *srv_name,
			  uint32 info_level,
			  const SHARE_INFO_CTR * ctr, uint32 *parm_error)
{
	if (srv_name == NULL || ctr == NULL)
	{
		(*parm_error) = 0;
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_ACCESS_DENIED;
}

/*******************************************************************
net share get info
********************************************************************/
uint32 _srv_net_share_get_info(const UNISTR2 *srv_name,
			       const UNISTR2 *share_name, uint32 info_level,
			       SHARE_INFO_CTR * ctr)
{
	fstring share;
	int snum;

	if (share_name == NULL || ctr == NULL)
	{
		return NT_STATUS_INVALID_PARAMETER;
	}

	unistr2_to_ascii(share, share_name, sizeof(share) - 1);
	if (share == NULL)
		return NT_STATUS_NO_MEMORY;

	snum = lp_servicenumber(share);

	if (snum < 0)
	{
		/* no such service */
		return 0x906;
	}

	switch (info_level)
	{
		case 1:
		{
			ctr->info.id1 = g_new(SHARE_INFO_1, 1);
			if (ctr->info.id1 == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			make_srv_share_1_info(&ctr->info.id1->info1_hdr,
					      &ctr->info.id1->info1_str,
					      snum);
			return NT_STATUS_NOPROBLEMO;
		}
		case 2:
		{
			ctr->info.id2 = g_new(SHARE_INFO_2, 1);
			if (ctr->info.id2 == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			make_srv_share_2_info(&ctr->info.id2->info2_hdr,
					      &ctr->info.id2->info2_str,
					      snum);
			return NT_STATUS_NOPROBLEMO;
		}
		case 502:
		{
			ctr->info.id502 = g_new(SHARE_INFO_502, 1);
			if (ctr->info.id502 == NULL)
			{
				return NT_STATUS_NO_MEMORY;
			}
			make_srv_share_502_info(&ctr->info.id502->info502_hdr,
						&ctr->info.id502->
						info502_data, snum);
			return NT_STATUS_NOPROBLEMO;
		}
		default:
		{
			return NT_STATUS_INVALID_INFO_CLASS;
		}
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_sess_0_info(SESS_INFO_0 * se0, SESS_INFO_0_STR * str0,
				 char *name)
{
	make_srv_sess_info0(se0, name);
	make_srv_sess_info0_str(str0, name);
}

/*******************************************************************
 fill in a sess info level 0 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_sess_info_0(SRV_SESS_INFO_0 * ss0, uint32 *snum,
				 uint32 *stot)
{
	uint32 num_entries = 0;
	struct connect_record *crec;
	uint32 session_count;

	if (!get_session_count(&crec, &session_count))
	{
		(*snum) = 0;
		(*stot) = 0;
		return;
	}

	(*stot) = session_count;

	DEBUG(0, ("Session Count : %u\n", session_count));

	if (ss0 == NULL)
	{
		(*snum) = 0;
		free(crec);
		return;
	}

	if (snum)
	{
		DEBUG(0, ("snum ok\n"));
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES;
		     (*snum)++)
		{
			make_srv_sess_0_info(&(ss0->info_0[num_entries]),
					     &(ss0->info_0_str[num_entries]),
					     crec[num_entries].machine);

			DEBUG(0, ("make_srv_sess_0_info\n"));
			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss0->num_entries_read = num_entries;
		ss0->ptr_sess_info = num_entries > 0 ? 1 : 0;
		ss0->num_entries_read2 = num_entries;

		if ((*snum) >= (*stot))
		{
			(*snum) = 0;
		}
	}
	else
	{
		ss0->num_entries_read = 0;
		ss0->ptr_sess_info = 0;
		ss0->num_entries_read2 = 0;
	}
	free(crec);
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_sess_1_info(SESS_INFO_1 * se1, SESS_INFO_1_STR * str1,
				 char *name, char *user,
				 uint32 num_opens,
				 uint32 open_time, uint32 idle_time,
				 uint32 usr_flgs)
{
	make_srv_sess_info1(se1, name, user, num_opens, open_time, idle_time,
			    usr_flgs);
	make_srv_sess_info1_str(str1, name, user);
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_sess_info_1(SRV_SESS_INFO_1 * ss1, uint32 *snum,
				 uint32 *stot)
{
	uint32 num_entries = 0;
	struct connect_record *crec;
	uint32 session_count;

	if (!get_session_count(&crec, &session_count))
	{
		(*snum) = 0;
		(*stot) = 0;
		return;
	}

	(*stot) = session_count;

	DEBUG(0, ("Session Count (info1) : %u\n", session_count));
	if (ss1 == NULL)
	{
		(*snum) = 0;
		free(crec);
		return;
	}

	DEBUG(5, ("make_srv_sess_1_ss1\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES;
		     (*snum)++)
		{
			DEBUG(0, ("sess1 machine: %s, uid : %u\n",
				  crec[num_entries].machine,
				  (uint32)crec[num_entries].uid));
			make_srv_sess_1_info(&(ss1->info_1[num_entries]),
					     &(ss1->info_1_str[num_entries]),
					     crec[num_entries].machine,
					     uidtoname(crec[num_entries].uid),
					     1, 10, 5, 0);
/* 	What are these on the End ??? */

			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss1->num_entries_read = num_entries;
		ss1->ptr_sess_info = num_entries > 0 ? 1 : 0;
		ss1->num_entries_read2 = num_entries;

		if ((*snum) >= (*stot))
		{
			(*snum) = 0;
		}
	}
	else
	{
		ss1->num_entries_read = 0;
		ss1->ptr_sess_info = 0;
		ss1->num_entries_read2 = 0;

		(*stot) = 0;
	}
	free(crec);
}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/
static uint32 make_srv_sess_info_ctr(SRV_SESS_INFO_CTR * ctr,
				     int switch_value, uint32 *resume_hnd,
				     uint32 *total_entries)
{
	uint32 status = 0x0;
	DEBUG(5, ("make_srv_sess_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 0:
		{
			make_srv_sess_info_0(&(ctr->sess.info0), resume_hnd,
					     total_entries);
			ctr->ptr_sess_ctr = 1;
			break;
		}
		case 1:
		{
			make_srv_sess_info_1(&(ctr->sess.info1), resume_hnd,
					     total_entries);
			ctr->ptr_sess_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,
			      ("make_srv_sess_info_ctr: unsupported switch value %d\n",
			       switch_value));
			(*resume_hnd) = 0;
			(*total_entries) = 0;
			ctr->ptr_sess_ctr = 0;
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}
	return status;
}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/
static uint32 make_srv_r_net_sess_enum(uint32 resume_hnd,
				       int switch_value,
				       SRV_SESS_INFO_CTR * ctr,
				       uint32 *total_entries,
				       ENUM_HND * enum_hnd, uint32 sess_level)
{
	uint32 status;

	DEBUG(5, ("make_srv_r_net_sess_enum: %d\n", __LINE__));

	if (sess_level == -1)
	{
		status = NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		status = make_srv_sess_info_ctr(ctr, switch_value,
						&resume_hnd, total_entries);
	}
	if (status != 0x0)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(enum_hnd, resume_hnd);

	return status;
}

/*******************************************************************
net sess enum
********************************************************************/
uint32 _srv_net_sess_enum(const UNISTR2 *srv_name,
			  uint32 switch_value, SRV_SESS_INFO_CTR * ctr,
			  uint32 preferred_len, ENUM_HND * enum_hnd,
			  uint32 *total_entries, uint32 sess_level)
{
	uint32 status;

	DEBUG(5, ("_srv_net_sess_enum: %d\n", __LINE__));

	/* set up the */
	status = make_srv_r_net_sess_enum(get_enum_hnd(enum_hnd),
					  ctr->switch_value,
					  ctr, total_entries,
					  enum_hnd, sess_level);

	DEBUG(5, ("_srv_net_sess_enum: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 fill in a conn info level 0 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_conn_info_0(SRV_CONN_INFO_0 * ss0, uint32 *snum,
				 uint32 *stot)
{
	uint32 num_entries = 0;
	struct connect_record *crec;
	uint32 connection_count;

	if (!get_connection_status(&crec, &connection_count))
	{
		(*snum) = 0;
		(*stot) = 0;
		return;
	}

	(*stot) = connection_count;

	if (ss0 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(0, ("make_srv_conn_0_ss0\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES;
		     (*snum)++)
		{
			make_srv_conn_info0(&(ss0->info_0[num_entries]),
					    (*snum));

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss0->num_entries_read = num_entries;
		ss0->ptr_conn_info = num_entries > 0 ? 1 : 0;
		ss0->num_entries_read2 = num_entries;

		if ((*snum) >= (*stot))
		{
			(*snum) = 0;
		}
	}
	else
	{
		ss0->num_entries_read = 0;
		ss0->ptr_conn_info = 0;
		ss0->num_entries_read2 = 0;

		(*stot) = 0;
	}

	free(crec);
}

/*******************************************************************
 fill in a conn info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_conn_1_info(CONN_INFO_1 * se1, CONN_INFO_1_STR * str1,
				 uint32 id, uint32 type,
				 uint32 num_opens, uint32 num_users,
				 uint32 open_time, char *usr_name,
				 char *net_name)
{
	make_srv_conn_info1(se1, id, type, num_opens, num_users, open_time,
			    usr_name, net_name);
	make_srv_conn_info1_str(str1, usr_name, net_name);
}

/*******************************************************************
 fill in a conn info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_conn_info_1(SRV_CONN_INFO_1 * ss1, uint32 *snum,
				 uint32 *stot)
{
	uint32 num_entries = 0;
	time_t current_time;
	time_t diff;

	struct connect_record *crec;
	uint32 connection_count;

	if (!get_connection_status(&crec, &connection_count))
	{
		(*snum) = 0;
		(*stot) = 0;
		return;
	}

	(*stot) = connection_count;

	if (ss1 == NULL)
	{
		(*snum) = 0;
		return;
	}

	current_time = time(NULL);

	DEBUG(5, ("make_srv_conn_1_ss1\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES;
		     (*snum)++)
		{
			diff = current_time - crec[num_entries].start;
			make_srv_conn_1_info(&(ss1->info_1[num_entries]),
					     &(ss1->info_1_str[num_entries]),
					     (*snum), 0, 0, 1, diff,
					     uidtoname(crec[num_entries].uid),
					     crec[num_entries].name);

/* FIXME : type of connection + number of locked files */

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss1->num_entries_read = num_entries;
		ss1->ptr_conn_info = num_entries > 0 ? 1 : 0;
		ss1->num_entries_read2 = num_entries;


		if ((*snum) >= (*stot))
		{
			(*snum) = 0;
		}
	}
	else
	{
		ss1->num_entries_read = 0;
		ss1->ptr_conn_info = 0;
		ss1->num_entries_read2 = 0;

		(*stot) = 0;
	}

	free(crec);
}

/*******************************************************************
 makes a SRV_R_NET_CONN_ENUM structure.
********************************************************************/
static uint32 make_srv_conn_info_ctr(SRV_CONN_INFO_CTR * ctr,
				     int switch_value, uint32 *resume_hnd,
				     uint32 *total_entries)
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5, ("make_srv_conn_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 0:
		{
			make_srv_conn_info_0(&(ctr->conn.info0), resume_hnd,
					     total_entries);
			ctr->ptr_conn_ctr = 1;
			break;
		}
		case 1:
		{
			make_srv_conn_info_1(&(ctr->conn.info1), resume_hnd,
					     total_entries);
			ctr->ptr_conn_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,
			      ("make_srv_conn_info_ctr: unsupported switch value %d\n",
			       switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_conn_ctr = 0;
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_CONN_ENUM structure.
********************************************************************/
static uint32 make_srv_r_net_conn_enum(uint32 resume_hnd,
				       int switch_value,
				       SRV_CONN_INFO_CTR * ctr,
				       uint32 *total_entries,
				       ENUM_HND * enum_hnd, uint32 conn_level)
{
	uint32 status;

	DEBUG(5, ("make_srv_r_net_conn_enum: %d\n", __LINE__));

	if (conn_level == -1)
	{
		status = (0xC0000000 | NT_STATUS_INVALID_INFO_CLASS);
	}
	else
	{
		status = make_srv_conn_info_ctr(ctr, switch_value,
						&resume_hnd, total_entries);
	}
	if (status != NT_STATUS_NOPROBLEMO)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(enum_hnd, resume_hnd);

	return status;
}

/*******************************************************************
net conn enum
********************************************************************/
uint32 _srv_net_conn_enum(const UNISTR2 *srv_name,
			  uint32 switch_value, SRV_CONN_INFO_CTR * ctr,
			  uint32 preferred_len, ENUM_HND * enum_hnd,
			  uint32 *total_entries, uint32 conn_level)
{
	uint32 status;

	DEBUG(5, ("_srv_net_conn_enum: %d\n", __LINE__));

	/* set up the */
	status = make_srv_r_net_conn_enum(get_enum_hnd(enum_hnd),
					  ctr->switch_value,
					  ctr, total_entries,
					  enum_hnd, conn_level);

	DEBUG(5, ("_srv_net_conn_enum: %d\n", __LINE__));

	return status;
}

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/
static void make_srv_file_3_info(FILE_INFO_3 * fl3, FILE_INFO_3_STR * str3,
				 uint32 fnum, uint32 perms, uint32 num_locks,
				 char *path_name, char *user_name)
{
	make_srv_file_info3(fl3, fnum, perms, num_locks, path_name,
			    user_name);
	make_srv_file_info3_str(str3, path_name, user_name);
}

/*******************************************************************
 fill in a file info level 3 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void make_srv_file_info_3(SRV_FILE_INFO_3 * fl3, uint32 *fnum,
				 uint32 *ftot)
{
	uint32 num_entries = 0;
	(*ftot) = 1;

	if (fl3 == NULL)
	{
		(*fnum) = 0;
		return;
	}

	DEBUG(5, ("make_srv_file_3_fl3\n"));

	fl3->info_3 = g_new0(FILE_INFO_3 *, (*ftot));
	fl3->info_3_str = g_new0(FILE_INFO_3_STR *, (*ftot));

	if (fl3->info_3 == NULL || fl3->info_3_str == NULL)
	{
		safe_free(fl3->info_3);
		safe_free(fl3->info_3_str);
		(*fnum) = 0;
		return;
	}

	for (; (*fnum) < (*ftot); (*fnum)++)
	{
		fl3->info_3[num_entries] = g_new(FILE_INFO_3, 1);
		fl3->info_3_str[num_entries] = g_new(FILE_INFO_3_STR, 1);

		make_srv_file_3_info(fl3->info_3[num_entries],
				     fl3->info_3_str[num_entries],
				     (*fnum), 0x35, 0,
				     "\\PIPE\\samr", "dummy user");

		/* move on to creating next file */
		num_entries++;
	}

	fl3->num_entries_read = num_entries;
	fl3->ptr_file_info = num_entries > 0 ? 1 : 0;
	fl3->num_entries_read2 = num_entries;

	if ((*fnum) >= (*ftot))
	{
		(*fnum) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/
static uint32 make_srv_file_info_ctr(SRV_FILE_INFO_CTR * ctr,
				     int switch_value, uint32 *resume_hnd,
				     uint32 *total_entries)
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5, ("make_srv_file_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 3:
		{
			make_srv_file_info_3(&(ctr->file.info3), resume_hnd,
					     total_entries);
			ctr->ptr_file_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,
			      ("make_srv_file_info_ctr: unsupported switch value %d\n",
			       switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_file_ctr = 0;
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_CONN_ENUM structure.
********************************************************************/
static uint32 make_srv_r_net_file_enum(uint32 resume_hnd,
				       int switch_value,
				       SRV_FILE_INFO_CTR * ctr,
				       uint32 *total_entries,
				       ENUM_HND * enum_hnd, uint32 file_level)
{
	uint32 status;

	DEBUG(5, ("make_srv_r_net_file_enum: %d\n", __LINE__));

	if (file_level == 0)
	{
		status = NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		status = make_srv_file_info_ctr(ctr, switch_value,
						&resume_hnd, total_entries);
	}
	if (status != NT_STATUS_NOPROBLEMO)
	{
		resume_hnd = 0;
	}
	make_enum_hnd(enum_hnd, resume_hnd);

	return status;
}

/*******************************************************************
net file enum
********************************************************************/
uint32 _srv_net_file_enum(const UNISTR2 *srv_name,
			  uint32 switch_value, SRV_FILE_INFO_CTR * ctr,
			  uint32 preferred_len, ENUM_HND * enum_hnd,
			  uint32 *total_entries, uint32 file_level)
{
	uint32 status;

	DEBUG(5, ("_srv_net_file_enum: %d\n", __LINE__));

	/* set up the */
	status = make_srv_r_net_file_enum(get_enum_hnd(enum_hnd),
					  ctr->switch_value,
					  ctr, total_entries,
					  enum_hnd, file_level);

	DEBUG(5, ("_srv_net_file_enum: %d\n", __LINE__));

	return status;
}
