
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
extern pstring global_myname;

/*******************************************************************
 Fill in a share info level 1 structure.
 See ipc.c:fill_share_info()
 ********************************************************************/

static void init_srv_share_1_info(SH_INFO_1 *sh1, SH_INFO_1_STR *str1, int snum)
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

	init_srv_share_info1(sh1, net_name, type, remark);
	init_srv_share_info1_str(str1, net_name, remark);
}

/*******************************************************************
 Fill in a share info level 1 structure.
 ********************************************************************/

static BOOL init_srv_share_info_1(SRV_SHARE_INFO_1 *sh1, uint32 *snum, uint32 *svcs)
{
	uint32 num_entries = 0;
	uint32 res_handle;
	int i;

	DEBUG(5,("init_srv_share_info_1\n"));

	memset(sh1, '\0', sizeof(SRV_SHARE_INFO_1));

	/* First count the number of entries. */

	res_handle = *snum;
	*svcs = lp_numservices();

	for (; *snum < *svcs; (*snum)++) {
		if (lp_browseable(*snum) && lp_snum_ok(*snum))
			num_entries++;
	}

	if(num_entries) {
		if(!(sh1->info_1 = (SH_INFO_1 *)malloc(num_entries * sizeof(SH_INFO_1)))) {
			DEBUG(0,("init_srv_share_info_1: malloc fail for %d SH_INFO_1.",
				num_entries ));
			return False;
		}

		memset(sh1->info_1, '\0', num_entries * sizeof(SH_INFO_1));

		if(!(sh1->info_1_str = (SH_INFO_1_STR *)malloc(num_entries * sizeof(SH_INFO_1_STR)))) {
			DEBUG(0,("init_srv_share_info_1: malloc fail for %d SH_INFO_1_STR.",
				num_entries ));
			free(sh1->info_1);
			sh1->info_1 = NULL;
			return False;
		}

		memset(sh1->info_1_str, '\0', num_entries * sizeof(SH_INFO_1_STR));
	}

	for (*snum = res_handle, i = 0; *snum < *svcs; (*snum)++) {
		if (lp_browseable(*snum) && lp_snum_ok(*snum)) {
			init_srv_share_1_info(&sh1->info_1[i], &sh1->info_1_str[i], *snum);
			i++;
		}
	}

	sh1->num_entries_read = num_entries;
	sh1->ptr_share_info = (num_entries > 0) ? 1 : 0;
	sh1->num_entries_read2 = num_entries;
	
	if ((*snum) >= (*svcs))
		(*snum) = 0;

	return True;
}

/*******************************************************************
 Fill in a share info level 2 structure.
 See ipc.c:fill_share_info()
 ********************************************************************/

static void init_srv_share_2_info(SH_INFO_2 *sh2, SH_INFO_2_STR *str2, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	pstrcpy(path, lp_pathname(snum));
	pstrcpy(passwd, "");
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;
		
	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	init_srv_share_info2(sh2, net_name, type, remark, 0, 0xffffffff, 1, path, passwd);
	init_srv_share_info2_str(str2, net_name, remark, path, passwd);
}

/*******************************************************************
 Fill in a share info level 2 structure.
 ********************************************************************/

static BOOL init_srv_share_info_2(SRV_SHARE_INFO_2 *sh2, uint32 *snum, uint32 *svcs)
{
	uint32 num_entries = 0;
	uint32 res_handle;
	int i;

	DEBUG(5,("init_srv_share_info_2\n"));

	memset(sh2, '\0', sizeof(SRV_SHARE_INFO_2));

	/* Count the number of entries. */

	res_handle = *snum;
	*svcs = lp_numservices();

	for (; *snum < *svcs; (*snum)++) {
		if (lp_browseable((*snum)) && lp_snum_ok((*snum)))
			num_entries++;
	}

	if(num_entries) {
		if(!(sh2->info_2 = (SH_INFO_2 *)malloc(num_entries * sizeof(SH_INFO_2)))) {
			DEBUG(0,("init_srv_share_info_2: malloc fail for %d SH_INFO_2.",
				num_entries ));
			return False;
		}

		memset(sh2->info_2, '\0', num_entries * sizeof(SH_INFO_2));

		if(!(sh2->info_2_str = (SH_INFO_2_STR *)malloc(num_entries * sizeof(SH_INFO_2_STR)))) {
			DEBUG(0,("init_srv_share_info_2: malloc fail for %d SH_INFO_2_STR.",
				num_entries ));
			free(sh2->info_2);
			sh2->info_2 = NULL;
			return False;
		}

		memset(sh2->info_2_str, '\0', num_entries * sizeof(SH_INFO_2_STR));
	}

	for (i = 0, *snum = res_handle; *snum < *svcs; (*snum)++) {
		if (lp_browseable((*snum)) && lp_snum_ok((*snum))) {
			init_srv_share_2_info(&sh2->info_2[i], &sh2->info_2_str[i], *snum);
			i++;
		}
	}

	sh2->num_entries_read  = num_entries;
	sh2->ptr_share_info    = num_entries > 0 ? 1 : 0;
	sh2->num_entries_read2 = num_entries;
	
	if (*snum >= *svcs)
		*snum = 0;

	return True;
}

/*******************************************************************
 makes a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/

static uint32 init_srv_share_info_ctr(SRV_SHARE_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)  
{
	uint32 status = 0x0;
	DEBUG(5,("init_srv_share_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value) {
	case 1:
		if(!init_srv_share_info_1(&ctr->share.info1, resume_hnd, total_entries)) {
			*resume_hnd = 0;
			*total_entries = 0;
			ctr->ptr_share_ctr = 0;
			return (status = 0xC0000000 | NT_STATUS_NO_MEMORY);
		}
		ctr->ptr_share_ctr = 1;
		break;
	case 2:
		if(!init_srv_share_info_2(&ctr->share.info2, resume_hnd, total_entries)) {
			*resume_hnd = 0;
			*total_entries = 0;
			ctr->ptr_share_ctr = 0;
			return (status = 0xC0000000 | NT_STATUS_NO_MEMORY);
		}
		ctr->ptr_share_ctr = 2;
		break;
	default:
		DEBUG(5,("init_srv_share_info_ctr: unsupported switch value %d\n",
	          switch_value));
		*resume_hnd = 0;
		*total_entries = 0;
		ctr->ptr_share_ctr = 0;
		status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	return status;
}

/*******************************************************************
 Inits a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/

static void init_srv_r_net_share_enum(SRV_R_NET_SHARE_ENUM *r_n,
				uint32 resume_hnd, int share_level, int switch_value)  
{
	DEBUG(5,("init_srv_r_net_share_enum: %d\n", __LINE__));

	r_n->share_level  = share_level;
	if (share_level == 0)
		r_n->status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	else
		r_n->status = init_srv_share_info_ctr(&r_n->ctr, switch_value,
						&resume_hnd, &r_n->total_entries);

	if (r_n->status != 0x0)
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 Net share enum.
********************************************************************/

static BOOL srv_reply_net_share_enum(SRV_Q_NET_SHARE_ENUM *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_SHARE_ENUM r_n;
	BOOL ret;

	DEBUG(5,("srv_net_share_enum: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	init_srv_r_net_share_enum(&r_n,
				get_enum_hnd(&q_n->enum_hnd),
				q_n->share_level,
				q_n->ctr.switch_value);

	/* store the response in the SMB stream */
	ret = srv_io_r_net_share_enum("", &r_n, rdata, 0);

	/* Free the memory used by the response. */
	free_srv_r_net_share_enum(&r_n);

	DEBUG(5,("srv_net_share_enum: %d\n", __LINE__));

	return ret;
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_sess_0_info(SESS_INFO_0    *se0, SESS_INFO_0_STR *str0,
				char *name)
{
	init_srv_sess_info0    (se0 , name);
	init_srv_sess_info0_str(str0, name);
}

/*******************************************************************
 fill in a sess info level 0 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_sess_info_0(SRV_SESS_INFO_0 *ss0, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss0 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_sess_0_ss0\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++)
		{
			init_srv_sess_0_info(&(ss0->info_0    [num_entries]),
								 &(ss0->info_0_str[num_entries]), "MACHINE");

			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss0->num_entries_read  = num_entries;
		ss0->ptr_sess_info     = num_entries > 0 ? 1 : 0;
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
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_sess_1_info(SESS_INFO_1    *se1, SESS_INFO_1_STR *str1,
				char *name, char *user,
				uint32 num_opens,
				uint32 open_time, uint32 idle_time,
				uint32 usr_flgs)
{
	init_srv_sess_info1    (se1 , name, user, num_opens, open_time, idle_time, usr_flgs);
	init_srv_sess_info1_str(str1, name, user);
}

/*******************************************************************
 fill in a sess info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_sess_info_1(SRV_SESS_INFO_1 *ss1, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss1 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_sess_1_ss1\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++)
		{
			init_srv_sess_1_info(&(ss1->info_1    [num_entries]),
								 &(ss1->info_1_str[num_entries]),
			                     "MACHINE", "dummy_user", 1, 10, 5, 0);

			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss1->num_entries_read  = num_entries;
		ss1->ptr_sess_info     = num_entries > 0 ? 1 : 0;
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
}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/
static uint32 init_srv_sess_info_ctr(SRV_SESS_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	uint32 status = 0x0;
	DEBUG(5,("init_srv_sess_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 0:
		{
			init_srv_sess_info_0(&(ctr->sess.info0), resume_hnd, total_entries);
			ctr->ptr_sess_ctr = 1;
			break;
		}
		case 1:
		{
			init_srv_sess_info_1(&(ctr->sess.info1), resume_hnd, total_entries);
			ctr->ptr_sess_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,("init_srv_sess_info_ctr: unsupported switch value %d\n",
			          switch_value));
			(*resume_hnd) = 0;
			(*total_entries) = 0;
			ctr->ptr_sess_ctr = 0;
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/
static void init_srv_r_net_sess_enum(SRV_R_NET_SESS_ENUM *r_n,
				uint32 resume_hnd, int sess_level, int switch_value)  
{
	DEBUG(5,("init_srv_r_net_sess_enum: %d\n", __LINE__));

	r_n->sess_level  = sess_level;
	if (sess_level == -1)
	{
		r_n->status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		r_n->status = init_srv_sess_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);
	}
	if (r_n->status != 0x0)
	{
		resume_hnd = 0;
	}
	init_enum_hnd(&(r_n->enum_hnd), resume_hnd);
}

/*******************************************************************
net sess enum
********************************************************************/
static void srv_reply_net_sess_enum(SRV_Q_NET_SESS_ENUM *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_SESS_ENUM r_n;
	SRV_SESS_INFO_CTR ctr;

	r_n.ctr = &ctr;

	DEBUG(5,("srv_net_sess_enum: %d\n", __LINE__));

	/* set up the */
	init_srv_r_net_sess_enum(&r_n,
				get_enum_hnd(&q_n->enum_hnd),
				q_n->sess_level,
				q_n->ctr->switch_value);

	/* store the response in the SMB stream */
	srv_io_r_net_sess_enum("", &r_n, rdata, 0);

	DEBUG(5,("srv_net_sess_enum: %d\n", __LINE__));
}

/*******************************************************************
 fill in a conn info level 0 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_conn_info_0(SRV_CONN_INFO_0 *ss0, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss0 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_0_ss0\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES; (*snum)++)
		{
			init_srv_conn_info0(&(ss0->info_0    [num_entries]), (*stot));

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss0->num_entries_read  = num_entries;
		ss0->ptr_conn_info     = num_entries > 0 ? 1 : 0;
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
}

/*******************************************************************
 fill in a conn info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_conn_1_info(CONN_INFO_1    *se1, CONN_INFO_1_STR *str1,
				uint32 id, uint32 type,
				uint32 num_opens, uint32 num_users, uint32 open_time,
				char *usr_name, char *net_name)
{
	init_srv_conn_info1    (se1 , id, type, num_opens, num_users, open_time, usr_name, net_name);
	init_srv_conn_info1_str(str1, usr_name, net_name);
}

/*******************************************************************
 fill in a conn info level 1 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_conn_info_1(SRV_CONN_INFO_1 *ss1, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss1 == NULL)
	{
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_1_ss1\n"));

	if (snum)
	{
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES; (*snum)++)
		{
			init_srv_conn_1_info(&(ss1->info_1    [num_entries]),
								 &(ss1->info_1_str[num_entries]),
			                     (*stot), 0x3, 1, 1, 3,"dummy_user", "IPC$");

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss1->num_entries_read  = num_entries;
		ss1->ptr_conn_info     = num_entries > 0 ? 1 : 0;
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
}

/*******************************************************************
 makes a SRV_R_NET_CONN_ENUM structure.
********************************************************************/
static uint32 init_srv_conn_info_ctr(SRV_CONN_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	uint32 status = 0x0;
	DEBUG(5,("init_srv_conn_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 0:
		{
			init_srv_conn_info_0(&(ctr->conn.info0), resume_hnd, total_entries);
			ctr->ptr_conn_ctr = 1;
			break;
		}
		case 1:
		{
			init_srv_conn_info_1(&(ctr->conn.info1), resume_hnd, total_entries);
			ctr->ptr_conn_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,("init_srv_conn_info_ctr: unsupported switch value %d\n",
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
static void init_srv_r_net_conn_enum(SRV_R_NET_CONN_ENUM *r_n,
				uint32 resume_hnd, int conn_level, int switch_value)  
{
	DEBUG(5,("init_srv_r_net_conn_enum: %d\n", __LINE__));

	r_n->conn_level  = conn_level;
	if (conn_level == -1)
	{
		r_n->status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		r_n->status = init_srv_conn_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);
	}
	if (r_n->status != 0x0)
	{
		resume_hnd = 0;
	}
	init_enum_hnd(&(r_n->enum_hnd), resume_hnd);
}

/*******************************************************************
net conn enum
********************************************************************/
static void srv_reply_net_conn_enum(SRV_Q_NET_CONN_ENUM *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_CONN_ENUM r_n;
	SRV_CONN_INFO_CTR ctr;

	r_n.ctr = &ctr;

	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	/* set up the */
	init_srv_r_net_conn_enum(&r_n,
				get_enum_hnd(&q_n->enum_hnd),
				q_n->conn_level,
				q_n->ctr->switch_value);

	/* store the response in the SMB stream */
	srv_io_r_net_conn_enum("", &r_n, rdata, 0);

	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));
}

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/
static void init_srv_file_3_info(FILE_INFO_3     *fl3, FILE_INFO_3_STR *str3,
				uint32 fnum, uint32 perms, uint32 num_locks,
				char *path_name, char *user_name)
{
	init_srv_file_info3    (fl3 , fnum, perms, num_locks, path_name, user_name);
	init_srv_file_info3_str(str3, path_name, user_name);
}

/*******************************************************************
 fill in a file info level 3 structure.

 this function breaks the rule that i'd like to be in place, namely
 it doesn't receive its data as arguments: it has to call lp_xxxx()
 functions itself.  yuck.

 ********************************************************************/
static void init_srv_file_info_3(SRV_FILE_INFO_3 *fl3, uint32 *fnum, uint32 *ftot)
{
	uint32 num_entries = 0;
	(*ftot) = 1;

	if (fl3 == NULL)
	{
		(*fnum) = 0;
		return;
	}

	DEBUG(5,("init_srv_file_3_fl3\n"));

	for (; (*fnum) < (*ftot) && num_entries < MAX_FILE_ENTRIES; (*fnum)++)
	{
		init_srv_file_3_info(&(fl3->info_3    [num_entries]),
			                 &(fl3->info_3_str[num_entries]),
		                     (*fnum), 0x35, 0, "\\PIPE\\samr", "dummy user");

		/* move on to creating next file */
		num_entries++;
	}

	fl3->num_entries_read  = num_entries;
	fl3->ptr_file_info     = num_entries > 0 ? 1 : 0;
	fl3->num_entries_read2 = num_entries;
	
	if ((*fnum) >= (*ftot))
	{
		(*fnum) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/
static uint32 init_srv_file_info_ctr(SRV_FILE_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)  
{
	uint32 status = 0x0;
	DEBUG(5,("init_srv_file_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value)
	{
		case 3:
		{
			init_srv_file_info_3(&(ctr->file.info3), resume_hnd, total_entries);
			ctr->ptr_file_ctr = 1;
			break;
		}
		default:
		{
			DEBUG(5,("init_srv_file_info_ctr: unsupported switch value %d\n",
			          switch_value));
			(*resume_hnd = 0);
			(*total_entries) = 0;
			ctr->ptr_file_ctr = 0;
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/
static void init_srv_r_net_file_enum(SRV_R_NET_FILE_ENUM *r_n,
				uint32 resume_hnd, int file_level, int switch_value)  
{
	DEBUG(5,("init_srv_r_net_file_enum: %d\n", __LINE__));

	r_n->file_level  = file_level;
	if (file_level == 0)
	{
		r_n->status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
	}
	else
	{
		r_n->status = init_srv_file_info_ctr(r_n->ctr, switch_value, &resume_hnd, &(r_n->total_entries));
	}
	if (r_n->status != 0x0)
	{
		resume_hnd = 0;
	}
	init_enum_hnd(&(r_n->enum_hnd), resume_hnd);
}

/*******************************************************************
net file enum
********************************************************************/
static void srv_reply_net_file_enum(SRV_Q_NET_FILE_ENUM *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_FILE_ENUM r_n;
	SRV_FILE_INFO_CTR ctr;

	r_n.ctr = &ctr;

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));

	/* set up the */
	init_srv_r_net_file_enum(&r_n,
				get_enum_hnd(&q_n->enum_hnd),
				q_n->file_level,
				q_n->ctr->switch_value);

	/* store the response in the SMB stream */
	srv_io_r_net_file_enum("", &r_n, rdata, 0);

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));
}

/*******************************************************************
net server get info
********************************************************************/

static void srv_reply_net_srv_get_info(SRV_Q_NET_SRV_GET_INFO *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_SRV_GET_INFO r_n;
	uint32 status = 0x0;
	SRV_INFO_CTR ctr;


	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	switch (q_n->switch_value)
	{
		case 102:
		{
			init_srv_info_102(&ctr.srv.sv102,
			                  500, global_myname, lp_serverstring(),
			                  lp_major_announce_version(), lp_minor_announce_version(),
			                  lp_default_server_announce(),
			                  0xffffffff, /* users */
			                  0xf, /* disc */
			                  0, /* hidden */
			                  240, /* announce */
			                  3000, /* announce delta */
			                  100000, /* licenses */
			                  "c:\\"); /* user path */
			break;
		}
		case 101:
		{
			init_srv_info_101(&ctr.srv.sv101,
			                  500, global_myname,
			                  lp_major_announce_version(), lp_minor_announce_version(),
			                  lp_default_server_announce(),
			                  lp_serverstring());
			break;
		}
		default:
		{
			status = 0xC0000000 | NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	}

	/* set up the net server get info structure */
	init_srv_r_net_srv_get_info(&r_n, q_n->switch_value, &ctr, status);

	/* store the response in the SMB stream */
	srv_io_r_net_srv_get_info("", &r_n, rdata, 0);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));
}

/*******************************************************************
********************************************************************/
static BOOL api_srv_net_srv_get_info( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_SRV_GET_INFO q_n;

	/* grab the net server get info */
	srv_io_q_net_srv_get_info("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_srv_get_info(&q_n, rdata);

	return True;
}


/*******************************************************************
********************************************************************/
static BOOL api_srv_net_file_enum( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_FILE_ENUM q_n;
	SRV_FILE_INFO_CTR ctr;

	q_n.ctr = &ctr;

	/* grab the net file enum */
	srv_io_q_net_file_enum("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_file_enum(&q_n, rdata);

	return True;
}


/*******************************************************************
********************************************************************/
static BOOL api_srv_net_conn_enum( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_CONN_ENUM q_n;
	SRV_CONN_INFO_CTR ctr;

	q_n.ctr = &ctr;

	/* grab the net server get enum */
	srv_io_q_net_conn_enum("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_conn_enum(&q_n, rdata);

	return True;
}


/*******************************************************************
********************************************************************/
static BOOL api_srv_net_sess_enum( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_SESS_ENUM q_n;
	SRV_SESS_INFO_CTR ctr;

	q_n.ctr = &ctr;

	/* grab the net server get enum */
	srv_io_q_net_sess_enum("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_sess_enum(&q_n, rdata);

	return True;
}


/*******************************************************************
 RPC to enumerate shares.
********************************************************************/

static BOOL api_srv_net_share_enum( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_SHARE_ENUM q_n;
	BOOL ret;

	/* Unmarshall the net server get enum. */
	if(!srv_io_q_net_share_enum("", &q_n, data, 0)) {
		DEBUG(0,("api_srv_net_share_enum: Failed to unmarshall SRV_Q_NET_SHARE_ENUM.\n"));
		return False;
	}

	ret = srv_reply_net_share_enum(&q_n, rdata);

	/* Free any data allocated in the unmarshalling. */
	free_srv_q_net_share_enum(&q_n);

	return ret;
}

/*******************************************************************
time of day
********************************************************************/
static BOOL srv_reply_net_remote_tod(SRV_Q_NET_REMOTE_TOD *q_n,
				prs_struct *rdata)
{
	SRV_R_NET_REMOTE_TOD r_n;
	TIME_OF_DAY_INFO tod;
	struct tm *t;
	time_t unixdate = time(NULL);

	r_n.tod = &tod;
	r_n.ptr_srv_tod = 0x1;
	r_n.status = 0x0;

	DEBUG(5,("srv_reply_net_remote_tod: %d\n", __LINE__));

	t = gmtime(&unixdate);

	/* set up the */
	init_time_of_day_info(&tod,
	                      unixdate,
	                      0,
	                      t->tm_hour,
	                      t->tm_min,
	                      t->tm_sec,
	                      0,
	                      TimeDiff(unixdate)/60,
	                      10000,
	                      t->tm_mday,
	                      t->tm_mon + 1,
	                      1900+t->tm_year,
	                      t->tm_wday);
	
	/* store the response in the SMB stream */
	srv_io_r_net_remote_tod("", &r_n, rdata, 0);
	
	DEBUG(5,("srv_reply_net_remote_tod: %d\n", __LINE__));

	return True;
}
/*******************************************************************
********************************************************************/
static BOOL api_srv_net_remote_tod( uint16 vuid, prs_struct *data,
                                    prs_struct *rdata )
{
	SRV_Q_NET_REMOTE_TOD q_n;

	/* grab the net server get enum */
	srv_io_q_net_remote_tod("", &q_n, data, 0);

	/* construct reply.  always indicate success */
	srv_reply_net_remote_tod(&q_n, rdata);

	return True;
}


/*******************************************************************
\PIPE\srvsvc commands
********************************************************************/
struct api_struct api_srv_cmds[] =
{
	{ "SRV_NETCONNENUM"     , SRV_NETCONNENUM     , api_srv_net_conn_enum    },
	{ "SRV_NETSESSENUM"     , SRV_NETSESSENUM     , api_srv_net_sess_enum    },
	{ "SRV_NETSHAREENUM"    , SRV_NETSHAREENUM    , api_srv_net_share_enum   },
	{ "SRV_NETFILEENUM"     , SRV_NETFILEENUM     , api_srv_net_file_enum    },
	{ "SRV_NET_SRV_GET_INFO", SRV_NET_SRV_GET_INFO, api_srv_net_srv_get_info },
	{ "SRV_NET_REMOTE_TOD"  , SRV_NET_REMOTE_TOD  , api_srv_net_remote_tod   },
	{ NULL                  , 0                   , NULL                     }
};

/*******************************************************************
receives a srvsvc pipe and responds.
********************************************************************/
BOOL api_srvsvc_rpc(pipes_struct *p, prs_struct *data)
{
	return api_rpcTNP(p, "api_srvsvc_rpc", api_srv_cmds, data);
}
