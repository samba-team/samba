/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison					2001.
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

/* This is the implementation of the srvsvc pipe. */

#include "includes.h"

extern int DEBUGLEVEL;
extern pstring global_myname;

/*******************************************************************
 Fill in a share info level 1 structure.
 ********************************************************************/

static void init_srv_share_info_1(SRV_SHARE_INFO_1 *sh1, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	pstring_sub(remark,"%S",lp_servicename(snum));
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;
		
	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC", lp_fstype(snum)))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	init_srv_share_info1(&sh1->info_1, net_name, type, remark);
	init_srv_share_info1_str(&sh1->info_1_str, net_name, remark);
}

/*******************************************************************
 Fill in a share info level 2 structure.
 ********************************************************************/

static void init_srv_share_info_2(SRV_SHARE_INFO_2 *sh2, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	pstring_sub(remark,"%S",lp_servicename(snum));
	pstrcpy(path, "C:");
	pstrcat(path, lp_pathname(snum));
	pstrcpy(passwd, "");
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;
		
	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC", lp_fstype(snum)))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	init_srv_share_info2(&sh2->info_2, net_name, type, remark, 0, 0xffffffff, 1, path, passwd);
	init_srv_share_info2_str(&sh2->info_2_str, net_name, remark, path, passwd);
}

/*******************************************************************
 Fake up a Everyone, full access for now.
 ********************************************************************/

static SEC_DESC *get_share_security( TALLOC_CTX *ctx, int snum, size_t *psize)
{
	extern DOM_SID global_sid_World;
	SEC_ACCESS sa;
	SEC_ACE ace;
	SEC_ACL *psa = NULL;
	SEC_DESC *psd = NULL;

    init_sec_access(&sa, GENERIC_ALL_ACCESS );
    init_sec_ace(&ace, &global_sid_World, SEC_ACE_TYPE_ACCESS_ALLOWED, sa, 0);

	if ((psa = make_sec_acl(ctx, NT4_ACL_REVISION, 1, &ace)) != NULL) {
		psd = make_sec_desc(ctx, SEC_DESC_REVISION, NULL, NULL, NULL, psa, psize);
	}

	if (!psd) {
		DEBUG(0,("get_share_security: Failed to make SEC_DESC.\n"));
		return NULL;
	}

	return psd;
}

/*******************************************************************
 Fill in a share info level 502 structure.
 ********************************************************************/

static void init_srv_share_info_502(TALLOC_CTX *ctx, SRV_SHARE_INFO_502 *sh502, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;
	SEC_DESC *sd;
	size_t sd_size;

	ZERO_STRUCTP(sh502);

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	pstring_sub(remark,"%S",lp_servicename(snum));
	pstrcpy(path, "C:");
	pstrcat(path, lp_pathname(snum));
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

	sd = get_share_security(ctx, snum, &sd_size);

	init_srv_share_info502(&sh502->info_502, net_name, type, remark, 0, 0xffffffff, 1, path, passwd, sd, sd_size);
	init_srv_share_info502_str(&sh502->info_502_str, net_name, remark, path, passwd, sd, sd_size);
}

/***************************************************************************
 Fill in a share info level 1005 structure.
 ***************************************************************************/

static void init_srv_share_info_1005(SRV_SHARE_INFO_1005* sh1005, int snum)
{
	sh1005->dfs_root_flag = 0;

#ifdef WITH_MSDFS
	if(lp_host_msdfs() && lp_msdfs_root(snum))
		sh1005->dfs_root_flag = 3;
#endif

}

/*******************************************************************
 True if it ends in '$'.
 ********************************************************************/

static BOOL is_admin_share(int snum)
{
	pstring net_name;

	pstrcpy(net_name, lp_servicename(snum));
	return (net_name[strlen(net_name)] == '$') ? True : False;
}

/*******************************************************************
 Fill in a share info structure.
 ********************************************************************/

static BOOL init_srv_share_info_ctr(TALLOC_CTX *ctx, SRV_SHARE_INFO_CTR *ctr,
	       uint32 info_level, uint32 *resume_hnd, uint32 *total_entries, BOOL all_shares)
{
	int num_entries = 0;
	int num_services = lp_numservices();
	int snum;

	DEBUG(5,("init_srv_share_info_ctr\n"));

	ZERO_STRUCTPN(ctr);

	ctr->info_level = ctr->switch_value = info_level;
	*resume_hnd = 0;

	/* Count the number of entries. */
	for (snum = 0; snum < num_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) )
			num_entries++;
	}

	*total_entries = num_entries;
	ctr->num_entries2 = ctr->num_entries = num_entries;
	ctr->ptr_share_info = ctr->ptr_entries = 1;

	if (!num_entries)
		return True;

	switch (info_level) {
	case 1:
	{
		SRV_SHARE_INFO_1 *info1;
		int i = 0;

		info1 = talloc(ctx, num_entries * sizeof(SRV_SHARE_INFO_1));

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) ) {
				init_srv_share_info_1(&info1[i++], snum);
			}
		}

		ctr->share.info1 = info1;
		break;
	}

	case 2:
	{
		SRV_SHARE_INFO_2 *info2;
		int i = 0;

		info2 = talloc(ctx, num_entries * sizeof(SRV_SHARE_INFO_2));

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) ) {
				init_srv_share_info_2(&info2[i++], snum);
			}
		}

		ctr->share.info2 = info2;
		break;
	}

	case 502:
	{
		SRV_SHARE_INFO_502 *info502;
		int i = 0;

		info502 = talloc(ctx, num_entries * sizeof(SRV_SHARE_INFO_502));

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) ) {
				init_srv_share_info_502(ctx, &info502[i++], snum);
			}
		}

		ctr->share.info502 = info502;
		break;
	}

	default:
		DEBUG(5,("init_srv_share_info_ctr: unsupported switch value %d\n", info_level));
		return False;
	}

	return True;
}

/*******************************************************************
 Inits a SRV_R_NET_SHARE_ENUM structure.
********************************************************************/

static void init_srv_r_net_share_enum(TALLOC_CTX *ctx, SRV_R_NET_SHARE_ENUM *r_n,
				      uint32 info_level, uint32 resume_hnd, BOOL all)  
{
	DEBUG(5,("init_srv_r_net_share_enum: %d\n", __LINE__));

	if (init_srv_share_info_ctr(ctx, &r_n->ctr, info_level,
				    &resume_hnd, &r_n->total_entries, all)) {
		r_n->status = NT_STATUS_NOPROBLEMO;
	} else {
		r_n->status = NT_STATUS_INVALID_INFO_CLASS;
	}

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 Inits a SRV_R_NET_SHARE_GET_INFO structure.
********************************************************************/

static void init_srv_r_net_share_get_info(TALLOC_CTX *ctx, SRV_R_NET_SHARE_GET_INFO *r_n,
				  char *share_name, uint32 info_level)
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	int snum;

	DEBUG(5,("init_srv_r_net_share_get_info: %d\n", __LINE__));

	r_n->info.switch_value = info_level;

	snum = find_service(share_name);

	if (snum >= 0) {
		switch (info_level) {
		case 1:
			init_srv_share_info_1(&r_n->info.share.info1, snum);
			break;
		case 2:
			init_srv_share_info_2(&r_n->info.share.info2, snum);
			break;
		case 502:
			init_srv_share_info_502(ctx, &r_n->info.share.info502, snum);
			break;
		case 1005:
			init_srv_share_info_1005(&r_n->info.share.info1005, snum);
			break;
		default:
			DEBUG(5,("init_srv_net_share_get_info: unsupported switch value %d\n", info_level));
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	} else {
		status = NT_STATUS_BAD_NETWORK_NAME;
	}

	r_n->info.ptr_share_ctr = (status == NT_STATUS_NOPROBLEMO) ? 1 : 0;
	r_n->status = status;
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_0_info(SESS_INFO_0 *se0, SESS_INFO_0_STR *str0, char *name)
{
	init_srv_sess_info0(se0, name);
	init_srv_sess_info0_str(str0, name);
}

/*******************************************************************
 fill in a sess info level 0 structure.
 ********************************************************************/

static void init_srv_sess_info_0(SRV_SESS_INFO_0 *ss0, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss0 == NULL) {
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_sess_0_ss0\n"));

	if (snum) {
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++) {
			init_srv_sess_0_info(&ss0->info_0[num_entries],
								 &ss0->info_0_str[num_entries], "MACHINE");

			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss0->num_entries_read  = num_entries;
		ss0->ptr_sess_info     = num_entries > 0 ? 1 : 0;
		ss0->num_entries_read2 = num_entries;
		
		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
		ss0->num_entries_read = 0;
		ss0->ptr_sess_info = 0;
		ss0->num_entries_read2 = 0;
	}
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_1_info(SESS_INFO_1 *se1, SESS_INFO_1_STR *str1,
				char *name, char *user,
				uint32 num_opens,
				uint32 open_time, uint32 idle_time,
				uint32 usr_flgs)
{
	init_srv_sess_info1(se1 , name, user, num_opens, open_time, idle_time, usr_flgs);
	init_srv_sess_info1_str(str1, name, user);
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_info_1(SRV_SESS_INFO_1 *ss1, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss1 == NULL) {
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_sess_1_ss1\n"));

	if (snum) {
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++) {
			init_srv_sess_1_info(&ss1->info_1[num_entries],
								 &ss1->info_1_str[num_entries],
			                     "MACHINE", "dummy_user", 1, 10, 5, 0);

			/* move on to creating next session */
			/* move on to creating next sess */
			num_entries++;
		}

		ss1->num_entries_read  = num_entries;
		ss1->ptr_sess_info     = num_entries > 0 ? 1 : 0;
		ss1->num_entries_read2 = num_entries;
		
		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
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
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5,("init_srv_sess_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value) {
	case 0:
		init_srv_sess_info_0(&(ctr->sess.info0), resume_hnd, total_entries);
		ctr->ptr_sess_ctr = 1;
		break;
	case 1:
		init_srv_sess_info_1(&(ctr->sess.info1), resume_hnd, total_entries);
		ctr->ptr_sess_ctr = 1;
		break;
	default:
		DEBUG(5,("init_srv_sess_info_ctr: unsupported switch value %d\n", switch_value));
		(*resume_hnd) = 0;
		(*total_entries) = 0;
		ctr->ptr_sess_ctr = 0;
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
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
		r_n->status = NT_STATUS_INVALID_INFO_CLASS;
	else
		r_n->status = init_srv_sess_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

	if (r_n->status != NT_STATUS_NOPROBLEMO)
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 fill in a conn info level 0 structure.
 ********************************************************************/

static void init_srv_conn_info_0(SRV_CONN_INFO_0 *ss0, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss0 == NULL) {
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_0_ss0\n"));

	if (snum) {
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES; (*snum)++) {

			init_srv_conn_info0(&ss0->info_0[num_entries], (*stot));

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss0->num_entries_read  = num_entries;
		ss0->ptr_conn_info     = num_entries > 0 ? 1 : 0;
		ss0->num_entries_read2 = num_entries;
		
		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
		ss0->num_entries_read = 0;
		ss0->ptr_conn_info = 0;
		ss0->num_entries_read2 = 0;

		(*stot) = 0;
	}
}

/*******************************************************************
 fill in a conn info level 1 structure.
 ********************************************************************/

static void init_srv_conn_1_info(CONN_INFO_1 *se1, CONN_INFO_1_STR *str1,
				uint32 id, uint32 type,
				uint32 num_opens, uint32 num_users, uint32 open_time,
				char *usr_name, char *net_name)
{
	init_srv_conn_info1(se1 , id, type, num_opens, num_users, open_time, usr_name, net_name);
	init_srv_conn_info1_str(str1, usr_name, net_name);
}

/*******************************************************************
 fill in a conn info level 1 structure.
 ********************************************************************/

static void init_srv_conn_info_1(SRV_CONN_INFO_1 *ss1, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss1 == NULL) {
		(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_1_ss1\n"));

	if (snum) {
		for (; (*snum) < (*stot) && num_entries < MAX_CONN_ENTRIES; (*snum)++) {
			init_srv_conn_1_info(&ss1->info_1[num_entries],
								 &ss1->info_1_str[num_entries],
			                     (*stot), 0x3, 1, 1, 3,"dummy_user", "IPC$");

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss1->num_entries_read  = num_entries;
		ss1->ptr_conn_info     = num_entries > 0 ? 1 : 0;
		ss1->num_entries_read2 = num_entries;
		

		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
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
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5,("init_srv_conn_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value) {
	case 0:
		init_srv_conn_info_0(&ctr->conn.info0, resume_hnd, total_entries);
		ctr->ptr_conn_ctr = 1;
		break;
	case 1:
		init_srv_conn_info_1(&ctr->conn.info1, resume_hnd, total_entries);
		ctr->ptr_conn_ctr = 1;
		break;
	default:
		DEBUG(5,("init_srv_conn_info_ctr: unsupported switch value %d\n", switch_value));
		(*resume_hnd = 0);
		(*total_entries) = 0;
		ctr->ptr_conn_ctr = 0;
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
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
		r_n->status = NT_STATUS_INVALID_INFO_CLASS;
	else
		r_n->status = init_srv_conn_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

	if (r_n->status != NT_STATUS_NOPROBLEMO)
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/

static void init_srv_file_3_info(FILE_INFO_3 *fl3, FILE_INFO_3_STR *str3,
				uint32 fnum, uint32 perms, uint32 num_locks,
				char *path_name, char *user_name)
{
	init_srv_file_info3(fl3 , fnum, perms, num_locks, path_name, user_name);
	init_srv_file_info3_str(str3, path_name, user_name);
}

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/

static void init_srv_file_info_3(SRV_FILE_INFO_3 *fl3, uint32 *fnum, uint32 *ftot)
{
	uint32 num_entries = 0;
	(*ftot) = 1;

	if (fl3 == NULL) {
		(*fnum) = 0;
		return;
	}

	DEBUG(5,("init_srv_file_3_fl3\n"));

	for (; (*fnum) < (*ftot) && num_entries < MAX_FILE_ENTRIES; (*fnum)++) {
		init_srv_file_3_info(&fl3->info_3[num_entries],
			                 &fl3->info_3_str[num_entries],
		                     (*fnum), 0x35, 0, "\\PIPE\\samr", "dummy user");

		/* move on to creating next file */
		num_entries++;
	}

	fl3->num_entries_read  = num_entries;
	fl3->ptr_file_info     = num_entries > 0 ? 1 : 0;
	fl3->num_entries_read2 = num_entries;
	
	if ((*fnum) >= (*ftot)) {
		(*fnum) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/

static uint32 init_srv_file_info_ctr(SRV_FILE_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)  
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	DEBUG(5,("init_srv_file_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value) {
	case 3:
		init_srv_file_info_3(&ctr->file.info3, resume_hnd, total_entries);
		ctr->ptr_file_ctr = 1;
		break;
	default:
		DEBUG(5,("init_srv_file_info_ctr: unsupported switch value %d\n", switch_value));
		(*resume_hnd = 0);
		(*total_entries) = 0;
		ctr->ptr_file_ctr = 0;
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
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
		r_n->status = NT_STATUS_INVALID_INFO_CLASS;
	else
		r_n->status = init_srv_file_info_ctr(r_n->ctr, switch_value, &resume_hnd, &(r_n->total_entries));

	if (r_n->status != NT_STATUS_NOPROBLEMO)
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
net server get info
********************************************************************/

uint32 _srv_net_srv_get_info(pipes_struct *p, SRV_Q_NET_SRV_GET_INFO *q_u, SRV_R_NET_SRV_GET_INFO *r_u)
{
	uint32 status = NT_STATUS_NOPROBLEMO;
	SRV_INFO_CTR *ctr = (SRV_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_INFO_CTR));

	if (!ctr)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(ctr);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	switch (q_u->switch_value) {
	case 102:
		init_srv_info_102(&ctr->srv.sv102,
		                  500, global_myname, 
						string_truncate(lp_serverstring(), MAX_SERVER_STRING_LENGTH),
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
	case 101:
		init_srv_info_101(&ctr->srv.sv101,
		                  500, global_myname,
		                  lp_major_announce_version(), lp_minor_announce_version(),
		                  lp_default_server_announce(),
		                  string_truncate(lp_serverstring(), MAX_SERVER_STRING_LENGTH));
		break;
	case 100:
		init_srv_info_100(&ctr->srv.sv100, 500, global_myname);
		break;
	default:
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	/* set up the net server get info structure */
	init_srv_r_net_srv_get_info(r_u, q_u->switch_value, ctr, status);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net file enum
********************************************************************/

uint32 _srv_net_file_enum(pipes_struct *p, SRV_Q_NET_FILE_ENUM *q_u, SRV_R_NET_FILE_ENUM *r_u)
{
	r_u->ctr = (SRV_FILE_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_FILE_INFO_CTR));
	if (!r_u->ctr)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(r_u->ctr);

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));

	/* set up the */
	init_srv_r_net_file_enum(r_u,
				get_enum_hnd(&q_u->enum_hnd),
				q_u->file_level,
				q_u->ctr->switch_value);

	DEBUG(5,("srv_net_file_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net conn enum
********************************************************************/

uint32 _srv_net_conn_enum(pipes_struct *p, SRV_Q_NET_CONN_ENUM *q_u, SRV_R_NET_CONN_ENUM *r_u)
{
	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	r_u->ctr = (SRV_CONN_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_CONN_INFO_CTR));
	if (!r_u->ctr)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(r_u->ctr);

	/* set up the */
	init_srv_r_net_conn_enum(r_u,
				get_enum_hnd(&q_u->enum_hnd),
				q_u->conn_level,
				q_u->ctr->switch_value);

	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net sess enum
********************************************************************/

uint32 _srv_net_sess_enum(pipes_struct *p, SRV_Q_NET_SESS_ENUM *q_u, SRV_R_NET_SESS_ENUM *r_u)
{
	DEBUG(5,("_srv_net_sess_enum: %d\n", __LINE__));

	r_u->ctr = (SRV_SESS_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_SESS_INFO_CTR));
	if (!r_u->ctr)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(r_u->ctr);

	/* set up the */
	init_srv_r_net_sess_enum(r_u,
				get_enum_hnd(&q_u->enum_hnd),
				q_u->sess_level,
				q_u->ctr->switch_value);

	DEBUG(5,("_srv_net_sess_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share enum all.
********************************************************************/

uint32 _srv_net_share_enum_all(pipes_struct *p, SRV_Q_NET_SHARE_ENUM *q_u, SRV_R_NET_SHARE_ENUM *r_u)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	init_srv_r_net_share_enum(p->mem_ctx, r_u,
				q_u->ctr.info_level,
				get_enum_hnd(&q_u->enum_hnd), True);

	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share enum.
********************************************************************/

uint32 _srv_net_share_enum(pipes_struct *p, SRV_Q_NET_SHARE_ENUM *q_u, SRV_R_NET_SHARE_ENUM *r_u)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	init_srv_r_net_share_enum(p->mem_ctx, r_u,
				q_u->ctr.info_level,
				get_enum_hnd(&q_u->enum_hnd), False);

	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share get info.
********************************************************************/

uint32 _srv_net_share_get_info(pipes_struct *p, SRV_Q_NET_SHARE_GET_INFO *q_u, SRV_R_NET_SHARE_GET_INFO *r_u)
{
	fstring share_name;

	DEBUG(5,("_srv_net_share_get_info: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	unistr2_to_ascii(share_name, &q_u->uni_share_name, sizeof(share_name));
	init_srv_r_net_share_get_info(p->mem_ctx, r_u, share_name, q_u->info_level);

	DEBUG(5,("_srv_net_share_get_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share set info.
********************************************************************/

uint32 _srv_net_share_set_info(pipes_struct *p, SRV_Q_NET_SHARE_SET_INFO *q_u, SRV_R_NET_SHARE_SET_INFO *r_u)
{
	fstring share_name;
	uint32 status = NT_STATUS_NOPROBLEMO;
	int snum;
	fstring servicename;
	fstring comment;
	pstring pathname;

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	unistr2_to_ascii(share_name, &q_u->uni_share_name, sizeof(share_name));

	r_u->switch_value = 0;

	snum = find_service(share_name);

	/* For now we only handle setting the security descriptor. JRA. */

	if (snum >= 0) {
		switch (q_u->info_level) {
		case 1:
			status = ERROR_ACCESS_DENIED;
			break;
		case 2:
			status = ERROR_ACCESS_DENIED;
			break;
		case 502:
			/* we set sd's here. FIXME. JRA */
			status = ERROR_ACCESS_DENIED;
			break;
		case 1005:
			status = ERROR_ACCESS_DENIED;
			break;
		default:
			DEBUG(5,("_srv_net_share_set_info: unsupported switch value %d\n", q_u->info_level));
			status = NT_STATUS_INVALID_INFO_CLASS;
			break;
		}
	} else {
		status = NT_STATUS_BAD_NETWORK_NAME;
	}

	r_u->status = status;

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share add. Call 'add_share_command "sharename" "pathname" "comment"'
********************************************************************/

uint32 _srv_net_share_add(pipes_struct *p, SRV_Q_NET_SHARE_ADD *q_u, SRV_R_NET_SHARE_ADD *r_u)
{
	struct current_user user;
	pstring command;
	uint32 status = NT_STATUS_NOPROBLEMO;
	fstring share_name;
	fstring comment;
	pstring pathname;
	char *ptr;
	int type;
	int snum;

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	r_u->switch_value = 0;

	get_current_user(&user,p);

	if (user.uid != 0)
		return ERROR_ACCESS_DENIED;

	if (!lp_add_share_cmd())
		return ERROR_ACCESS_DENIED;

	switch (q_u->info_level) {
	case 1:
		/* Not enough info in a level 1 to do anything. */
		status = ERROR_ACCESS_DENIED;
		break;
	case 2:
		unistr2_to_ascii(share_name, &q_u->info.share.info2.info_2_str.uni_netname, sizeof(share_name));
		unistr2_to_ascii(comment, &q_u->info.share.info2.info_2_str.uni_remark, sizeof(share_name));
		unistr2_to_ascii(pathname, &q_u->info.share.info2.info_2_str.uni_path, sizeof(share_name));
		break;
	case 502:
		/* we set sd's here. FIXME. JRA */
		unistr2_to_ascii(share_name, &q_u->info.share.info502.info_502_str.uni_netname, sizeof(share_name));
		unistr2_to_ascii(comment, &q_u->info.share.info502.info_502_str.uni_remark, sizeof(share_name));
		unistr2_to_ascii(pathname, &q_u->info.share.info502.info_502_str.uni_path, sizeof(share_name));
		break;
	case 1005:
		/* DFS only level. */
		status = ERROR_ACCESS_DENIED;
		break;
	default:
		DEBUG(5,("_srv_net_share_add: unsupported switch value %d\n", q_u->info_level));
		status = NT_STATUS_INVALID_INFO_CLASS;
		break;
	}

	snum = find_service(share_name);

	/* Share already exists. */
	if (snum >= 0)
		return NT_STATUS_BAD_NETWORK_NAME;

	/* Convert any '\' paths to '/' */
	unix_format(pathname);
	unix_clean_name(pathname);

	/* NT is braindead - it wants a C: prefix to a pathname ! */
	ptr = pathname;
	if (strlen(pathname) > 2 && ptr[1] == ':' && ptr[0] != '/')
		ptr += 2;

	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\" \"%s\"",
			lp_add_share_cmd(), share_name, ptr, comment );

/* HERE ! JRA */

	r_u->status = status;

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share delete. Call "delete share command" with the share name as
 a parameter.
********************************************************************/

uint32 _srv_net_share_del(pipes_struct *p, SRV_Q_NET_SHARE_DEL *q_u, SRV_R_NET_SHARE_DEL *r_u)
{
	struct current_user user;
	pstring command;
	fstring share_name;
	int ret;
	int snum;

	DEBUG(5,("_srv_net_share_del: %d\n", __LINE__));

	unistr2_to_ascii(share_name, &q_u->uni_share_name, sizeof(share_name));

	snum = find_service(share_name);

	if (snum < 0)
		return NT_STATUS_BAD_NETWORK_NAME;

	get_current_user(&user,p);

	if (user.uid != 0)
		return ERROR_ACCESS_DENIED;

	if (!lp_delete_share_cmd())
		return ERROR_ACCESS_DENIED;

	slprintf(command, sizeof(command)-1, "%s \"%s\"", lp_delete_share_cmd(), lp_servicename(snum));
	dos_to_unix(command, True);  /* Convert to unix-codepage */

	DEBUG(10,("_srv_net_share_del: Running [%s]\n", command ));
	if ((ret = smbrun(command, NULL, False)) != 0) {
		DEBUG(0,("_srv_net_share_del: Running [%s] returned (%d)\n", command, ret ));
		return ERROR_ACCESS_DENIED;
	}

	/* Send SIGHUP to process group. */
	kill(0, SIGHUP);

	lp_killservice(snum);

	return NT_STATUS_NOPROBLEMO;
}

/*******************************************************************
time of day
********************************************************************/

uint32 _srv_net_remote_tod(pipes_struct *p, SRV_Q_NET_REMOTE_TOD *q_u, SRV_R_NET_REMOTE_TOD *r_u)
{
	TIME_OF_DAY_INFO *tod;
	struct tm *t;
	time_t unixdate = time(NULL);

	tod = (TIME_OF_DAY_INFO *)talloc(p->mem_ctx, sizeof(TIME_OF_DAY_INFO));
	if (!tod)
		return NT_STATUS_NO_MEMORY;

	ZERO_STRUCTP(tod);
 
	r_u->tod = tod;
	r_u->ptr_srv_tod = 0x1;
	r_u->status = NT_STATUS_NOPROBLEMO;

	DEBUG(5,("_srv_net_remote_tod: %d\n", __LINE__));

	t = gmtime(&unixdate);

	/* set up the */
	init_time_of_day_info(tod,
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
	
	DEBUG(5,("_srv_net_remote_tod: %d\n", __LINE__));

	return r_u->status;
}
