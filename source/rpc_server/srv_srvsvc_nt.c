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

extern pstring global_myname;

/*******************************************************************
 Fill in a share info level 1 structure.
 ********************************************************************/

static void init_srv_share_info_1(pipes_struct *p, SRV_SHARE_INFO_1 *sh1, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	standard_sub_conn(p->conn, remark, sizeof(remark));
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;
		
	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name) || strequal("ADMIN$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	init_srv_share_info1(&sh1->info_1, net_name, type, remark);
	init_srv_share_info1_str(&sh1->info_1_str, net_name, remark);
}

/*******************************************************************
 Fill in a share info level 2 structure.
 ********************************************************************/

static void init_srv_share_info_2(pipes_struct *p, SRV_SHARE_INFO_2 *sh2, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	standard_sub_conn(p->conn, remark, sizeof(remark));
	pstrcpy(path, "C:");
	pstrcat(path, lp_pathname(snum));

	/*
	 * Change / to \\ so that win2k will see it as a valid path.  This was added to
	 * enable use of browsing in win2k add share dialog.
	 */ 

	string_replace(path, '/', '\\');

	pstrcpy(passwd, "");
	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;
		
	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name) || strequal("ADMIN$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	init_srv_share_info2(&sh2->info_2, net_name, type, remark, 0, 0xffffffff, 1, path, passwd);
	init_srv_share_info2_str(&sh2->info_2_str, net_name, remark, path, passwd);
}

/*******************************************************************
 What to do when smb.conf is updated.
 ********************************************************************/

static void smb_conf_updated(int msg_type, pid_t src, void *buf, size_t len)
{
	DEBUG(10,("smb_conf_updated: Got message saying smb.conf was updated. Reloading.\n"));
	reload_services(False);
}

/*******************************************************************
 Create the share security tdb.
 ********************************************************************/

static TDB_CONTEXT *share_tdb; /* used for share security descriptors */
#define SHARE_DATABASE_VERSION_V1 1
#define SHARE_DATABASE_VERSION_V2 2 /* version id in little endian. */

BOOL share_info_db_init(void)
{
	static pid_t local_pid;
	const char *vstring = "INFO/version";
	int32 vers_id;
 
	if (share_tdb && local_pid == sys_getpid())
		return True;
	share_tdb = tdb_open_log(lock_path("share_info.tdb"), 0, TDB_DEFAULT, O_RDWR|O_CREAT, 0600);
	if (!share_tdb) {
		DEBUG(0,("Failed to open share info database %s (%s)\n",
			lock_path("share_info.tdb"), strerror(errno) ));
		return False;
	}
 
	local_pid = sys_getpid();
 
	/* handle a Samba upgrade */
	tdb_lock_bystring(share_tdb, vstring,0);

	/* Cope with byte-reversed older versions of the db. */
	vers_id = tdb_fetch_int32(share_tdb, vstring);
	if ((vers_id == SHARE_DATABASE_VERSION_V1) || (IREV(vers_id) == SHARE_DATABASE_VERSION_V1)) {
		/* Written on a bigendian machine with old fetch_int code. Save as le. */
		tdb_store_int32(share_tdb, vstring, SHARE_DATABASE_VERSION_V2);
		vers_id = SHARE_DATABASE_VERSION_V2;
	}

	if (vers_id != SHARE_DATABASE_VERSION_V2) {
		tdb_traverse(share_tdb, tdb_traverse_delete_fn, NULL);
		tdb_store_int32(share_tdb, vstring, SHARE_DATABASE_VERSION_V2);
	}
	tdb_unlock_bystring(share_tdb, vstring);

	message_register(MSG_SMB_CONF_UPDATED, smb_conf_updated);
 
	return True;
}

/*******************************************************************
 Fake up a Everyone, full access as a default.
 ********************************************************************/

static SEC_DESC *get_share_security_default( TALLOC_CTX *ctx, int snum, size_t *psize)
{
	extern DOM_SID global_sid_World;
	extern struct generic_mapping file_generic_mapping;
	SEC_ACCESS sa;
	SEC_ACE ace;
	SEC_ACL *psa = NULL;
	SEC_DESC *psd = NULL;
	uint32 def_access = GENERIC_ALL_ACCESS;

	se_map_generic(&def_access, &file_generic_mapping);

	init_sec_access(&sa, GENERIC_ALL_ACCESS | def_access );
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
 Pull a security descriptor from the share tdb.
 ********************************************************************/

static SEC_DESC *get_share_security( TALLOC_CTX *ctx, int snum, size_t *psize)
{
	prs_struct ps;
	fstring key;
	SEC_DESC *psd = NULL;

	*psize = 0;

	/* Fetch security descriptor from tdb */
 
	slprintf(key, sizeof(key)-1, "SECDESC/%s", lp_servicename(snum));
 
	if (tdb_prs_fetch(share_tdb, key, &ps, ctx)!=0 ||
		!sec_io_desc("get_share_security", &psd, &ps, 1)) {
 
		DEBUG(4,("get_share_security: using default secdesc for %s\n", lp_servicename(snum) ));
 
		return get_share_security_default(ctx, snum, psize);
	}

	if (psd)
		*psize = sec_desc_size(psd);

	prs_mem_free(&ps);
	return psd;
}

/*******************************************************************
 Store a security descriptor in the share db.
 ********************************************************************/

static BOOL set_share_security(TALLOC_CTX *ctx, const char *share_name, SEC_DESC *psd)
{
	prs_struct ps;
	TALLOC_CTX *mem_ctx = NULL;
	fstring key;
	BOOL ret = False;

	mem_ctx = talloc_init();
	if (mem_ctx == NULL)
		return False;

	prs_init(&ps, (uint32)sec_desc_size(psd), mem_ctx, MARSHALL);
 
	if (!sec_io_desc("share_security", &psd, &ps, 1))
		goto out;
 
	slprintf(key, sizeof(key)-1, "SECDESC/%s", share_name);
 
	if (tdb_prs_store(share_tdb, key, &ps)==0) {
		ret = True;
		DEBUG(5,("set_share_security: stored secdesc for %s\n", share_name ));
	} else {
		DEBUG(1,("set_share_security: Failed to store secdesc for %s\n", share_name ));
	} 

	/* Free malloc'ed memory */
 
 out:
 
	prs_mem_free(&ps);
	if (mem_ctx)
		talloc_destroy(mem_ctx);
	return ret;
}

/*******************************************************************
 Delete a security descriptor.
********************************************************************/

static BOOL delete_share_security(int snum)
{
	TDB_DATA kbuf;
	fstring key;

	slprintf(key, sizeof(key)-1, "SECDESC/%s", lp_servicename(snum));
	kbuf.dptr = key;
	kbuf.dsize = strlen(key)+1;

	if (tdb_delete(share_tdb, kbuf) != 0) {
		DEBUG(0,("delete_share_security: Failed to delete entry for share %s\n",
				lp_servicename(snum) ));
		return False;
	}

	return True;
}

/*******************************************************************
 Map any generic bits to file specific bits.
********************************************************************/

void map_generic_share_sd_bits(SEC_DESC *psd)
{
	extern struct generic_mapping file_generic_mapping;
	int i;
	SEC_ACL *ps_dacl = NULL;

	if (!psd)
		return;

	ps_dacl = psd->dacl;
	if (!ps_dacl)
		return;

	for (i = 0; i < ps_dacl->num_aces; i++) {
		SEC_ACE *psa = &ps_dacl->ace[i];
		uint32 orig_mask = psa->info.mask;

		se_map_generic(&psa->info.mask, &file_generic_mapping);
		psa->info.mask |= orig_mask;
	}	
}

/*******************************************************************
 Can this user access with share with the required permissions ?
********************************************************************/

BOOL share_access_check(connection_struct *conn, int snum, uint16 vuid, uint32 desired_access)
{
	uint32 granted;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = NULL;
	SEC_DESC *psd = NULL;
	size_t sd_size;
	NT_USER_TOKEN *token = NULL;
	user_struct *vuser = get_valid_user_struct(vuid);
	BOOL ret = True;

	mem_ctx = talloc_init();
	if (mem_ctx == NULL)
		return False;

	psd = get_share_security(mem_ctx, snum, &sd_size);

	if (!psd)
		goto out;

	if (vuser)
		token = vuser->nt_user_token;
	else
		token = conn->nt_user_token;

	ret = se_access_check(psd, token, desired_access, &granted, &status);

  out:

	talloc_destroy(mem_ctx);

	return ret;
}

/*******************************************************************
 Fill in a share info level 501 structure.
********************************************************************/

static void init_srv_share_info_501(pipes_struct *p, SRV_SHARE_INFO_501 *sh501, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	uint32 type;

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	standard_sub_conn(p->conn, remark,sizeof(remark));

	len_net_name = strlen(net_name);

	/* work out the share type */
	type = STYPE_DISKTREE;

	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal("IPC$", net_name) || strequal("ADMIN$", net_name))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;
	
	init_srv_share_info501(&sh501->info_501, net_name, type, remark, (lp_csc_policy(snum) << 4));
	init_srv_share_info501_str(&sh501->info_501_str, net_name, remark);
}

/*******************************************************************
 Fill in a share info level 502 structure.
 ********************************************************************/

static void init_srv_share_info_502(pipes_struct *p, SRV_SHARE_INFO_502 *sh502, int snum)
{
	int len_net_name;
	pstring net_name;
	pstring remark;
	pstring path;
	pstring passwd;
	uint32 type;
	SEC_DESC *sd;
	size_t sd_size;
	TALLOC_CTX *ctx = p->mem_ctx;


	ZERO_STRUCTP(sh502);

	pstrcpy(net_name, lp_servicename(snum));
	pstrcpy(remark, lp_comment(snum));
	standard_sub_conn(p->conn, remark,sizeof(remark));
	pstrcpy(path, "C:");
	pstrcat(path, lp_pathname(snum));

	/*
	 * Change / to \\ so that win2k will see it as a valid path.  This was added to
	 * enable use of browsing in win2k add share dialog.
	 */ 

	string_replace(path, '/', '\\');

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
	init_srv_share_info502_str(&sh502->info_502_str, &sh502->info_502, net_name, remark, path, passwd, sd, sd_size);
}

/***************************************************************************
 Fill in a share info level 1005 structure.
 ***************************************************************************/

static void init_srv_share_info_1005(SRV_SHARE_INFO_1005* sh1005, int snum)
{
	sh1005->misc_flags = 0;

#ifdef WITH_MSDFS
	if(lp_host_msdfs() && lp_msdfs_root(snum))
		sh1005->misc_flags = 3;
#endif
	
	sh1005->misc_flags |= (lp_csc_policy(snum) << 4);

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

static BOOL init_srv_share_info_ctr(pipes_struct *p, SRV_SHARE_INFO_CTR *ctr,
	       uint32 info_level, uint32 *resume_hnd, uint32 *total_entries, BOOL all_shares)
{
	int num_entries = 0;
	int num_services = lp_numservices();
	int snum;
	TALLOC_CTX *ctx = p->mem_ctx;

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
				init_srv_share_info_1(p, &info1[i++], snum);
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
				init_srv_share_info_2(p, &info2[i++], snum);
			}
		}

		ctr->share.info2 = info2;
		break;
	}

	case 501:
	{
		SRV_SHARE_INFO_501 *info501;
		int i = 0;
	
		info501 = talloc(ctx, num_entries * sizeof(SRV_SHARE_INFO_501));

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) ) {
				init_srv_share_info_501(p, &info501[i++], snum);
			}
		}
	
		ctr->share.info501 = info501;
		break;
	}

	case 502:
	{
		SRV_SHARE_INFO_502 *info502;
		int i = 0;

		info502 = talloc(ctx, num_entries * sizeof(SRV_SHARE_INFO_502));

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_admin_share(snum)) ) {
				init_srv_share_info_502(p, &info502[i++], snum);
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

static void init_srv_r_net_share_enum(pipes_struct *p, SRV_R_NET_SHARE_ENUM *r_n,
				      uint32 info_level, uint32 resume_hnd, BOOL all)  
{
	DEBUG(5,("init_srv_r_net_share_enum: %d\n", __LINE__));

	if (init_srv_share_info_ctr(p, &r_n->ctr, info_level,
				    &resume_hnd, &r_n->total_entries, all)) {
		r_n->status = WERR_OK;
	} else {
		r_n->status = WERR_UNKNOWN_LEVEL;
	}

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 Inits a SRV_R_NET_SHARE_GET_INFO structure.
********************************************************************/

static void init_srv_r_net_share_get_info(pipes_struct *p, SRV_R_NET_SHARE_GET_INFO *r_n,
				  char *share_name, uint32 info_level)
{
	WERROR status = WERR_OK;
	int snum;

	DEBUG(5,("init_srv_r_net_share_get_info: %d\n", __LINE__));

	r_n->info.switch_value = info_level;

	snum = find_service(share_name);

	if (snum >= 0) {
		switch (info_level) {
		case 1:
			init_srv_share_info_1(p, &r_n->info.share.info1, snum);
			break;
		case 2:
			init_srv_share_info_2(p, &r_n->info.share.info2, snum);
			break;
		case 501:
			init_srv_share_info_501(p, &r_n->info.share.info501, snum);
			break;
		case 502:
			init_srv_share_info_502(p, &r_n->info.share.info502, snum);
			break;
		case 1005:
			init_srv_share_info_1005(&r_n->info.share.info1005, snum);
			break;
		default:
			DEBUG(5,("init_srv_net_share_get_info: unsupported switch value %d\n", info_level));
			status = WERR_UNKNOWN_LEVEL;
			break;
		}
	} else {
		status = WERR_INVALID_NAME;
	}

	r_n->info.ptr_share_ctr = W_ERROR_IS_OK(status) ? 1 : 0;
	r_n->status = status;
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_0_info(SESS_INFO_0 *se0, SESS_INFO_0_STR *str0, const char *name)
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
				const char *name, const char *user,
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

static WERROR init_srv_sess_info_ctr(SRV_SESS_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	WERROR status = WERR_OK;
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
		status = WERR_UNKNOWN_LEVEL;
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
		r_n->status = WERR_UNKNOWN_LEVEL;
	else
		r_n->status = init_srv_sess_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

	if (!W_ERROR_IS_OK(r_n->status))
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
				const char *usr_name, const char *net_name)
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

static WERROR init_srv_conn_info_ctr(SRV_CONN_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	WERROR status = WERR_OK;
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
		status = WERR_UNKNOWN_LEVEL;
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
		r_n->status = WERR_UNKNOWN_LEVEL;
	else
		r_n->status = init_srv_conn_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

	if (!W_ERROR_IS_OK(r_n->status))
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
 fill in a file info level 3 structure.
 ********************************************************************/

static void init_srv_file_3_info(FILE_INFO_3 *fl3, FILE_INFO_3_STR *str3,
				uint32 fnum, uint32 perms, uint32 num_locks,
				const char *path_name, const char *user_name)
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

static WERROR init_srv_file_info_ctr(SRV_FILE_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)  
{
	WERROR status = WERR_OK;
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
		status = WERR_UNKNOWN_LEVEL;
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
		r_n->status = WERR_UNKNOWN_LEVEL;
	else
		r_n->status = init_srv_file_info_ctr(r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

	if (!W_ERROR_IS_OK(r_n->status))
		resume_hnd = 0;

	init_enum_hnd(&r_n->enum_hnd, resume_hnd);
}

/*******************************************************************
net server get info
********************************************************************/

WERROR _srv_net_srv_get_info(pipes_struct *p, SRV_Q_NET_SRV_GET_INFO *q_u, SRV_R_NET_SRV_GET_INFO *r_u)
{
	WERROR status = WERR_OK;
	SRV_INFO_CTR *ctr = (SRV_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_INFO_CTR));

	if (!ctr)
		return WERR_NOMEM;

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
		status = WERR_UNKNOWN_LEVEL;
		break;
	}

	/* set up the net server get info structure */
	init_srv_r_net_srv_get_info(r_u, q_u->switch_value, ctr, status);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net server set info
********************************************************************/

WERROR _srv_net_srv_set_info(pipes_struct *p, SRV_Q_NET_SRV_SET_INFO *q_u, SRV_R_NET_SRV_SET_INFO *r_u)
{
	WERROR status = WERR_OK;

	DEBUG(5,("srv_net_srv_set_info: %d\n", __LINE__));

	/* Set up the net server set info structure. */

	init_srv_r_net_srv_set_info(r_u, 0x0, status);

	DEBUG(5,("srv_net_srv_set_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net file enum
********************************************************************/

WERROR _srv_net_file_enum(pipes_struct *p, SRV_Q_NET_FILE_ENUM *q_u, SRV_R_NET_FILE_ENUM *r_u)
{
	r_u->ctr = (SRV_FILE_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_FILE_INFO_CTR));
	if (!r_u->ctr)
		return WERR_NOMEM;

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

WERROR _srv_net_conn_enum(pipes_struct *p, SRV_Q_NET_CONN_ENUM *q_u, SRV_R_NET_CONN_ENUM *r_u)
{
	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	r_u->ctr = (SRV_CONN_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_CONN_INFO_CTR));
	if (!r_u->ctr)
		return WERR_NOMEM;

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

WERROR _srv_net_sess_enum(pipes_struct *p, SRV_Q_NET_SESS_ENUM *q_u, SRV_R_NET_SESS_ENUM *r_u)
{
	DEBUG(5,("_srv_net_sess_enum: %d\n", __LINE__));

	r_u->ctr = (SRV_SESS_INFO_CTR *)talloc(p->mem_ctx, sizeof(SRV_SESS_INFO_CTR));
	if (!r_u->ctr)
		return WERR_NOMEM;

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

WERROR _srv_net_share_enum_all(pipes_struct *p, SRV_Q_NET_SHARE_ENUM *q_u, SRV_R_NET_SHARE_ENUM *r_u)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	init_srv_r_net_share_enum(p, r_u,
				q_u->ctr.info_level,
				get_enum_hnd(&q_u->enum_hnd), True);

	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share enum.
********************************************************************/

WERROR _srv_net_share_enum(pipes_struct *p, SRV_Q_NET_SHARE_ENUM *q_u, SRV_R_NET_SHARE_ENUM *r_u)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	init_srv_r_net_share_enum(p, r_u,
				q_u->ctr.info_level,
				get_enum_hnd(&q_u->enum_hnd), False);

	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Net share get info.
********************************************************************/

WERROR _srv_net_share_get_info(pipes_struct *p, SRV_Q_NET_SHARE_GET_INFO *q_u, SRV_R_NET_SHARE_GET_INFO *r_u)
{
	fstring share_name;

	DEBUG(5,("_srv_net_share_get_info: %d\n", __LINE__));

	/* Create the list of shares for the response. */
	unistr2_to_dos(share_name, &q_u->uni_share_name, sizeof(share_name));
	init_srv_r_net_share_get_info(p, r_u, share_name, q_u->info_level);

	DEBUG(5,("_srv_net_share_get_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Check a given DOS pathname is valid for a share.
********************************************************************/

static char *valid_share_pathname(char *dos_pathname)
{
	pstring saved_pathname;
	pstring unix_pathname;
	char *ptr;
	int ret;

	/* Convert any '\' paths to '/' */
	unix_format(dos_pathname);
	unix_clean_name(dos_pathname);

	/* NT is braindead - it wants a C: prefix to a pathname ! So strip it. */
	ptr = dos_pathname;
	if (strlen(dos_pathname) > 2 && ptr[1] == ':' && ptr[0] != '/')
		ptr += 2;

	/* Only abolute paths allowed. */
	if (*ptr != '/')
		return NULL;

	/* Can we cd to it ? */

	/* First save our current directory. */
	if (getcwd(saved_pathname, sizeof(saved_pathname)) == NULL)
		return False;

	pstrcpy(unix_pathname, ptr);
	
	ret = chdir(unix_pathname);

	/* We *MUST* be able to chdir back. Abort if we can't. */
	if (chdir(saved_pathname) == -1)
		smb_panic("valid_share_pathname: Unable to restore current directory.\n");

	return (ret != -1) ? ptr : NULL;
}

/*******************************************************************
 Net share set info. Modify share details.
********************************************************************/

WERROR _srv_net_share_set_info(pipes_struct *p, SRV_Q_NET_SHARE_SET_INFO *q_u, SRV_R_NET_SHARE_SET_INFO *r_u)
{
	struct current_user user;
	pstring command;
	fstring share_name;
	fstring comment;
	pstring pathname;
	int type;
	int snum;
	int ret;
	char *ptr;
	SEC_DESC *psd = NULL;

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	unistr2_to_dos(share_name, &q_u->uni_share_name, sizeof(share_name));

	r_u->switch_value = 0;

	if (strequal(share_name,"IPC$") || strequal(share_name,"ADMIN$") || strequal(share_name,"global"))
		return WERR_ACCESS_DENIED;

	snum = find_service(share_name);

	/* Does this share exist ? */
	if (snum < 0)
		return WERR_INVALID_NAME;

	/* No change to printer shares. */
	if (lp_print_ok(snum))
		return WERR_ACCESS_DENIED;

	get_current_user(&user,p);

	if (user.uid != 0)
		return WERR_ACCESS_DENIED;

	switch (q_u->info_level) {
	case 1:
		/* Not enough info in a level 1 to do anything. */
		return WERR_ACCESS_DENIED;
	case 2:
		unistr2_to_dos(comment, &q_u->info.share.info2.info_2_str.uni_remark, sizeof(share_name));
		unistr2_to_dos(pathname, &q_u->info.share.info2.info_2_str.uni_path, sizeof(share_name));
		type = q_u->info.share.info2.info_2.type;
		psd = NULL;
		break;
	case 502:
		unistr2_to_dos(comment, &q_u->info.share.info502.info_502_str.uni_remark, sizeof(share_name));
		unistr2_to_dos(pathname, &q_u->info.share.info502.info_502_str.uni_path, sizeof(share_name));
		type = q_u->info.share.info502.info_502.type;
		psd = q_u->info.share.info502.info_502_str.sd;
		map_generic_share_sd_bits(psd);
		break;
	case 1005:
		return WERR_ACCESS_DENIED;
	case 1501:
		fstrcpy(pathname, lp_pathname(snum));
		fstrcpy(comment, lp_comment(snum));
		psd = q_u->info.share.info1501.sdb->sec;
		map_generic_share_sd_bits(psd);
		type = STYPE_DISKTREE;
		break;
	default:
		DEBUG(5,("_srv_net_share_set_info: unsupported switch value %d\n", q_u->info_level));
		return WERR_UNKNOWN_LEVEL;
	}

	/* We can only modify disk shares. */
	if (type != STYPE_DISKTREE)
		return WERR_ACCESS_DENIED;
		
	/* Check if the pathname is valid. */
	if (!(ptr = valid_share_pathname( pathname )))
		return WERR_OBJECT_PATH_INVALID;

	/* Ensure share name, pathname and comment don't contain '"' characters. */
	string_replace(share_name, '"', ' ');
	string_replace(ptr, '"', ' ');
	string_replace(comment, '"', ' ');

	DEBUG(10,("_srv_net_share_set_info: change share command = %s\n",
		lp_change_share_cmd() ? lp_change_share_cmd() : "NULL" ));

	/* Only call modify function if something changed. */

	if (strcmp(ptr, lp_pathname(snum)) || strcmp(comment, lp_comment(snum)) ) {
		if (!lp_change_share_cmd() || !*lp_change_share_cmd())
			return WERR_ACCESS_DENIED;

		slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\" \"%s\" \"%s\"",
				lp_change_share_cmd(), CONFIGFILE, share_name, ptr, comment);

		DEBUG(10,("_srv_net_share_set_info: Running [%s]\n", command ));
		if ((ret = smbrun(command, NULL)) != 0) {
			DEBUG(0,("_srv_net_share_set_info: Running [%s] returned (%d)\n", command, ret ));
			return WERR_ACCESS_DENIED;
		}

		/* Tell everyone we updated smb.conf. */
		message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED, NULL, 0, False, NULL);

	} else {
		DEBUG(10,("_srv_net_share_set_info: No change to share name (%s)\n", share_name ));
	}

	/* Replace SD if changed. */
	if (psd) {
		SEC_DESC *old_sd;
		size_t sd_size;

		old_sd = get_share_security(p->mem_ctx, snum, &sd_size);

		if (old_sd && !sec_desc_equal(old_sd, psd)) {
			if (!set_share_security(p->mem_ctx, share_name, psd))
				DEBUG(0,("_srv_net_share_set_info: Failed to change security info in share %s.\n",
					share_name ));
		}
	}

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	return WERR_OK;
}

/*******************************************************************
 Net share add. Call 'add_share_command "sharename" "pathname" "comment" "read only = xxx"'
********************************************************************/

WERROR _srv_net_share_add(pipes_struct *p, SRV_Q_NET_SHARE_ADD *q_u, SRV_R_NET_SHARE_ADD *r_u)
{
	struct current_user user;
	pstring command;
	fstring share_name;
	fstring comment;
	pstring pathname;
	int type;
	int snum;
	int ret;
	char *ptr;
	SEC_DESC *psd = NULL;

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	r_u->switch_value = 0;

	get_current_user(&user,p);

	if (user.uid != 0) {
		DEBUG(10,("_srv_net_share_add: uid != 0. Access denied.\n"));
		return WERR_ACCESS_DENIED;
	}

	if (!lp_add_share_cmd() || !*lp_add_share_cmd()) {
		DEBUG(10,("_srv_net_share_add: No add share command\n"));
		return WERR_ACCESS_DENIED;
	}

	switch (q_u->info_level) {
	case 1:
		/* Not enough info in a level 1 to do anything. */
		return WERR_ACCESS_DENIED;
	case 2:
		unistr2_to_dos(share_name, &q_u->info.share.info2.info_2_str.uni_netname, sizeof(share_name));
		unistr2_to_dos(comment, &q_u->info.share.info2.info_2_str.uni_remark, sizeof(share_name));
		unistr2_to_dos(pathname, &q_u->info.share.info2.info_2_str.uni_path, sizeof(share_name));
		type = q_u->info.share.info2.info_2.type;
		break;
	case 502:
		unistr2_to_dos(share_name, &q_u->info.share.info502.info_502_str.uni_netname, sizeof(share_name));
		unistr2_to_dos(comment, &q_u->info.share.info502.info_502_str.uni_remark, sizeof(share_name));
		unistr2_to_dos(pathname, &q_u->info.share.info502.info_502_str.uni_path, sizeof(share_name));
		type = q_u->info.share.info502.info_502.type;
		psd = q_u->info.share.info502.info_502_str.sd;
		map_generic_share_sd_bits(psd);
		break;
	case 1005:
		/* DFS only level. */
		return WERR_ACCESS_DENIED;
	default:
		DEBUG(5,("_srv_net_share_add: unsupported switch value %d\n", q_u->info_level));
		return WERR_UNKNOWN_LEVEL;
	}

	if (strequal(share_name,"IPC$") || strequal(share_name,"ADMIN$") || strequal(share_name,"global"))
		return WERR_ACCESS_DENIED;

	snum = find_service(share_name);

	/* Share already exists. */
	if (snum >= 0)
		return WERR_ALREADY_EXISTS;

	/* We can only add disk shares. */
	if (type != STYPE_DISKTREE)
		return WERR_ACCESS_DENIED;
		
	/* Check if the pathname is valid. */
	if (!(ptr = valid_share_pathname( pathname )))
		return WERR_OBJECT_PATH_INVALID;

	/* Ensure share name, pathname and comment don't contain '"' characters. */
	string_replace(share_name, '"', ' ');
	string_replace(ptr, '"', ' ');
	string_replace(comment, '"', ' ');

	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\" \"%s\" \"%s\"",
			lp_add_share_cmd(), CONFIGFILE, share_name, ptr, comment);

	DEBUG(10,("_srv_net_share_add: Running [%s]\n", command ));
	if ((ret = smbrun(command, NULL)) != 0) {
		DEBUG(0,("_srv_net_share_add: Running [%s] returned (%d)\n", command, ret ));
		return WERR_ACCESS_DENIED;
	}

	if (psd) {
		if (!set_share_security(p->mem_ctx, share_name, psd))
			DEBUG(0,("_srv_net_share_add: Failed to add security info to share %s.\n",
				share_name ));
	}

	/* Tell everyone we updated smb.conf. */
	message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED, NULL, 0, False, NULL);

	/*
	 * We don't call reload_services() here, the message will
	 * cause this to be done before the next packet is read
	 * from the client. JRA.
	 */

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	return WERR_OK;
}

/*******************************************************************
 Net share delete. Call "delete share command" with the share name as
 a parameter.
********************************************************************/

WERROR _srv_net_share_del(pipes_struct *p, SRV_Q_NET_SHARE_DEL *q_u, SRV_R_NET_SHARE_DEL *r_u)
{
	struct current_user user;
	pstring command;
	fstring share_name;
	int ret;
	int snum;

	DEBUG(5,("_srv_net_share_del: %d\n", __LINE__));

	unistr2_to_dos(share_name, &q_u->uni_share_name, sizeof(share_name));

	if (strequal(share_name,"IPC$") || strequal(share_name,"ADMIN$") || strequal(share_name,"global"))
		return WERR_ACCESS_DENIED;

	snum = find_service(share_name);

	if (snum < 0)
		return WERR_NO_SUCH_SHARE;

	/* No change to printer shares. */
	if (lp_print_ok(snum))
		return WERR_ACCESS_DENIED;

	get_current_user(&user,p);

	if (user.uid != 0)
		return WERR_ACCESS_DENIED;

	if (!lp_delete_share_cmd() || !*lp_delete_share_cmd())
		return WERR_ACCESS_DENIED;

	slprintf(command, sizeof(command)-1, "%s \"%s\" \"%s\"",
			lp_delete_share_cmd(), CONFIGFILE, lp_servicename(snum));

	DEBUG(10,("_srv_net_share_del: Running [%s]\n", command ));
	if ((ret = smbrun(command, NULL)) != 0) {
		DEBUG(0,("_srv_net_share_del: Running [%s] returned (%d)\n", command, ret ));
		return WERR_ACCESS_DENIED;
	}

	/* Delete the SD in the database. */
	delete_share_security(snum);

	/* Tell everyone we updated smb.conf. */
	message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED, NULL, 0, False, NULL);

	lp_killservice(snum);

	return WERR_OK;
}

/*******************************************************************
time of day
********************************************************************/

WERROR _srv_net_remote_tod(pipes_struct *p, SRV_Q_NET_REMOTE_TOD *q_u, SRV_R_NET_REMOTE_TOD *r_u)
{
	TIME_OF_DAY_INFO *tod;
	struct tm *t;
	time_t unixdate = time(NULL);

	tod = (TIME_OF_DAY_INFO *)talloc(p->mem_ctx, sizeof(TIME_OF_DAY_INFO));
	if (!tod)
		return WERR_NOMEM;

	ZERO_STRUCTP(tod);
 
	r_u->tod = tod;
	r_u->ptr_srv_tod = 0x1;
	r_u->status = WERR_OK;

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

/***********************************************************************************
 Win9x NT tools get security descriptor.
***********************************************************************************/

WERROR _srv_net_file_query_secdesc(pipes_struct *p, SRV_Q_NET_FILE_QUERY_SECDESC *q_u,
			SRV_R_NET_FILE_QUERY_SECDESC *r_u)
{
	SEC_DESC *psd = NULL;
	size_t sd_size;
	fstring null_pw;
	fstring dev;
	pstring filename;
	pstring qualname;
	files_struct *fsp = NULL;
	SMB_STRUCT_STAT st;
	BOOL bad_path;
	int access_mode;
	int action;
	int ecode;
	struct current_user user;
	fstring user_name;
	connection_struct *conn = NULL;
	BOOL became_user = False; 

	ZERO_STRUCT(st);

	r_u->status = WERR_OK;

	unistr2_to_dos(qualname, &q_u->uni_qual_name, sizeof(qualname));

	/* Null password is ok - we are already an authenticated user... */
	*null_pw = '\0';
	fstrcpy(dev, "A:");

	get_current_user(&user, p);
	fstrcpy(user_name, uidtoname(user.uid));

	become_root();
	conn = make_connection(qualname, user_name, null_pw, 0, dev, user.vuid, &ecode);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to connect to %s\n", qualname));
		r_u->status = W_ERROR(ecode);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_query_secdesc: Can't become connected user!\n"));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
    became_user = True;

	unistr2_to_dos(filename, &q_u->uni_file_name, sizeof(filename));
	unix_convert(filename, conn, NULL, &bad_path, &st);
	fsp = open_file_shared(conn, filename, &st, SET_OPEN_MODE(DOS_OPEN_RDONLY),
				(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, 0, &access_mode, &action);

	if (!fsp) {
		/* Perhaps it is a directory */
		if (errno == EISDIR)
			fsp = open_directory(conn, filename, &st,FILE_READ_ATTRIBUTES,0,
					(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, &action);

		if (!fsp) {
			DEBUG(3,("_srv_net_file_query_secdesc: Unable to open file %s\n", filename));
			r_u->status = WERR_ACCESS_DENIED;
			goto error_exit;
		}
	}

	sd_size = conn->vfs_ops.get_nt_acl(fsp, fsp->fsp_name, &psd);

	if (sd_size == 0) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to get NT ACL for file %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	r_u->ptr_response = 1;
	r_u->size_response = sd_size;
	r_u->ptr_secdesc = 1;
	r_u->size_secdesc = sd_size;
	r_u->sec_desc = psd;

	psd->dacl->revision = (uint16) NT4_ACL_REVISION;

	close_file(fsp, True);
	unbecome_user();
	close_cnum(conn, user.vuid);
	return r_u->status;

  error_exit:

	if(fsp) {
		close_file(fsp, True);
	}

	if (became_user)
		unbecome_user();

	if (conn) 
		close_cnum(conn, user.vuid);

	return r_u->status;
}

/***********************************************************************************
 Win9x NT tools set security descriptor.
***********************************************************************************/

WERROR _srv_net_file_set_secdesc(pipes_struct *p, SRV_Q_NET_FILE_SET_SECDESC *q_u,
									SRV_R_NET_FILE_SET_SECDESC *r_u)
{
	BOOL ret;
	pstring filename;
	pstring qualname;
	fstring null_pw;
	fstring dev;
	files_struct *fsp = NULL;
	SMB_STRUCT_STAT st;
	BOOL bad_path;
	int access_mode;
	int action;
	int ecode;
	struct current_user user;
	fstring user_name;
	connection_struct *conn = NULL;
	BOOL became_user = False;

	ZERO_STRUCT(st);

	r_u->status = WERR_OK;

	unistr2_to_dos(qualname, &q_u->uni_qual_name, sizeof(qualname));

	/* Null password is ok - we are already an authenticated user... */
	*null_pw = '\0';
	fstrcpy(dev, "A:");

	get_current_user(&user, p);
	fstrcpy(user_name, uidtoname(user.uid));

	become_root();
	conn = make_connection(qualname, user_name, null_pw, 0, dev, user.vuid, &ecode);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to connect to %s\n", qualname));
		r_u->status = W_ERROR(ecode);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_set_secdesc: Can't become connected user!\n"));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
	became_user = True;

	unistr2_to_dos(filename, &q_u->uni_file_name, sizeof(filename));
	unix_convert(filename, conn, NULL, &bad_path, &st);

	fsp = open_file_shared(conn, filename, &st, SET_OPEN_MODE(DOS_OPEN_RDWR),
			(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, 0, &access_mode, &action);

	if (!fsp) {
		/* Perhaps it is a directory */
		if (errno == EISDIR)
			fsp = open_directory(conn, filename, &st,FILE_READ_ATTRIBUTES,0,
						(FILE_FAIL_IF_NOT_EXIST|FILE_EXISTS_OPEN), 0, &action);

		if (!fsp) {
			DEBUG(3,("_srv_net_file_set_secdesc: Unable to open file %s\n", filename));
			r_u->status = WERR_ACCESS_DENIED;
			goto error_exit;
		}
	}

	ret = conn->vfs_ops.set_nt_acl(fsp, fsp->fsp_name, q_u->sec_info, q_u->sec_desc);

	if (ret == False) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to set NT ACL on file %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	close_file(fsp, True);
	unbecome_user();
	close_cnum(conn, user.vuid);
	return r_u->status;

  error_exit:

	if(fsp) {
		close_file(fsp, True);
	}

	if (became_user)
		unbecome_user();

	if (conn) 
		close_cnum(conn, user.vuid);

	return r_u->status;
}

/***********************************************************************************
 It may be that we want to limit users to creating shares on certain areas of the UNIX file area.
 We could define areas by mapping Windows style disks to points on the UNIX directory hierarchy.
 These disks would the disks listed by this function.
 Users could then create shares relative to these disks.  Watch out for moving these disks around.
 "Nigel Williams" <nigel@veritas.com>.
***********************************************************************************/

const char *server_disks[] = {"C:"};

static uint32 get_server_disk_count(void)
{
	return sizeof(server_disks)/sizeof(server_disks[0]);
}

static uint32 init_server_disk_enum(uint32 *resume)
{
	uint32 server_disk_count = get_server_disk_count();

	/*resume can be an offset into the list for now*/

	if(*resume & 0x80000000)
		*resume = 0;

	if(*resume > server_disk_count)
		*resume = server_disk_count;

	return server_disk_count - *resume;
}

static const char *next_server_disk_enum(uint32 *resume)
{
	const char *disk;

	if(init_server_disk_enum(resume) == 0)
		return NULL;

	disk = server_disks[*resume];

	(*resume)++;

	DEBUG(10, ("next_server_disk_enum: reporting disk %s. resume handle %d.\n", disk, *resume));

	return disk;
}

WERROR _srv_net_disk_enum(pipes_struct *p, SRV_Q_NET_DISK_ENUM *q_u, SRV_R_NET_DISK_ENUM *r_u)
{
	uint32 i;
	const char *disk_name;
	uint32 resume=get_enum_hnd(&q_u->enum_hnd);

	r_u->status=WERR_OK;

	r_u->total_entries = init_server_disk_enum(&resume);

	r_u->disk_enum_ctr.unknown = 0; 

	r_u->disk_enum_ctr.disk_info_ptr = r_u->disk_enum_ctr.disk_info ? 1 : 0;

	/*allow one DISK_INFO for null terminator*/

	for(i = 0; i < MAX_SERVER_DISK_ENTRIES -1 && (disk_name = next_server_disk_enum(&resume)); i++) {

		r_u->disk_enum_ctr.entries_read++;

		/*copy disk name into a unicode string*/

		init_unistr3(&r_u->disk_enum_ctr.disk_info[i].disk_name, disk_name);    
	}

	/*add a terminating null string.  Is this there if there is more data to come?*/

	r_u->disk_enum_ctr.entries_read++;

	init_unistr3(&r_u->disk_enum_ctr.disk_info[i].disk_name, "");

	init_enum_hnd(&r_u->enum_hnd, resume);

	return r_u->status;
}

WERROR _srv_net_name_validate(pipes_struct *p, SRV_Q_NET_NAME_VALIDATE *q_u, SRV_R_NET_NAME_VALIDATE *r_u)
{
	int snum;
	fstring share_name;

	r_u->status=WERR_OK;

	switch(q_u->type) {

	case 0x9:

		/*check if share name is ok*/
		/*also check if we already have a share with this name*/

		unistr2_to_dos(share_name, &q_u->uni_name, sizeof(share_name));
		snum = find_service(share_name);

		/* Share already exists. */
		if (snum >= 0)
			r_u->status = WERR_ALREADY_EXISTS;
		break;

	default:
		/*unsupported type*/
		r_u->status = WERR_UNKNOWN_LEVEL;
		break;
	}

	return r_u->status;
}
