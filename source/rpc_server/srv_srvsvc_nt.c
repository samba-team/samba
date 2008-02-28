/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Jeremy Allison               2001.
 *  Copyright (C) Nigel Williams               2001.
 *  Copyright (C) Gerald (Jerry) Carter        2006.
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* This is the implementation of the srvsvc pipe. */

#include "includes.h"

extern const struct generic_mapping file_generic_mapping;

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Use for enumerating connections, pipes, & files */

struct file_enum_count {
	TALLOC_CTX *ctx;
	const char *username;
	int count;
	FILE_INFO_3 *info;
};

struct sess_file_count {
	struct server_id pid;
	uid_t uid;
	int count;
};

/****************************************************************************
 Count the entries belonging to a service in the connection db.
****************************************************************************/

static int pipe_enum_fn( struct db_record *rec, void *p)
{
	struct pipe_open_rec prec;
	struct file_enum_count *fenum = (struct file_enum_count *)p;
	FILE_INFO_3 *f;
	int i = fenum->count;
	char *fullpath = NULL;
	const char *username;

	if (rec->value.dsize != sizeof(struct pipe_open_rec))
		return 0;

	memcpy(&prec, rec->value.dptr, sizeof(struct pipe_open_rec));

	if ( !process_exists(prec.pid) ) {
		return 0;
	}

	username = uidtoname(prec.uid);

	if ((fenum->username != NULL)
	    && !strequal(username, fenum->username)) {
		return 0;
	}

	fullpath = talloc_asprintf(fenum->ctx, "\\PIPE\\%s", prec.name );
	if (!fullpath) {
		return 1;
	}

	f = TALLOC_REALLOC_ARRAY( fenum->ctx, fenum->info, FILE_INFO_3, i+1 );
	if ( !f ) {
		DEBUG(0,("conn_enum_fn: realloc failed for %d items\n", i+1));
		return 1;
	}
	fenum->info = f;

	init_srv_file_info3(
		&fenum->info[i],
		(uint32)((procid_to_pid(&prec.pid)<<16) & prec.pnum),
		(FILE_READ_DATA|FILE_WRITE_DATA),
		0, username, fullpath);

	TALLOC_FREE(fullpath);
	fenum->count++;

	return 0;
}

/*******************************************************************
********************************************************************/

static WERROR net_enum_pipes( TALLOC_CTX *ctx, const char *username,
			      FILE_INFO_3 **info, 
                              uint32 *count, uint32 resume )
{
	struct file_enum_count fenum;
	
	fenum.ctx = ctx;
	fenum.username = username;
	fenum.count = *count;
	fenum.info = *info;

	if (connections_traverse(pipe_enum_fn, &fenum) == -1) {
		DEBUG(0,("net_enum_pipes: traverse of connections.tdb "
			 "failed\n"));
		return WERR_NOMEM;
	}

	*info  = fenum.info;
	*count = fenum.count;

	return WERR_OK;
}

/*******************************************************************
********************************************************************/

static void enum_file_fn( const struct share_mode_entry *e,
                          const char *sharepath, const char *fname,
			  void *private_data )
{
 	struct file_enum_count *fenum =
 		(struct file_enum_count *)private_data;

	FILE_INFO_3 *f;
	int i = fenum->count;
	files_struct fsp;
	struct byte_range_lock *brl;
	int num_locks = 0;
	char *fullpath = NULL;
	uint32 permissions;
	const char *username;

	/* If the pid was not found delete the entry from connections.tdb */

	if ( !process_exists(e->pid) ) {
		return;
	}

	username = uidtoname(e->uid);

	if ((fenum->username != NULL)
	    && !strequal(username, fenum->username)) {
		return;
	}

	f = TALLOC_REALLOC_ARRAY( fenum->ctx, fenum->info, FILE_INFO_3, i+1 );
	if ( !f ) {
		DEBUG(0,("conn_enum_fn: realloc failed for %d items\n", i+1));
		return;
	}
	fenum->info = f;

	/* need to count the number of locks on a file */

	ZERO_STRUCT( fsp );
	fsp.file_id = e->id;

	if ( (brl = brl_get_locks(talloc_tos(), &fsp)) != NULL ) {
		num_locks = brl->num_locks;
		TALLOC_FREE(brl);
	}

	if ( strcmp( fname, "." ) == 0 ) {
		fullpath = talloc_asprintf(fenum->ctx, "C:%s", sharepath );
	} else {
		fullpath = talloc_asprintf(fenum->ctx, "C:%s/%s",
				sharepath, fname );
	}
	if (!fullpath) {
		return;
	}
	string_replace( fullpath, '/', '\\' );

	/* mask out create (what ever that is) */
	permissions = e->share_access & (FILE_READ_DATA|FILE_WRITE_DATA);

	/* now fill in the FILE_INFO_3 struct */
	init_srv_file_info3( &fenum->info[i],
			     e->share_file_id,
			     permissions,
			     num_locks,
			     username,
			     fullpath );

	TALLOC_FREE(fullpath);
	fenum->count++;
}

/*******************************************************************
********************************************************************/

static WERROR net_enum_files( TALLOC_CTX *ctx, const char *username,
			      FILE_INFO_3 **info, 
                              uint32 *count, uint32 resume )
{
	struct file_enum_count f_enum_cnt;

	f_enum_cnt.ctx = ctx;
	f_enum_cnt.username = username;
	f_enum_cnt.count = *count;
	f_enum_cnt.info = *info;
	
	share_mode_forall( enum_file_fn, (void *)&f_enum_cnt );
	
	*info  = f_enum_cnt.info;
	*count = f_enum_cnt.count;
	
	return WERR_OK;
}

/*******************************************************************
 Utility function to get the 'type' of a share from an snum.
 ********************************************************************/
static uint32 get_share_type(int snum)
{
	/* work out the share type */
	uint32 type = STYPE_DISKTREE;

	if (lp_print_ok(snum))
		type = STYPE_PRINTQ;
	if (strequal(lp_fstype(snum), "IPC"))
		type = STYPE_IPC;
	if (lp_administrative_share(snum))
		type |= STYPE_HIDDEN;

	return type;
}

/*******************************************************************
 Fill in a share info level 0 structure.
 ********************************************************************/

static void init_srv_share_info_0(pipes_struct *p, SRV_SHARE_INFO_0 *sh0, int snum)
{
	const char *net_name = lp_servicename(snum);

	init_srv_share_info0(&sh0->info_0, net_name);
	init_srv_share_info0_str(&sh0->info_0_str, net_name);
}

/*******************************************************************
 Fill in a share info level 1 structure.
 ********************************************************************/

static void init_srv_share_info_1(pipes_struct *p, SRV_SHARE_INFO_1 *sh1, int snum)
{
	char *net_name = lp_servicename(snum);
	char *remark = talloc_strdup(p->mem_ctx, lp_comment(snum));

	if (remark) {
		remark = standard_sub_conn(p->mem_ctx,
				p->conn,
				remark);
	}

	init_srv_share_info1(&sh1->info_1,
			net_name,
			get_share_type(snum),
			remark ? remark: "");
	init_srv_share_info1_str(&sh1->info_1_str,
			net_name,
			remark ? remark: "");
}

/*******************************************************************
 Fill in a share info level 2 structure.
 ********************************************************************/

static void init_srv_share_info_2(pipes_struct *p, SRV_SHARE_INFO_2 *sh2, int snum)
{
	char *remark = NULL;
	char *path = NULL;
	int max_connections = lp_max_connections(snum);
	uint32 max_uses = max_connections!=0 ? max_connections : 0xffffffff;
	int count = 0;
	char *net_name = lp_servicename(snum);

	remark = talloc_strdup(p->mem_ctx, lp_comment(snum));
	if (remark) {
		remark = standard_sub_conn(p->mem_ctx,
				p->conn,
				remark);
	}
	path = talloc_asprintf(p->mem_ctx,
			"C:%s", lp_pathname(snum));

	if (path) {
		/*
		 * Change / to \\ so that win2k will see it as a valid path.
		 * This was added to enable use of browsing in win2k add
		 * share dialog.
		 */

		string_replace(path, '/', '\\');
	}

	count = count_current_connections(net_name, false);
	init_srv_share_info2(&sh2->info_2,
				net_name,
				get_share_type(snum),
				remark ? remark : "",
				0,
				max_uses,
				count,
				path ? path : "",
				"");

	init_srv_share_info2_str(&sh2->info_2_str,
				net_name,
				remark ? remark : "",
				path ? path : "",
				"");
}

/*******************************************************************
 Map any generic bits to file specific bits.
********************************************************************/

static void map_generic_share_sd_bits(SEC_DESC *psd)
{
	int i;
	SEC_ACL *ps_dacl = NULL;

	if (!psd)
		return;

	ps_dacl = psd->dacl;
	if (!ps_dacl)
		return;

	for (i = 0; i < ps_dacl->num_aces; i++) {
		SEC_ACE *psa = &ps_dacl->aces[i];
		uint32 orig_mask = psa->access_mask;

		se_map_generic(&psa->access_mask, &file_generic_mapping);
		psa->access_mask |= orig_mask;
	}
}

/*******************************************************************
 Fill in a share info level 501 structure.
********************************************************************/

static void init_srv_share_info_501(pipes_struct *p, SRV_SHARE_INFO_501 *sh501, int snum)
{
	const char *net_name = lp_servicename(snum);
	char *remark = talloc_strdup(p->mem_ctx, lp_comment(snum));

	if (remark) {
		remark = standard_sub_conn(p->mem_ctx, p->conn, remark);
	}

	init_srv_share_info501(&sh501->info_501, net_name, get_share_type(snum),
			remark ? remark : "", (lp_csc_policy(snum) << 4));
	init_srv_share_info501_str(&sh501->info_501_str,
			net_name, remark ? remark : "");
}

/*******************************************************************
 Fill in a share info level 502 structure.
 ********************************************************************/

static void init_srv_share_info_502(pipes_struct *p, SRV_SHARE_INFO_502 *sh502, int snum)
{
	const char *net_name = lp_servicename(snum);
	char *path = NULL;
	SEC_DESC *sd = NULL;
	size_t sd_size = 0;
	TALLOC_CTX *ctx = p->mem_ctx;
	char *remark = talloc_strdup(ctx, lp_comment(snum));;

	ZERO_STRUCTP(sh502);

	if (remark) {
		remark = standard_sub_conn(ctx, p->conn, remark);
	}
	path = talloc_asprintf(ctx, "C:%s", lp_pathname(snum));
	if (path) {
		/*
		 * Change / to \\ so that win2k will see it as a valid path.  This was added to
		 * enable use of browsing in win2k add share dialog.
		 */
		string_replace(path, '/', '\\');
	}

	sd = get_share_security(ctx, lp_servicename(snum), &sd_size);

	init_srv_share_info502(&sh502->info_502,
			net_name,
			get_share_type(snum),
			remark ? remark : "",
			0,
			0xffffffff,
			1,
			path ? path : "",
			"",
			sd,
			sd_size);
	init_srv_share_info502_str(&sh502->info_502_str,
			net_name,
			remark ? remark : "",
			path ? path : "",
			"",
			sd,
			sd_size);
}

/***************************************************************************
 Fill in a share info level 1004 structure.
 ***************************************************************************/

static void init_srv_share_info_1004(pipes_struct *p, SRV_SHARE_INFO_1004* sh1004, int snum)
{
	char *remark = talloc_strdup(p->mem_ctx, lp_comment(snum));

	if (remark) {
		remark = standard_sub_conn(p->mem_ctx, p->conn, remark);
	}

	ZERO_STRUCTP(sh1004);

	init_srv_share_info1004(&sh1004->info_1004, remark ? remark : "");
	init_srv_share_info1004_str(&sh1004->info_1004_str,
			remark ? remark : "");
}

/***************************************************************************
 Fill in a share info level 1005 structure.
 ***************************************************************************/

static void init_srv_share_info_1005(pipes_struct *p, SRV_SHARE_INFO_1005* sh1005, int snum)
{
	sh1005->share_info_flags = 0;

	if(lp_host_msdfs() && lp_msdfs_root(snum))
		sh1005->share_info_flags |=
			SHARE_1005_IN_DFS | SHARE_1005_DFS_ROOT;
	sh1005->share_info_flags |=
		lp_csc_policy(snum) << SHARE_1005_CSC_POLICY_SHIFT;
}
/***************************************************************************
 Fill in a share info level 1006 structure.
 ***************************************************************************/

static void init_srv_share_info_1006(pipes_struct *p, SRV_SHARE_INFO_1006* sh1006, int snum)
{
	sh1006->max_uses = -1;
}

/***************************************************************************
 Fill in a share info level 1007 structure.
 ***************************************************************************/

static void init_srv_share_info_1007(pipes_struct *p, SRV_SHARE_INFO_1007* sh1007, int snum)
{
	uint32 flags = 0;

	ZERO_STRUCTP(sh1007);

	init_srv_share_info1007(&sh1007->info_1007, flags, "");
	init_srv_share_info1007_str(&sh1007->info_1007_str, "");
}

/*******************************************************************
 Fill in a share info level 1501 structure.
 ********************************************************************/

static void init_srv_share_info_1501(pipes_struct *p, SRV_SHARE_INFO_1501 *sh1501, int snum)
{
	SEC_DESC *sd;
	size_t sd_size;
	TALLOC_CTX *ctx = p->mem_ctx;

	ZERO_STRUCTP(sh1501);

	sd = get_share_security(ctx, lp_servicename(snum), &sd_size);

	sh1501->sdb = make_sec_desc_buf(p->mem_ctx, sd_size, sd);
}

/*******************************************************************
 True if it ends in '$'.
 ********************************************************************/

static bool is_hidden_share(int snum)
{
	const char *net_name = lp_servicename(snum);

	return (net_name[strlen(net_name) - 1] == '$') ? True : False;
}

/*******************************************************************
 Fill in a share info structure.
 ********************************************************************/

static bool init_srv_share_info_ctr(pipes_struct *p, SRV_SHARE_INFO_CTR *ctr,
	       uint32 info_level, uint32 *resume_hnd, uint32 *total_entries, bool all_shares)
{
	int num_entries = 0;
	int num_services = 0;
	int snum;
	TALLOC_CTX *ctx = p->mem_ctx;

	DEBUG(5,("init_srv_share_info_ctr\n"));

	ZERO_STRUCTPN(ctr);

	ctr->info_level = ctr->switch_value = info_level;
	*resume_hnd = 0;

	/* Ensure all the usershares are loaded. */
	become_root();
	num_services = load_usershare_shares();
	load_registry_shares();
	unbecome_root();

	/* Count the number of entries. */
	for (snum = 0; snum < num_services; snum++) {
		if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) )
			num_entries++;
	}

	*total_entries = num_entries;
	ctr->num_entries2 = ctr->num_entries = num_entries;
	ctr->ptr_share_info = ctr->ptr_entries = 1;

	if (!num_entries)
		return True;

	switch (info_level) {
	case 0:
	{
		SRV_SHARE_INFO_0 *info0 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_0, num_entries);
		int i = 0;

		if (!info0) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_0(p, &info0[i++], snum);
			}
		}

		ctr->share.info0 = info0;
		break;

	}

	case 1:
	{
		SRV_SHARE_INFO_1 *info1 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1, num_entries);
		int i = 0;

		if (!info1) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1(p, &info1[i++], snum);
			}
		}

		ctr->share.info1 = info1;
		break;
	}

	case 2:
	{
		SRV_SHARE_INFO_2 *info2 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_2, num_entries);
		int i = 0;

		if (!info2) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_2(p, &info2[i++], snum);
			}
		}

		ctr->share.info2 = info2;
		break;
	}

	case 501:
	{
		SRV_SHARE_INFO_501 *info501 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_501, num_entries);
		int i = 0;
	
		if (!info501) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_501(p, &info501[i++], snum);
			}
		}
	
		ctr->share.info501 = info501;
		break;
	}

	case 502:
	{
		SRV_SHARE_INFO_502 *info502 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_502, num_entries);
		int i = 0;

		if (!info502) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_502(p, &info502[i++], snum);
			}
		}

		ctr->share.info502 = info502;
		break;
	}

	/* here for completeness but not currently used with enum (1004 - 1501)*/
	
	case 1004:
	{
		SRV_SHARE_INFO_1004 *info1004 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1004, num_entries);
		int i = 0;

		if (!info1004) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1004(p, &info1004[i++], snum);
			}
		}

		ctr->share.info1004 = info1004;
		break;
	}

	case 1005:
	{
		SRV_SHARE_INFO_1005 *info1005 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1005, num_entries);
		int i = 0;

		if (!info1005) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1005(p, &info1005[i++], snum);
			}
		}

		ctr->share.info1005 = info1005;
		break;
	}

	case 1006:
	{
		SRV_SHARE_INFO_1006 *info1006 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1006, num_entries);
		int i = 0;

		if (!info1006) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1006(p, &info1006[i++], snum);
			}
		}

		ctr->share.info1006 = info1006;
		break;
	}

	case 1007:
	{
		SRV_SHARE_INFO_1007 *info1007 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1007, num_entries);
		int i = 0;

		if (!info1007) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1007(p, &info1007[i++], snum);
			}
		}

		ctr->share.info1007 = info1007;
		break;
	}

	case 1501:
	{
		SRV_SHARE_INFO_1501 *info1501 = TALLOC_ARRAY(ctx, SRV_SHARE_INFO_1501, num_entries);
		int i = 0;

		if (!info1501) {
			return False;
		}

		for (snum = *resume_hnd; snum < num_services; snum++) {
			if (lp_browseable(snum) && lp_snum_ok(snum) && (all_shares || !is_hidden_share(snum)) ) {
				init_srv_share_info_1501(p, &info1501[i++], snum);
			}
		}

		ctr->share.info1501 = info1501;
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
				      uint32 info_level, uint32 resume_hnd, bool all)  
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
		case 0:
			init_srv_share_info_0(p, &r_n->info.share.info0, snum);
			break;
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

			/* here for completeness */
		case 1004:
			init_srv_share_info_1004(p, &r_n->info.share.info1004, snum);
			break;
		case 1005:
			init_srv_share_info_1005(p, &r_n->info.share.info1005, snum);
			break;

			/* here for completeness 1006 - 1501 */
		case 1006:
			init_srv_share_info_1006(p, &r_n->info.share.info1006, snum);
			break;
		case 1007:
			init_srv_share_info_1007(p, &r_n->info.share.info1007, snum);
			break;
		case 1501:
			init_srv_share_info_1501(p, &r_n->info.share.info1501, snum);
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
 fill in a sess info level 0 structure.
 ********************************************************************/

static void init_srv_sess_info_0(pipes_struct *p, SRV_SESS_INFO_0 *ss0, uint32 *snum, uint32 *stot)
{
	struct sessionid *session_list;
	uint32 num_entries = 0;
	(*stot) = list_sessions(p->mem_ctx, &session_list);

	if (ss0 == NULL) {
		if (snum) {
			(*snum) = 0;
		}
		return;
	}

	DEBUG(5,("init_srv_sess_0_ss0\n"));

	if (snum) {
		for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++) {
			init_srv_sess_info0( &ss0->info_0[num_entries], session_list[(*snum)].remote_machine);
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
********************************************************************/

static void sess_file_fn( const struct share_mode_entry *e, 
                          const char *sharepath, const char *fname,
			  void *data )
{
	struct sess_file_count *sess = (struct sess_file_count *)data;
 
	if ( procid_equal(&e->pid, &sess->pid) && (sess->uid == e->uid) ) {
		sess->count++;
	}
	
	return;
}

/*******************************************************************
********************************************************************/

static int net_count_files( uid_t uid, struct server_id pid )
{
	struct sess_file_count s_file_cnt;

	s_file_cnt.count = 0;
	s_file_cnt.uid = uid;
	s_file_cnt.pid = pid;
	
	share_mode_forall( sess_file_fn, &s_file_cnt );
	
	return s_file_cnt.count;
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_info_1(pipes_struct *p, SRV_SESS_INFO_1 *ss1, uint32 *snum, uint32 *stot)
{
	struct sessionid *session_list;
	uint32 num_entries = 0;
	time_t now = time(NULL);

	if ( !snum ) {
		ss1->num_entries_read = 0;
		ss1->ptr_sess_info = 0;
		ss1->num_entries_read2 = 0;
		
		(*stot) = 0;

		return;
	}
	
	if (ss1 == NULL) {
		(*snum) = 0;
		return;
	}

	(*stot) = list_sessions(p->mem_ctx, &session_list);
	

	for (; (*snum) < (*stot) && num_entries < MAX_SESS_ENTRIES; (*snum)++) {
		uint32 num_files;
		uint32 connect_time;
		struct passwd *pw = sys_getpwnam(session_list[*snum].username);
		bool guest;
			
		if ( !pw ) {
			DEBUG(10,("init_srv_sess_info_1: failed to find owner: %s\n",
				session_list[*snum].username));
			continue;
		}
				
		connect_time = (uint32)(now - session_list[*snum].connect_start);
		num_files = net_count_files(pw->pw_uid, session_list[*snum].pid);
		guest = strequal( session_list[*snum].username, lp_guestaccount() );
					
		init_srv_sess_info1( &ss1->info_1[num_entries], 
		                     session_list[*snum].remote_machine,
				     session_list[*snum].username, 
				     num_files,
				     connect_time,
				     0, 
				     guest);
		num_entries++;
	}

	ss1->num_entries_read  = num_entries;
	ss1->ptr_sess_info     = num_entries > 0 ? 1 : 0;
	ss1->num_entries_read2 = num_entries;
	
	if ((*snum) >= (*stot)) {
		(*snum) = 0;
	}

}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/

static WERROR init_srv_sess_info_ctr(pipes_struct *p, SRV_SESS_INFO_CTR *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	WERROR status = WERR_OK;
	DEBUG(5,("init_srv_sess_info_ctr: %d\n", __LINE__));

	ctr->switch_value = switch_value;

	switch (switch_value) {
	case 0:
		init_srv_sess_info_0(p, &(ctr->sess.info0), resume_hnd, total_entries);
		ctr->ptr_sess_ctr = 1;
		break;
	case 1:
		init_srv_sess_info_1(p, &(ctr->sess.info1), resume_hnd, total_entries);
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

static void init_srv_r_net_sess_enum(pipes_struct *p, SRV_R_NET_SESS_ENUM *r_n,
				uint32 resume_hnd, int sess_level, int switch_value)  
{
	DEBUG(5,("init_srv_r_net_sess_enum: %d\n", __LINE__));

	r_n->sess_level  = sess_level;

	if (sess_level == -1)
		r_n->status = WERR_UNKNOWN_LEVEL;
	else
		r_n->status = init_srv_sess_info_ctr(p, r_n->ctr, switch_value, &resume_hnd, &r_n->total_entries);

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
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/

static WERROR net_file_enum_3( const char *username, SRV_R_NET_FILE_ENUM *r,
			       uint32 resume_hnd )
{
	TALLOC_CTX *ctx = talloc_tos();
	SRV_FILE_INFO_CTR *ctr = &r->ctr;

	/* TODO -- Windows enumerates 
	   (b) active pipes
	   (c) open directories and files */

	r->status = net_enum_files( ctx, username, &ctr->file.info3,
				    &ctr->num_entries, resume_hnd );
	if ( !W_ERROR_IS_OK(r->status))
		goto done;
		
	r->status = net_enum_pipes( ctx, username, &ctr->file.info3,
				    &ctr->num_entries, resume_hnd );
	if ( !W_ERROR_IS_OK(r->status))
		goto done;
	
	r->level = ctr->level = 3;
	r->total_entries = ctr->num_entries;
	/* ctr->num_entries = r->total_entries - resume_hnd; */
	ctr->num_entries2 = ctr->num_entries;
	ctr->ptr_file_info = 1;

	r->status = WERR_OK;

done:
	if ( ctr->num_entries > 0 ) 
		ctr->ptr_entries = 1;

	init_enum_hnd(&r->enum_hnd, 0);

	return r->status;
}

/*******************************************************************
*******************************************************************/

WERROR _srv_net_file_enum(pipes_struct *p, SRV_Q_NET_FILE_ENUM *q_u, SRV_R_NET_FILE_ENUM *r_u)
{
	const char *username = NULL;

	switch ( q_u->level ) {
	case 3:
		if (q_u->username) {
			username = rpcstr_pull_unistr2_talloc(
				p->mem_ctx, q_u->username);
			if (!username) {
				return WERR_NOMEM;
			}
		}

		return net_file_enum_3(username, r_u,
				       get_enum_hnd(&q_u->enum_hnd));
	default:
		return WERR_UNKNOWN_LEVEL;
	}
	
	return WERR_OK;
}

/*******************************************************************
net server get info
********************************************************************/

WERROR _srv_net_srv_get_info(pipes_struct *p, SRV_Q_NET_SRV_GET_INFO *q_u, SRV_R_NET_SRV_GET_INFO *r_u)
{
	WERROR status = WERR_OK;
	SRV_INFO_CTR *ctr = TALLOC_P(p->mem_ctx, SRV_INFO_CTR);

	if (!ctr)
		return WERR_NOMEM;

	ZERO_STRUCTP(ctr);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_srv_get_info\n"));
		return WERR_ACCESS_DENIED;
	}

	switch (q_u->switch_value) {

		/* Technically level 102 should only be available to
		   Administrators but there isn't anything super-secret
		   here, as most of it is made up. */

	case 102:
		init_srv_info_102(&ctr->srv.sv102,
		                  500, global_myname(), 
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
		                  500, global_myname(),
		                  lp_major_announce_version(), lp_minor_announce_version(),
		                  lp_default_server_announce(),
		                  string_truncate(lp_serverstring(), MAX_SERVER_STRING_LENGTH));
		break;
	case 100:
		init_srv_info_100(&ctr->srv.sv100, 500, global_myname());
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
net conn enum
********************************************************************/

WERROR _srv_net_conn_enum(pipes_struct *p, SRV_Q_NET_CONN_ENUM *q_u, SRV_R_NET_CONN_ENUM *r_u)
{
	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	r_u->ctr = TALLOC_P(p->mem_ctx, SRV_CONN_INFO_CTR);
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

	r_u->ctr = TALLOC_P(p->mem_ctx, SRV_SESS_INFO_CTR);
	if (!r_u->ctr)
		return WERR_NOMEM;

	ZERO_STRUCTP(r_u->ctr);

	/* set up the */
	init_srv_r_net_sess_enum(p, r_u,
				get_enum_hnd(&q_u->enum_hnd),
				q_u->sess_level,
				q_u->ctr->switch_value);

	DEBUG(5,("_srv_net_sess_enum: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
net sess del
********************************************************************/

WERROR _srv_net_sess_del(pipes_struct *p, SRV_Q_NET_SESS_DEL *q_u, SRV_R_NET_SESS_DEL *r_u)
{
	struct sessionid *session_list;
	struct current_user user;
	int num_sessions, snum;
	fstring username;
	fstring machine;
	bool not_root = False;

	rpcstr_pull_unistr2_fstring(username, &q_u->uni_user_name);
	rpcstr_pull_unistr2_fstring(machine, &q_u->uni_cli_name);

	/* strip leading backslashes if any */
	while (machine[0] == '\\') {
		memmove(machine, &machine[1], strlen(machine));
	}

	num_sessions = list_sessions(p->mem_ctx, &session_list);

	DEBUG(5,("_srv_net_sess_del: %d\n", __LINE__));

	r_u->status = WERR_ACCESS_DENIED;

	get_current_user(&user, p);

	/* fail out now if you are not root or not a domain admin */

	if ((user.ut.uid != sec_initial_uid()) && 
		( ! nt_token_check_domain_rid(p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS))) {

		goto done;
	}

	for (snum = 0; snum < num_sessions; snum++) {

		if ((strequal(session_list[snum].username, username) || username[0] == '\0' ) &&
		    strequal(session_list[snum].remote_machine, machine)) {

			NTSTATUS ntstat;
		
			if (user.ut.uid != sec_initial_uid()) {
				not_root = True;
				become_root();
			}

			ntstat = messaging_send(smbd_messaging_context(),
						session_list[snum].pid,
						MSG_SHUTDOWN, &data_blob_null);
			
			if (NT_STATUS_IS_OK(ntstat))
				r_u->status = WERR_OK;

			if (not_root) 
				unbecome_root();
		}
	}

	DEBUG(5,("_srv_net_sess_del: %d\n", __LINE__));


done:

	return r_u->status;
}

/*******************************************************************
 Net share enum all.
********************************************************************/

WERROR _srv_net_share_enum_all(pipes_struct *p, SRV_Q_NET_SHARE_ENUM *q_u, SRV_R_NET_SHARE_ENUM *r_u)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_share_enum_all\n"));
		return WERR_ACCESS_DENIED;
	}

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

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_share_enum\n"));
		return WERR_ACCESS_DENIED;
	}

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
	unistr2_to_ascii(share_name, &q_u->uni_share_name, sizeof(share_name));
	init_srv_r_net_share_get_info(p, r_u, share_name, q_u->info_level);

	DEBUG(5,("_srv_net_share_get_info: %d\n", __LINE__));

	return r_u->status;
}

/*******************************************************************
 Check a given DOS pathname is valid for a share.
********************************************************************/

char *valid_share_pathname(TALLOC_CTX *ctx, const char *dos_pathname)
{
	char *ptr = NULL;

	if (!dos_pathname) {
		return NULL;
	}

	ptr = talloc_strdup(ctx, dos_pathname);
	if (!ptr) {
		return NULL;
	}
	/* Convert any '\' paths to '/' */
	unix_format(ptr);
	ptr = unix_clean_name(ctx, ptr);
	if (!ptr) {
		return NULL;
	}

	/* NT is braindead - it wants a C: prefix to a pathname ! So strip it. */
	if (strlen(ptr) > 2 && ptr[1] == ':' && ptr[0] != '/')
		ptr += 2;

	/* Only absolute paths allowed. */
	if (*ptr != '/')
		return NULL;

	return ptr;
}

/*******************************************************************
 Net share set info. Modify share details.
********************************************************************/

WERROR _srv_net_share_set_info(pipes_struct *p, SRV_Q_NET_SHARE_SET_INFO *q_u, SRV_R_NET_SHARE_SET_INFO *r_u)
{
	struct current_user user;
	char *command = NULL;
	char *share_name = NULL;
	char *comment = NULL;
	char *pathname = NULL;
	int type;
	int snum;
	int ret;
	char *path = NULL;
	SEC_DESC *psd = NULL;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	bool is_disk_op = False;
	int max_connections = 0;
	TALLOC_CTX *ctx = p->mem_ctx;

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	share_name = unistr2_to_ascii_talloc(ctx, &q_u->uni_share_name);
	if (!share_name) {
		return WERR_NET_NAME_NOT_FOUND;
	}

	r_u->parm_error = 0;

	if ( strequal(share_name,"IPC$")
		|| ( lp_enable_asu_support() && strequal(share_name,"ADMIN$") )
		|| strequal(share_name,"global") )
	{
		return WERR_ACCESS_DENIED;
	}

	snum = find_service(share_name);

	/* Does this share exist ? */
	if (snum < 0)
		return WERR_NET_NAME_NOT_FOUND;

	/* No change to printer shares. */
	if (lp_print_ok(snum))
		return WERR_ACCESS_DENIED;

	get_current_user(&user,p);

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token, &se_diskop );

	/* fail out now if you are not root and not a disk op */

	if ( user.ut.uid != sec_initial_uid() && !is_disk_op )
		return WERR_ACCESS_DENIED;

	switch (q_u->info_level) {
	case 1:
		pathname = talloc_strdup(ctx, lp_pathname(snum));
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_remark);
		type = q_u->info.share.info2.info_2.type;
		psd = NULL;
		break;
	case 2:
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_remark);
		pathname = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_path);
		type = q_u->info.share.info2.info_2.type;
		max_connections = (q_u->info.share.info2.info_2.max_uses == 0xffffffff) ? 0 : q_u->info.share.info2.info_2.max_uses;
		psd = NULL;
		break;
#if 0
		/* not supported on set but here for completeness */
	case 501:
		unistr2_to_ascii(comment, &q_u->info.share.info501.info_501_str.uni_remark, sizeof(comment));
		type = q_u->info.share.info501.info_501.type;
		psd = NULL;
		break;
#endif
	case 502:
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info502.info_502_str.uni_remark);
		pathname = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info502.info_502_str.uni_path);
		type = q_u->info.share.info502.info_502.type;
		psd = q_u->info.share.info502.info_502_str.sd;
		map_generic_share_sd_bits(psd);
		break;
	case 1004:
		pathname = talloc_strdup(ctx, lp_pathname(snum));
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info1004.info_1004_str.uni_remark);
		type = STYPE_DISKTREE;
		break;
	case 1005:
                /* XP re-sets the csc policy even if it wasn't changed by the
		   user, so we must compare it to see if it's what is set in
		   smb.conf, so that we can contine other ops like setting
		   ACLs on a share */
		if (((q_u->info.share.info1005.share_info_flags &
		      SHARE_1005_CSC_POLICY_MASK) >>
		     SHARE_1005_CSC_POLICY_SHIFT) == lp_csc_policy(snum))
			return WERR_OK;
		else {
			DEBUG(3, ("_srv_net_share_set_info: client is trying to change csc policy from the network; must be done with smb.conf\n"));
			return WERR_ACCESS_DENIED;
		}
	case 1006:
	case 1007:
		return WERR_ACCESS_DENIED;
	case 1501:
		pathname = talloc_strdup(ctx, lp_pathname(snum));
		comment = talloc_strdup(ctx, lp_comment(snum));
		psd = q_u->info.share.info1501.sdb->sd;
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
	if (!(path = valid_share_pathname(p->mem_ctx, pathname )))
		return WERR_OBJECT_PATH_INVALID;

	/* Ensure share name, pathname and comment don't contain '"' characters. */
	string_replace(share_name, '"', ' ');
	string_replace(path, '"', ' ');
	if (comment) {
		string_replace(comment, '"', ' ');
	}

	DEBUG(10,("_srv_net_share_set_info: change share command = %s\n",
		lp_change_share_cmd() ? lp_change_share_cmd() : "NULL" ));

	/* Only call modify function if something changed. */

	if (strcmp(path, lp_pathname(snum)) || strcmp(comment, lp_comment(snum))
			|| (lp_max_connections(snum) != max_connections)) {
		if (!lp_change_share_cmd() || !*lp_change_share_cmd()) {
			DEBUG(10,("_srv_net_share_set_info: No change share command\n"));
			return WERR_ACCESS_DENIED;
		}

		command = talloc_asprintf(p->mem_ctx,
				"%s \"%s\" \"%s\" \"%s\" \"%s\" %d",
				lp_change_share_cmd(),
				get_dyn_CONFIGFILE(),
				share_name,
				path,
				comment ? comment : "",
				max_connections);
		if (!command) {
			return WERR_NOMEM;
		}

		DEBUG(10,("_srv_net_share_set_info: Running [%s]\n", command ));

		/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/

		if (is_disk_op)
			become_root();

		if ( (ret = smbrun(command, NULL)) == 0 ) {
			/* Tell everyone we updated smb.conf. */
			message_send_all(smbd_messaging_context(),
					 MSG_SMB_CONF_UPDATED, NULL, 0,
					 NULL);
		}

		if ( is_disk_op )
			unbecome_root();

		/********* END SeDiskOperatorPrivilege BLOCK *********/

		DEBUG(3,("_srv_net_share_set_info: Running [%s] returned (%d)\n", command, ret ));		

		TALLOC_FREE(command);

		if ( ret != 0 )
			return WERR_ACCESS_DENIED;
	} else {
		DEBUG(10,("_srv_net_share_set_info: No change to share name (%s)\n", share_name ));
	}

	/* Replace SD if changed. */
	if (psd) {
		SEC_DESC *old_sd;
		size_t sd_size;

		old_sd = get_share_security(p->mem_ctx, lp_servicename(snum), &sd_size);

		if (old_sd && !sec_desc_equal(old_sd, psd)) {
			if (!set_share_security(share_name, psd))
				DEBUG(0,("_srv_net_share_set_info: Failed to change security info in share %s.\n",
					share_name ));
		}
	}

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	return WERR_OK;
}

/*******************************************************************
 Net share add. Call 'add_share_command "sharename" "pathname"
 "comment" "max connections = "
********************************************************************/

WERROR _srv_net_share_add(pipes_struct *p, SRV_Q_NET_SHARE_ADD *q_u, SRV_R_NET_SHARE_ADD *r_u)
{
	struct current_user user;
	char *command = NULL;
	char *share_name = NULL;
	char *comment = NULL;
	char *pathname = NULL;
	int type;
	int snum;
	int ret;
	char *path;
	SEC_DESC *psd = NULL;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	bool is_disk_op;
	int max_connections = 0;
	TALLOC_CTX *ctx = p->mem_ctx;

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	r_u->parm_error = 0;

	get_current_user(&user,p);

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token, &se_diskop );

	if (user.ut.uid != sec_initial_uid()  && !is_disk_op )
		return WERR_ACCESS_DENIED;

	if (!lp_add_share_cmd() || !*lp_add_share_cmd()) {
		DEBUG(10,("_srv_net_share_add: No add share command\n"));
		return WERR_ACCESS_DENIED;
	}

	switch (q_u->info_level) {
	case 0:
		/* No path. Not enough info in a level 0 to do anything. */
		return WERR_ACCESS_DENIED;
	case 1:
		/* Not enough info in a level 1 to do anything. */
		return WERR_ACCESS_DENIED;
	case 2:
		share_name = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_netname);
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_remark);
		pathname = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info2.info_2_str.uni_path);
		max_connections = (q_u->info.share.info2.info_2.max_uses == 0xffffffff) ? 0 : q_u->info.share.info2.info_2.max_uses;
		type = q_u->info.share.info2.info_2.type;
		break;
	case 501:
		/* No path. Not enough info in a level 501 to do anything. */
		return WERR_ACCESS_DENIED;
	case 502:
		share_name = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info502.info_502_str.uni_netname);
		comment = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info502.info_502_str.uni_remark);
		pathname = unistr2_to_ascii_talloc(ctx,
				&q_u->info.share.info502.info_502_str.uni_path);
		type = q_u->info.share.info502.info_502.type;
		psd = q_u->info.share.info502.info_502_str.sd;
		map_generic_share_sd_bits(psd);
		break;

		/* none of the following contain share names.  NetShareAdd does not have a separate parameter for the share name */ 

	case 1004:
	case 1005:
	case 1006:
	case 1007:
		return WERR_ACCESS_DENIED;
	case 1501:
		/* DFS only level. */
		return WERR_ACCESS_DENIED;
	default:
		DEBUG(5,("_srv_net_share_add: unsupported switch value %d\n", q_u->info_level));
		return WERR_UNKNOWN_LEVEL;
	}

	/* check for invalid share names */

	if (!share_name || !validate_net_name(share_name,
				INVALID_SHARENAME_CHARS,
				strlen(share_name))) {
		DEBUG(5,("_srv_net_name_validate: Bad sharename \"%s\"\n",
					share_name ? share_name : ""));
		return WERR_INVALID_NAME;
	}

	if (strequal(share_name,"IPC$") || strequal(share_name,"global")
			|| (lp_enable_asu_support() &&
					strequal(share_name,"ADMIN$"))) {
		return WERR_ACCESS_DENIED;
	}

	snum = find_service(share_name);

	/* Share already exists. */
	if (snum >= 0) {
		return WERR_ALREADY_EXISTS;
	}

	/* We can only add disk shares. */
	if (type != STYPE_DISKTREE) {
		return WERR_ACCESS_DENIED;
	}

	/* Check if the pathname is valid. */
	if (!(path = valid_share_pathname(p->mem_ctx, pathname))) {
		return WERR_OBJECT_PATH_INVALID;
	}

	/* Ensure share name, pathname and comment don't contain '"' characters. */
	string_replace(share_name, '"', ' ');
	string_replace(path, '"', ' ');
	if (comment) {
		string_replace(comment, '"', ' ');
	}

	command = talloc_asprintf(ctx,
			"%s \"%s\" \"%s\" \"%s\" \"%s\" %d",
			lp_add_share_cmd(),
			get_dyn_CONFIGFILE(),
			share_name,
			path,
			comment ? comment : "",
			max_connections);
	if (!command) {
		return WERR_NOMEM;
	}

	DEBUG(10,("_srv_net_share_add: Running [%s]\n", command ));

	/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/

	if ( is_disk_op )
		become_root();

	if ( (ret = smbrun(command, NULL)) == 0 ) {
		/* Tell everyone we updated smb.conf. */
		message_send_all(smbd_messaging_context(),
				 MSG_SMB_CONF_UPDATED, NULL, 0, NULL);
	}

	if ( is_disk_op )
		unbecome_root();

	/********* END SeDiskOperatorPrivilege BLOCK *********/

	DEBUG(3,("_srv_net_share_add: Running [%s] returned (%d)\n", command, ret ));

	TALLOC_FREE(command);

	if ( ret != 0 )
		return WERR_ACCESS_DENIED;

	if (psd) {
		if (!set_share_security(share_name, psd)) {
			DEBUG(0,("_srv_net_share_add: Failed to add security info to share %s.\n", share_name ));
		}
	}

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
	char *command = NULL;
	char *share_name = NULL;
	int ret;
	int snum;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	bool is_disk_op;
	struct share_params *params;
	TALLOC_CTX *ctx = p->mem_ctx;

	DEBUG(5,("_srv_net_share_del: %d\n", __LINE__));

	share_name = unistr2_to_ascii_talloc(ctx, &q_u->uni_share_name);

	if (!share_name) {
		return WERR_NET_NAME_NOT_FOUND;
	}
	if ( strequal(share_name,"IPC$")
		|| ( lp_enable_asu_support() && strequal(share_name,"ADMIN$") )
		|| strequal(share_name,"global") )
	{
		return WERR_ACCESS_DENIED;
	}

	if (!(params = get_share_params(p->mem_ctx, share_name))) {
		return WERR_NO_SUCH_SHARE;
	}

	snum = find_service(share_name);

	/* No change to printer shares. */
	if (lp_print_ok(snum))
		return WERR_ACCESS_DENIED;

	get_current_user(&user,p);

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token, &se_diskop );

	if (user.ut.uid != sec_initial_uid()  && !is_disk_op )
		return WERR_ACCESS_DENIED;

	if (!lp_delete_share_cmd() || !*lp_delete_share_cmd()) {
		DEBUG(10,("_srv_net_share_del: No delete share command\n"));
		return WERR_ACCESS_DENIED;
	}

	command = talloc_asprintf(ctx,
			"%s \"%s\" \"%s\"",
			lp_delete_share_cmd(),
			get_dyn_CONFIGFILE(),
			lp_servicename(snum));
	if (!command) {
		return WERR_NOMEM;
	}

	DEBUG(10,("_srv_net_share_del: Running [%s]\n", command ));

	/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/

	if ( is_disk_op )
		become_root();

	if ( (ret = smbrun(command, NULL)) == 0 ) {
		/* Tell everyone we updated smb.conf. */
		message_send_all(smbd_messaging_context(),
				 MSG_SMB_CONF_UPDATED, NULL, 0, NULL);
	}

	if ( is_disk_op )
		unbecome_root();

	/********* END SeDiskOperatorPrivilege BLOCK *********/

	DEBUG(3,("_srv_net_share_del: Running [%s] returned (%d)\n", command, ret ));

	if ( ret != 0 )
		return WERR_ACCESS_DENIED;

	/* Delete the SD in the database. */
	delete_share_security(lp_servicename(params->service));

	lp_killservice(params->service);

	return WERR_OK;
}

WERROR _srv_net_share_del_sticky(pipes_struct *p, SRV_Q_NET_SHARE_DEL *q_u, SRV_R_NET_SHARE_DEL *r_u)
{
	DEBUG(5,("_srv_net_share_del_stick: %d\n", __LINE__));

	return _srv_net_share_del(p, q_u, r_u);
}

/*******************************************************************
time of day
********************************************************************/

WERROR _srv_net_remote_tod(pipes_struct *p, SRV_Q_NET_REMOTE_TOD *q_u, SRV_R_NET_REMOTE_TOD *r_u)
{
	TIME_OF_DAY_INFO *tod;
	struct tm *t;
	time_t unixdate = time(NULL);

	/* We do this call first as if we do it *after* the gmtime call
	   it overwrites the pointed-to values. JRA */

	uint32 zone = get_time_zone(unixdate)/60;

	DEBUG(5,("_srv_net_remote_tod: %d\n", __LINE__));

	if ( !(tod = TALLOC_ZERO_P(p->mem_ctx, TIME_OF_DAY_INFO)) )
		return WERR_NOMEM;

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
	                      zone,
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
	DATA_BLOB null_pw;
	char *filename_in = NULL;
	char *filename = NULL;
	char *qualname = NULL;
	SMB_STRUCT_STAT st;
	NTSTATUS nt_status;
	struct current_user user;
	connection_struct *conn = NULL;
	bool became_user = False;
	TALLOC_CTX *ctx = p->mem_ctx;

	ZERO_STRUCT(st);

	r_u->status = WERR_OK;

	qualname = unistr2_to_ascii_talloc(ctx, &q_u->uni_qual_name);
	if (!qualname) {
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	/* Null password is ok - we are already an authenticated user... */
	null_pw = data_blob_null;

	get_current_user(&user, p);

	become_root();
	conn = make_connection(qualname, null_pw, "A:", user.vuid, &nt_status);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to connect to %s\n", qualname));
		r_u->status = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_query_secdesc: Can't become connected user!\n"));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
	became_user = True;

	filename_in = unistr2_to_ascii_talloc(ctx, &q_u->uni_file_name);
	if (!filename_in) {
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = unix_convert(ctx, conn, filename_in, False, &filename, NULL, &st);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("_srv_net_file_query_secdesc: bad pathname %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = check_name(conn, filename);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("_srv_net_file_query_secdesc: can't access %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = SMB_VFS_GET_NT_ACL(conn, filename,
				       (OWNER_SECURITY_INFORMATION
					|GROUP_SECURITY_INFORMATION
					|DACL_SECURITY_INFORMATION), &psd);

	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to get NT ACL for file %s\n", filename));
		r_u->status = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	sd_size = ndr_size_security_descriptor(psd, 0);

	r_u->ptr_response = 1;
	r_u->size_response = sd_size;
	r_u->ptr_secdesc = 1;
	r_u->size_secdesc = sd_size;
	r_u->sec_desc = psd;

	psd->dacl->revision = NT4_ACL_REVISION;

	unbecome_user();
	close_cnum(conn, user.vuid);
	return r_u->status;

error_exit:

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
	char *filename_in = NULL;
	char *filename = NULL;
	char *qualname = NULL;
	DATA_BLOB null_pw;
	files_struct *fsp = NULL;
	SMB_STRUCT_STAT st;
	NTSTATUS nt_status;
	struct current_user user;
	connection_struct *conn = NULL;
	bool became_user = False;
	TALLOC_CTX *ctx = p->mem_ctx;

	ZERO_STRUCT(st);

	r_u->status = WERR_OK;

	qualname = unistr2_to_ascii_talloc(ctx, &q_u->uni_qual_name);
	if (!qualname) {
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	/* Null password is ok - we are already an authenticated user... */
	null_pw = data_blob_null;

	get_current_user(&user, p);

	become_root();
	conn = make_connection(qualname, null_pw, "A:", user.vuid, &nt_status);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to connect to %s\n", qualname));
		r_u->status = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_set_secdesc: Can't become connected user!\n"));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
	became_user = True;

	filename_in= unistr2_to_ascii_talloc(ctx, &q_u->uni_file_name);
	if (!filename_in) {
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = unix_convert(ctx, conn, filename, False, &filename, NULL, &st);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("_srv_net_file_set_secdesc: bad pathname %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = check_name(conn, filename);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(3,("_srv_net_file_set_secdesc: can't access %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = open_file_stat(conn, NULL, filename, &st, &fsp);

	if ( !NT_STATUS_IS_OK(nt_status) ) {
		/* Perhaps it is a directory */
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_IS_A_DIRECTORY))
			nt_status = open_directory(conn, NULL, filename, &st,
						FILE_READ_ATTRIBUTES,
						FILE_SHARE_READ|FILE_SHARE_WRITE,
						FILE_OPEN,
						0,
						FILE_ATTRIBUTE_DIRECTORY,
						NULL, &fsp);

		if ( !NT_STATUS_IS_OK(nt_status) ) {
			DEBUG(3,("_srv_net_file_set_secdesc: Unable to open file %s\n", filename));
			r_u->status = ntstatus_to_werror(nt_status);
			goto error_exit;
		}
	}

	nt_status = SMB_VFS_SET_NT_ACL(fsp, fsp->fsp_name, q_u->sec_info, q_u->sec_desc);

	if (!NT_STATUS_IS_OK(nt_status) ) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to set NT ACL on file %s\n", filename));
		r_u->status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	close_file(fsp, NORMAL_CLOSE);
	unbecome_user();
	close_cnum(conn, user.vuid);
	return r_u->status;

error_exit:

	if(fsp) {
		close_file(fsp, NORMAL_CLOSE);
	}

	if (became_user) {
		unbecome_user();
	}

	if (conn) {
		close_cnum(conn, user.vuid);
	}

	return r_u->status;
}

/***********************************************************************************
 It may be that we want to limit users to creating shares on certain areas of the UNIX file area.
 We could define areas by mapping Windows style disks to points on the UNIX directory hierarchy.
 These disks would the disks listed by this function.
 Users could then create shares relative to these disks.  Watch out for moving these disks around.
 "Nigel Williams" <nigel@veritas.com>.
***********************************************************************************/

static const char *server_disks[] = {"C:"};

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
	TALLOC_CTX *ctx = p->mem_ctx;
	uint32 resume=get_enum_hnd(&q_u->enum_hnd);

	r_u->status=WERR_OK;

	r_u->total_entries = init_server_disk_enum(&resume);

	r_u->disk_enum_ctr.unknown = 0; 

	if(!(r_u->disk_enum_ctr.disk_info =  TALLOC_ARRAY(ctx, DISK_INFO, MAX_SERVER_DISK_ENTRIES))) {
		return WERR_NOMEM;
	}

	r_u->disk_enum_ctr.disk_info_ptr = r_u->disk_enum_ctr.disk_info ? 1 : 0;

	/*allow one DISK_INFO for null terminator*/

	for(i = 0; i < MAX_SERVER_DISK_ENTRIES -1 && (disk_name = next_server_disk_enum(&resume)); i++) {

		r_u->disk_enum_ctr.entries_read++;

		/*copy disk name into a unicode string*/

		init_unistr3(&r_u->disk_enum_ctr.disk_info[i].disk_name, disk_name);    
	}

	/* add a terminating null string.  Is this there if there is more data to come? */

	r_u->disk_enum_ctr.entries_read++;

	init_unistr3(&r_u->disk_enum_ctr.disk_info[i].disk_name, "");

	init_enum_hnd(&r_u->enum_hnd, resume);

	return r_u->status;
}

/********************************************************************
********************************************************************/

WERROR _srv_net_name_validate(pipes_struct *p, SRV_Q_NET_NAME_VALIDATE *q_u, SRV_R_NET_NAME_VALIDATE *r_u)
{
	fstring sharename;

	switch ( q_u->type ) {
	case 0x9:
		rpcstr_pull(sharename, q_u->sharename.buffer, sizeof(sharename), q_u->sharename.uni_str_len*2, 0);
		if ( !validate_net_name( sharename, INVALID_SHARENAME_CHARS, sizeof(sharename) ) ) {
			DEBUG(5,("_srv_net_name_validate: Bad sharename \"%s\"\n", sharename));
			return WERR_INVALID_NAME;
		}
		break;

	default:
		return WERR_UNKNOWN_LEVEL;
	}

	return WERR_OK;
}


/********************************************************************
********************************************************************/

WERROR _srvsvc_NetFileClose(pipes_struct *p, struct srvsvc_NetFileClose *r)
{
	return WERR_ACCESS_DENIED;
}


/********************************************************************
********************************************************************/

WERROR _srvsvc_NetCharDevEnum(pipes_struct *p, struct srvsvc_NetCharDevEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevGetInfo(pipes_struct *p, struct srvsvc_NetCharDevGetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevControl(pipes_struct *p, struct srvsvc_NetCharDevControl *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQEnum(pipes_struct *p, struct srvsvc_NetCharDevQEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQGetInfo(pipes_struct *p, struct srvsvc_NetCharDevQGetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQSetInfo(pipes_struct *p, struct srvsvc_NetCharDevQSetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQPurge(pipes_struct *p, struct srvsvc_NetCharDevQPurge *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQPurgeSelf(pipes_struct *p, struct srvsvc_NetCharDevQPurgeSelf *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetConnEnum(pipes_struct *p, struct srvsvc_NetConnEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetFileEnum(pipes_struct *p, struct srvsvc_NetFileEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetFileGetInfo(pipes_struct *p, struct srvsvc_NetFileGetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSessEnum(pipes_struct *p, struct srvsvc_NetSessEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSessDel(pipes_struct *p, struct srvsvc_NetSessDel *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareAdd(pipes_struct *p, struct srvsvc_NetShareAdd *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareEnumAll(pipes_struct *p, struct srvsvc_NetShareEnumAll *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareGetInfo(pipes_struct *p, struct srvsvc_NetShareGetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareSetInfo(pipes_struct *p, struct srvsvc_NetShareSetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDel(pipes_struct *p, struct srvsvc_NetShareDel *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDelSticky(pipes_struct *p, struct srvsvc_NetShareDelSticky *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareCheck(pipes_struct *p, struct srvsvc_NetShareCheck *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSrvGetInfo(pipes_struct *p, struct srvsvc_NetSrvGetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSrvSetInfo(pipes_struct *p, struct srvsvc_NetSrvSetInfo *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetDiskEnum(pipes_struct *p, struct srvsvc_NetDiskEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerStatisticsGet(pipes_struct *p, struct srvsvc_NetServerStatisticsGet *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportAdd(pipes_struct *p, struct srvsvc_NetTransportAdd *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportEnum(pipes_struct *p, struct srvsvc_NetTransportEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportDel(pipes_struct *p, struct srvsvc_NetTransportDel *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetRemoteTOD(pipes_struct *p, struct srvsvc_NetRemoteTOD *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSetServiceBits(pipes_struct *p, struct srvsvc_NetSetServiceBits *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathType(pipes_struct *p, struct srvsvc_NetPathType *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathCanonicalize(pipes_struct *p, struct srvsvc_NetPathCanonicalize *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathCompare(pipes_struct *p, struct srvsvc_NetPathCompare *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetNameValidate(pipes_struct *p, struct srvsvc_NetNameValidate *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRPRNAMECANONICALIZE(pipes_struct *p, struct srvsvc_NETRPRNAMECANONICALIZE *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPRNameCompare(pipes_struct *p, struct srvsvc_NetPRNameCompare *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareEnum(pipes_struct *p, struct srvsvc_NetShareEnum *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDelStart(pipes_struct *p, struct srvsvc_NetShareDelStart *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDelCommit(pipes_struct *p, struct srvsvc_NetShareDelCommit *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetGetFileSecurity(pipes_struct *p, struct srvsvc_NetGetFileSecurity *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSetFileSecurity(pipes_struct *p, struct srvsvc_NetSetFileSecurity *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerTransportAddEx(pipes_struct *p, struct srvsvc_NetServerTransportAddEx *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerSetServiceBitsEx(pipes_struct *p, struct srvsvc_NetServerSetServiceBitsEx *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSGETVERSION(pipes_struct *p, struct srvsvc_NETRDFSGETVERSION *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSCREATELOCALPARTITION(pipes_struct *p, struct srvsvc_NETRDFSCREATELOCALPARTITION *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSDELETELOCALPARTITION(pipes_struct *p, struct srvsvc_NETRDFSDELETELOCALPARTITION *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSSETLOCALVOLUMESTATE(pipes_struct *p, struct srvsvc_NETRDFSSETLOCALVOLUMESTATE *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSSETSERVERINFO(pipes_struct *p, struct srvsvc_NETRDFSSETSERVERINFO *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSCREATEEXITPOINT(pipes_struct *p, struct srvsvc_NETRDFSCREATEEXITPOINT *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSDELETEEXITPOINT(pipes_struct *p, struct srvsvc_NETRDFSDELETEEXITPOINT *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSMODIFYPREFIX(pipes_struct *p, struct srvsvc_NETRDFSMODIFYPREFIX *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSFIXLOCALVOLUME(pipes_struct *p, struct srvsvc_NETRDFSFIXLOCALVOLUME *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSMANAGERREPORTSITEINFO(pipes_struct *p, struct srvsvc_NETRDFSMANAGERREPORTSITEINFO *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRSERVERTRANSPORTDELEX(pipes_struct *p, struct srvsvc_NETRSERVERTRANSPORTDELEX *r)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

