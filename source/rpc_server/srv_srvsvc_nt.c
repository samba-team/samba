/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Jeremy Allison               2001.
 *  Copyright (C) Nigel Williams               2001.
 *  Copyright (C) Gerald (Jerry) Carter        2006.
 *  Copyright (C) Jelmer Vernooij			   2006.
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

#define MAX_SERVER_DISK_ENTRIES 15

extern struct generic_mapping file_generic_mapping;
extern userdom_struct current_user_info;

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/* Use for enumerating connections, pipes, & files */

struct file_enum_count {
	TALLOC_CTX *ctx;
	uint32 count;
	struct srvsvc_NetFileInfo3 *info;
};

struct sess_file_count {
	pid_t pid;
	uid_t uid;
	int count;
};

/****************************************************************************
 Count the entries belonging to a service in the connection db.
****************************************************************************/

static int pipe_enum_fn( TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, void *p)
{
	struct pipe_open_rec prec;
	struct file_enum_count *fenum = (struct file_enum_count *)p;
 
	if (dbuf.dsize != sizeof(struct pipe_open_rec))
		return 0;

	memcpy(&prec, dbuf.dptr, sizeof(struct pipe_open_rec));
 
	if ( process_exists(prec.pid) ) {
		struct srvsvc_NetFileInfo3 *f;
		int i = fenum->count;
		pstring fullpath;
		
		snprintf( fullpath, sizeof(fullpath), "\\PIPE\\%s", prec.name );
		
		f = TALLOC_REALLOC_ARRAY( fenum->ctx, fenum->info, struct srvsvc_NetFileInfo3, i+1 );
		if ( !f ) {
			DEBUG(0,("conn_enum_fn: realloc failed for %d items\n", i+1));
			return 1;
		}

		fenum->info = f;
		
		fenum->info[i].fid = (uint32)((procid_to_pid(&prec.pid)<<16) & prec.pnum);
		fenum->info[i].permissions = (FILE_READ_DATA|FILE_WRITE_DATA);
		fenum->info[i].num_locks = 0;
		fenum->info[i].user = uidtoname( prec.uid );
		fenum->info[i].path = fullpath;
			
		fenum->count++;
	}

	return 0;
}

/*******************************************************************
********************************************************************/

static WERROR net_enum_pipes( TALLOC_CTX *ctx, struct srvsvc_NetFileInfo3 **info, 
                              uint32 *count, uint32 *resume )
{
	struct file_enum_count fenum;
	TDB_CONTEXT *conn_tdb = conn_tdb_ctx();

	if ( !conn_tdb ) {
		DEBUG(0,("net_enum_pipes: Failed to retrieve the connections tdb handle!\n"));
		return WERR_ACCESS_DENIED;
	}
	
	fenum.ctx = ctx;
	fenum.info = *info;
	fenum.count = *count;

	if (tdb_traverse(conn_tdb, pipe_enum_fn, &fenum) == -1) {
		DEBUG(0,("net_enum_pipes: traverse of connections.tdb failed with error %s.\n",
			tdb_errorstr(conn_tdb) ));
		return WERR_NOMEM;
	}
	
	*info  = fenum.info;
	*count = fenum.count;
	
	return WERR_OK;}

/*******************************************************************
********************************************************************/

/* global needed to make use of the share_mode_forall() callback */
static struct file_enum_count f_enum_cnt;

static void enum_file_fn( const struct share_mode_entry *e, 
                          const char *sharepath, const char *fname,
			  void *dummy )
{
	struct file_enum_count *fenum = &f_enum_cnt;
 
	/* If the pid was not found delete the entry from connections.tdb */

	if ( process_exists(e->pid) ) {
		struct srvsvc_NetFileInfo3 *f;
		int i = fenum->count;
		files_struct fsp;
		struct byte_range_lock *brl;
		int num_locks = 0;
		pstring fullpath;
		uint32 permissions;
		
		f = TALLOC_REALLOC_ARRAY( fenum->ctx, fenum->info, struct srvsvc_NetFileInfo3, i+1 );			
		if ( !f ) {
			DEBUG(0,("conn_enum_fn: realloc failed for %d items\n", i+1));
			return;
		}
		fenum->info = f;

		/* need to count the number of locks on a file */
		
		ZERO_STRUCT( fsp );		
		fsp.dev   = e->dev;
		fsp.inode = e->inode;
		
		if ( (brl = brl_get_locks_readonly(NULL,&fsp)) != NULL ) {
			num_locks = brl->num_locks;
			TALLOC_FREE( brl );
		}
		
		if ( strcmp( fname, "." ) == 0 ) {
			pstr_sprintf( fullpath, "C:%s", sharepath );
		} else {
			pstr_sprintf( fullpath, "C:%s/%s", sharepath, fname );
		}
		string_replace( fullpath, '/', '\\' );
		
		/* mask out create (what ever that is) */
		permissions = e->share_access & (FILE_READ_DATA|FILE_WRITE_DATA);

		fenum->info[i].fid = e->share_file_id;
		fenum->info[i].permissions = permissions;
		fenum->info[i].num_locks = num_locks;
		fenum->info[i].user = uidtoname(e->uid);
		fenum->info[i].path = fullpath;
			
		fenum->count++;
	}

	return;

}

/*******************************************************************
********************************************************************/

static WERROR net_enum_files( TALLOC_CTX *ctx, struct srvsvc_NetFileInfo3 **info, 
                              uint32 *count, uint32 *resume )
{
	f_enum_cnt.ctx = ctx;
	f_enum_cnt.count = *count;
	f_enum_cnt.info = *info;
	
	share_mode_forall( enum_file_fn, NULL );
	
	*info  = f_enum_cnt.info;
	*count = f_enum_cnt.count;
	
	return WERR_OK;
}

/*******************************************************************
 Utility function to get the 'type' of a share from a share definition.
 ********************************************************************/
static uint32 get_share_type(const struct share_params *params)
{
	char *net_name = lp_servicename(params->service);
	int len_net_name = strlen(net_name);
	
	/* work out the share type */
	uint32 type = STYPE_DISKTREE;

	if (lp_print_ok(params->service))
		type = STYPE_PRINTQ;
	if (strequal(lp_fstype(params->service), "IPC"))
		type = STYPE_IPC;
	if (net_name[len_net_name] == '$')
		type |= STYPE_HIDDEN;

	return type;
}
	
/*******************************************************************
 Fill in a share info level 0 structure.
 ********************************************************************/

static void init_srv_share_info_0(pipes_struct *p, struct srvsvc_NetShareInfo0 *sh0,
				  const struct share_params *params)
{
	sh0->name = lp_servicename(params->service);
}

/*******************************************************************
 Fill in a share info level 1 structure.
 ********************************************************************/

static void init_srv_share_info_1(pipes_struct *p, struct srvsvc_NetShareInfo1 *sh1,
				  const struct share_params *params)
{
	connection_struct *conn = p->conn;

	sh1->comment = talloc_sub_advanced(p->mem_ctx, lp_servicename(SNUM(conn)),
				     conn->user, conn->connectpath, conn->gid,
				     get_current_username(),
				     current_user_info.domain,
				     lp_comment(params->service));

	sh1->name = lp_servicename(params->service);
	sh1->type = get_share_type(params);
}

/*******************************************************************
 Fill in a share info level 2 structure.
 ********************************************************************/

static void init_srv_share_info_2(pipes_struct *p, struct srvsvc_NetShareInfo2 *sh2,
				  const struct share_params *params)
{
	connection_struct *conn = p->conn;
	char *remark;
	char *path;
	int max_connections = lp_max_connections(params->service);
	uint32 max_uses = max_connections!=0 ? max_connections : 0xffffffff;
	int count = 0;
	char *net_name = lp_servicename(params->service);
	
	remark = talloc_sub_advanced(p->mem_ctx, lp_servicename(SNUM(conn)),
				     conn->user, conn->connectpath, conn->gid,
				     get_current_username(),
				     current_user_info.domain,
				     lp_comment(params->service));
	path = talloc_asprintf(p->mem_ctx, "C:%s",
			       lp_pathname(params->service));

	/*
	 * Change / to \\ so that win2k will see it as a valid path.  This was
	 * added to enable use of browsing in win2k add share dialog.
	 */ 

	string_replace(path, '/', '\\');

	count = count_current_connections( net_name, False  );
	sh2->name = net_name;
	sh2->type = get_share_type(params);
	sh2->comment = remark;
	sh2->permissions = 0;
	sh2->max_users = max_uses;
	sh2->current_users = count;
	sh2->path = path;
	sh2->password = "";
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

static void init_srv_share_info_501(pipes_struct *p, struct srvsvc_NetShareInfo501 *sh501,
				    const struct share_params *params)
{
	connection_struct *conn = p->conn;
	char *remark;
	const char *net_name = lp_servicename(params->service);

	remark = talloc_sub_advanced(p->mem_ctx, lp_servicename(SNUM(conn)),
				     conn->user, conn->connectpath, conn->gid,
				     get_current_username(),
				     current_user_info.domain,
				     lp_comment(params->service));


	sh501->name = net_name;
	sh501->type = get_share_type(params);
	sh501->comment = remark;
	sh501->csc_policy = (lp_csc_policy(params->service) << 4);
}

/*******************************************************************
 Fill in a share info level 502 structure.
 ********************************************************************/

static void init_srv_share_info_502(pipes_struct *p, struct srvsvc_NetShareInfo502 *sh502,
				    const struct share_params *params)
{
	int max_connections = lp_max_connections(params->service);
	uint32 max_uses = max_connections!=0 ? max_connections : 0xffffffff;
	connection_struct *conn = p->conn;
	int count; 
	char *net_name;
	char *remark;
	char *path;
	SEC_DESC *sd;
	size_t sd_size;
	TALLOC_CTX *ctx = p->mem_ctx;


	ZERO_STRUCTP(sh502);

	net_name = lp_servicename(params->service);
	count = count_current_connections( net_name, False  );

	remark = talloc_sub_advanced(p->mem_ctx, lp_servicename(SNUM(conn)),
				     conn->user, conn->connectpath, conn->gid,
				     get_current_username(),
				     current_user_info.domain,
				     lp_comment(params->service));

	path = talloc_asprintf(p->mem_ctx, "C:%s",
			       lp_pathname(params->service));

	/*
	 * Change / to \\ so that win2k will see it as a valid path.  This was
	 * added to enable use of browsing in win2k add share dialog.
	 */ 

	string_replace(path, '/', '\\');

	sd = get_share_security(ctx, lp_servicename(params->service),
				&sd_size);

	sh502->name = net_name;
	sh502->type = get_share_type(params);
	sh502->comment = remark;
	sh502->path = path;
	sh502->password = "";
	sh502->sd = sd;
	sh502->permissions = 0;
	sh502->max_users = max_uses;
	sh502->current_users = count;
	sh502->unknown = 1;
}

/***************************************************************************
 Fill in a share info level 1004 structure.
 ***************************************************************************/

static void init_srv_share_info_1004(pipes_struct *p,
				     struct srvsvc_NetShareInfo1004* sh1004,
				     const struct share_params *params)
{
	connection_struct *conn = p->conn;
	char *remark;

	remark = talloc_sub_advanced(p->mem_ctx, lp_servicename(SNUM(conn)),
				     conn->user, conn->connectpath, conn->gid,
				     get_current_username(),
				     current_user_info.domain,
				     lp_comment(params->service));

	ZERO_STRUCTP(sh1004);

	sh1004->comment = remark;
}

/***************************************************************************
 Fill in a share info level 1005 structure.
 ***************************************************************************/

static void init_srv_share_info_1005(pipes_struct *p,
				     struct srvsvc_NetShareInfo1005* sh1005,
				     const struct share_params *params)
{
	sh1005->dfs_flags = 0;

	if(lp_host_msdfs() && lp_msdfs_root(params->service))
		sh1005->dfs_flags |= 
			SHARE_1005_IN_DFS | SHARE_1005_DFS_ROOT;
	sh1005->dfs_flags |= 
		lp_csc_policy(params->service) << SHARE_1005_CSC_POLICY_SHIFT;
}
/***************************************************************************
 Fill in a share info level 1006 structure.
 ***************************************************************************/

static void init_srv_share_info_1006(pipes_struct *p,
				     struct srvsvc_NetShareInfo1006* sh1006,
				     const struct share_params *params)
{
	sh1006->max_users = -1;
}

/***************************************************************************
 Fill in a share info level 1007 structure.
 ***************************************************************************/

static void init_srv_share_info_1007(pipes_struct *p,
				     struct srvsvc_NetShareInfo1007* sh1007,
				     const struct share_params *params)
{
	uint32 flags = 0;

	ZERO_STRUCTP(sh1007);
  
	sh1007->flags = flags;
	sh1007->alternate_directory_name = "";
}

/*******************************************************************
 Fill in a share info level 1501 structure.
 ********************************************************************/

static void init_srv_share_info_1501(pipes_struct *p,
				     struct sec_desc_buf *sh1501,
				     const struct share_params *params)
{
	SEC_DESC *sd;
	size_t sd_size;
	TALLOC_CTX *ctx = p->mem_ctx;

	ZERO_STRUCTP(sh1501);

	sd = get_share_security(ctx, lp_servicename(params->service),
				&sd_size);

	sh1501->sd = sd;
}

/*******************************************************************
 True if it ends in '$'.
 ********************************************************************/

static BOOL is_hidden_share(const struct share_params *params)
{
	const char *net_name = lp_servicename(params->service);

	return (net_name[strlen(net_name) - 1] == '$');
}

/*******************************************************************
 Fill in a share info structure.
 ********************************************************************/

static WERROR init_srv_share_info_ctr(pipes_struct *p,
				      union srvsvc_NetShareCtr *ctr,
				      uint32 info_level, uint32 *resume_hnd,
				      uint32 *total_entries, BOOL all_shares)
{
	TALLOC_CTX *ctx = p->mem_ctx;
	struct share_iterator *shares;
	struct share_params *share;
	WERROR result = WERR_NOMEM;

	DEBUG(5,("init_srv_share_info_ctr\n"));

	ZERO_STRUCTP(ctr);

	if (resume_hnd) {
		*resume_hnd = 0;
	}

	/* Ensure all the usershares are loaded. */
	become_root();
	load_usershare_shares();
	load_registry_shares();
	unbecome_root();

	*total_entries = 0;

	if (!(shares = share_list_all(ctx))) {
		DEBUG(5, ("Could not list shares\n"));
		return WERR_ACCESS_DENIED;
	}

	switch (info_level) {
	case 0:
		if (!(ctr->ctr0 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr0))) {
			goto done;
		}
		break;
	case 1:
		if (!(ctr->ctr1 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1))) {
			goto done;
		}
		break;
	case 2:
		if (!(ctr->ctr2 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr2))) {
			goto done;
		}
		break;
	case 501:
		if (!(ctr->ctr501 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr501))) {
			goto done;
		}
		break;
	case 502:
		if (!(ctr->ctr502 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr502))) {
			goto done;
		}
		break;
	case 1004:
		if (!(ctr->ctr1004 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1004))) {
			goto done;
		}
		break;
	case 1005:
		if (!(ctr->ctr1005 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1005))) {
			goto done;
		}
		break;
	case 1006:
		if (!(ctr->ctr1006 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1006))) {
			goto done;
		}
		break;
	case 1007:
		if (!(ctr->ctr1007 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1007))) {
			goto done;
		}
		break;
	case 1501:
		if (!(ctr->ctr1501 = talloc_zero(
			      p->mem_ctx, struct srvsvc_NetShareCtr1501))) {
			goto done;
		}
		break;
	default:
		DEBUG(5,("init_srv_share_info_ctr: unsupported switch "
			 "value %d\n", info_level));
		return WERR_UNKNOWN_LEVEL;
	}

	while ((share = next_share(shares)) != NULL) {
		if (!lp_browseable(share->service)) {
			continue;
		}
		if (!all_shares && is_hidden_share(share)) {
			continue;
		}

		switch (info_level) {
		case 0:
		{
			struct srvsvc_NetShareInfo0 i;
			init_srv_share_info_0(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo0, i,
				     &ctr->ctr0->array, &ctr->ctr0->count);
			if (ctr->ctr0->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr0->count;
			break;
		}

		case 1:
		{
			struct srvsvc_NetShareInfo1 i;
			init_srv_share_info_1(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo1, i,
				     &ctr->ctr1->array, &ctr->ctr1->count);
			if (ctr->ctr1->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1->count;
			break;
		}

		case 2:
		{
			struct srvsvc_NetShareInfo2 i;
			init_srv_share_info_2(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo2, i,
				     &ctr->ctr2->array, &ctr->ctr2->count);
			if (ctr->ctr2->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr2->count;
			break;
		}

		case 501:
		{
			struct srvsvc_NetShareInfo501 i;
			init_srv_share_info_501(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo501, i,
				     &ctr->ctr501->array, &ctr->ctr501->count);
			if (ctr->ctr501->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr501->count;
			break;
		}

		case 502:
		{
			struct srvsvc_NetShareInfo502 i;
			init_srv_share_info_502(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo502, i,
				     &ctr->ctr502->array, &ctr->ctr502->count);
			if (ctr->ctr502->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr502->count;
			break;
		}

		/* here for completeness but not currently used with enum
		 * (1004 - 1501)*/
	
		case 1004:
		{
			struct srvsvc_NetShareInfo1004 i;
			init_srv_share_info_1004(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo1004, i,
				     &ctr->ctr1004->array, &ctr->ctr1004->count);
			if (ctr->ctr1004->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1004->count;
			break;
		}

		case 1005:
		{
			struct srvsvc_NetShareInfo1005 i;
			init_srv_share_info_1005(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo1005, i,
				     &ctr->ctr1005->array, &ctr->ctr1005->count);
			if (ctr->ctr1005->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1005->count;
			break;
		}

		case 1006:
		{
			struct srvsvc_NetShareInfo1006 i;
			init_srv_share_info_1006(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo1006, i,
				     &ctr->ctr1006->array, &ctr->ctr1006->count);
			if (ctr->ctr1006->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1006->count;
			break;
		}

		case 1007:
		{
			struct srvsvc_NetShareInfo1007 i;
			init_srv_share_info_1007(p, &i, share);
			ADD_TO_ARRAY(ctx, struct srvsvc_NetShareInfo1007, i,
				     &ctr->ctr1007->array, &ctr->ctr1007->count);
			if (ctr->ctr1007->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1007->count;
			break;
		}

		case 1501:
		{
			struct sec_desc_buf i;
			init_srv_share_info_1501(p, &i, share);
			ADD_TO_ARRAY(ctx, struct sec_desc_buf, i,
				     &ctr->ctr1501->array, &ctr->ctr1501->count);
			if (ctr->ctr1501->array == NULL) {
				return WERR_NOMEM;
			}
			*total_entries = ctr->ctr1501->count;
			break;
		}
		}

		TALLOC_FREE(share);
	}

	result = WERR_OK;
 done:
	TALLOC_FREE(shares);
	return result;
}

/*******************************************************************
 fill in a sess info level 0 structure.
 ********************************************************************/

static void init_srv_sess_info_0(pipes_struct *p, struct srvsvc_NetSessCtr0 *ss0, uint32 *snum, uint32 *stot)
{
	struct sessionid *session_list;
	uint32 num_entries = 0;
	(*stot) = list_sessions(&session_list);

	if (ss0 == NULL) {
		if (snum) {
			(*snum) = 0;
		}
		SAFE_FREE(session_list);
		return;
	}

	DEBUG(5,("init_srv_sess_0_ss0\n"));

	ss0->array = talloc_array(p->mem_ctx, struct srvsvc_NetSessInfo0, *stot);

	if (snum) {
		for (; (*snum) < (*stot); (*snum)++) {
			ss0->array[num_entries].client = session_list[(*snum)].remote_machine;
			num_entries++;
		}

		ss0->count = num_entries;
		
		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
		ss0->array = NULL;
		ss0->count = 0;
	}
	SAFE_FREE(session_list);
}

/*******************************************************************
********************************************************************/

static void sess_file_fn( const struct share_mode_entry *e, 
                          const char *sharepath, const char *fname,
			  void *private_data )
{
	struct sess_file_count *sess = (struct sess_file_count *)private_data;
 
	if ( (procid_to_pid(&e->pid) == sess->pid) && (sess->uid == e->uid) ) {
		sess->count++;
	}
	
	return;
}

/*******************************************************************
********************************************************************/

static int net_count_files( uid_t uid, pid_t pid )
{
	struct sess_file_count s_file_cnt;

	s_file_cnt.count = 0;
	s_file_cnt.uid = uid;
	s_file_cnt.pid = pid;
	
	share_mode_forall( sess_file_fn, (void *)&s_file_cnt );
	
	return s_file_cnt.count;
}

/*******************************************************************
 fill in a sess info level 1 structure.
 ********************************************************************/

static void init_srv_sess_info_1(pipes_struct *p, struct srvsvc_NetSessCtr1 *ss1, uint32 *snum, uint32 *stot)
{
	struct sessionid *session_list;
	uint32 num_entries = 0;
	time_t now = time(NULL);

	if ( !snum ) {
		ss1->count = 0;
		ss1->array = NULL;
		
		(*stot) = 0;

		return;
	}
	
	if (ss1 == NULL) {
		if (snum != NULL)
			(*snum) = 0;
		return;
	}

	(*stot) = list_sessions(&session_list);

	ss1->array = talloc_array(p->mem_ctx, struct srvsvc_NetSessInfo1, *stot);
	
	for (; (*snum) < (*stot); (*snum)++) {
		uint32 num_files;
		uint32 connect_time;
		struct passwd *pw = sys_getpwnam(session_list[*snum].username);
		BOOL guest;
			
		if ( !pw ) {
			DEBUG(10,("init_srv_sess_info_1: failed to find owner: %s\n",
				session_list[*snum].username));
			continue;
		}
				
		connect_time = (uint32)(now - session_list[*snum].connect_start);
		num_files = net_count_files(pw->pw_uid, session_list[*snum].pid);
		guest = strequal( session_list[*snum].username, lp_guestaccount() );
					
		ss1->array[num_entries].client = session_list[*snum].remote_machine;
		ss1->array[num_entries].user = session_list[*snum].username; 
		ss1->array[num_entries].num_open = num_files;
		ss1->array[num_entries].time = connect_time;
		ss1->array[num_entries].idle_time = 0;
		ss1->array[num_entries].user_flags = guest;

		num_entries++;
	}

	ss1->count = num_entries;
	
	if ((*snum) >= (*stot)) {
		(*snum) = 0;
	}

	SAFE_FREE(session_list);
}

/*******************************************************************
 makes a SRV_R_NET_SESS_ENUM structure.
********************************************************************/

static WERROR init_srv_sess_info_ctr(pipes_struct *p, union srvsvc_NetSessCtr *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	WERROR status = WERR_OK;
	DEBUG(5,("init_srv_sess_info_ctr: %d\n", __LINE__));

	switch (switch_value) {
	case 0:
		ctr->ctr0 = talloc(p->mem_ctx, struct srvsvc_NetSessCtr0);
		init_srv_sess_info_0(p, ctr->ctr0, resume_hnd, total_entries);
		break;
	case 1:
		ctr->ctr1 = talloc(p->mem_ctx, struct srvsvc_NetSessCtr1);
		init_srv_sess_info_1(p, ctr->ctr1, resume_hnd, total_entries);
		break;
	default:
		DEBUG(5,("init_srv_sess_info_ctr: unsupported switch value %d\n", switch_value));
		if (resume_hnd != NULL)
			(*resume_hnd) = 0;
		(*total_entries) = 0;
		ctr->ctr0 = NULL;
		status = WERR_UNKNOWN_LEVEL;
		break;
	}

	return status;
}

/*******************************************************************
 fill in a conn info level 0 structure.
 ********************************************************************/

static void init_srv_conn_info_0(pipes_struct *p, struct srvsvc_NetConnCtr0 *ss0, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss0 == NULL) {
		if (snum != NULL)
			(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_0_ss0\n"));

	if (snum) {
		ss0->array = talloc_array(p->mem_ctx, struct srvsvc_NetConnInfo0, *stot);
		for (; (*snum) < (*stot); (*snum)++) {

			ss0->array[num_entries].conn_id = (*stot);

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss0->count = num_entries;
		
		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
		ss0->array = NULL;
		ss0->count = 0;

		(*stot) = 0;
	}
}

/*******************************************************************
 fill in a conn info level 1 structure.
 ********************************************************************/

static void init_srv_conn_info_1(pipes_struct *p, struct srvsvc_NetConnCtr1 *ss1, uint32 *snum, uint32 *stot)
{
	uint32 num_entries = 0;
	(*stot) = 1;

	if (ss1 == NULL) {
		if (snum != NULL)
			(*snum) = 0;
		return;
	}

	DEBUG(5,("init_srv_conn_1_ss1\n"));

	if (snum) {
		ss1->array = talloc_array(p->mem_ctx, struct srvsvc_NetConnInfo1, *stot);
		for (; (*snum) < (*stot); (*snum)++) {
			ss1->array[num_entries].conn_id = (*stot);
			ss1->array[num_entries].conn_type = 0x3;
			ss1->array[num_entries].num_open = 1;
			ss1->array[num_entries].num_users = 1;
			ss1->array[num_entries].conn_time = 3;
			ss1->array[num_entries].user = "dummy_user";
			ss1->array[num_entries].share = "IPC$";

			/* move on to creating next connection */
			/* move on to creating next conn */
			num_entries++;
		}

		ss1->count = num_entries;

		if ((*snum) >= (*stot)) {
			(*snum) = 0;
		}

	} else {
		ss1->count = 0;
		ss1->array = NULL;
		
		(*stot) = 0;
	}
}

/*******************************************************************
 makes a SRV_R_NET_CONN_ENUM structure.
********************************************************************/

static WERROR init_srv_conn_info_ctr(pipes_struct *p, union srvsvc_NetConnCtr *ctr,
				int switch_value, uint32 *resume_hnd, uint32 *total_entries)
{
	WERROR status = WERR_OK;
	DEBUG(5,("init_srv_conn_info_ctr: %d\n", __LINE__));

	switch (switch_value) {
	case 0:
		init_srv_conn_info_0(p, ctr->ctr0, resume_hnd, total_entries);
		break;
	case 1:
		init_srv_conn_info_1(p, ctr->ctr1, resume_hnd, total_entries);
		break;
	default:
		DEBUG(5,("init_srv_conn_info_ctr: unsupported switch value %d\n", switch_value));
		ctr->ctr0 = NULL;
		(*resume_hnd) = 0;
		(*total_entries) = 0;
		status = WERR_UNKNOWN_LEVEL;
		break;
	}

	return status;
}

/*******************************************************************
 makes a SRV_R_NET_FILE_ENUM structure.
********************************************************************/

static WERROR net_file_enum_3(pipes_struct *p, union srvsvc_NetFileCtr *ctr, uint32 *resume_hnd, uint32 *num_entries )
{
	TALLOC_CTX *ctx = get_talloc_ctx();
	WERROR status;

	/* TODO -- Windows enumerates 
	   (b) active pipes
	   (c) open directories and files */

	ctr->ctr3 = talloc_zero(p->mem_ctx, struct srvsvc_NetFileCtr3);
	
	status = net_enum_files( ctx, &ctr->ctr3->array, num_entries, resume_hnd );
	if ( !W_ERROR_IS_OK(status))
		return status;
		
	status = net_enum_pipes( ctx, &ctr->ctr3->array, num_entries, resume_hnd );
	if ( !W_ERROR_IS_OK(status))
		return status;

	ctr->ctr3->count = *num_entries;
	
	return WERR_OK;
}

/*******************************************************************
*******************************************************************/

WERROR _srvsvc_NetFileEnum(pipes_struct *p, const char *server_unc, const char *path, const char *user, uint32_t *level, union srvsvc_NetFileCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	switch ( *level ) {
	case 3:
		return net_file_enum_3(p, ctr, resume_handle, totalentries );	
	default:
		return WERR_UNKNOWN_LEVEL;
	}
	
	return WERR_OK;
}

/*******************************************************************
net server get info
********************************************************************/

WERROR _srvsvc_NetSrvGetInfo(pipes_struct *p, const char *server_unc, uint32_t level, union srvsvc_NetSrvInfo *info)
{
	WERROR status = WERR_OK;

	ZERO_STRUCTP(info);

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_srv_get_info\n"));
		return WERR_ACCESS_DENIED;
	}

	switch (level) {

		/* Technically level 102 should only be available to
		   Administrators but there isn't anything super-secret
		   here, as most of it is made up. */

	case 102:
		info->info102 = talloc_zero(p->mem_ctx, struct srvsvc_NetSrvInfo102);

		info->info102->platform_id = 500;
		info->info102->version_major = lp_major_announce_version();
		info->info102->version_minor = lp_minor_announce_version();
		info->info102->server_name = global_myname(); 
		info->info102->server_type = lp_default_server_announce();
		info->info102->userpath = "C:\\";
		info->info102->licenses = 10000;
		info->info102->anndelta = 3000;
		info->info102->disc = 0xf;
		info->info102->users = 0xffffffff;
		info->info102->hidden = 0;
		info->info102->announce = 240;
		info->info102->comment = lp_serverstring();
		break;
	case 101:
		info->info101 = talloc_zero(p->mem_ctx, struct srvsvc_NetSrvInfo101);
			info->info101->platform_id = 500;
			info->info101->server_name = global_myname();
			info->info101->version_major = lp_major_announce_version();
			info->info101->version_minor = lp_minor_announce_version();
			info->info101->server_type = lp_default_server_announce();
			info->info101->comment = lp_serverstring();
		break;
	case 100:
		info->info100 = talloc_zero(p->mem_ctx, struct srvsvc_NetSrvInfo100);
		info->info100->platform_id = 500;
		info->info100->server_name = global_myname();
		break;
	default:
		return WERR_UNKNOWN_LEVEL;
		break;
	}

	DEBUG(5,("srv_net_srv_get_info: %d\n", __LINE__));

	return status;
}

/*******************************************************************
net server set info
********************************************************************/

WERROR _srvsvc_NetSrvSetInfo(pipes_struct *p, const char *server_unc, uint32_t level, union srvsvc_NetSrvInfo info, uint32_t *parm_error)
{
	/* Set up the net server set info structure. */
	if (parm_error) {
		*parm_error = 0;
	}
	return WERR_OK;
}

/*******************************************************************
net conn enum
********************************************************************/

WERROR _srvsvc_NetConnEnum(pipes_struct *p, const char *server_unc, const char *path, uint32_t *level, union srvsvc_NetConnCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	DEBUG(5,("srv_net_conn_enum: %d\n", __LINE__));

	ZERO_STRUCTP(ctr);

	/* set up the */
	return init_srv_conn_info_ctr(p, ctr, *level, resume_handle, totalentries);
}

/*******************************************************************
net sess enum
********************************************************************/

WERROR _srvsvc_NetSessEnum(pipes_struct *p, const char *server_unc, const char *client, const char *user, uint32_t *level, union srvsvc_NetSessCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	DEBUG(5,("_srv_net_sess_enum: %d\n", __LINE__));

	ZERO_STRUCTP(ctr);

	/* set up the */
	return init_srv_sess_info_ctr(p, ctr,
				*level, 
				resume_handle,
				totalentries);
}

/*******************************************************************
net sess del
********************************************************************/

WERROR _srvsvc_NetSessDel(pipes_struct *p, const char *server_unc, const char *client, const char *user)
{
	struct sessionid *session_list;
	int num_sessions, snum;
	WERROR status;

	char *machine = talloc_strdup(p->mem_ctx, server_unc);

	/* strip leading backslashes if any */
	while (machine[0] == '\\') {
		memmove(machine, &machine[1], strlen(machine));
	}

	num_sessions = list_sessions(&session_list);

	DEBUG(5,("_srv_net_sess_del: %d\n", __LINE__));

	status = WERR_ACCESS_DENIED;

	/* fail out now if you are not root or not a domain admin */

	if ((p->pipe_user.ut.uid != sec_initial_uid()) && 
		( ! nt_token_check_domain_rid(p->pipe_user.nt_user_token, DOMAIN_GROUP_RID_ADMINS))) {

		goto done;
	}

	for (snum = 0; snum < num_sessions; snum++) {

		if ((strequal(session_list[snum].username, user) || user[0] == '\0' ) &&
		    strequal(session_list[snum].remote_machine, machine)) {
		
			if (message_send_pid(pid_to_procid(session_list[snum].pid), MSG_SHUTDOWN, NULL, 0, False))
				status = WERR_OK;
		}
	}

	DEBUG(5,("_srv_net_sess_del: %d\n", __LINE__));


done:
	SAFE_FREE(session_list);

	return status;
}

/*******************************************************************
 Net share enum all.
********************************************************************/

WERROR _srvsvc_NetShareEnumAll(pipes_struct *p, const char *server_unc, uint32_t *level, union srvsvc_NetShareCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_share_enum_all\n"));
		return WERR_ACCESS_DENIED;
	}

	/* Create the list of shares for the response. */
	return init_srv_share_info_ctr(p, ctr, *level,
					      resume_handle, totalentries, True);
}

/*******************************************************************
 Net share enum.
********************************************************************/

WERROR _srvsvc_NetShareEnum(pipes_struct *p, const char *server_unc, uint32_t *level, union srvsvc_NetShareCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	DEBUG(5,("_srv_net_share_enum: %d\n", __LINE__));

	if (!pipe_access_check(p)) {
		DEBUG(3, ("access denied to srv_net_share_enum\n"));
		return WERR_ACCESS_DENIED;
	}

	/* Create the list of shares for the response. */
	return init_srv_share_info_ctr(p, ctr, *level,
					      resume_handle, totalentries, False);
}

/*******************************************************************
 Net share get info.
********************************************************************/

WERROR _srvsvc_NetShareGetInfo(pipes_struct *p, const char *server_unc, const char *share_name, uint32_t level, union srvsvc_NetShareInfo *info)
{
	const struct share_params *params;

	params = get_share_params(p->mem_ctx, share_name);

	if (params != NULL) {
		switch (level) {
		case 0:
			info->info0 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo0);
			init_srv_share_info_0(p, info->info0,
					      params);
			break;
		case 1:
			info->info1 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo1);
			init_srv_share_info_1(p, info->info1,
					      params);
			break;
		case 2:
			info->info2 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo2);
			init_srv_share_info_2(p, info->info2,
					      params);
			break;
		case 501:
			info->info501 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo501);
			init_srv_share_info_501(p, info->info501,
						params);
			break;
		case 502:
			info->info502 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo502);
			init_srv_share_info_502(p, info->info502,
						params);
			break;

			/* here for completeness */
		case 1004:
			info->info1004 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo1004);
			init_srv_share_info_1004(p, info->info1004,
						 params);
			break;
		case 1005:
			info->info1005 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo1005);
			init_srv_share_info_1005(p, info->info1005,
						 params);
			break;

			/* here for completeness 1006 - 1501 */
		case 1006:
			info->info1006 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo1006);
			init_srv_share_info_1006(p, info->info1006,
						 params);
			break;
		case 1007:
			info->info1007 = talloc(p->mem_ctx, struct srvsvc_NetShareInfo1007);
			init_srv_share_info_1007(p, info->info1007,
						 params);
			break;
		case 1501:
			info->info1501 = talloc(p->mem_ctx, struct sec_desc_buf);
			init_srv_share_info_1501(p, info->info1501,
						 params);
			break;
		default:
			DEBUG(5,("init_srv_net_share_get_info: unsupported "
				 "switch value %d\n", level));
			return WERR_UNKNOWN_LEVEL;
			break;
		}
	} else {
		return WERR_INVALID_NAME;
	}

	return WERR_OK;
}

/*******************************************************************
 Check a given DOS pathname is valid for a share.
********************************************************************/

char *valid_share_pathname(char *dos_pathname)
{
	char *ptr;

	/* Convert any '\' paths to '/' */
	unix_format(dos_pathname);
	unix_clean_name(dos_pathname);

	/* NT is braindead - it wants a C: prefix to a pathname ! So strip it. */
	ptr = dos_pathname;
	if (strlen(dos_pathname) > 2 && ptr[1] == ':' && ptr[0] != '/')
		ptr += 2;

	/* Only absolute paths allowed. */
	if (*ptr != '/')
		return NULL;

	return ptr;
}

static void setval_helper(struct registry_key *key, const char *name,
			  const char *value, WERROR *err)
{
	struct registry_value val;

	if (!W_ERROR_IS_OK(*err)) {
		return;
	}

	ZERO_STRUCT(val);
	val.type = REG_SZ;
	val.v.sz.str = CONST_DISCARD(char *, value);
	val.v.sz.len = strlen(value)+1;

	*err = reg_setvalue(key, name, &val);
}

static WERROR add_share(const char *share_name, const char *path,
			const char *comment, uint32 max_connections,
			const struct nt_user_token *token,
			BOOL is_disk_op)
{
	if (lp_add_share_cmd() && *lp_add_share_cmd()) {
		char *command;
		int ret;

		if (asprintf(&command, "%s \"%s\" \"%s\" \"%s\" \"%s\" %d",
			     lp_add_share_cmd(), dyn_CONFIGFILE, share_name,
			     path, comment, max_connections) == -1) {
			return WERR_NOMEM;
		}

		DEBUG(10,("add_share: Running [%s]\n", command ));

		/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/
	
		if ( is_disk_op )
			become_root();

		if ( (ret = smbrun(command, NULL)) == 0 ) {
			/* Tell everyone we updated smb.conf. */
			message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED,
					 NULL, 0, False, NULL);
		}

		if ( is_disk_op )
			unbecome_root();
		
		/********* END SeDiskOperatorPrivilege BLOCK *********/

		DEBUG(3,("_srv_net_share_add: Running [%s] returned (%d)\n",
			 command, ret ));

		/*
		 * No fallback to registry shares, the user did define a add
		 * share command, so fail here.
		 */

		SAFE_FREE(command);
		return (ret == 0) ? WERR_OK : WERR_ACCESS_DENIED;
	}

	if (lp_registry_shares()) {
		char *keyname;
		struct registry_key *key;
		enum winreg_CreateAction action;
		WERROR err;
		TALLOC_CTX *mem_ctx;

		if (!(keyname = talloc_asprintf(NULL, "%s\\%s", KEY_SMBCONF,
						share_name))) {
			return WERR_NOMEM;
		}

		mem_ctx = (TALLOC_CTX *)keyname;

		err = reg_create_path(mem_ctx, keyname, REG_KEY_WRITE,
				      is_disk_op ? get_root_nt_token():token,
				      &action, &key);

		if (action != REG_CREATED_NEW_KEY) {
			err = WERR_ALREADY_EXISTS;
		}

		if (!W_ERROR_IS_OK(err)) {
			TALLOC_FREE(mem_ctx);
			return err;
		}

		setval_helper(key, "path", path, &err);
		if ((comment != NULL) && (comment[0] != '\0')) {
			setval_helper(key, "comment", comment, &err);
		}
		if (max_connections != 0) {
			char tmp[16];
			snprintf(tmp, sizeof(tmp), "%d", max_connections);
			setval_helper(key, "max connections", tmp, &err);
		}

		if (!W_ERROR_IS_OK(err)) {
			/*
			 * Hmmmm. We'd need transactions on the registry to
			 * get this right....
			 */
			reg_delete_path(is_disk_op ? get_root_nt_token():token,
					keyname);
		}
		TALLOC_FREE(mem_ctx);
		return err;
	}

	return WERR_ACCESS_DENIED;
}

static WERROR delete_share(const char *sharename, 
			   const struct nt_user_token *token,
			   BOOL is_disk_op)
{
	if (lp_delete_share_cmd() && *lp_delete_share_cmd()) {
		char *command;
		int ret;

		if (asprintf(&command, "%s \"%s\" \"%s\"",
			     lp_delete_share_cmd(), dyn_CONFIGFILE,
			     sharename)) {
			return WERR_NOMEM;
		}

		DEBUG(10,("delete_share: Running [%s]\n", command ));

		/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/
	
		if ( is_disk_op )
			become_root();

		if ( (ret = smbrun(command, NULL)) == 0 ) {
			/* Tell everyone we updated smb.conf. */
			message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED,
					 NULL, 0, False, NULL);
		}

		if ( is_disk_op )
			unbecome_root();

		/********* END SeDiskOperatorPrivilege BLOCK *********/

		SAFE_FREE(command);

		DEBUG(3,("_srv_net_share_del: Running [%s] returned (%d)\n",
			 command, ret ));
		return (ret == 0) ? WERR_OK : WERR_ACCESS_DENIED;
	}

	if (lp_registry_shares()) {
		char *keyname;
		WERROR err;

		if (asprintf(&keyname, "%s\\%s", KEY_SMBCONF,
			     sharename) == -1) {
			return WERR_NOMEM;
		}

		err = reg_delete_path(is_disk_op ? get_root_nt_token():token,
				      keyname);
		SAFE_FREE(keyname);
		return err;
	}

	return WERR_ACCESS_DENIED;
}

static WERROR change_share(const char *share_name, const char *path,
			   const char *comment, uint32 max_connections,
			   const struct nt_user_token *token,
			   BOOL is_disk_op)
{
	if (lp_change_share_cmd() && *lp_change_share_cmd()) {
		char *command;
		int ret;

		if (asprintf(&command, "%s \"%s\" \"%s\" \"%s\" \"%s\" %d",
			     lp_change_share_cmd(), dyn_CONFIGFILE, share_name,
			     path, comment, max_connections) == -1) {
			return WERR_NOMEM;
		}

		DEBUG(10,("_srv_net_share_set_info: Running [%s]\n", command));
				
		/********* BEGIN SeDiskOperatorPrivilege BLOCK *********/
	
		if ( is_disk_op )
			become_root();
			
		if ( (ret = smbrun(command, NULL)) == 0 ) {
			/* Tell everyone we updated smb.conf. */
			message_send_all(conn_tdb_ctx(), MSG_SMB_CONF_UPDATED,
					 NULL, 0, False, NULL);
		}
		
		if ( is_disk_op )
			unbecome_root();
			
		/********* END SeDiskOperatorPrivilege BLOCK *********/

		DEBUG(3,("_srv_net_share_set_info: Running [%s] returned "
			 "(%d)\n", command, ret ));

		SAFE_FREE(command);

		return (ret == 0) ? WERR_OK : WERR_ACCESS_DENIED;
	}

	if (lp_registry_shares()) {
		char *keyname;
		struct registry_key *key;
		WERROR err;
		TALLOC_CTX *mem_ctx;

		if (!(keyname = talloc_asprintf(NULL, "%s\\%s", KEY_SMBCONF,
						share_name))) {
			return WERR_NOMEM;
		}

		mem_ctx = (TALLOC_CTX *)keyname;

		err = reg_open_path(mem_ctx, keyname, REG_KEY_WRITE,
				    is_disk_op ? get_root_nt_token():token,
				    &key);
		if (!W_ERROR_IS_OK(err)) {
			TALLOC_FREE(mem_ctx);
			return err;
		}

		setval_helper(key, "path", path, &err);

		reg_deletevalue(key, "comment");
		if ((comment != NULL) && (comment[0] != '\0')) {
			setval_helper(key, "comment", comment, &err);
		}

		reg_deletevalue(key, "max connections");
		if (max_connections != 0) {
			char tmp[16];
			snprintf(tmp, sizeof(tmp), "%d", max_connections);
			setval_helper(key, "max connections", tmp, &err);
		}

		TALLOC_FREE(mem_ctx);
		return err;
	}		

	return WERR_ACCESS_DENIED;
}

/*******************************************************************
 Net share set info. Modify share details.
********************************************************************/

WERROR _srvsvc_NetShareSetInfo(pipes_struct *p, const char *server_unc,
			       const char *share_name, uint32_t level,
			       union srvsvc_NetShareInfo info,
			       uint32_t *parm_error)
{
	pstring comment;
	pstring pathname;
	int type;
	int snum;
	char *path;
	SEC_DESC *psd = NULL;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	BOOL is_disk_op = False;
	int max_connections = 0;
	fstring tmp_share_name;

	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	if (parm_error) {
		*parm_error = 0;
	}

	if ( strequal(share_name,"IPC$") 
		|| ( lp_enable_asu_support() && strequal(share_name,"ADMIN$") )
		|| strequal(share_name,"global") )
	{
		return WERR_ACCESS_DENIED;
	}

	fstrcpy(tmp_share_name, share_name);
	snum = find_service(tmp_share_name);

	/* Does this share exist ? */
	if (snum < 0)
		return WERR_NET_NAME_NOT_FOUND;

	/* No change to printer shares. */
	if (lp_print_ok(snum))
		return WERR_ACCESS_DENIED;

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token,
					  &se_diskop );
	
	/* fail out now if you are not root and not a disk op */
	
	if ( p->pipe_user.ut.uid != sec_initial_uid() && !is_disk_op )
		return WERR_ACCESS_DENIED;

	switch (level) {
	case 1:
		pstrcpy(pathname, lp_pathname(snum));
		pstrcpy(comment, info.info1->comment);
		type = info.info1->type;
		psd = NULL;
		break;
	case 2:
		pstrcpy(comment, info.info2->comment);
		pstrcpy(pathname, info.info2->path);
		type = info.info2->type;
		max_connections = (info.info2->max_users == 0xffffffff) ?
			0 : info.info2->max_users;
		psd = NULL;
		break;
	case 502:
		pstrcpy(comment, info.info502->comment);
		pstrcpy(pathname, info.info502->path);
		type = info.info502->type;
		psd = info.info502->sd;
		map_generic_share_sd_bits(psd);
		break;
	case 1004:
		pstrcpy(pathname, lp_pathname(snum));
		pstrcpy(comment, info.info1004->comment);
		type = STYPE_DISKTREE;
		break;
	case 1005:
                /* XP re-sets the csc policy even if it wasn't changed by the
		   user, so we must compare it to see if it's what is set in
		   smb.conf, so that we can contine other ops like setting
		   ACLs on a share */
		if (((info.info1005->dfs_flags &
		      SHARE_1005_CSC_POLICY_MASK) >>
		     SHARE_1005_CSC_POLICY_SHIFT) == lp_csc_policy(snum))
			return WERR_OK;
		else {
			DEBUG(3, ("_srv_net_share_set_info: client is trying "
				  "to change csc policy from the network; "
				  "must be done with smb.conf\n"));
			return WERR_ACCESS_DENIED;
		}
	case 1006:
	case 1007:
		return WERR_ACCESS_DENIED;
	case 1501:
		pstrcpy(pathname, lp_pathname(snum));
		pstrcpy(comment, lp_comment(snum));
		psd = info.info1501->sd;
		map_generic_share_sd_bits(psd);
		type = STYPE_DISKTREE;
		break;
	default:
		DEBUG(5,("_srv_net_share_set_info: unsupported switch value "
			 "%d\n", level));
		return WERR_UNKNOWN_LEVEL;
	}

	/* We can only modify disk shares. */
	if (type != STYPE_DISKTREE)
		return WERR_ACCESS_DENIED;
		
	/* Check if the pathname is valid. */
	if (!(path = valid_share_pathname( pathname )))
		return WERR_OBJECT_PATH_INVALID;

	/* Ensure share name, pathname and comment don't contain '"'
	 * characters. */
	string_replace(tmp_share_name, '"', ' ');
	string_replace(path, '"', ' ');
	string_replace(comment, '"', ' ');

	DEBUG(10,("_srv_net_share_set_info: change share command = %s\n",
		  lp_change_share_cmd() ? lp_change_share_cmd() : "NULL" ));

	/* Only call modify function if something changed. */
	
	if (strcmp(path, lp_pathname(snum))
	    || strcmp(comment, lp_comment(snum)) 
	    || (lp_max_connections(snum) != max_connections) ) {
		WERROR err;

		err = change_share(tmp_share_name, path, comment,
				   max_connections, p->pipe_user.nt_user_token,
				   is_disk_op);

		if (!W_ERROR_IS_OK(err)) {
			return err;
		}
	}

	/* Replace SD if changed. */
	if (psd) {
		SEC_DESC *old_sd;
		size_t sd_size;

		old_sd = get_share_security(p->mem_ctx, lp_servicename(snum),
					    &sd_size);

		if (old_sd && !sec_desc_equal(old_sd, psd)) {
			if (!set_share_security(share_name, psd)) {
				DEBUG(0,("_srv_net_share_set_info: Failed to "
					 "change security info in share %s.\n",
					 share_name ));
			}
		}
	}
			
	DEBUG(5,("_srv_net_share_set_info: %d\n", __LINE__));

	return WERR_OK;
}


/*******************************************************************
 Net share add. Call 'add_share_command "sharename" "pathname" 
 "comment" "max connections = "
********************************************************************/

WERROR _srvsvc_NetShareAdd(pipes_struct *p, const char *server_unc,
			   uint32_t level, union srvsvc_NetShareInfo info,
			   uint32_t *parm_error)
{
	pstring share_name;
	pstring comment;
	pstring pathname;
	char *path;
	int type;
	SEC_DESC *psd = NULL;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	BOOL is_disk_op;
	uint32 max_connections = 0;
	WERROR err;

	DEBUG(5,("_srv_net_share_add: %d\n", __LINE__));

	if (parm_error) {
		*parm_error = 0;
	}

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token,
					  &se_diskop );

	if (p->pipe_user.ut.uid != sec_initial_uid()  && !is_disk_op ) 
		return WERR_ACCESS_DENIED;

	switch (level) {
	case 0:
		/* No path. Not enough info in a level 0 to do anything. */
		return WERR_ACCESS_DENIED;
	case 1:
		/* Not enough info in a level 1 to do anything. */
		return WERR_ACCESS_DENIED;
	case 2:
		pstrcpy(share_name, info.info2->name);
		pstrcpy(comment, info.info2->comment);
		pstrcpy(pathname, info.info2->path);
		max_connections = (info.info2->max_users == 0xffffffff) ?
			0 : info.info2->max_users;
		type = info.info2->type;
		break;
	case 501:
		/* No path. Not enough info in a level 501 to do anything. */
		return WERR_ACCESS_DENIED;
	case 502:
		pstrcpy(share_name, info.info502->name);
		pstrcpy(comment, info.info502->comment);
		pstrcpy(pathname, info.info502->path);
		type = info.info502->type;
		psd = info.info502->sd;
		map_generic_share_sd_bits(psd);
		break;

		/* none of the following contain share names.  NetShareAdd
		 * does not have a separate parameter for the share name */ 

	case 1004:
	case 1005:
	case 1006:
	case 1007:
		return WERR_ACCESS_DENIED;
	case 1501:
		/* DFS only level. */
		return WERR_ACCESS_DENIED;
	default:
		DEBUG(5,("_srv_net_share_add: unsupported switch value %d\n",
			 level));
		return WERR_UNKNOWN_LEVEL;
	}

	/* check for invalid share names */

	if ( !validate_net_name( share_name, INVALID_SHARENAME_CHARS,
				 sizeof(share_name) ) ) {
		DEBUG(5,("_srv_net_name_validate: Bad sharename \"%s\"\n",
			 share_name));
		return WERR_INVALID_NAME;
	}

	if ( strequal(share_name,"IPC$") || strequal(share_name,"global")
	     || ( lp_enable_asu_support() && strequal(share_name,"ADMIN$") ) )
	{
		return WERR_ACCESS_DENIED;
	}

	if (get_share_params(p->mem_ctx, share_name) != NULL) {
		/* Share already exists. */
		return WERR_ALREADY_EXISTS;
	}

	/* We can only add disk shares. */
	if (type != STYPE_DISKTREE)
		return WERR_ACCESS_DENIED;
		
	/* Check if the pathname is valid. */
	if (!(path = valid_share_pathname( pathname )))
		return WERR_OBJECT_PATH_INVALID;

	/* Ensure share name, pathname and comment don't contain '"'
	 * characters. */

	string_replace(share_name, '"', ' ');
	string_replace(path, '"', ' ');
	string_replace(comment, '"', ' ');

	err = add_share(share_name, path, comment, max_connections,
			p->pipe_user.nt_user_token, is_disk_op);

	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	if (psd) {
		if (!set_share_security(share_name, psd)) {
			DEBUG(0,("_srv_net_share_add: Failed to add security "
				 "info to share %s.\n", share_name ));
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

WERROR _srvsvc_NetShareDel(pipes_struct *p, const char *server_unc,
			   const char *share_name, uint32_t reserved)
{
	struct share_params *params;
	SE_PRIV se_diskop = SE_DISK_OPERATOR;
	BOOL is_disk_op;
	WERROR err;

	DEBUG(5,("_srv_net_share_del: %d\n", __LINE__));

	if ( strequal(share_name,"IPC$") 
	     || ( lp_enable_asu_support() && strequal(share_name,"ADMIN$") )
	     || strequal(share_name,"global") )
	{
		return WERR_ACCESS_DENIED;
	}

	if (!(params = get_share_params(p->mem_ctx, share_name))) {
		return WERR_NO_SUCH_SHARE;
	}

	/* No change to printer shares. */
	if (lp_print_ok(params->service))
		return WERR_ACCESS_DENIED;

	is_disk_op = user_has_privileges( p->pipe_user.nt_user_token,
					  &se_diskop );

	if (p->pipe_user.ut.uid != sec_initial_uid()  && !is_disk_op ) 
		return WERR_ACCESS_DENIED;

	err = delete_share(lp_servicename(params->service),
			   p->pipe_user.nt_user_token, is_disk_op);

	if (!W_ERROR_IS_OK(err)) {
		return err;
	}

	/* Delete the SD in the database. */
	delete_share_security(params);

	lp_killservice(params->service);

	return WERR_OK;
}

WERROR _srvsvc_NetShareDelSticky(pipes_struct *p, const char *server_unc,
				 const char *share_name, uint32_t reserved)
{
	DEBUG(5,("_srv_net_share_del_stick: %d\n", __LINE__));

	return _srvsvc_NetShareDel(p, server_unc, share_name, reserved);
}

/*******************************************************************
time of day
********************************************************************/

WERROR _srvsvc_NetRemoteTOD(pipes_struct *p, const char *server_unc, struct srvsvc_NetRemoteTODInfo *tod)
{
	struct tm *t;
	time_t unixdate = time(NULL);
	WERROR status = WERR_OK;

	/* We do this call first as if we do it *after* the gmtime call
	   it overwrites the pointed-to values. JRA */

	uint32 zone = get_time_zone(unixdate)/60;

	DEBUG(5,("_srv_net_remote_tod: %d\n", __LINE__));

	t = gmtime(&unixdate);

	/* set up the */
	tod->elapsed = unixdate;
	tod->msecs = 0;
	tod->hours = t->tm_hour;
	tod->mins = t->tm_min;
	tod->secs = t->tm_sec;
	tod->hunds = 0;
	tod->timezone = zone;
	tod->tinterval = 10000;
	tod->day = t->tm_mday;
	tod->month = t->tm_mon + 1;
	tod->year = 1900+t->tm_year;
	tod->weekday = t->tm_wday;
	
	DEBUG(5,("_srv_net_remote_tod: %d\n", __LINE__));

	return status;
}

/***********************************************************************************
 Win9x NT tools get security descriptor.
***********************************************************************************/

WERROR _srvsvc_NetGetFileSecurity(pipes_struct *p, const char *server_unc, const char *share, const char *file, uint32_t securityinformation, struct sec_desc_buf *sd_buf)
{
	SEC_DESC *psd = NULL;
	size_t sd_size;
	DATA_BLOB null_pw;
	files_struct *fsp = NULL;
	SMB_STRUCT_STAT st;
	BOOL bad_path;
	NTSTATUS nt_status;
	connection_struct *conn = NULL;
	BOOL became_user = False; 
	WERROR status = WERR_OK;
	pstring tmp_file;

	ZERO_STRUCT(st);


	/* Null password is ok - we are already an authenticated user... */
	null_pw = data_blob(NULL, 0);

	become_root();
	conn = make_connection(share, null_pw, "A:", p->pipe_user.vuid, &nt_status);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to connect to %s\n", share));
		status = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_query_secdesc: Can't become connected user!\n"));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
	became_user = True;

	pstrcpy(tmp_file, file);
	unix_convert(tmp_file, conn, NULL, &bad_path, &st);
	if (bad_path) {
		DEBUG(3,("_srv_net_file_query_secdesc: bad pathname %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	if (!check_name(file,conn)) {
		DEBUG(3,("_srv_net_file_query_secdesc: can't access %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	nt_status = open_file_stat(conn, file, &st, &fsp);
	if (!NT_STATUS_IS_OK(nt_status)) {
		/* Perhaps it is a directory */
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_IS_A_DIRECTORY))
			nt_status = open_directory(conn, file, &st,
					READ_CONTROL_ACCESS,
					FILE_SHARE_READ|FILE_SHARE_WRITE,
					FILE_OPEN,
					0,
					NULL, &fsp);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(3,("_srv_net_file_query_secdesc: Unable to open file %s\n", file));
			status = WERR_ACCESS_DENIED;
			goto error_exit;
		}
	}

	sd_size = SMB_VFS_GET_NT_ACL(fsp, fsp->fsp_name, (OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION), &psd);

	if (sd_size == 0) {
		DEBUG(3,("_srv_net_file_query_secdesc: Unable to get NT ACL for file %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	sd_buf->sd_size= sd_size;
	sd_buf->sd = psd;

	psd->dacl->revision = (uint16) NT4_ACL_REVISION;

	close_file(fsp, NORMAL_CLOSE);
	unbecome_user();
	close_cnum(conn, p->pipe_user.vuid);
	return status;

error_exit:

	if(fsp) {
		close_file(fsp, NORMAL_CLOSE);
	}

	if (became_user)
		unbecome_user();

	if (conn) 
		close_cnum(conn, p->pipe_user.vuid);

	return status;
}

/***********************************************************************************
 Win9x NT tools set security descriptor.
***********************************************************************************/

WERROR _srvsvc_NetSetFileSecurity(pipes_struct *p, const char *server_unc, const char *share, const char *file, uint32_t securityinformation, struct sec_desc_buf sd_buf)
{
	BOOL ret;
	DATA_BLOB null_pw;
	files_struct *fsp = NULL;
	SMB_STRUCT_STAT st;
	BOOL bad_path;
	NTSTATUS nt_status;
	connection_struct *conn = NULL;
	BOOL became_user = False;
	WERROR status = WERR_OK;
	pstring tmp_file;

	ZERO_STRUCT(st);

	/* Null password is ok - we are already an authenticated user... */
	null_pw = data_blob(NULL, 0);

	become_root();
	conn = make_connection(share, null_pw, "A:", p->pipe_user.vuid, &nt_status);
	unbecome_root();

	if (conn == NULL) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to connect to %s\n", share));
		status = ntstatus_to_werror(nt_status);
		goto error_exit;
	}

	if (!become_user(conn, conn->vuid)) {
		DEBUG(0,("_srv_net_file_set_secdesc: Can't become connected user!\n"));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}
	became_user = True;

	pstrcpy(tmp_file, file);
	unix_convert(tmp_file, conn, NULL, &bad_path, &st);
	if (bad_path) {
		DEBUG(3,("_srv_net_file_set_secdesc: bad pathname %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	if (!check_name(file,conn)) {
		DEBUG(3,("_srv_net_file_set_secdesc: can't access %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}


	nt_status = open_file_stat(conn, file, &st, &fsp);

	if (!NT_STATUS_IS_OK(nt_status)) {
		/* Perhaps it is a directory */
		if (NT_STATUS_EQUAL(nt_status, NT_STATUS_FILE_IS_A_DIRECTORY))
			nt_status = open_directory(conn, file, &st,
						FILE_READ_ATTRIBUTES,
						FILE_SHARE_READ|FILE_SHARE_WRITE,
						FILE_OPEN,
						0,
						NULL, &fsp);

		if (!NT_STATUS_IS_OK(nt_status)) {
			DEBUG(3,("_srv_net_file_set_secdesc: Unable to open file %s\n", file));
			status = WERR_ACCESS_DENIED;
			goto error_exit;
		}
	}

	ret = SMB_VFS_SET_NT_ACL(fsp, fsp->fsp_name, securityinformation, sd_buf.sd);

	if (ret == False) {
		DEBUG(3,("_srv_net_file_set_secdesc: Unable to set NT ACL on file %s\n", file));
		status = WERR_ACCESS_DENIED;
		goto error_exit;
	}

	close_file(fsp, NORMAL_CLOSE);
	unbecome_user();
	close_cnum(conn, p->pipe_user.vuid);
	return status;

error_exit:

	if(fsp) {
		close_file(fsp, NORMAL_CLOSE);
	}

	if (became_user) {
		unbecome_user();
	}

	if (conn) {
		close_cnum(conn, p->pipe_user.vuid);
	}

	return status;
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

WERROR _srvsvc_NetDiskEnum(pipes_struct *p, const char *server_unc, uint32_t level, struct srvsvc_NetDiskInfo *info, uint32_t maxlen, uint32_t *totalentries, uint32_t *resume_handle)
{
	uint32 i;
	const char *disk_name;

	WERROR status = WERR_OK;

	*totalentries = init_server_disk_enum(resume_handle);
	info->count = 0;

	if(!(info->disks =  TALLOC_ARRAY(p->mem_ctx, struct srvsvc_NetDiskInfo0, MAX_SERVER_DISK_ENTRIES))) {
		return WERR_NOMEM;
	}

	/*allow one struct srvsvc_NetDiskInfo0 for null terminator*/

	for(i = 0; i < MAX_SERVER_DISK_ENTRIES -1 && (disk_name = next_server_disk_enum(resume_handle)); i++) {

		info->count++;
		(*totalentries)++;

		/*copy disk name into a unicode string*/

		info->disks[i].disk = disk_name; 
	}

	/* add a terminating null string.  Is this there if there is more data to come? */

	info->count++;
	(*totalentries)++;

	info->disks[i].disk = "";

	return status;
}

/********************************************************************
********************************************************************/

WERROR _srvsvc_NetNameValidate(pipes_struct *p, const char *server_unc, const char *name, uint32_t name_type, uint32_t flags)
{
	int len;

	if ((flags != 0x0) && (flags != 0x80000000)) {
		return WERR_INVALID_PARAM;
	}

	switch ( name_type ) {
	case 0x9:
		len = strlen_m(name);

		if ((flags == 0x0) && (len > 81)) {
			DEBUG(5,("_srv_net_name_validate: share name too long (%s > 81 chars)\n", name));
			return WERR_INVALID_NAME;
		}
		if ((flags == 0x80000000) && (len > 13)) {
			DEBUG(5,("_srv_net_name_validate: share name too long (%s > 13 chars)\n", name));
			return WERR_INVALID_NAME;
		}

		if ( ! validate_net_name( name, INVALID_SHARENAME_CHARS, sizeof(name) ) ) {
			DEBUG(5,("_srv_net_name_validate: Bad sharename \"%s\"\n", name));
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

WERROR _srvsvc_NetFileClose(pipes_struct *p, const char *server_unc, uint32_t fid)
{
	return WERR_ACCESS_DENIED;
}

WERROR _srvsvc_NetCharDevEnum(pipes_struct *p, const char *server_unc, uint32_t *level, union srvsvc_NetCharDevCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevGetInfo(pipes_struct *p, const char *server_unc, const char *device_name, uint32_t level, union srvsvc_NetCharDevInfo *info)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevControl(pipes_struct *p, const char *server_unc, const char *device_name, uint32_t opcode)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQEnum(pipes_struct *p, const char *server_unc, const char *user, uint32_t *level, union srvsvc_NetCharDevQCtr *ctr, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQGetInfo(pipes_struct *p, const char *server_unc, const char *queue_name, const char *user, uint32_t level, union srvsvc_NetCharDevQInfo *info)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQSetInfo(pipes_struct *p, const char *server_unc, const char *queue_name, uint32_t level, union srvsvc_NetCharDevQInfo info, uint32_t *parm_error)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQPurge(pipes_struct *p, const char *server_unc, const char *queue_name)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetCharDevQPurgeSelf(pipes_struct *p, const char *server_unc, const char *queue_name, const char *computer_name)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetFileGetInfo(pipes_struct *p, const char *server_unc, uint32_t fid, uint32_t level, union srvsvc_NetFileInfo *info)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareCheck(pipes_struct *p, const char *server_unc, const char *device_name, enum srvsvc_ShareType *type)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerStatisticsGet(pipes_struct *p, const char *server_unc, const char *service, uint32_t level, uint32_t options, struct srvsvc_Statistics *stats)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportAdd(pipes_struct *p, const char *server_unc, uint32_t level, union srvsvc_NetTransportInfo info)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportEnum(pipes_struct *p, const char *server_unc, uint32_t *level, union srvsvc_NetTransportCtr *transports, uint32_t max_buffer, uint32_t *totalentries, uint32_t *resume_handle)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetTransportDel(pipes_struct *p, const char *server_unc, uint32_t unknown, struct srvsvc_NetTransportInfo0 transport)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetSetServiceBits(pipes_struct *p, const char *server_unc, const char *transport, uint32_t servicebits, uint32_t updateimmediately)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathType(pipes_struct *p, const char *server_unc, const char *path, uint32_t pathflags, uint32_t *pathtype)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathCanonicalize(pipes_struct *p, const char *server_unc, const char *path, uint8_t *can_path, uint32_t maxbuf, const char *prefix, uint32_t *pathtype, uint32_t pathflags)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPathCompare(pipes_struct *p, const char *server_unc, const char *path1, const char *path2, uint32_t pathtype, uint32_t pathflags)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRPRNAMECANONICALIZE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetPRNameCompare(pipes_struct *p, const char *server_unc, const char *name1, const char *name2, uint32_t name_type, uint32_t flags)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDelStart(pipes_struct *p, const char *server_unc, const char *share, uint32_t reserved, struct policy_handle *hnd)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetShareDelCommit(pipes_struct *p, struct policy_handle *hnd)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerTransportAddEx(pipes_struct *p, const char *server_unc, uint32_t level, union srvsvc_NetTransportInfo info)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NetServerSetServiceBitsEx(pipes_struct *p, const char *server_unc, const char *emulated_server_unc, const char *transport, uint32_t servicebitsofinterest, uint32_t servicebits, uint32_t updateimmediately)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSGETVERSION(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSCREATELOCALPARTITION(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSDELETELOCALPARTITION(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSSETLOCALVOLUMESTATE(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSSETSERVERINFO(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSCREATEEXITPOINT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSDELETEEXITPOINT(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRSERVERTRANSPORTDELEX(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSMANAGERREPORTSITEINFO(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSMODIFYPREFIX(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}

WERROR _srvsvc_NETRDFSFIXLOCALVOLUME(pipes_struct *p)
{
	p->rng_fault_state = True;
	return WERR_NOT_SUPPORTED;
}
