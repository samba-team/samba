/* 
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997,
 *  Copyright (C) Jeremy Allison		    1999,
 *  Copyright (C) Nigel Williams		    2001,
 *  Copyright (C) Jim McDonough (jmcd@us.ibm.com)   2002.
 *  Copyright (C) Gerald (Jerry) Carter             2006.
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

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_PARSE

/*******************************************************************
 Inits a SESS_INFO_0_STR structure
********************************************************************/

void init_srv_sess_info0( SESS_INFO_0 *ss0, const char *name )
{
	ZERO_STRUCTP( ss0 );

	if ( name ) {
		if ( (ss0->sharename = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL ) {
			DEBUG(0,("init_srv_sess_info0: talloc failed!\n"));
			return;
		}
		init_unistr2( ss0->sharename, name, UNI_STR_TERMINATE );
	}
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_sess_info_0(const char *desc, SRV_SESS_INFO_0 *ss0, prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_info_0");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_entries_read", ps, depth, &ss0->num_entries_read))
		return False;
	if(!prs_uint32("ptr_sess_info", ps, depth, &ss0->ptr_sess_info))
		return False;

	if (ss0->ptr_sess_info != 0) {
		uint32 i;
		uint32 num_entries = ss0->num_entries_read;

		if (num_entries > MAX_SESS_ENTRIES) {
			num_entries = MAX_SESS_ENTRIES; /* report this! */
		}

		if(!prs_uint32("num_entries_read2", ps, depth, &ss0->num_entries_read2))
			return False;

		SMB_ASSERT_ARRAY(ss0->info_0, num_entries);

		/* first the pointers */
		for (i = 0; i < num_entries; i++) {
			if ( !prs_io_unistr2_p("", ps, depth, &ss0->info_0[i].sharename ) )
				return False;
		}

		/* now the strings */
		for (i = 0; i < num_entries; i++) {
			if ( !prs_io_unistr2("sharename", ps, depth, ss0->info_0[i].sharename ))
				return False;
		}

		if(!prs_align(ps))
			return False;
	}

	return True;
}

/*******************************************************************
 Inits a SESS_INFO_1 structure
********************************************************************/

void init_srv_sess_info1( SESS_INFO_1 *ss1, const char *name, const char *user,
                          uint32 num_opens, uint32 open_time, uint32 idle_time,
                          uint32 user_flags)
{
	DEBUG(5,("init_srv_sess_info1: %s\n", name));

	ZERO_STRUCTP( ss1 );

	if ( name ) {
		if ( (ss1->sharename = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL ) {
			DEBUG(0,("init_srv_sess_info0: talloc failed!\n"));
			return;
		}
		init_unistr2( ss1->sharename, name, UNI_STR_TERMINATE );
	}

	if ( user ) {
		if ( (ss1->username = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL ) {
			DEBUG(0,("init_srv_sess_info0: talloc failed!\n"));
			return;
		}
		init_unistr2( ss1->username, user, UNI_STR_TERMINATE );
	}

	ss1->num_opens  = num_opens;
	ss1->open_time  = open_time;
	ss1->idle_time  = idle_time;
	ss1->user_flags = user_flags;
}


/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_sess_info_1(const char *desc, SRV_SESS_INFO_1 *ss1, prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_info_1");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_entries_read", ps, depth, &ss1->num_entries_read))
		return False;
	if(!prs_uint32("ptr_sess_info", ps, depth, &ss1->ptr_sess_info))
		return False;

	if (ss1->ptr_sess_info != 0) {
		uint32 i;
		uint32 num_entries = ss1->num_entries_read;

		if (num_entries > MAX_SESS_ENTRIES) {
			num_entries = MAX_SESS_ENTRIES; /* report this! */
		}

		if(!prs_uint32("num_entries_read2", ps, depth, &ss1->num_entries_read2))
			return False;

		SMB_ASSERT_ARRAY(ss1->info_1, num_entries);

		/* first the pointers and flags */

		for (i = 0; i < num_entries; i++) {

			if ( !prs_io_unistr2_p("", ps, depth, &ss1->info_1[i].sharename ))
				return False;
			if ( !prs_io_unistr2_p("", ps, depth, &ss1->info_1[i].username ))
				return False;

			if(!prs_uint32("num_opens ", ps, depth, &ss1->info_1[i].num_opens))
				return False;
			if(!prs_uint32("open_time ", ps, depth, &ss1->info_1[i].open_time))
				return False;
			if(!prs_uint32("idle_time ", ps, depth, &ss1->info_1[i].idle_time))
				return False;
			if(!prs_uint32("user_flags", ps, depth, &ss1->info_1[i].user_flags))
				return False;
		}

		/* now the strings */

		for (i = 0; i < num_entries; i++) {
			if ( !prs_io_unistr2("", ps, depth, ss1->info_1[i].sharename ))
				return False;
			if ( !prs_io_unistr2("", ps, depth, ss1->info_1[i].username ))
				return False;
		}

		if(!prs_align(ps))
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_sess_ctr(const char *desc, SRV_SESS_INFO_CTR **pp_ctr, prs_struct *ps, int depth)
{
	SRV_SESS_INFO_CTR *ctr = *pp_ctr;

	prs_debug(ps, depth, desc, "srv_io_srv_sess_ctr");
	depth++;

	if(UNMARSHALLING(ps)) {
		ctr = *pp_ctr = PRS_ALLOC_MEM(ps, SRV_SESS_INFO_CTR, 1);
		if (ctr == NULL)
			return False;
	}

	if (ctr == NULL)
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("switch_value", ps, depth, &ctr->switch_value))
		return False;
	if(!prs_uint32("ptr_sess_ctr", ps, depth, &ctr->ptr_sess_ctr))
		return False;

	if (ctr->ptr_sess_ctr != 0) {
		switch (ctr->switch_value) {
		case 0:
			if(!srv_io_srv_sess_info_0("", &ctr->sess.info0, ps, depth))
				return False;
			break;
		case 1:
			if(!srv_io_srv_sess_info_1("", &ctr->sess.info1, ps, depth))
				return False;
			break;
		default:
			DEBUG(5,("%s no session info at switch_value %d\n",
			         tab_depth(5,depth), ctr->switch_value));
			break;
		}
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_q_net_sess_enum(const char *desc, SRV_Q_NET_SESS_ENUM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_sess_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_pointer("servername", ps, depth, (void*)&q_u->servername,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_pointer("qualifier", ps, depth, (void*)&q_u->qualifier,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_pointer("username", ps, depth, (void*)&q_u->username,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("sess_level", ps, depth, &q_u->sess_level))
		return False;
	
	if (q_u->sess_level != (uint32)-1) {
		if(!srv_io_srv_sess_ctr("sess_ctr", &q_u->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("preferred_len", ps, depth, &q_u->preferred_len))
		return False;

	if(!smb_io_enum_hnd("enum_hnd", &q_u->enum_hnd, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_r_net_sess_enum(const char *desc, SRV_R_NET_SESS_ENUM *r_n, prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_sess_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("sess_level", ps, depth, &r_n->sess_level))
		return False;

	if (r_n->sess_level != (uint32)-1) {
		if(!srv_io_srv_sess_ctr("sess_ctr", &r_n->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("total_entries", ps, depth, &r_n->total_entries))
		return False;
	if(!smb_io_enum_hnd("enum_hnd", &r_n->enum_hnd, ps, depth))
		return False;
	if(!prs_werror("status", ps, depth, &r_n->status))
		return False;

	return True;
}

/*******************************************************************
 Inits a CONN_INFO_0 structure
********************************************************************/

void init_srv_conn_info0(CONN_INFO_0 *ss0, uint32 id)
{
	DEBUG(5,("init_srv_conn_info0\n"));

	ss0->id = id;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_conn_info0(const char *desc, CONN_INFO_0 *ss0, prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info0");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("id", ps, depth, &ss0->id))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_conn_info_0(const char *desc, SRV_CONN_INFO_0 *ss0, prs_struct *ps, int depth)
{
	if (ss0 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_info_0");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_entries_read", ps, depth, &ss0->num_entries_read))
		return False;
	if(!prs_uint32("ptr_conn_info", ps, depth, &ss0->ptr_conn_info))
		return False;

	if (ss0->ptr_conn_info != 0) {
		int i;
		int num_entries = ss0->num_entries_read;

		if (num_entries > MAX_CONN_ENTRIES) {
			num_entries = MAX_CONN_ENTRIES; /* report this! */
		}

		if(!prs_uint32("num_entries_read2", ps, depth, &ss0->num_entries_read2))
			return False;

		for (i = 0; i < num_entries; i++) {
			if(!srv_io_conn_info0("", &ss0->info_0[i], ps, depth))
				return False;
		}

		if(!prs_align(ps))
			return False;
	}

	return True;
}

/*******************************************************************
 Inits a CONN_INFO_1_STR structure
********************************************************************/

void init_srv_conn_info1_str(CONN_INFO_1_STR *ss1, const char *usr_name, const char *net_name)
{
	DEBUG(5,("init_srv_conn_info1_str\n"));

	init_unistr2(&ss1->uni_usr_name, usr_name, UNI_STR_TERMINATE);
	init_unistr2(&ss1->uni_net_name, net_name, UNI_STR_TERMINATE);
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_conn_info1_str(const char *desc, CONN_INFO_1_STR *ss1, prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info1_str");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("", &ss1->uni_usr_name, True, ps, depth))
		return False;
	if(!smb_io_unistr2("", &ss1->uni_net_name, True, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Inits a CONN_INFO_1 structure
********************************************************************/

void init_srv_conn_info1(CONN_INFO_1 *ss1, 
				uint32 id, uint32 type,
				uint32 num_opens, uint32 num_users, uint32 open_time,
				const char *usr_name, const char *net_name)
{
	DEBUG(5,("init_srv_conn_info1: %s %s\n", usr_name, net_name));

	ss1->id        = id       ;
	ss1->type      = type     ;
	ss1->num_opens = num_opens ;
	ss1->num_users = num_users;
	ss1->open_time = open_time;

	ss1->ptr_usr_name = (usr_name != NULL) ? 1 : 0;
	ss1->ptr_net_name = (net_name != NULL) ? 1 : 0;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_conn_info1(const char *desc, CONN_INFO_1 *ss1, prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_conn_info1");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("id          ", ps, depth, &ss1->id))
		return False;
	if(!prs_uint32("type        ", ps, depth, &ss1->type))
		return False;
	if(!prs_uint32("num_opens   ", ps, depth, &ss1->num_opens))
		return False;
	if(!prs_uint32("num_users   ", ps, depth, &ss1->num_users))
		return False;
	if(!prs_uint32("open_time   ", ps, depth, &ss1->open_time))
		return False;

	if(!prs_uint32("ptr_usr_name", ps, depth, &ss1->ptr_usr_name))
		return False;
	if(!prs_uint32("ptr_net_name", ps, depth, &ss1->ptr_net_name))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_conn_info_1(const char *desc, SRV_CONN_INFO_1 *ss1, prs_struct *ps, int depth)
{
	if (ss1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_info_1");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("num_entries_read", ps, depth, &ss1->num_entries_read))
		return False;
	if(!prs_uint32("ptr_conn_info", ps, depth, &ss1->ptr_conn_info))
		return False;

	if (ss1->ptr_conn_info != 0) {
		int i;
		int num_entries = ss1->num_entries_read;

		if (num_entries > MAX_CONN_ENTRIES) {
			num_entries = MAX_CONN_ENTRIES; /* report this! */
		}

		if(!prs_uint32("num_entries_read2", ps, depth, &ss1->num_entries_read2))
			return False;

		for (i = 0; i < num_entries; i++) {
			if(!srv_io_conn_info1("", &ss1->info_1[i], ps, depth))
				return False;
		}

		for (i = 0; i < num_entries; i++) {
			if(!srv_io_conn_info1_str("", &ss1->info_1_str[i], ps, depth))
				return False;
		}

		if(!prs_align(ps))
			return False;
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_conn_ctr(const char *desc, SRV_CONN_INFO_CTR **pp_ctr, prs_struct *ps, int depth)
{
	SRV_CONN_INFO_CTR *ctr = *pp_ctr;

	prs_debug(ps, depth, desc, "srv_io_srv_conn_ctr");
	depth++;

	if (UNMARSHALLING(ps)) {
		ctr = *pp_ctr = PRS_ALLOC_MEM(ps, SRV_CONN_INFO_CTR, 1);
		if (ctr == NULL)
			return False;
	}
		
	if (ctr == NULL)
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("switch_value", ps, depth, &ctr->switch_value))
		return False;
	if(!prs_uint32("ptr_conn_ctr", ps, depth, &ctr->ptr_conn_ctr))
		return False;

	if (ctr->ptr_conn_ctr != 0) {
		switch (ctr->switch_value) {
		case 0:
			if(!srv_io_srv_conn_info_0("", &ctr->conn.info0, ps, depth))
				return False;
			break;
		case 1:
			if(!srv_io_srv_conn_info_1("", &ctr->conn.info1, ps, depth))
				return False;
			break;
		default:
			DEBUG(5,("%s no connection info at switch_value %d\n",
			         tab_depth(5,depth), ctr->switch_value));
			break;
		}
	}

	return True;
}

/*******************************************************************
  Reads or writes a structure.
********************************************************************/

void init_srv_q_net_conn_enum(SRV_Q_NET_CONN_ENUM *q_n, 
				const char *srv_name, const char *qual_name,
				uint32 conn_level, SRV_CONN_INFO_CTR *ctr,
				uint32 preferred_len,
				ENUM_HND *hnd)
{
	DEBUG(5,("init_q_net_conn_enum\n"));

	q_n->ctr = ctr;

	init_buf_unistr2(&q_n->uni_srv_name, &q_n->ptr_srv_name, srv_name );
	init_buf_unistr2(&q_n->uni_qual_name, &q_n->ptr_qual_name, qual_name);

	q_n->conn_level    = conn_level;
	q_n->preferred_len = preferred_len;

	memcpy(&q_n->enum_hnd, hnd, sizeof(*hnd));
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_q_net_conn_enum(const char *desc, SRV_Q_NET_CONN_ENUM *q_n, prs_struct *ps, int depth)
{
	if (q_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_conn_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_srv_name ", ps, depth, &q_n->ptr_srv_name))
		return False;
	if(!smb_io_unistr2("", &q_n->uni_srv_name, q_n->ptr_srv_name, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_qual_name", ps, depth, &q_n->ptr_qual_name))
		return False;
	if(!smb_io_unistr2("", &q_n->uni_qual_name, q_n->ptr_qual_name, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("conn_level", ps, depth, &q_n->conn_level))
		return False;
	
	if (q_n->conn_level != (uint32)-1) {
		if(!srv_io_srv_conn_ctr("conn_ctr", &q_n->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("preferred_len", ps, depth, &q_n->preferred_len))
		return False;

	if(!smb_io_enum_hnd("enum_hnd", &q_n->enum_hnd, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_r_net_conn_enum(const char *desc,  SRV_R_NET_CONN_ENUM *r_n, prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_conn_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("conn_level", ps, depth, &r_n->conn_level))
		return False;

	if (r_n->conn_level != (uint32)-1) {
		if(!srv_io_srv_conn_ctr("conn_ctr", &r_n->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("total_entries", ps, depth, &r_n->total_entries))
		return False;
	if(!smb_io_enum_hnd("enum_hnd", &r_n->enum_hnd, ps, depth))
		return False;
	if(!prs_werror("status", ps, depth, &r_n->status))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_file_info3_str(const char *desc, FILE_INFO_3 *sh1, prs_struct *ps, int depth)
{
	if (sh1 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_file_info3_str");
	depth++;

	if(!prs_align(ps))
		return False;

	if ( sh1->path ) {
		if(!smb_io_unistr2("", sh1->path, True, ps, depth))
			return False;
	}

	if ( sh1->user ) {
		if(!smb_io_unistr2("", sh1->user, True, ps, depth))
			return False;
	}

	return True;
}

/*******************************************************************
 Inits a FILE_INFO_3 structure
********************************************************************/

void init_srv_file_info3( FILE_INFO_3 *fl3, uint32 id, uint32 perms, uint32 num_locks,
                          const char *user_name, const char *path_name )
{
	fl3->id        = id;	
	fl3->perms     = perms;
	fl3->num_locks = num_locks;

        if ( path_name ) {
                if ( (fl3->path = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL )
                        return;
                init_unistr2(fl3->path, path_name, UNI_STR_TERMINATE);
        }

        if ( user_name ) {
                if ( (fl3->user = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL )
                        return;
                init_unistr2(fl3->user, user_name, UNI_STR_TERMINATE);
        }

	return;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_file_info3(const char *desc, FILE_INFO_3 *fl3, prs_struct *ps, int depth)
{
	uint32 uni_p;

	if (fl3 == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_file_info3");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("id           ", ps, depth, &fl3->id))
		return False;
	if(!prs_uint32("perms        ", ps, depth, &fl3->perms))
		return False;
	if(!prs_uint32("num_locks    ", ps, depth, &fl3->num_locks))
		return False;

	uni_p = fl3->path ? 1 : 0;
	if(!prs_uint32("ptr", ps, depth, &uni_p))
		return False;
	if (UNMARSHALLING(ps)) {
		if ( (fl3->path = PRS_ALLOC_MEM( ps, UNISTR2, 1)) == NULL ) {
			return False;
		}
	}

	uni_p = fl3->user ? 1 : 0;
	if(!prs_uint32("ptr", ps, depth, &uni_p))
		return False;
	if (UNMARSHALLING(ps)) {
		if ( (fl3->user = PRS_ALLOC_MEM( ps, UNISTR2, 1)) == NULL ) {
			return False;
		}
	}

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

static bool srv_io_srv_file_ctr(const char *desc, SRV_FILE_INFO_CTR *ctr, prs_struct *ps, int depth)
{
	if (ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_srv_file_ctr");
	depth++;

	if (UNMARSHALLING(ps)) {
		ZERO_STRUCTP(ctr);
	}

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("level", ps, depth, &ctr->level))
		return False;

	if(!prs_uint32("ptr_file_info", ps, depth, &ctr->ptr_file_info))
		return False;
	if(!prs_uint32("num_entries", ps, depth, &ctr->num_entries))
		return False;
	if(!prs_uint32("ptr_entries", ps, depth, &ctr->ptr_entries))
		return False;

	if (ctr->ptr_entries == 0)
		return True;

	if(!prs_uint32("num_entries2", ps, depth, &ctr->num_entries2))
		return False;

	switch (ctr->level) {
	case 3: {
		FILE_INFO_3 *info3 = ctr->file.info3;
		int num_entries = ctr->num_entries;
		int i;

		if (UNMARSHALLING(ps) && num_entries) {
			if (!(info3 = PRS_ALLOC_MEM(ps, FILE_INFO_3, num_entries)))
				return False;
			ctr->file.info3 = info3;
		}

		for (i = 0; i < num_entries; i++) {
			if(!srv_io_file_info3("", &ctr->file.info3[i], ps, depth)) 
				return False;
		}

		for (i = 0; i < num_entries; i++) {
			if(!srv_io_file_info3_str("", &ctr->file.info3[i], ps, depth))
				return False;
		}
		break;
	}
	default:
		DEBUG(5,("%s no file info at switch_value %d\n", tab_depth(5,depth), ctr->level));
		break;
	}
			
	return True;
}

/*******************************************************************
 Inits a SRV_Q_NET_FILE_ENUM structure.
********************************************************************/

void init_srv_q_net_file_enum(SRV_Q_NET_FILE_ENUM *q_n, 
			      const char *srv_name, const char *qual_name, 
			      const char *user_name,
			      uint32 file_level, SRV_FILE_INFO_CTR *ctr,
			      uint32 preferred_len,
			      ENUM_HND *hnd)
{
	uint32 ptr;

	if ( srv_name ) {
		if ( (q_n->servername = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL )
			return;
		init_buf_unistr2(q_n->servername, &ptr, srv_name);
	}

	if ( qual_name ) {
		if ( (q_n->qualifier = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL )
			return;
		init_buf_unistr2(q_n->qualifier,  &ptr, qual_name);
	}

	if ( user_name ) {
		if ( (q_n->username = TALLOC_P( talloc_tos(), UNISTR2 )) == NULL )
			return;
		init_buf_unistr2(q_n->username,   &ptr, user_name);
	}

	q_n->level = q_n->ctr.level = file_level;

	q_n->preferred_len = preferred_len;
	q_n->ctr.ptr_file_info = 1;
	q_n->ctr.num_entries = 0;
	q_n->ctr.num_entries2 = 0;

	memcpy(&q_n->enum_hnd, hnd, sizeof(*hnd));
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_q_net_file_enum(const char *desc, SRV_Q_NET_FILE_ENUM *q_u, prs_struct *ps, int depth)
{
	if (q_u == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_q_net_file_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_pointer("servername", ps, depth, (void*)&q_u->servername,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_pointer("qualifier", ps, depth, (void*)&q_u->qualifier,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_pointer("username", ps, depth, (void*)&q_u->username,
			sizeof(UNISTR2), (PRS_POINTER_CAST)prs_io_unistr2))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("level", ps, depth, &q_u->level))
		return False;

	if (q_u->level != (uint32)-1) {
		if(!srv_io_srv_file_ctr("file_ctr", &q_u->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("preferred_len", ps, depth, &q_u->preferred_len))
		return False;

	if(!smb_io_enum_hnd("enum_hnd", &q_u->enum_hnd, ps, depth))
		return False;

	return True;
}

/*******************************************************************
 Reads or writes a structure.
********************************************************************/

bool srv_io_r_net_file_enum(const char *desc, SRV_R_NET_FILE_ENUM *r_n, prs_struct *ps, int depth)
{
	if (r_n == NULL)
		return False;

	prs_debug(ps, depth, desc, "srv_io_r_net_file_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("level", ps, depth, &r_n->level))
		return False;

	if (r_n->level != 0) {
		if(!srv_io_srv_file_ctr("file_ctr", &r_n->ctr, ps, depth))
			return False;
	}

	if(!prs_uint32("total_entries", ps, depth, &r_n->total_entries))
		return False;
	if(!smb_io_enum_hnd("enum_hnd", &r_n->enum_hnd, ps, depth))
		return False;
	if(!prs_werror("status", ps, depth, &r_n->status))
		return False;

	return True;
}
