/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  MSDfs RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-2000,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-2000,
 *  Copyright (C) Shirish Kalele               2000.
 *  Copyright (C) Jeremy Allison				2001.
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
#include "rpc_parse.h"   

/******************************************************************* 
Make a DFS_Q_DFS_QUERY structure
*******************************************************************/

void init_dfs_q_dfs_exist(DFS_Q_DFS_EXIST *q_d)
{
	q_d->dummy = 0;
}

/*************************************************************
 Read/write a DFS_Q_DFS_EXIST structure - dummy...
 ************************************************************/

BOOL dfs_io_q_dfs_exist(const char *desc, DFS_Q_DFS_EXIST *q_d, prs_struct *ps, int depth)
{
	if(q_d == NULL)
		return False;
  
	prs_debug(ps, depth, desc, "dfs_io_q_dfs_exist");

	return True;
}
  
/*************************************************************
 Read/write a DFS_R_DFS_EXIST structure
 ************************************************************/

BOOL dfs_io_r_dfs_exist(const char *desc, DFS_R_DFS_EXIST *q_d, prs_struct *ps, int depth)
{
	if(q_d == NULL)
		return False;
  
	prs_debug(ps, depth, desc, "dfs_io_r_dfs_exist");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("exist flag", ps, 0, &q_d->status))
		return False;

	return True;
}
  
/******************************************************************* 
Make a DFS_Q_DFS_REMOVE structure
*******************************************************************/

BOOL init_dfs_q_dfs_remove(DFS_Q_DFS_REMOVE *q_d, const char *entrypath, 
			   const char *servername, const char *sharename)
{
	DEBUG(5,("init_dfs_q_dfs_remove\n"));
	init_unistr2(&q_d->DfsEntryPath, entrypath,  strlen(entrypath)+1);
	init_unistr2(&q_d->ServerName,   servername, strlen(servername)+1);
	init_unistr2(&q_d->ShareName,    sharename,  strlen(sharename)+1);
	q_d->ptr_ServerName = q_d->ptr_ShareName = 1;
	return True;
}

/******************************************************************* 
Read/write a DFS_Q_DFS_REMOVE structure
*******************************************************************/

BOOL dfs_io_q_dfs_remove(const char *desc, DFS_Q_DFS_REMOVE *q_d, prs_struct *ps, int depth)
{
	if(q_d == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_q_dfs_remove");
	depth++;
  
	if(!prs_align(ps))
		return False;
  
	if(!smb_io_unistr2("DfsEntryPath",&q_d->DfsEntryPath, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_ServerName", ps, depth, &q_d->ptr_ServerName))
		return False;
	if(q_d->ptr_ServerName)
		if (!smb_io_unistr2("ServerName",&q_d->ServerName, q_d->ptr_ServerName, ps, depth))
			return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_ShareName", ps, depth, &q_d->ptr_ShareName))
		return False;
	if(q_d->ptr_ShareName)
		if (!smb_io_unistr2("ShareName",&q_d->ShareName,  q_d->ptr_ShareName, ps, depth))
			return False;
	if(!prs_align(ps))
		return False;

	return True;
}

/******************************************************************* 
Read/write a DFS_R_DFS_REMOVE structure
*******************************************************************/

BOOL dfs_io_r_dfs_remove(const char *desc, DFS_R_DFS_REMOVE *r_d, prs_struct *ps, int depth)
{
	if(r_d == NULL)	
		return False;

	prs_debug(ps, depth, desc, "dfs_io_r_dfs_remove");
	depth++;

	if(!prs_werror("status", ps, depth, &r_d->status))
		return False;

	return True;
}

/******************************************************************* 
Make a DFS_Q_DFS_ADD structure
*******************************************************************/

BOOL init_dfs_q_dfs_add(DFS_Q_DFS_ADD *q_d, const char *entrypath, const char *servername,
			const char *sharename, const char *comment, uint32 flags)
{
	DEBUG(5,("init_dfs_q_dfs_add\n"));
	q_d->ptr_DfsEntryPath = q_d->ptr_ServerName = q_d->ptr_ShareName = 1;
	init_unistr2(&q_d->DfsEntryPath, entrypath,  strlen(entrypath)+1);
	init_unistr2(&q_d->ServerName,   servername, strlen(servername)+1);
	init_unistr2(&q_d->ShareName,    sharename,  strlen(sharename)+1);
	if(comment != NULL) {
		init_unistr2(&q_d->Comment,      comment,    strlen(comment)+1);
		q_d->ptr_Comment = 1;
	} else {
		q_d->ptr_Comment = 0;
	}

	q_d->Flags = flags;
	return True;
}

/************************************************************
 Read/write a DFS_Q_DFS_ADD structure
 ************************************************************/

BOOL dfs_io_q_dfs_add(const char *desc, DFS_Q_DFS_ADD *q_d, prs_struct *ps, int depth)
{
	if(q_d == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_q_dfs_add");
	depth++;
  
	if(!prs_align(ps))
		return False;
  
	if(!smb_io_unistr2("DfsEntryPath",&q_d->DfsEntryPath, 1, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!smb_io_unistr2("ServerName",&q_d->ServerName, 1, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_ShareName", ps, depth, &q_d->ptr_ShareName))
		return False;
	if(!smb_io_unistr2("ShareName",&q_d->ShareName,  1, ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_Comment", ps, depth, &q_d->ptr_Comment))
		return False;
	if(!smb_io_unistr2("",&q_d->Comment, q_d->ptr_Comment , ps, depth))
		return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("Flags", ps, depth, &q_d->Flags))
		return True;

	return True;
}

/************************************************************
 Read/write a DFS_R_DFS_ADD structure 
 ************************************************************/

BOOL dfs_io_r_dfs_add(const char *desc, DFS_R_DFS_ADD *r_d, prs_struct *ps, int depth)
{
	if(r_d == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_r_dfs_add");
	depth++;

	if(!prs_werror("status", ps, depth, &r_d->status))
		return False;

	return True;
}

BOOL init_dfs_q_dfs_get_info(DFS_Q_DFS_GET_INFO *q_d, const char *entrypath,
			     const char *servername, const char *sharename, 
			     uint32 info_level)
{
	DEBUG(5,("init_dfs_q2_get_info\n"));
	init_unistr2(&q_d->uni_path, entrypath,  strlen(entrypath)+1);
	init_unistr2(&q_d->uni_server,   servername, strlen(servername)+1);
	init_unistr2(&q_d->uni_share,    sharename,  strlen(sharename)+1);
	q_d->level = info_level;
	q_d->ptr_server = q_d->ptr_share = 1;
	return True;
}

/************************************************************
 Read/write a DFS_Q_GET_INFO structure
 ************************************************************/

BOOL dfs_io_q_dfs_get_info(const char* desc, DFS_Q_DFS_GET_INFO* q_i, prs_struct* ps, int depth)
{
	if(q_i == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_q_dfs_get_info");
	depth++;

	if(!smb_io_unistr2("",&q_i->uni_path, 1, ps, depth))
		return False;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_server", ps, depth, &q_i->ptr_server))
		return False;

	if(q_i->ptr_server)
		if (!smb_io_unistr2("",&q_i->uni_server, q_i->ptr_server, ps, depth))
			return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_share", ps, depth, &q_i->ptr_share))
		return False;
	if(q_i->ptr_share)
		if(!smb_io_unistr2("", &q_i->uni_share, q_i->ptr_share, ps, depth))
			return False;
	if(!prs_align(ps))
		return False;

	if(!prs_uint32("level", ps, depth, &q_i->level))
		return False;
	return True;
}

/************************************************************
 Read/write a DFS_R_GET_INFO structure
 ************************************************************/

BOOL dfs_io_r_dfs_get_info(const char* desc, DFS_R_DFS_GET_INFO* r_i, prs_struct* ps, int depth)
{
	if(r_i == NULL)
		return False;
  
	if(!prs_uint32("level", ps, depth, &r_i->level))
		return False;
	if(!prs_uint32("ptr_ctr", ps, depth, &r_i->ptr_ctr))
		return False;

	if(!dfs_io_dfs_info_ctr("", &r_i->ctr, 1, r_i->level, ps, depth))
		return False;
	if(!prs_werror("status", ps, depth, &r_i->status))
		return False;
	return True;
}
			   
/************************************************************
 Make a DFS_Q_DFS_ENUM structure
 ************************************************************/
BOOL init_dfs_q_dfs_enum(DFS_Q_DFS_ENUM *q_d, uint32 level, DFS_INFO_CTR *ctr)
{
	q_d->level = level;
	q_d->maxpreflen = -1;
	q_d->ptr_buffer = 1;
	q_d->level2 = level;
  
	q_d->ptr_num_entries = 1;
	q_d->num_entries = 0;
	q_d->num_entries2 = 0;
	q_d->reshnd.ptr_hnd = 1;
	q_d->reshnd.handle = 0;
	return True;
}
  
/************************************************************
 Read or write the DFS_Q_DFS_ENUM structure 
 ************************************************************/

BOOL dfs_io_q_dfs_enum(const char *desc, DFS_Q_DFS_ENUM *q_d, prs_struct *ps, int depth)
{
	if(q_d == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_q_dfs_enum");
	depth++;
  
	if(!prs_align(ps))
		return False;
  
	if(!prs_uint32("level", ps, depth, &q_d->level))
		return False;
	if(!prs_uint32("maxpreflen", ps, depth, &q_d->maxpreflen))
		return False;
	if(!prs_uint32("ptr_buffer", ps, depth, &q_d->ptr_buffer))
		return False;
	if(!prs_uint32("level2", ps, depth, &q_d->level2))
		return False;
	if(!prs_uint32("level3", ps, depth, &q_d->level2))
		return False;
  
	if(!prs_uint32("ptr_num_entries", ps, depth, &q_d->ptr_num_entries))
		return False;
	if(!prs_uint32("num_entries", ps, depth, &q_d->num_entries))
		return False;
	if(!prs_uint32("num_entries2", ps, depth, &q_d->num_entries2))
		return False;
	if(!smb_io_enum_hnd("resume_hnd",&q_d->reshnd, ps, depth))
		return False;
	return True;
}

/************************************************************
 Read/write a DFS_INFO_CTR structure
 ************************************************************/

BOOL dfs_io_dfs_info_ctr(const char *desc, DFS_INFO_CTR* ctr, uint32 num_entries, uint32 level, prs_struct* ps, int depth)
{
	int i=0;

	switch(level) {
	case 1:
		depth++;
		/* should depend on whether marshalling or unmarshalling! */
		if(UNMARSHALLING(ps)) {
			ctr->dfs.info1 = (DFS_INFO_1 *)prs_alloc_mem(ps, sizeof(DFS_INFO_1)*num_entries);
			if (!ctr->dfs.info1)
				return False;
		}

		for(i=0;i<num_entries;i++) {
			if(!prs_uint32("ptr_entrypath",ps, depth, &ctr->dfs.info1[i].ptr_entrypath))
				return False;
		}
		for(i=0;i<num_entries;i++) {
			if(!smb_io_unistr2("", &ctr->dfs.info1[i].entrypath, ctr->dfs.info1[i].ptr_entrypath, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
		}
		depth--;
		break;
	case 2:
		depth++;
		if(UNMARSHALLING(ps)) {
			ctr->dfs.info2 = (DFS_INFO_2 *)prs_alloc_mem(ps, num_entries*sizeof(DFS_INFO_2));
			if (!ctr->dfs.info2)
				return False;
		}

		for(i=0;i<num_entries;i++) {
			if(!prs_uint32("ptr_entrypath", ps, depth, &ctr->dfs.info2[i].ptr_entrypath))
				return False;
			if(!prs_uint32("ptr_comment", ps, depth, &ctr->dfs.info2[i].ptr_comment))
				return False;
			if(!prs_uint32("state", ps, depth, &ctr->dfs.info2[i].state))
				return False;
			if(!prs_uint32("num_storages", ps, depth, &ctr->dfs.info2[i].num_storages))
				return False;
		}
		for(i=0;i<num_entries;i++) {
			if(!smb_io_unistr2("", &ctr->dfs.info2[i].entrypath, ctr->dfs.info2[i].ptr_entrypath, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
			if(!smb_io_unistr2("",&ctr->dfs.info2[i].comment, ctr->dfs.info2[i].ptr_comment, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
		}
		depth--;
		break;
	case 3:
		depth++;
		if(UNMARSHALLING(ps)) {
			ctr->dfs.info3 = (DFS_INFO_3 *)prs_alloc_mem(ps, num_entries*sizeof(DFS_INFO_3));
			if (!ctr->dfs.info3)
				return False;
		}

		for(i=0;i<num_entries;i++) {
			if(!prs_uint32("ptr_entrypath", ps, depth, &ctr->dfs.info3[i].ptr_entrypath))
				return False;
			if(!prs_uint32("ptr_comment", ps, depth, &ctr->dfs.info3[i].ptr_comment))
				return False;
			if(!prs_uint32("state", ps, depth, &ctr->dfs.info3[i].state))
				return False;
			if(!prs_uint32("num_storages", ps, depth, &ctr->dfs.info3[i].num_storages))
				return False;
			if(!prs_uint32("ptr_storages", ps, depth, &ctr->dfs.info3[i].ptr_storages))
				return False;
		}
		for(i=0;i<num_entries;i++) {
			if(!smb_io_unistr2("", &ctr->dfs.info3[i].entrypath, ctr->dfs.info3[i].ptr_entrypath, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
			if(!smb_io_unistr2("", &ctr->dfs.info3[i].comment, ctr->dfs.info3[i].ptr_comment, ps, depth))
				return False;
			if(!prs_align(ps))
				return False;
			if(!prs_uint32("num_storage_infos", ps, depth, &ctr->dfs.info3[i].num_storage_infos))
				return False;

			if(!dfs_io_dfs_storage_info("storage_info", &ctr->dfs.info3[i], ps, depth))
				return False;
		}
	}

	return True;
}

/************************************************************
 Read/write a DFS_R_DFS_ENUM structure
 ************************************************************/

BOOL dfs_io_r_dfs_enum(const char *desc, DFS_R_DFS_ENUM *q_d, prs_struct *ps, int depth)
{
	DFS_INFO_CTR *ctr;
	if(q_d == NULL)
		return False;
	ctr = q_d->ctr;
	if(ctr == NULL)
		return False;

	prs_debug(ps, depth, desc, "dfs_io_r_dfs_enum");
	depth++;

	if(!prs_align(ps))
		return False;

	if(!prs_uint32("ptr_buffer", ps, depth, &q_d->ptr_buffer))
		return False;
	if(!prs_uint32("level", ps, depth, &q_d->level))
		return False;
	if(!prs_uint32("level2", ps, depth, &ctr->switch_value))
		return False;
	if(!prs_uint32("ptr_num_entries", ps, depth, &q_d->ptr_num_entries))
		return False;
	if(q_d->ptr_num_entries)
		if(!prs_uint32("num_entries", ps, depth, &q_d->num_entries))
			return False;
	if(!prs_uint32("ptr_num_entries2", ps, depth, &q_d->ptr_num_entries2))
		return False;
	if(q_d->ptr_num_entries2)
		if(!prs_uint32("num_entries2", ps, depth, &ctr->num_entries))
			return False;

	if(!dfs_io_dfs_info_ctr("", ctr, q_d->num_entries, q_d->level, ps, depth))
		return False;

	if(!smb_io_enum_hnd("resume_hnd", &q_d->reshnd, ps, depth))
		return False;
	if(!prs_werror("status", ps, depth, &q_d->status))
		return False;
	return True;
}

BOOL dfs_io_dfs_storage_info(const char *desc, DFS_INFO_3* info3, prs_struct *ps, int depth)
{
	int i=0;
	if(info3 == NULL)
		return False;
  
	prs_debug(ps, depth, desc, "smb_io_dfs_storage_info");
	depth++;

	if(UNMARSHALLING(ps)) {
		info3->storages = (DFS_STORAGE_INFO *)prs_alloc_mem(ps, info3->num_storage_infos*sizeof(DFS_STORAGE_INFO));
		if (!info3->storages)
			return False;
	}

	for(i=0;i<info3->num_storage_infos;i++) {
		if(!prs_uint32("storage_state", ps, depth, &info3->storages[i].state))
			return False;
		if(!prs_uint32("ptr_servername", ps, depth, &info3->storages[i].ptr_servername))
			return False;
		if(!prs_uint32("ptr_sharename", ps, depth, &info3->storages[i].ptr_sharename))
			return False;
	}

	for(i=0;i<info3->num_storage_infos;i++) {
		if(!smb_io_unistr2("servername", &info3->storages[i].servername, info3->storages[i].ptr_servername, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
		if(!smb_io_unistr2("sharename", &info3->storages[i].sharename, info3->storages[i].ptr_sharename, ps, depth))
			return False;
		if(!prs_align(ps))
			return False;
	}

	return True;
}
