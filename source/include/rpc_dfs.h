/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba parameters and setup
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996 - 2000
   Copyright (C) Shirish Kalele 2000

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

#ifndef _RPC_DFS_H
#define _RPC_DFS_H

/* NETDFS pipe: calls */
#define DFS_EXIST                0x00
#define DFS_ADD                  0x01
#define DFS_REMOVE               0x02
#define DFS_GET_INFO             0x04
#define DFS_ENUM                 0x05

/* dfsadd flags */
#define DFSFLAG_ADD_VOLUME           0x00000001
#define DFSFLAG_RESTORE_VOLUME       0x00000002

typedef struct dfs_q_dfs_exist
{
  uint32 dummy;
}
DFS_Q_DFS_EXIST;

/* status == 1 if dfs exists. */
typedef struct dfs_r_dfs_exist
{
	uint32 status;          /* Not a WERROR or NTSTATUS code */
}
DFS_R_DFS_EXIST;

typedef struct dfs_q_dfs_add
{
  uint32 ptr_DfsEntryPath;
  UNISTR2 DfsEntryPath;
  uint32 ptr_ServerName;
  UNISTR2 ServerName;
  uint32 ptr_ShareName;
  UNISTR2 ShareName;
  uint32 ptr_Comment;
  UNISTR2 Comment;
  uint32 Flags;
}
DFS_Q_DFS_ADD;

typedef struct dfs_r_dfs_add
{
  WERROR status;
}
DFS_R_DFS_ADD;

/********************************************/
typedef struct dfs_q_dfs_remove
{
  UNISTR2 DfsEntryPath;
  uint32 ptr_ServerName;
  UNISTR2 ServerName;
  uint32 ptr_ShareName;
  UNISTR2 ShareName;
}
DFS_Q_DFS_REMOVE;

typedef struct dfs_r_dfs_remove
{
  WERROR status;
}
DFS_R_DFS_REMOVE;

/********************************************/
typedef struct dfs_info_1
{
  uint32 ptr_entrypath;
  UNISTR2 entrypath;
}
DFS_INFO_1;

typedef struct dfs_info_2
{
  uint32 ptr_entrypath;
  UNISTR2 entrypath;
  uint32 ptr_comment;
  UNISTR2 comment;
  uint32 state;
  uint32 num_storages;
}
DFS_INFO_2;

typedef struct dfs_storage_info
{
  uint32 state;
  uint32 ptr_servername;
  UNISTR2 servername;
  uint32 ptr_sharename;
  UNISTR2 sharename;
}
DFS_STORAGE_INFO;

typedef struct dfs_info_3
{
  uint32 ptr_entrypath;
  UNISTR2 entrypath;
  uint32 ptr_comment;
  UNISTR2 comment;
  uint32 state;
  uint32 num_storages;
  uint32 ptr_storages;
  uint32 num_storage_infos;
  DFS_STORAGE_INFO* storages;
}
DFS_INFO_3;

typedef struct dfs_info_ctr
{
  
  uint32 switch_value;
  uint32 num_entries;
  uint32 ptr_dfs_ctr; /* pointer to dfs info union */
  union
  {
    DFS_INFO_1 *info1;
    DFS_INFO_2 *info2;
    DFS_INFO_3 *info3;
  } dfs;
}
DFS_INFO_CTR;

typedef struct dfs_q_dfs_get_info
{
  UNISTR2 uni_path;
  
  uint32 ptr_server;
  UNISTR2 uni_server;

  uint32 ptr_share;
  UNISTR2 uni_share;
  
  uint32 level;
}
DFS_Q_DFS_GET_INFO;

typedef struct dfs_r_dfs_get_info
{
  uint32 level;
  uint32 ptr_ctr;
  DFS_INFO_CTR ctr;
  WERROR status;
}
DFS_R_DFS_GET_INFO;

typedef struct dfs_q_dfs_enum
{
  uint32 level;
  uint32 maxpreflen;
  uint32 ptr_buffer;
  uint32 level2;
  uint32 ptr_num_entries;
  uint32 num_entries;
  uint32 ptr_num_entries2;
  uint32 num_entries2;
  ENUM_HND reshnd;
}
DFS_Q_DFS_ENUM;

typedef struct dfs_r_dfs_enum
{
  DFS_INFO_CTR *ctr;
  uint32 ptr_buffer;
  uint32 level;
  uint32 level2;
  uint32 ptr_num_entries;
  uint32 num_entries;
  uint32 ptr_num_entries2;
  uint32 num_entries2;
  ENUM_HND reshnd;
  WERROR status;
}
DFS_R_DFS_ENUM;

#endif  
