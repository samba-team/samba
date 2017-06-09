/*
   Unix SMB/Netbios implementation.
   Copyright (c) 2017 Ralph Boehme <slow@samba.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _OFFLOAD_TOKEN_H_
#define _OFFLOAD_TOKEN_H_

struct vfs_offload_ctx;
struct req_resume_key_rsp;

NTSTATUS vfs_offload_token_ctx_init(TALLOC_CTX *mem_ctx,
				    struct vfs_offload_ctx **_ctx);
NTSTATUS vfs_offload_token_db_store_fsp(struct vfs_offload_ctx *ctx,
					const files_struct *fsp,
					const DATA_BLOB *token_blob);
NTSTATUS vfs_offload_token_db_fetch_fsp(struct vfs_offload_ctx *ctx,
					const DATA_BLOB *token_blob,
					files_struct **fsp);
NTSTATUS vfs_offload_token_create_blob(TALLOC_CTX *mem_ctx,
				       const files_struct *fsp,
				       uint32_t fsctl,
				       DATA_BLOB *token_blob);
NTSTATUS vfs_offload_token_check_handles(uint32_t fsctl,
					 files_struct *src_fsp,
					 files_struct *dst_fsp);
#endif
