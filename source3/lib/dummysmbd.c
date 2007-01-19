/*
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Gerald (Jerry) Carter          2004.

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

/* Stupid dummy functions required due to the horrible dependency mess
   in Samba. */

#include "includes.h"

int find_service(fstring service)
{
	return -1;
}

BOOL conn_snum_used(int snum)
{
	return False;
}

void cancel_pending_lock_requests_by_fid(files_struct *fsp, struct byte_range_lock *br_lck)
{
}

NTSTATUS dptr_create(connection_struct *conn, pstring path, BOOL old_handle, BOOL expect_close,uint16 spid,
		                const char *wcard, BOOL wcard_has_wild, uint32 attr, struct dptr_struct **dptr_ret)
{
	return NT_STATUS_OK;
}

int dptr_CloseDir(struct dptr_struct *dptr)
{
	return 0;
}

const char *dptr_ReadDirName(struct dptr_struct *dptr, long *poffset, SMB_STRUCT_STAT *pst)
{
	return NULL;
}

void send_stat_cache_delete_message(const char *name)
{
}
