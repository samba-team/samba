/* 
   Unix SMB/CIFS implementation.

   common share info functions

   Copyright (C) Stefan (metze) Metzmacher 2004
   
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

#include "includes.h"
#include "librpc/gen_ndr/ndr_srvsvc.h"

/* 
    Here are common server info functions used by some dcerpc server interfaces
*/

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_count_of_shares(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	/* what's about int -> uint32_t overflow */
	return lp_numservices();
}

const char *dcesrv_common_get_share_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return talloc_strdup(mem_ctx, lp_servicename(snum));
}

const char *dcesrv_common_get_share_comment(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return talloc_strdup(mem_ctx, lp_comment(snum));
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_permissions(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_max_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return lp_max_connections(snum);
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_current_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 1;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_type(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	/* for disk share	0x00000000
	 * for print share	0x00000001
	 * for IPC$ share	0x00000003 
	 *
	 * administrative shares:
	 * ADMIN$, IPC$, C$, D$, E$ ...  are type |= 0x80000000
	 * this ones are hidden in NetShareEnum, but shown in NetShareEnumAll
	 */
	uint32_t share_type = 0;

	if (!lp_browseable(snum)) {
		share_type |= STYPE_HIDDEN;
	}

	if (strcasecmp(lp_fstype(snum), "IPC") == 0) {
		share_type |= STYPE_IPC;
		return share_type;
	}

	if (lp_print_ok(snum)) {
		share_type |= STYPE_PRINTQ;
		return share_type;
	}

	share_type |= STYPE_DISKTREE;

	return share_type;
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_share_path(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	if (strcasecmp(lp_fstype(snum), "IPC") == 0) {
		return talloc_strdup(mem_ctx, "");
	}
	return talloc_strdup(mem_ctx, "C:\\");
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_share_password(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return NULL;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_csc_policy(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_dfs_flags(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_unknown(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
struct security_descriptor *dcesrv_common_get_security_descriptor(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return NULL;
}
