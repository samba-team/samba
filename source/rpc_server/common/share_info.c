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
	return lp_servicename(snum);
}

const char *dcesrv_common_get_share_comment(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return lp_comment(snum);
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_permissions(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_share_max_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 10;
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
	if (strcasecmp(lp_servicename(snum), "IPC$") == 0) {
		return 3;
	}
	if (lp_print_ok(snum)) {
		return 1;
	}
	return 0;
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_share_path(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return "C:\\";
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
uint32_t dcesrv_common_get_share_unknown(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
struct security_descriptor *dcesrv_common_get_security_descriptor(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, int snum)
{
	return NULL;
}
