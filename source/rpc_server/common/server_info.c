/* 
   Unix SMB/CIFS implementation.

   common server info functions

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
uint32_t dcesrv_common_get_platform_id(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "platform_id", 500);
}

const char *dcesrv_common_get_server_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, const char *server_unc)
{
	const char *p = server_unc;

	/* if there's no string return our NETBIOS name */
	if (!p) {
		return talloc_strdup(mem_ctx, lp_netbios_name());
	}

	/* if there're '\\\\' in front remove them otherwise just pass the string */
	if (p[0] == '\\' && p[1] == '\\') {
		p += 2;
	}

	return talloc_strdup(mem_ctx, p);
}

const char *dcesrv_common_get_domain_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, lp_workgroup());
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_version_major(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "version_major", 5);
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_version_minor(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "version_minor", 2);
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_server_type(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_default_server_announce();
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_lan_root(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, "");
}
