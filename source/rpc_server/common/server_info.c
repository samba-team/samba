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
	return 500;
}

const char *dcesrv_common_get_server_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_netbios_name();
}

const char *dcesrv_common_get_domain_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_workgroup();
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_version_major(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 5;
}

/* This hardcoded value should go into a ldb database! */
uint32_t dcesrv_common_get_version_minor(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 2;
}

/* This hardcoded value should go into a ldb database! */
const char *dcesrv_common_get_lan_root(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return "";
}
