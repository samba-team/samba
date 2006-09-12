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
#include "librpc/gen_ndr/ndr_srvsvc.h"
#include "rpc_server/dcerpc_server.h"

/* 
    Here are common server info functions used by some dcerpc server interfaces
*/

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ enum srvsvc_PlatformId dcesrv_common_get_platform_id(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	enum srvsvc_PlatformId id;

	id = lp_parm_int(-1, "server_info", "platform_id", PLATFORM_ID_NT);

	return id;
}

_PUBLIC_ const char *dcesrv_common_get_server_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, const char *server_unc)
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
_PUBLIC_ uint32_t dcesrv_common_get_version_major(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "version_major", 5);
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_version_minor(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "version_minor", 2);
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_version_build(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_parm_int(-1, "server_info", "version_build", 3790);
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_server_type(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return lp_default_server_announce();
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ const char *dcesrv_common_get_lan_root(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, "");
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return -1;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_disc(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 15;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_hidden(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_announce(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 240;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_anndelta(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 3000;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ uint32_t dcesrv_common_get_licenses(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return 0;
}

/* This hardcoded value should go into a ldb database! */
_PUBLIC_ const char *dcesrv_common_get_userpath(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx)
{
	return talloc_strdup(mem_ctx, "c:\\");
}

#define INVALID_SHARE_NAME_CHARS " \"*+,./:;<=>?[\\]|"

_PUBLIC_ bool dcesrv_common_validate_share_name(TALLOC_CTX *mem_ctx, const char *share_name)
{
	if (strpbrk(share_name, INVALID_SHARE_NAME_CHARS)) {
		return False;
	}

	return True;
}
