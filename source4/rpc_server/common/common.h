/* 
   Unix SMB/CIFS implementation.

   common macros for the dcerpc server interfaces

   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Tridgell 2004
   
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

#ifndef _DCERPC_SERVER_COMMON_H_
#define _DCERPC_SERVER_COMMON_H_

struct share_config;
struct dcesrv_context;
enum srvsvc_ShareType dcesrv_common_get_share_type(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, struct share_config *scfg);
enum srvsvc_PlatformId dcesrv_common_get_platform_id(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx);
const char *dcesrv_common_get_lan_root(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx);
const char *dcesrv_common_get_server_name(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, const char *server_unc);
uint32_t dcesrv_common_get_share_permissions(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, struct share_config *scfg);
uint32_t dcesrv_common_get_share_current_users(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, struct share_config *scfg);
const char *dcesrv_common_get_share_path(TALLOC_CTX *mem_ctx, struct dcesrv_context *dce_ctx, struct share_config *scfg);

struct dcesrv_context;

struct dcerpc_server_info { 
	const char *domain_name;
	uint32_t version_major;
	uint32_t version_minor;
	uint32_t version_build;
};

#endif /* _DCERPC_SERVER_COMMON_H_ */
