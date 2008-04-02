/* 
   Unix SMB/CIFS implementation.
   Auth session handling
   Copyright (C) Andrew Bartlett   2001
   Copyright (C) Stefan Metzmacher 2005
   
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

#ifndef _SAMBA_AUTH_SESSION_H
#define _SAMBA_AUTH_SESSION_H

struct auth_session_info {
	struct security_token *security_token;
	struct auth_serversupplied_info *server_info;
	DATA_BLOB session_key;
	struct cli_credentials *credentials;
};

#include "librpc/gen_ndr/netlogon.h"

struct auth_session_info *system_session_anon(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx);
struct auth_session_info *system_session(TALLOC_CTX *mem_ctx, struct loadparm_context *lp_ctx) ;
NTSTATUS auth_anonymous_server_info(TALLOC_CTX *mem_ctx, 
				    const char *netbios_name,
				    struct auth_serversupplied_info **_server_info) ;
NTSTATUS auth_generate_session_info(TALLOC_CTX *mem_ctx, 
				    struct loadparm_context *lp_ctx,
				    struct auth_serversupplied_info *server_info, 
				    struct auth_session_info **_session_info) ;

NTSTATUS make_server_info_netlogon_validation(TALLOC_CTX *mem_ctx,
					      const char *account_name,
					      uint16_t validation_level,
					      union netr_Validation *validation,
					      struct auth_serversupplied_info **_server_info);
NTSTATUS auth_anonymous_session_info(TALLOC_CTX *parent_ctx, 
				     struct loadparm_context *lp_ctx,
				     struct auth_session_info **_session_info);

struct auth_session_info *anonymous_session(TALLOC_CTX *mem_ctx, 
					    struct loadparm_context *lp_ctx);


#endif /* _SAMBA_AUTH_SESSION_H */
