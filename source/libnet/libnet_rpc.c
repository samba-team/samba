/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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

/* connect to a dcerpc interface of a domains PDC */
NTSTATUS libnet_rpc_connect_pdc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_rpc_connect *r)
{
	NTSTATUS status;
	const char *binding = NULL;
	const char *pdc = NULL;

	/* TODO: find real PDC!
	 * 	 for now I use the  lp_netbios_name()
	 *	 that's the most important for me as we don't have
	 *	 smbpasswd in samba4 (and this is good!:-) --metze
	 */
	pdc = lp_netbios_name();

	binding = talloc_asprintf(mem_ctx, "ncacn_np:%s",pdc);

	status = dcerpc_pipe_connect(&r->pdc.out.dcerpc_pipe,
					binding,
					r->pdc.in.dcerpc_iface_uuid,
					r->pdc.in.dcerpc_iface_version,
					ctx->user.domain_name,
					ctx->user.account_name,
					ctx->user.password); 

	return status;
}

/* connect to a dcerpc interface */
NTSTATUS libnet_rpc_connect(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_rpc_connect *r)
{
	switch (r->pdc.level) {
		case LIBNET_RPC_CONNECT_PDC:
			return libnet_rpc_connect_pdc(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
