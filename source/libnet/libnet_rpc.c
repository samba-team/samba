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

/* find a domain pdc generic */
static NTSTATUS libnet_find_pdc_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_find_pdc *r)
{
	BOOL ret;
	struct in_addr ip;

	ret = get_pdc_ip(mem_ctx, r->generic.in.domain_name, &ip);
	if (!ret) {
		/* fallback to a workstation name */
		ret = resolve_name(mem_ctx, r->generic.in.domain_name, &ip, 0x20);
		if (!ret) {
			return NT_STATUS_NO_LOGON_SERVERS;
		}
	}

	r->generic.out.pdc_name = talloc_strdup(mem_ctx, inet_ntoa(ip));

	return NT_STATUS_OK;
}

/* find a domain pdc */
NTSTATUS libnet_find_pdc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_find_pdc *r)
{
	switch (r->generic.level) {
		case LIBNET_FIND_PDC_GENERIC:
			return libnet_find_pdc_generic(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}

/* connect to a dcerpc interface of a domains PDC */
static NTSTATUS libnet_rpc_connect_pdc(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_rpc_connect *r)
{
	NTSTATUS status;
	const char *binding = NULL;
	union libnet_find_pdc f;

	f.generic.level			= LIBNET_FIND_PDC_GENERIC;
	f.generic.in.domain_name	= r->pdc.in.domain_name;

	status = libnet_find_pdc(ctx, mem_ctx, &f);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	binding = talloc_asprintf(mem_ctx, "ncacn_np:%s",
					f.generic.out.pdc_name);

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
