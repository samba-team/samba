/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Rafal Szczesniak <mimir@samba.org> 2005
   
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
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr.h"


static NTSTATUS libnet_CreateUser_generic(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_CreateUser *r)
{
	NTSTATUS status;
	union libnet_CreateUser r2;
	
	r2.samr.level             = LIBNET_CREATE_USER_SAMR;
	r2.samr.in.user_name      = r->generic.in.user_name;
	r2.samr.in.domain_name    = r->generic.in.domain_name;
	
	status = libnet_CreateUser(ctx, mem_ctx, &r2);
	
	r->generic.out.error_string   = r2.samr.out.error_string;

	return status;
}


static NTSTATUS libnet_CreateUser_samr(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_CreateUser *r)
{
	NTSTATUS status;
	union libnet_rpc_connect cn;
	union libnet_find_pdc fp;
	
	/* find domain pdc */
	fp.generic.level             = LIBNET_FIND_PDC_GENERIC;
	fp.generic.in.domain_name    = r->samr.in.domain_name;

	status = libnet_find_pdc(ctx, mem_ctx, &fp);
	if (!NT_STATUS_IS_OK(status)) return status;

	/* connect rpc service of remote server */
	cn.standard.level                      = LIBNET_RPC_CONNECT_STANDARD;
	cn.standard.in.server_name             = fp.generic.out.pdc_name;
	cn.standard.in.dcerpc_iface_name       = DCERPC_SAMR_NAME;
	cn.standard.in.dcerpc_iface_uuid       = DCERPC_SAMR_UUID;
	cn.standard.in.dcerpc_iface_version    = DCERPC_SAMR_VERSION;

	status = libnet_rpc_connect(ctx, mem_ctx, &cn);
	if (!NT_STATUS_IS_OK(status)) {
		r->samr.out.error_string = talloc_asprintf(mem_ctx,
							   "Connection to SAMR pipe domain '%s' PDC failed: %s\n",
							   r->samr.in.domain_name, nt_errstr(status));
		return status;
	}

	/* create user via samr call (to be continued) */
	return status;
}


NTSTATUS libnet_CreateUser(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, union libnet_CreateUser *r)
{
	switch (r->generic.level) {
	case LIBNET_CREATE_USER_GENERIC:
		return libnet_CreateUser_generic(ctx, mem_ctx, r);
	case LIBNET_CREATE_USER_SAMR:
		return libnet_CreateUser_samr(ctx, mem_ctx, r);
	}

	return NT_STATUS_INVALID_LEVEL;
}
