/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Rafal Szczesniak 2005
   
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
#include "lib/cmdline/popt_common.h"
#include "libnet/libnet.h"
#include "librpc/gen_ndr/nbt.h"
#include "torture/torture.h"


BOOL torture_lookup(struct torture_context *torture)
{
	BOOL ret;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_Lookup lookup;
	const char *address;

	mem_ctx = talloc_init("test_lookup");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	address = talloc_array(ctx, const char, 16);

	lookup.in.hostname = lp_parm_string(-1, "torture", "host");
	lookup.in.type     = NBT_NAME_CLIENT;
	lookup.in.methods  = NULL;
	lookup.out.address = &address;

	status = libnet_Lookup(ctx, mem_ctx, &lookup);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't lookup name %s: %s\n", lookup.in.hostname, nt_errstr(status));
		ret = False;
		goto done;
	}

	ret = True;

done:
	talloc_free(mem_ctx);
	return ret;
}


BOOL torture_lookup_host(struct torture_context *torture)
{
	BOOL ret;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_Lookup lookup;
	const char *address;

	mem_ctx = talloc_init("test_lookup_host");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	address = talloc_array(mem_ctx, const char, 16);

	lookup.in.hostname = lp_parm_string(-1, "torture", "host");
	lookup.in.methods  = NULL;
	lookup.out.address = &address;

	status = libnet_LookupHost(ctx, mem_ctx, &lookup);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't lookup host %s: %s\n", lookup.in.hostname, nt_errstr(status));
		ret = False;
		goto done;
	}

	ret = True;

done:
	talloc_free(mem_ctx);
	return ret;
}


BOOL torture_lookup_pdc(struct torture_context *torture)
{
	BOOL ret;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;
	struct libnet_LookupDCs *lookup;

	mem_ctx = talloc_init("test_lookup_pdc");

	ctx = libnet_context_init(NULL);
	ctx->cred = cmdline_credentials;

	talloc_steal(ctx, mem_ctx);

	lookup = talloc(mem_ctx, struct libnet_LookupDCs);
	if (!lookup) {
		ret = False;
		goto done;
	}

	lookup->in.domain_name = lp_workgroup();
	lookup->in.name_type   = NBT_NAME_PDC;

	status = libnet_LookupDCs(ctx, mem_ctx, lookup);

	if (!NT_STATUS_IS_OK(status)) {
		printf("Couldn't lookup pdc %s: %s\n", lookup->in.domain_name, nt_errstr(status));
		ret = False;
		goto done;
	}

	ret = True;

done:
	talloc_free(mem_ctx);
	return ret;
}
