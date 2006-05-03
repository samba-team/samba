/* 
   Unix SMB/CIFS implementation.

   dcerpc torture tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Rafal Szczesniak 2006

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
#include "torture/torture.h"
#include "lib/events/events.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "torture/rpc/rpc.h"

/*
  This test initiates multiple rpc bind requests and verifies
  whether all of them are served.
*/


BOOL torture_async_bind(struct torture_context *torture)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	struct event_context *evt_ctx;
	int i;
	const char *binding_string;
	struct cli_credentials *creds;

#define ASYNC_COUNT 100
	struct composite_context *bind_req[ASYNC_COUNT];
	struct dcerpc_pipe *pipe[ASYNC_COUNT];
	struct dcerpc_interface_table *table[ASYNC_COUNT];

	if (!lp_parm_bool(-1, "torture", "dangerous", False)) {
		printf("async bind test disabled - enable dangerous tests to use\n");
		return True;
	}

	binding_string = lp_parm_string(-1, "torture", "binding");

	/* talloc context */
	mem_ctx = talloc_init("torture_async_bind");
	if (mem_ctx == NULL) return False;

	/* event context */
	evt_ctx = event_context_init(mem_ctx);
	if (evt_ctx == NULL) return False;

	/* credentials */
	creds = cmdline_credentials;

	for (i = 0; i < ASYNC_COUNT; i++) {
		table[i] = &dcerpc_table_lsarpc;
		bind_req[i] = dcerpc_pipe_connect_send(mem_ctx, &pipe[i], binding_string,
						       table[i], creds, evt_ctx);
	}

	for (i = 0; i < ASYNC_COUNT; i++) {
		status = dcerpc_pipe_connect_recv(bind_req[i], mem_ctx, &pipe[i]);
		if (!NT_STATUS_IS_OK(status)) return False;
	}

	talloc_free(mem_ctx);
	return True;
}
