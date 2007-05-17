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
#include "libcli/composite/composite.h"
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
	extern int torture_numasync;

	struct composite_context **bind_req;
	struct dcerpc_pipe **pipe;
	const struct dcerpc_interface_table **table;

	if (!torture_setting_bool(torture, "async", False)) {
		printf("async bind test disabled - enable async tests to use\n");
		return True;
	}
	
	binding_string = torture_setting_string(torture, "binding", NULL);

	/* talloc context */
	mem_ctx = talloc_init("torture_async_bind");
	if (mem_ctx == NULL) return False;

	bind_req = talloc_array(torture, struct composite_context*, torture_numasync);
	if (bind_req == NULL) return False;
	pipe     = talloc_array(torture, struct dcerpc_pipe*, torture_numasync);
	if (pipe == NULL) return False;
	table    = talloc_array(torture, const struct dcerpc_interface_table*, torture_numasync);
	if (table == NULL) return False;
	
	/* credentials */
	creds = cmdline_credentials;

	/* event context */
	evt_ctx = cli_credentials_get_event_context(creds);
	if (evt_ctx == NULL) return False;

	/* send bind requests */
	for (i = 0; i < torture_numasync; i++) {
		table[i] = &dcerpc_table_lsarpc;
		bind_req[i] = dcerpc_pipe_connect_send(mem_ctx, binding_string,
						       table[i], creds, evt_ctx);
	}

	/* recv bind requests */
	for (i = 0; i < torture_numasync; i++) {
		status = dcerpc_pipe_connect_recv(bind_req[i], mem_ctx, &pipe[i]);
		if (!NT_STATUS_IS_OK(status)) {
			printf("async rpc connection failed: %s\n", nt_errstr(status));
			return False;
		}
	}

	talloc_free(mem_ctx);
	return True;
}
