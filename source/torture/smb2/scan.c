/* 
   Unix SMB/CIFS implementation.

   SMB2 opcode scanner

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "lib/cmdline/popt_common.h"
#include "lib/events/events.h"


/* 
   scan for valid SMB2 opcodes
*/
BOOL torture_smb2_scan(void)
{
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct smb2_tree *tree;
	const char *host = lp_parm_string(-1, "torture", "host");
	const char *share = lp_parm_string(-1, "torture", "share");
	struct cli_credentials *credentials = cmdline_credentials;
	NTSTATUS status;
	int opcode;
	struct smb2_request *req;

	status = smb2_connect(mem_ctx, host, share, credentials, &tree, 
			      event_context_find(mem_ctx));
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connection failed - %s\n", nt_errstr(status));
		return False;
	}

	tree->session->transport->options.timeout = 3;

	for (opcode=0;opcode<1000;opcode++) {
		req = smb2_request_init_tree(tree, opcode, 2);
		SSVAL(req->out.body, 0, 0);
		smb2_transport_send(req);
		if (!smb2_request_receive(req)) {
			talloc_free(tree);
			status = smb2_connect(mem_ctx, host, share, credentials, &tree, 
					      event_context_find(mem_ctx));
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connection failed - %s\n", nt_errstr(status));
				return False;
			}
			tree->session->transport->options.timeout = 3;
		} else {
			status = smb2_request_destroy(req);
			printf("active opcode %4d gave status %s\n", opcode, nt_errstr(status));
		}
	}

	talloc_free(mem_ctx);

	return True;
}
