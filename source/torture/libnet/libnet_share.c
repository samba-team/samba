/* 
   Unix SMB/CIFS implementation.
   Test suite for libnet calls.

   Copyright (C) Gregory LEOCADIE <gleocadie@idealx.com> 2005
   
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
#include "lib/cmdline/popt_common.h"


#define TEST_SHARENAME "libnetsharetest"


BOOL torture_listshares(void)
{
	struct libnet_ListShares share;
	NTSTATUS  status;
	uint32_t levels[] = { 0, 1, 2, 501, 502 };
	int i;
	BOOL ret = True;
	struct libnet_context* libnetctx;
	const char* host;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("test_listshares");
	host = lp_parm_string(-1, "torture", "host");

	libnetctx = libnet_context_init(NULL);
	libnetctx->cred = cmdline_credentials;
	
	printf("Testing libnet_ListShare\n");
	
	share.in.server_name = talloc_asprintf(mem_ctx, "%s", host);

	for (i = 0; i < ARRAY_SIZE(levels); i++) {
		share.in.level = levels[i];
		printf("testing libnet_ListShare level %u\n", share.in.level);

		status = libnet_ListShares(libnetctx, mem_ctx, &share);
		if (!NT_STATUS_IS_OK(status)) {
			printf("libnet_ListShare level %u failed - %s\n", share.in.level, nt_errstr(status));
			ret = False;
		}
	}

	return ret;
}


BOOL torture_delshare(void)
{
	struct libnet_context* libnetctx;
	const char* host;
	TALLOC_CTX *mem_ctx;
	NTSTATUS  status;
	BOOL ret = True;
	struct libnet_DelShare share;
	
	mem_ctx = talloc_init("test_listshares");
	host = lp_parm_string(-1, "torture", "host");

	libnetctx = libnet_context_init(NULL);
	libnetctx->cred = cmdline_credentials;

	share.in.server_name	= host;
	share.in.share_name	= TEST_SHARENAME;

	status = libnet_DelShare(libnetctx, mem_ctx, &share);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
	}

	talloc_free(mem_ctx);

	return ret;
}
