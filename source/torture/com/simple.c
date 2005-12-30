/* 
   Unix SMB/CIFS implementation.
   run the "simple" example (D)COM program 

   Copyright (C) Jelmer Vernooij 2004
   
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
#include "lib/com/com.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "lib/cmdline/popt_common.h"

#define DEFAULT_TRANS 4096

static BOOL test_readwrite(TALLOC_CTX *mem_ctx, const char *host)
{
	BOOL ret = True;
	struct GUID IID[2];
	struct GUID clsid;
	WERROR error;
	struct IUnknown *interfaces[3];
	WERROR results[2];
	struct com_context *ctx;
	char test_data[5];
	int i;

	com_init();

	com_init_ctx(&ctx, NULL);
	dcom_client_init(ctx, cmdline_credentials);

	IID[0] = dcerpc_table_IStream.uuid;
	IID[1] = dcerpc_table_IUnknown.uuid;
	GUID_from_string(CLSID_SIMPLE, &clsid);

	if (host) {
		error = dcom_create_object(ctx, &clsid, 
					   host, 2, IID,
					   &interfaces, 
					   results);
	} else {
		error = com_create_object(ctx, &clsid, 2, IID, interfaces, results);
	}

	if (!W_ERROR_IS_OK(error)) {
		printf("(d)com_create_object failed - %s\n", win_errstr(error));
		return False;
	}
	
	error = IStream_Read((struct IStream *)interfaces[0], mem_ctx, NULL, 20, 20, 30);
	if (!W_ERROR_IS_OK(error)) {
		printf("IStream::Read() failed - %s\n", win_errstr(error));
		ret = False;
	}

	for (i = 0; i < 5; i++) {
		test_data[i] = i+1;
	}

	error = IStream_Write((struct IStream *)interfaces[0], mem_ctx, &test_data, 5, NULL);
	if (!W_ERROR_IS_OK(error)) {
		printf("IStream::Write() failed - %s\n", win_errstr(error));
		ret = False;
	}

	IUnknown_Release((struct IUnknown *)interfaces[1], mem_ctx);

	return True;
}

BOOL torture_com_simple(void)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_init("torture_dcom_simple");
	const char *host = lp_parm_string(-1, "dcom", "host");

	ret &= test_readwrite(mem_ctx, host);

	talloc_free(mem_ctx);

	return ret;
}
