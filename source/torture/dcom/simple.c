/* 
   Unix SMB/CIFS implementation.
   run the "simple" example DCOM program 

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
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"

#define CLSID_SIMPLE "5e9ddec7-5767-11cf-beab-00aa006c3606"
#define DEFAULT_TRANS 4096

BOOL torture_dcom_simple(void)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct GUID IID[2];
	struct GUID clsid;
	WERROR error;
	struct dcom_interface *interfaces;
	struct IStream_Read r_read;
	struct IStream_Write r_write;
	WERROR results[2];
	struct dcom_context *ctx;

	mem_ctx = talloc_init("torture_dcom_simple");

	dcom_init(&ctx, lp_parm_string(-1, "torture", "userdomain"),
			  	lp_parm_string(-1, "torture", "username"), 
				  lp_parm_string(-1, "torture", "password"));

	GUID_from_string(DCERPC_ISTREAM_UUID, &IID[0]);
	GUID_from_string(DCERPC_IUNKNOWN_UUID, &IID[1]);
	GUID_from_string(CLSID_SIMPLE, &clsid);
	error = dcom_create_object(ctx, &clsid, 
							  lp_parm_string(-1, "torture", "binding"), 2, IID,
							  &interfaces, 
							  results);
							  

	if (!W_ERROR_IS_OK(error)) {
		printf("dcom_create_object failed - %s\n", win_errstr(error));
		return False;
	}
	
	ZERO_STRUCT(r_read);
	status = dcerpc_IStream_Read(&interfaces[0], mem_ctx, &r_read);
	if (NT_STATUS_IS_ERR(status)) {
		printf("IStream::Read() failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_IStream_Write(&interfaces[0], mem_ctx, &r_write);
	if (NT_STATUS_IS_ERR(status)) {
		printf("IStream::Write() failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_IUnknown_Release(&interfaces[1], mem_ctx, NULL);
	if (NT_STATUS_IS_ERR(status)) {
		printf("IUnknown::Release() failed - %s\n", nt_errstr(status));
		return False;
	}

	talloc_destroy(mem_ctx);

	torture_rpc_close(p);
	return ret;
}
