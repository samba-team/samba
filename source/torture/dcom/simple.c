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
	char pv[DEFAULT_TRANS];
	struct dcom_interface *interfaces;
	struct IStream_Read r_read;
	struct IStream_Write r_write;

	mem_ctx = talloc_init("torture_dcom_simple");

	GUID_from_string(DCERPC_ISTREAM_UUID, &IID[0]);
	GUID_from_string(DCERPC_IUNKNOWN_UUID, &IID[1]);
	GUID_from_string(CLSID_SIMPLE, &clsid);
	error = dcom_create_object(mem_ctx, &clsid, "192.168.4.28", 2, IID, &interfaces);

	if (!W_ERROR_IS_OK(error)) {
		printf("dcom_create_object failed - %s\n", win_errstr(error));
		return False;
	}
	
	ZERO_STRUCT(r_read);
	status = dcerpc_IStream_Read(interfaces[0].pipe, &interfaces[0].ipid, mem_ctx, &r_read);
	if (NT_STATUS_IS_ERR(error)) {
		printf("IStream::Read() failed - %s\n", win_errstr(error));
		return False;
	}

	
	status = dcerpc_IStream_Write(interfaces[0].pipe, &interfaces[0].ipid, mem_ctx, &r_write);
	if (NT_STATUS_IS_ERR(error)) {
		printf("IStream::Write() failed - %s\n", win_errstr(error));
		return False;
	}

	/*FIXME: dcerpc_IUnknown_Release();*/

	talloc_destroy(mem_ctx);

	torture_rpc_close(p);
	return ret;
}
