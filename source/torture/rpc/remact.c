/* 
   Unix SMB/CIFS implementation.
   test suite for remoteactivation operations

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
#include "librpc/gen_ndr/ndr_remact.h"
#include "librpc/gen_ndr/ndr_epmapper.h"

#define CLSID_TEST "00000316-0000-0000-C000-000000000046"
#define CLSID_SIMPLE "5e9ddec7-5767-11cf-beab-00aa006c3606"
#define CLSID_COFFEEMACHINE "DB7C21F8-FE33-4C11-AEA5-CEB56F076FBB"

static int test_RemoteActivation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct RemoteActivation r;
	NTSTATUS status;
	struct GUID iids[2];
	uint16 protseq[3] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_UUID };

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	uuid_generate_random(&r.in.this.cid);
	GUID_from_string(CLSID_SIMPLE, &r.in.Clsid);
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = 3;
	r.in.protseq = protseq;
	r.in.Interfaces = 1;
	GUID_from_string(DCERPC_IUNKNOWN_UUID, &iids[0]);
	r.in.pIIDs = iids;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "RemoteActivation: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "RemoteActivation: %s\n", win_errstr(r.out.result));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.hr)) {
		fprintf(stderr, "RemoteActivation: %s\n", win_errstr(r.out.hr));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.results[0])) {
		fprintf(stderr, "RemoteActivation: %s\n", win_errstr(r.out.results[0]));
		return 0;
	}

	GUID_from_string(DCERPC_ICLASSFACTORY_UUID, &iids[0]);
	r.in.Mode = MODE_GET_CLASS_OBJECT;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "RemoteActivation(GetClassObject): %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "RemoteActivation(GetClassObject): %s\n", win_errstr(r.out.result));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.hr)) {
		fprintf(stderr, "RemoteActivation(GetClassObject): %s\n", win_errstr(r.out.hr));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.results[0])) {
		fprintf(stderr, "RemoteActivation: %s\n", win_errstr(r.out.results[0]));
		return 0;
	}

	return 1;
}

BOOL torture_rpc_remact(void)
{
     NTSTATUS status;
     struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_remact");

	status = torture_rpc_connection(&p, 
					DCERPC_IREMOTEACTIVATION_NAME,
					DCERPC_IREMOTEACTIVATION_UUID, 
					DCERPC_IREMOTEACTIVATION_VERSION);

	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	if(!test_RemoteActivation(p, mem_ctx))
		ret = False;

	talloc_destroy(mem_ctx);

    torture_rpc_close(p);

	return ret;
}
