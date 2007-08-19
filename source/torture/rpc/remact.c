/* 
   Unix SMB/CIFS implementation.
   test suite for remoteactivation operations

   Copyright (C) Jelmer Vernooij 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "torture/rpc/rpc.h"

#define CLSID_IMAGEDOC "02B01C80-E03D-101A-B294-00DD010F2BF9"
#define DCERPC_IUNKNOWN_UUID "00000000-0000-0000-c000-000000000046"
#define DCERPC_ICLASSFACTORY_UUID "00000001-0000-0000-c000-000000000046"

static int test_RemoteActivation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct RemoteActivation r;
	NTSTATUS status;
	struct GUID iids[1];
	uint16_t protseq[3] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_UUID };

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	r.in.this.cid = GUID_random();
	GUID_from_string(CLSID_IMAGEDOC, &r.in.Clsid);
	r.in.ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY;
	r.in.num_protseqs = 3;
	r.in.protseq = protseq;
	r.in.Interfaces = 1;
	GUID_from_string(DCERPC_IUNKNOWN_UUID, &iids[0]);
	r.in.pIIDs = iids;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		printf("RemoteActivation: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		printf("RemoteActivation: %s\n", win_errstr(r.out.result));
		return 0;
	}

	if(!W_ERROR_IS_OK(*r.out.hr)) {
		printf("RemoteActivation: %s\n", win_errstr(*r.out.hr));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.results[0])) {
		printf("RemoteActivation: %s\n", win_errstr(r.out.results[0]));
		return 0;
	}

	GUID_from_string(DCERPC_ICLASSFACTORY_UUID, &iids[0]);
	r.in.Interfaces = 1;
	r.in.Mode = MODE_GET_CLASS_OBJECT;

	status = dcerpc_RemoteActivation(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		printf("RemoteActivation(GetClassObject): %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		printf("RemoteActivation(GetClassObject): %s\n", win_errstr(r.out.result));
		return 0;
	}

	if(!W_ERROR_IS_OK(*r.out.hr)) {
		printf("RemoteActivation(GetClassObject): %s\n", win_errstr(*r.out.hr));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.results[0])) {
		printf("RemoteActivation(GetClassObject): %s\n", win_errstr(r.out.results[0]));
		return 0;
	}

	return 1;
}

BOOL torture_rpc_remact(struct torture_context *torture)
{
	NTSTATUS status;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_remact");

	status = torture_rpc_connection(mem_ctx,
					&p, 
					&ndr_table_IRemoteActivation);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if(!test_RemoteActivation(p, mem_ctx))
		ret = False;

	talloc_free(mem_ctx);

	return ret;
}
