/* 
   Unix SMB/CIFS implementation.
   test suite for oxidresolve operations

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
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_remact.h"
#include "librpc/gen_ndr/ndr_epmapper.h"

#define CLSID_TEST "00000316-0000-0000-C000-000000000046"
#define CLSID_SIMPLE "5e9ddec7-5767-11cf-beab-00aa006c3606"
#define CLSID_COFFEEMACHINE "DB7C21F8-FE33-4C11-AEA5-CEB56F076FBB"

static int test_RemoteActivation(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, HYPER_T *oxid, struct GUID *oid)
{
	struct RemoteActivation r;
	NTSTATUS status;
	struct GUID iids[2];
	uint16 protseq[3] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_NCALRPC, EPM_PROTOCOL_UUID };

	ZERO_STRUCT(r.in);
	r.in.this.version.MajorVersion = 5;
	r.in.this.version.MinorVersion = 1;
	r.in.this.cid = GUID_random();
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

	*oid = r.out.ipidRemUnknown;
	*oxid = r.out.pOxid;

	return 1;
}

static int test_SimplePing(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, HYPER_T setid)
{
	struct SimplePing r;
	NTSTATUS status;

	r.in.SetId = &setid;

	status = dcerpc_SimplePing(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "SimplePing: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "SimplePing: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

static int test_ComplexPing(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, HYPER_T *setid, struct GUID oid)
{
	struct ComplexPing r;
	NTSTATUS status;

	*setid = 0;
	ZERO_STRUCT(r.in);

	r.in.SequenceNum = 0;
	r.in.SetId = setid;
	r.in.cAddToSet = 1;
	r.in.AddToSet = &oid;

	status = dcerpc_ComplexPing(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ComplexPing: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ComplexPing: %s\n", win_errstr(r.out.result));
		return 0;
	}

	

	return 1;
}

static int test_ServerAlive(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct ServerAlive r;
	NTSTATUS status;

	status = dcerpc_ServerAlive(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ServerAlive: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ServerAlive: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

static int test_ResolveOxid(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, HYPER_T oxid)
{
	struct ResolveOxid r;
	NTSTATUS status;
	uint16 protseq[2] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB };	

	r.in.pOxid = oxid;
	r.in.cRequestedProtseqs = 2;
	r.in.arRequestedProtseqs = protseq;

	status = dcerpc_ResolveOxid(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ResolveOxid: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ResolveOxid: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

static int test_ResolveOxid2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, HYPER_T oxid)
{
	struct ResolveOxid2 r;
	NTSTATUS status;
	uint16 protseq[2] = { EPM_PROTOCOL_TCP, EPM_PROTOCOL_SMB };	

	r.in.pOxid = oxid;
	r.in.cRequestedProtseqs = 2;
	r.in.arRequestedProtseqs = protseq;

	status = dcerpc_ResolveOxid2(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ResolveOxid2: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ResolveOxid2: %s\n", win_errstr(r.out.result));
		return 0;
	}
	
	printf("Remote server versions: %d, %d\n", r.out.ComVersion.MajorVersion, r.out.ComVersion.MinorVersion);

	return 1;
}



static int test_ServerAlive2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct ServerAlive2 r;
	NTSTATUS status;

	status = dcerpc_ServerAlive2(p, mem_ctx, &r);
	if(NT_STATUS_IS_ERR(status)) {
		fprintf(stderr, "ServerAlive2: %s\n", nt_errstr(status));
		return 0;
	}

	if(!W_ERROR_IS_OK(r.out.result)) {
		fprintf(stderr, "ServerAlive2: %s\n", win_errstr(r.out.result));
		return 0;
	}

	return 1;
}

BOOL torture_rpc_oxidresolve(void)
{
        NTSTATUS status;
       struct dcerpc_pipe *p, *premact;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	HYPER_T setid;
	HYPER_T oxid;
	struct GUID oid;

	mem_ctx = talloc_init("torture_rpc_oxidresolve");

	status = torture_rpc_connection(&premact, 
					DCERPC_IREMOTEACTIVATION_NAME, 
					DCERPC_IREMOTEACTIVATION_UUID, 
					DCERPC_IREMOTEACTIVATION_VERSION);								
			
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}

	status = dcerpc_secondary_connection(premact, &p, 
					DCERPC_IOXIDRESOLVER_NAME, 
					DCERPC_IOXIDRESOLVER_UUID, 
					DCERPC_IOXIDRESOLVER_VERSION);

	if(!test_RemoteActivation(premact, mem_ctx, &oxid, &oid))
		return False;

	if(!test_ServerAlive(p, mem_ctx))
		ret = False;

	if(!test_ComplexPing(p, mem_ctx, &setid, oid))
		ret = False;

	if(!test_SimplePing(p, mem_ctx, setid))
		ret = False;

	if(!test_ServerAlive2(p, mem_ctx))
		ret = False;

	if(!test_ResolveOxid(p, mem_ctx, oxid))
		ret = False;

	if(!test_ResolveOxid2(p, mem_ctx, oxid))
		ret = False;

	talloc_destroy(mem_ctx);

    torture_rpc_close(p);

	return ret;
}
