/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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

/*
  this makes the debug code display the right thing
*/
static void init_lsa_Name(struct lsa_Name *name, const char *s)
{
	name->name = s;
	name->name_len = strlen_m(s)*2;
	name->name_size = name->name_len;
}

static BOOL test_OpenPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	uint16 system_name = '\\';

	printf("\ntesting OpenPolicy\n");

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = &system_name;
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_OpenPolicy2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	printf("\ntesting OpenPolicy2\n");

	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	r.in.system_name = "\\";
	r.in.attr = &attr;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.handle = handle;

	status = dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_LookupNames(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle,
			    struct lsa_TransNameArray *tnames)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_Name *names;
	uint32 count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames\n");

	sids.count = 0;
	sids.sids = NULL;

	names = talloc(mem_ctx, tnames->count * sizeof(names[0]));
	for (i=0;i<tnames->count;i++) {
		init_lsa_Name(&names[i], tnames->names[i].name.name);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;

	status = dcerpc_lsa_LookupNames(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}


static BOOL test_LookupSids(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray names;
	uint32 count = sids->num_sids;
	NTSTATUS status;

	printf("\nTesting LookupSids\n");

	names.count = 0;
	names.names = NULL;

	r.in.handle = handle;
	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupSids failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	if (!test_LookupNames(p, mem_ctx, handle, &names)) {
		return False;
	}

	return True;
}

static BOOL test_LookupPrivName(struct dcerpc_pipe *p, 
				TALLOC_CTX *mem_ctx, 
				struct policy_handle *handle,
				struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_LookupPrivName r;

	r.in.handle = handle;
	r.in.luid = luid;

	status = dcerpc_lsa_LookupPrivName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("\nLookupPrivName failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_EnumPrivsAccount(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 				  
				  struct policy_handle *handle,
				  struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivsAccount r;

	printf("Testing EnumPrivsAccount\n");

	r.in.handle = acct_handle;

	status = dcerpc_lsa_EnumPrivsAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.privs) {
		int i;
		for (i=0;i<r.out.privs->count;i++) {
			test_LookupPrivName(p, mem_ctx, handle, 
					    &r.out.privs->set[i].luid);
		}
	}

	return True;
}

static BOOL test_EnumAccountRights(struct dcerpc_pipe *p, 
				   TALLOC_CTX *mem_ctx, 
				   struct policy_handle *acct_handle,
				   struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_EnumAccountRights r;
	struct lsa_RightSet rights;

	printf("Testing EnumAccountRights\n");

	r.in.handle = acct_handle;
	r.in.sid = sid;
	r.out.rights = &rights;

	status = dcerpc_lsa_EnumAccountRights(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccountRights failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_QuerySecObj(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle,
			     struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_QuerySecObj r;

	printf("Testing QuerySecObj\n");

	r.in.handle = acct_handle;
	r.in.sec_info = 7;

	status = dcerpc_lsa_QuerySecObj(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecObj failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_OpenAccount(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle,
			     struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_OpenAccount r;
	struct policy_handle acct_handle;

	printf("Testing OpenAccount\n");

	r.in.handle = handle;
	r.in.sid = sid;
	r.in.desired_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_EnumPrivsAccount(p, mem_ctx, handle, &acct_handle)) {
		return False;
	}

	if (!test_QuerySecObj(p, mem_ctx, handle, &acct_handle)) {
		return False;
	}

	return True;
}

static BOOL test_EnumAccounts(struct dcerpc_pipe *p, 
			  TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumAccounts r;
	struct lsa_SidArray sids1, sids2;
	uint32 resume_handle = 0;
	int i;

	printf("\ntesting EnumAccounts\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 100;
	r.out.resume_handle = &resume_handle;
	r.out.sids = &sids1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumAccounts(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccounts failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_LookupSids(p, mem_ctx, handle, &sids1)) {
		return False;
	}

	printf("testing all accounts\n");
	for (i=0;i<sids1.num_sids;i++) {
		test_OpenAccount(p, mem_ctx, handle, sids1.sids[i].sid);
		test_EnumAccountRights(p, mem_ctx, handle, sids1.sids[i].sid);
	}
	printf("\n");

	if (sids1.num_sids < 3) {
		return True;
	}
	
	printf("trying EnumAccounts partial listing (asking for 1 at 2)\n");
	resume_handle = 2;
	r.in.num_entries = 1;
	r.out.sids = &sids2;

	status = dcerpc_lsa_EnumAccounts(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccounts failed - %s\n", nt_errstr(status));
		return False;
	}

	if (sids2.num_sids != 1) {
		printf("Returned wrong number of entries (%d)\n", sids2.num_sids);
		return False;
	}

	return True;
}


static BOOL test_EnumPrivs(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx, 
			   struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivs r;
	struct lsa_PrivArray privs1;
	uint32 resume_handle = 0;

	printf("\ntesting EnumPrivs\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_count = 1000;
	r.out.resume_handle = &resume_handle;
	r.out.privs = &privs1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumPrivs(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivs failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_EnumTrustDom(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	struct lsa_EnumTrustDom r;
	NTSTATUS status;
	uint32 resume_handle = 0;
	struct lsa_DomainList domains;

	printf("\nTesting EnumTrustDom\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 1000;
	r.out.domains = &domains;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_lsa_EnumTrustDom(p, mem_ctx, &r);

	/* NO_MORE_ENTRIES is allowed */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		return True;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumTrustDom failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}

static BOOL test_QueryInfoPolicy(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy r;
	NTSTATUS status;
	int i;
	BOOL ret = True;
	printf("\nTesting QueryInfoPolicy\n");

	for (i=1;i<13;i++) {
		r.in.handle = handle;
		r.in.level = i;

		printf("\ntrying QueryInfoPolicy level %d\n", i);

		status = dcerpc_lsa_QueryInfoPolicy(p, mem_ctx, &r);

		if ((i == 9 || i == 10 || i == 11) &&
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("server failed level %u (OK)\n", i);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfoPolicy failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return ret;
}

static BOOL test_Delete(struct dcerpc_pipe *p, 
		       TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Delete r;

	printf("\ntesting Delete - but what does it do?\n");

	r.in.handle = handle;
	status = dcerpc_lsa_Delete(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Delete failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}

static BOOL test_Close(struct dcerpc_pipe *p, 
		       TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Close r;
	struct policy_handle handle2;

	printf("\ntesting Close\n");

	r.in.handle = handle;
	r.out.handle = &handle2;

	status = dcerpc_lsa_Close(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	status = dcerpc_lsa_Close(p, mem_ctx, &r);
	/* its really a fault - we need a status code for rpc fault */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}

BOOL torture_rpc_lsa(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle handle;

	mem_ctx = talloc_init("torture_rpc_lsa");

	status = torture_rpc_connection(&p, 
					DCERPC_LSARPC_NAME, 
					DCERPC_LSARPC_UUID, 
					DCERPC_LSARPC_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	p->flags |= DCERPC_DEBUG_PRINT_BOTH;

	if (!test_OpenPolicy(p, mem_ctx)) {
		ret = False;
	}

	if (!test_OpenPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumAccounts(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumPrivs(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_EnumTrustDom(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (!test_QueryInfoPolicy(p, mem_ctx, &handle)) {
		ret = False;
	}
	
#if 0
	if (!test_Delete(p, mem_ctx, &handle)) {
		ret = False;
	}
#endif
	
	if (!test_Close(p, mem_ctx, &handle)) {
		ret = False;
	}

	talloc_destroy(mem_ctx);

        torture_rpc_close(p);

	return ret;
}
