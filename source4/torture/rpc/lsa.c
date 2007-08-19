/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc operations

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/netlogon.h"
#include "lib/events/events.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "torture/rpc/rpc.h"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static BOOL test_OpenPolicy(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	uint16_t system_name = '\\';

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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			return True;
		}
		printf("OpenPolicy failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


BOOL test_lsa_OpenPolicy2(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
			  struct policy_handle **handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	printf("\ntesting OpenPolicy2\n");

	*handle = talloc(mem_ctx, struct policy_handle);
	if (!*handle) {
		return False;
	}

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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = *handle;

	status = dcerpc_lsa_OpenPolicy2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			talloc_free(*handle);
			*handle = NULL;
			return True;
		}
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
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(mem_ctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
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

static BOOL test_LookupNames2(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle,
			      struct lsa_TransNameArray2 *tnames)
{
	struct lsa_LookupNames2 r;
	struct lsa_TransSidArray2 sids;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames2 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(mem_ctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.unknown1 = 0;
	r.in.unknown2 = 0;
	r.out.count = &count;
	r.out.sids = &sids;

	status = dcerpc_lsa_LookupNames2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames2 failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}


static BOOL test_LookupNames3(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle,
			      struct lsa_TransNameArray2 *tnames)
{
	struct lsa_LookupNames3 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames3 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(mem_ctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.unknown1 = 0;
	r.in.unknown2 = 0;
	r.out.count = &count;
	r.out.sids = &sids;

	status = dcerpc_lsa_LookupNames3(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames3 failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	return True;
}

static BOOL test_LookupNames4(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct lsa_TransNameArray2 *tnames)
{
	struct lsa_LookupNames4 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames4 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(mem_ctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.unknown1 = 0;
	r.in.unknown2 = 0;
	r.out.count = &count;
	r.out.sids = &sids;

	status = dcerpc_lsa_LookupNames4(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupNames4 failed - %s\n", nt_errstr(status));
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
	uint32_t count = sids->num_sids;
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


static BOOL test_LookupSids2(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct policy_handle *handle,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids2 r;
	struct lsa_TransNameArray2 names;
	uint32_t count = sids->num_sids;
	NTSTATUS status;

	printf("\nTesting LookupSids2\n");

	names.count = 0;
	names.names = NULL;

	r.in.handle = handle;
	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = 1;
	r.in.count = &count;
	r.in.unknown1 = 0;
	r.in.unknown2 = 0;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids2(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		printf("LookupSids2 failed - %s\n", nt_errstr(status));
		return False;
	}

	printf("\n");

	if (!test_LookupNames2(p, mem_ctx, handle, &names)) {
		return False;
	}

	if (!test_LookupNames3(p, mem_ctx, handle, &names)) {
		return False;
	}

	return True;
}

static BOOL test_LookupSids3(struct dcerpc_pipe *p, 
			    TALLOC_CTX *mem_ctx, 
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids3 r;
	struct lsa_TransNameArray2 names;
	uint32_t count = sids->num_sids;
	NTSTATUS status;

	printf("\nTesting LookupSids3\n");

	names.count = 0;
	names.names = NULL;

	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = 1;
	r.in.count = &count;
	r.in.unknown1 = 0;
	r.in.unknown2 = 0;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids3(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			return True;
		}
		printf("LookupSids3 failed - %s - not considered an error\n", 
		       nt_errstr(status));
		return False;
	}

	printf("\n");

	if (!test_LookupNames4(p, mem_ctx, &names)) {
		return False;
	}

	return True;
}

BOOL test_many_LookupSids(struct dcerpc_pipe *p, 
			  TALLOC_CTX *mem_ctx, 
			  struct policy_handle *handle)
{
	uint32_t count;
	NTSTATUS status;
	struct lsa_SidArray sids;
	int i;

	printf("\nTesting LookupSids with lots of SIDs\n");

	sids.num_sids = 100;

	sids.sids = talloc_array(mem_ctx, struct lsa_SidPtr, sids.num_sids);

	for (i=0; i<sids.num_sids; i++) {
		const char *sidstr = "S-1-5-32-545";
		sids.sids[i].sid = dom_sid_parse_talloc(mem_ctx, sidstr);
	}

	count = sids.num_sids;

	if (handle) {
		struct lsa_LookupSids r;
		struct lsa_TransNameArray names;
		names.count = 0;
		names.names = NULL;

		r.in.handle = handle;
		r.in.sids = &sids;
		r.in.names = &names;
		r.in.level = 1;
		r.in.count = &names.count;
		r.out.count = &count;
		r.out.names = &names;
		
		status = dcerpc_lsa_LookupSids(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
			printf("LookupSids failed - %s\n", nt_errstr(status));
			return False;
		}
		
		printf("\n");
		
		if (!test_LookupNames(p, mem_ctx, handle, &names)) {
			return False;
		}
	} else {
		struct lsa_LookupSids3 r;
		struct lsa_TransNameArray2 names;

		names.count = 0;
		names.names = NULL;

		printf("\nTesting LookupSids3\n");
		
		r.in.sids = &sids;
		r.in.names = &names;
		r.in.level = 1;
		r.in.count = &count;
		r.in.unknown1 = 0;
		r.in.unknown2 = 0;
		r.out.count = &count;
		r.out.names = &names;
		
		status = dcerpc_lsa_LookupSids3(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
			    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
				printf("not considering %s to be an error\n", nt_errstr(status));
				return True;
			}
			printf("LookupSids3 failed - %s\n", 
			       nt_errstr(status));
			return False;
		}
		if (!test_LookupNames4(p, mem_ctx, &names)) {
			return False;
		}
	}

	printf("\n");



	return True;
}

static void lookupsids_cb(struct rpc_request *req)
{
	int *replies = (int *)req->async.private_data;
	NTSTATUS status;

	status = dcerpc_ndr_request_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lookupsids returned %s\n", nt_errstr(status));
		*replies = -1;
	}

	if (*replies >= 0) {
		*replies += 1;
	}
}

static BOOL test_LookupSids_async(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	struct lsa_SidArray sids;
	struct lsa_SidPtr sidptr;
	uint32_t *count;
	struct lsa_TransNameArray *names;
	struct lsa_LookupSids *r;
	struct rpc_request **req;
	int i, replies;
	BOOL ret = True;
	const int num_async_requests = 50;

	count = talloc_array(mem_ctx, uint32_t, num_async_requests);
	names = talloc_array(mem_ctx, struct lsa_TransNameArray, num_async_requests);
	r = talloc_array(mem_ctx, struct lsa_LookupSids, num_async_requests);

	printf("\nTesting %d async lookupsids request\n", num_async_requests);

	req = talloc_array(mem_ctx, struct rpc_request *, num_async_requests);

	sids.num_sids = 1;
	sids.sids = &sidptr;
	sidptr.sid = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-545");

	replies = 0;

	for (i=0; i<num_async_requests; i++) {
		count[i] = 0;
		names[i].count = 0;
		names[i].names = NULL;

		r[i].in.handle = handle;
		r[i].in.sids = &sids;
		r[i].in.names = &names[i];
		r[i].in.level = 1;
		r[i].in.count = &names[i].count;
		r[i].out.count = &count[i];
		r[i].out.names = &names[i];
		
		req[i] = dcerpc_lsa_LookupSids_send(p, req, &r[i]);
		if (req[i] == NULL) {
			ret = False;
			break;
		}

		req[i]->async.callback = lookupsids_cb;
		req[i]->async.private_data = &replies;
	}

	while (replies >= 0 && replies < num_async_requests) {
		event_loop_once(p->conn->event_ctx);
	}

	talloc_free(req);

	if (replies < 0) {
		ret = False;
	}

	return ret;
}

static BOOL test_LookupPrivValue(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle,
				 struct lsa_String *name)
{
	NTSTATUS status;
	struct lsa_LookupPrivValue r;
	struct lsa_LUID luid;

	r.in.handle = handle;
	r.in.name = name;
	r.out.luid = &luid;

	status = dcerpc_lsa_LookupPrivValue(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("\nLookupPrivValue failed - %s\n", nt_errstr(status));
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

static BOOL test_RemovePrivilegesFromAccount(struct dcerpc_pipe *p, 
					     TALLOC_CTX *mem_ctx, 				  
					     struct policy_handle *acct_handle,
					     struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_RemovePrivilegesFromAccount r;
	struct lsa_PrivilegeSet privs;
	BOOL ret = True;

	printf("Testing RemovePrivilegesFromAccount\n");

	r.in.handle = acct_handle;
	r.in.remove_all = 0;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(mem_ctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	status = dcerpc_lsa_RemovePrivilegesFromAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("RemovePrivilegesFromAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

static BOOL test_AddPrivilegesToAccount(struct dcerpc_pipe *p, 
					TALLOC_CTX *mem_ctx, 				  
					struct policy_handle *acct_handle,
					struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_AddPrivilegesToAccount r;
	struct lsa_PrivilegeSet privs;
	BOOL ret = True;

	printf("Testing AddPrivilegesToAccount\n");

	r.in.handle = acct_handle;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(mem_ctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	status = dcerpc_lsa_AddPrivilegesToAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddPrivilegesToAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	return ret;
}

static BOOL test_EnumPrivsAccount(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 				  
				  struct policy_handle *handle,
				  struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivsAccount r;
	BOOL ret = True;

	printf("Testing EnumPrivsAccount\n");

	r.in.handle = acct_handle;

	status = dcerpc_lsa_EnumPrivsAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (r.out.privs && r.out.privs->count > 0) {
		int i;
		for (i=0;i<r.out.privs->count;i++) {
			test_LookupPrivName(p, mem_ctx, handle, 
					    &r.out.privs->set[i].luid);
		}

		ret &= test_RemovePrivilegesFromAccount(p, mem_ctx, acct_handle, 
							&r.out.privs->set[0].luid);
		ret &= test_AddPrivilegesToAccount(p, mem_ctx, acct_handle, 
						   &r.out.privs->set[0].luid);
	}

	return ret;
}

static BOOL test_Delete(struct dcerpc_pipe *p, 
		       TALLOC_CTX *mem_ctx, 
		       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Delete r;

	printf("testing Delete\n");

	r.in.handle = handle;
	status = dcerpc_lsa_Delete(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Delete failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_CreateAccount(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx, 
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateAccount r;
	struct dom_sid2 *newsid;
	struct policy_handle acct_handle;

	newsid = dom_sid_parse_talloc(mem_ctx, "S-1-5-12349876-4321-2854");

	printf("Testing CreateAccount\n");

	r.in.handle = handle;
	r.in.sid = newsid;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_CreateAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_Delete(p, mem_ctx, &acct_handle)) {
		return False;
	}

	return True;
}

static BOOL test_DeleteTrustedDomain(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle,
				     struct lsa_StringLarge name)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomainByName r;
	struct policy_handle trustdom_handle;

	r.in.handle = handle;
	r.in.name.string = name.string;
	r.in.access_mask = SEC_STD_DELETE;
	r.out.trustdom_handle = &trustdom_handle;

	status = dcerpc_lsa_OpenTrustedDomainByName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lsa_OpenTrustedDomainByName failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_Delete(p, mem_ctx, &trustdom_handle)) {
		return False;
	}

	return True;
}

static BOOL test_DeleteTrustedDomainBySid(struct dcerpc_pipe *p, 
					  TALLOC_CTX *mem_ctx, 
					  struct policy_handle *handle,
					  struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_DeleteTrustedDomain r;

	r.in.handle = handle;
	r.in.dom_sid = sid;

	status = dcerpc_lsa_DeleteTrustedDomain(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lsa_DeleteTrustedDomain failed - %s\n", nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_CreateSecret(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateSecret r;
	struct lsa_OpenSecret r2;
	struct lsa_SetSecret r3;
	struct lsa_QuerySecret r4;
	struct lsa_SetSecret r5;
	struct lsa_QuerySecret r6;
	struct lsa_SetSecret r7;
	struct lsa_QuerySecret r8;
	struct policy_handle sec_handle, sec_handle2, sec_handle3;
	struct lsa_Delete d;
	struct lsa_DATA_BUF buf1;
	struct lsa_DATA_BUF_PTR bufp1;
	struct lsa_DATA_BUF_PTR bufp2;
	DATA_BLOB enc_key;
	BOOL ret = True;
	DATA_BLOB session_key;
	NTTIME old_mtime, new_mtime;
	DATA_BLOB blob1, blob2;
	const char *secret1 = "abcdef12345699qwerty";
	char *secret2;
 	const char *secret3 = "ABCDEF12345699QWERTY";
	char *secret4;
 	const char *secret5 = "NEW-SAMBA4-SECRET";
	char *secret6;
	char *secname[2];
	int i;
	const int LOCAL = 0;
	const int GLOBAL = 1;

	secname[LOCAL] = talloc_asprintf(mem_ctx, "torturesecret-%u", (uint_t)random());
	secname[GLOBAL] = talloc_asprintf(mem_ctx, "G$torturesecret-%u", (uint_t)random());

	for (i=0; i< 2; i++) {
		printf("Testing CreateSecret of %s\n", secname[i]);
		
		init_lsa_String(&r.in.name, secname[i]);
		
		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle;
		
		status = dcerpc_lsa_CreateSecret(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("CreateSecret failed - %s\n", nt_errstr(status));
			return False;
		}
		
		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle3;
		
		status = dcerpc_lsa_CreateSecret(p, mem_ctx, &r);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			printf("CreateSecret should have failed OBJECT_NAME_COLLISION - %s\n", nt_errstr(status));
			return False;
		}
		
		r2.in.handle = handle;
		r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r2.in.name = r.in.name;
		r2.out.sec_handle = &sec_handle2;
		
		printf("Testing OpenSecret\n");
		
		status = dcerpc_lsa_OpenSecret(p, mem_ctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenSecret failed - %s\n", nt_errstr(status));
			return False;
		}
		
		status = dcerpc_fetch_session_key(p, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
			return False;
		}
		
		enc_key = sess_encrypt_string(secret1, &session_key);
		
		r3.in.sec_handle = &sec_handle;
		r3.in.new_val = &buf1;
		r3.in.old_val = NULL;
		r3.in.new_val->data = enc_key.data;
		r3.in.new_val->length = enc_key.length;
		r3.in.new_val->size = enc_key.length;
		
		printf("Testing SetSecret\n");
		
		status = dcerpc_lsa_SetSecret(p, mem_ctx, &r3);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			return False;
		}
		
		r3.in.sec_handle = &sec_handle;
		r3.in.new_val = &buf1;
		r3.in.old_val = NULL;
		r3.in.new_val->data = enc_key.data;
		r3.in.new_val->length = enc_key.length;
		r3.in.new_val->size = enc_key.length;
		
		/* break the encrypted data */
		enc_key.data[0]++;

		printf("Testing SetSecret with broken key\n");
		
		status = dcerpc_lsa_SetSecret(p, mem_ctx, &r3);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_UNKNOWN_REVISION)) {
			printf("SetSecret should have failed UNKNOWN_REVISION - %s\n", nt_errstr(status));
			ret = False;
		}
		
		data_blob_free(&enc_key);
		
		ZERO_STRUCT(new_mtime);
		ZERO_STRUCT(old_mtime);
		
		/* fetch the secret back again */
		r4.in.sec_handle = &sec_handle;
		r4.in.new_val = &bufp1;
		r4.in.new_mtime = &new_mtime;
		r4.in.old_val = NULL;
		r4.in.old_mtime = NULL;
		
		bufp1.buf = NULL;
		
		printf("Testing QuerySecret\n");
		status = dcerpc_lsa_QuerySecret(p, mem_ctx, &r4);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = False;
		} else {
			if (r4.out.new_val == NULL || r4.out.new_val->buf == NULL) {
				printf("No secret buffer returned\n");
				ret = False;
			} else {
				blob1.data = r4.out.new_val->buf->data;
				blob1.length = r4.out.new_val->buf->size;
				
				blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
				
				secret2 = sess_decrypt_string(mem_ctx, 
							      &blob1, &session_key);
				
				if (strcmp(secret1, secret2) != 0) {
					printf("Returned secret '%s' doesn't match '%s'\n", 
					       secret2, secret1);
					ret = False;
				}
			}
		}
		
		enc_key = sess_encrypt_string(secret3, &session_key);
		
		r5.in.sec_handle = &sec_handle;
		r5.in.new_val = &buf1;
		r5.in.old_val = NULL;
		r5.in.new_val->data = enc_key.data;
		r5.in.new_val->length = enc_key.length;
		r5.in.new_val->size = enc_key.length;
		
		printf("Testing SetSecret (existing value should move to old)\n");
		
		status = dcerpc_lsa_SetSecret(p, mem_ctx, &r5);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			ret = False;
		}
		
		data_blob_free(&enc_key);
		
		ZERO_STRUCT(new_mtime);
		ZERO_STRUCT(old_mtime);
		
		/* fetch the secret back again */
		r6.in.sec_handle = &sec_handle;
		r6.in.new_val = &bufp1;
		r6.in.new_mtime = &new_mtime;
		r6.in.old_val = &bufp2;
		r6.in.old_mtime = &old_mtime;
		
		bufp1.buf = NULL;
		bufp2.buf = NULL;
		
		status = dcerpc_lsa_QuerySecret(p, mem_ctx, &r6);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = False;
			secret4 = NULL;
		} else {

			if (r6.out.new_val->buf == NULL || r6.out.old_val->buf == NULL 
				|| r6.out.new_mtime == NULL || r6.out.old_mtime == NULL) {
				printf("Both secret buffers and both times not returned\n");
				ret = False;
				secret4 = NULL;
			} else {
				blob1.data = r6.out.new_val->buf->data;
				blob1.length = r6.out.new_val->buf->size;
				
				blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
				
				secret4 = sess_decrypt_string(mem_ctx, 
							      &blob1, &session_key);
				
				if (strcmp(secret3, secret4) != 0) {
					printf("Returned NEW secret %s doesn't match %s\n", secret4, secret3);
					ret = False;
				}

				blob1.data = r6.out.old_val->buf->data;
				blob1.length = r6.out.old_val->buf->length;
				
				blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
				
				secret2 = sess_decrypt_string(mem_ctx, 
							      &blob1, &session_key);
				
				if (strcmp(secret1, secret2) != 0) {
					printf("Returned OLD secret %s doesn't match %s\n", secret2, secret1);
					ret = False;
				}
				
				if (*r6.out.new_mtime == *r6.out.old_mtime) {
					printf("Returned secret %s had same mtime for both secrets: %s\n", 
					       secname[i],
					       nt_time_string(mem_ctx, *r6.out.new_mtime));
					ret = False;
				}
			}
		}

		enc_key = sess_encrypt_string(secret5, &session_key);
		
		r7.in.sec_handle = &sec_handle;
		r7.in.old_val = &buf1;
		r7.in.old_val->data = enc_key.data;
		r7.in.old_val->length = enc_key.length;
		r7.in.old_val->size = enc_key.length;
		r7.in.new_val = NULL;
		
		printf("Testing SetSecret of old Secret only\n");
		
		status = dcerpc_lsa_SetSecret(p, mem_ctx, &r7);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			ret = False;
		}
		
		data_blob_free(&enc_key);
		
		/* fetch the secret back again */
		r8.in.sec_handle = &sec_handle;
		r8.in.new_val = &bufp1;
		r8.in.new_mtime = &new_mtime;
		r8.in.old_val = &bufp2;
		r8.in.old_mtime = &old_mtime;
		
		bufp1.buf = NULL;
		bufp2.buf = NULL;
		
		status = dcerpc_lsa_QuerySecret(p, mem_ctx, &r8);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = False;
		} else {
			if (!r8.out.new_val || !r8.out.old_val) {
				printf("in/out pointers not returned, despite being set on in for QuerySecret\n");
				ret = False;
			} else if (r8.out.new_val->buf == NULL) {
				if (i != LOCAL) { 
					printf("NEW secret buffer not returned after GLOBAL OLD set\n");
					ret = False;
				}
			} else if (r8.out.old_val->buf == NULL) {
				printf("OLD secret buffer not returned after OLD set\n");
				ret = False;
			} else if (r8.out.new_mtime == NULL || r8.out.old_mtime == NULL) {
				printf("Both times not returned after OLD set\n");
				ret = False;
			} else {
				if (i == LOCAL) { 
					printf("NEW secret buffer should not be returned after LOCAL OLD set\n");
					ret = False;
				}
				blob1.data = r8.out.new_val->buf->data;
				blob1.length = r8.out.new_val->buf->length;
				
				blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
				
				secret6 = sess_decrypt_string(mem_ctx,
							      &blob1, &session_key);
				
				if (strcmp(secret3, secret4) != 0) {
					printf("Returned NEW secret '%s' doesn't match '%s'\n", secret4, secret3);
					ret = False;
				}

				blob1.data = r8.out.old_val->buf->data;
				blob1.length = r8.out.old_val->buf->size;
				
				blob2 = data_blob_talloc(mem_ctx, NULL, blob1.length);
				
				secret6 = sess_decrypt_string(mem_ctx,
							      &blob1, &session_key);
				
				if (strcmp(secret5, secret6) != 0) {
					printf("Returned OLD secret %s doesn't match %s\n", secret5, secret6);
					ret = False;
				}
				
				if (*r8.out.new_mtime == *r8.out.old_mtime) {
					if (i != GLOBAL) { 
						printf("Returned secret %s had same mtime for both secrets: %s\n", 
						       secname[i],
						       nt_time_string(mem_ctx, *r8.out.new_mtime));
						ret = False;
					}
				} else {
					printf("Returned secret %s should have had same mtime for both secrets: %s != %s\n", 
					       secname[i],
					       nt_time_string(mem_ctx, *r8.out.old_mtime),
					       nt_time_string(mem_ctx, *r8.out.new_mtime));
					ret = False;
				}
			}
		}

		if (!test_Delete(p, mem_ctx, &sec_handle)) {
			ret = False;
		}
		
		d.in.handle = &sec_handle2;
		status = dcerpc_lsa_Delete(p, mem_ctx, &d);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
			printf("Second delete expected INVALID_HANDLE - %s\n", nt_errstr(status));
			ret = False;
		} else {

			printf("Testing OpenSecret of just-deleted secret\n");
			
			status = dcerpc_lsa_OpenSecret(p, mem_ctx, &r2);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				printf("OpenSecret expected OBJECT_NAME_NOT_FOUND - %s\n", nt_errstr(status));
				ret = False;
			}
		}
		
	}

	return ret;
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
		printf("EnumAccountRights of %s failed - %s\n", 
		       dom_sid_string(mem_ctx, sid), nt_errstr(status));
		return False;
	}

	return True;
}


static BOOL test_QuerySecurity(struct dcerpc_pipe *p, 
			     TALLOC_CTX *mem_ctx, 
			     struct policy_handle *handle,
			     struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_QuerySecurity r;

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping QuerySecurity test against Samba4\n");
		return True;
	}

	printf("Testing QuerySecurity\n");

	r.in.handle = acct_handle;
	r.in.sec_info = 7;

	status = dcerpc_lsa_QuerySecurity(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
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
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAccount failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!test_EnumPrivsAccount(p, mem_ctx, handle, &acct_handle)) {
		return False;
	}

	if (!test_QuerySecurity(p, mem_ctx, handle, &acct_handle)) {
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
	uint32_t resume_handle = 0;
	int i;
	BOOL ret = True;

	printf("\ntesting EnumAccounts\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 100;
	r.out.resume_handle = &resume_handle;
	r.out.sids = &sids1;

	resume_handle = 0;
	while (True) {
		status = dcerpc_lsa_EnumAccounts(p, mem_ctx, &r);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumAccounts failed - %s\n", nt_errstr(status));
			return False;
		}

		if (!test_LookupSids(p, mem_ctx, handle, &sids1)) {
			return False;
		}

		if (!test_LookupSids2(p, mem_ctx, handle, &sids1)) {
			return False;
		}

		if (!test_LookupSids3(p, mem_ctx, &sids1)) {
			return False;
		}

		printf("testing all accounts\n");
		for (i=0;i<sids1.num_sids;i++) {
			ret &= test_OpenAccount(p, mem_ctx, handle, sids1.sids[i].sid);
			ret &= test_EnumAccountRights(p, mem_ctx, handle, sids1.sids[i].sid);
		}
		printf("\n");
	}

	if (sids1.num_sids < 3) {
		return ret;
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

static BOOL test_LookupPrivDisplayName(struct dcerpc_pipe *p,
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle,
				struct lsa_String *priv_name)
{
	struct lsa_LookupPrivDisplayName r;
	NTSTATUS status;
	/* produce a reasonable range of language output without screwing up
	   terminals */
	uint16_t language_id = (random() % 4) + 0x409;

	printf("testing LookupPrivDisplayName(%s)\n", priv_name->string);
	
	r.in.handle = handle;
	r.in.name = priv_name;
	r.in.language_id = &language_id;
	r.out.language_id = &language_id;
	r.in.unknown = 0;

	status = dcerpc_lsa_LookupPrivDisplayName(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupPrivDisplayName failed - %s\n", nt_errstr(status));
		return False;
	}
	printf("%s -> \"%s\"  (language 0x%x/0x%x)\n", 
	       priv_name->string, r.out.disp_name->string, 
	       *r.in.language_id, *r.out.language_id);

	return True;
}

static BOOL test_EnumAccountsWithUserRight(struct dcerpc_pipe *p, 
				TALLOC_CTX *mem_ctx,
				struct policy_handle *handle,
				struct lsa_String *priv_name)
{
	struct lsa_EnumAccountsWithUserRight r;
	struct lsa_SidArray sids;
	NTSTATUS status;

	ZERO_STRUCT(sids);
	
	printf("testing EnumAccountsWithUserRight(%s)\n", priv_name->string);
	
	r.in.handle = handle;
	r.in.name = priv_name;
	r.out.sids = &sids;

	status = dcerpc_lsa_EnumAccountsWithUserRight(p, mem_ctx, &r);

	/* NT_STATUS_NO_MORE_ENTRIES means noone has this privilege */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		return True;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccountsWithUserRight failed - %s\n", nt_errstr(status));
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
	uint32_t resume_handle = 0;
	int i;
	BOOL ret = True;

	printf("\ntesting EnumPrivs\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_count = 100;
	r.out.resume_handle = &resume_handle;
	r.out.privs = &privs1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumPrivs(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivs failed - %s\n", nt_errstr(status));
		return False;
	}

	for (i = 0; i< privs1.count; i++) {
		test_LookupPrivDisplayName(p, mem_ctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		test_LookupPrivValue(p, mem_ctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		if (!test_EnumAccountsWithUserRight(p, mem_ctx, handle, (struct lsa_String *)&privs1.privs[i].name)) {
			ret = False;
		}
	}

	return ret;
}

static BOOL test_QueryForestTrustInformation(struct dcerpc_pipe *p, 
					     TALLOC_CTX *mem_ctx, 
					     struct policy_handle *handle,
					     const char *trusted_domain_name)
{
	BOOL ret = True;
	struct lsa_lsaRQueryForestTrustInformation r;
	NTSTATUS status;
	struct lsa_String string;
	struct lsa_ForestTrustInformation info, *info_ptr;
	uint16_t unknown = 0;

	printf("\nTesting lsaRQueryForestTrustInformation\n");

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping QueryForestTrustInformation against Samba4\n");
		return True;
	}

	ZERO_STRUCT(string);

	if (trusted_domain_name) {
		init_lsa_String(&string, trusted_domain_name);
	}

	info_ptr = &info;

	r.in.handle = handle;
	r.in.trusted_domain_name = &string;
	r.in.unknown = 0;
	r.out.forest_trust_info = &info_ptr;

	status = dcerpc_lsa_lsaRQueryForestTrustInformation(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("lsaRQueryForestTrustInformation failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

static BOOL test_query_each_TrustDomEx(struct dcerpc_pipe *p, 
				       TALLOC_CTX *mem_ctx, 
				       struct policy_handle *handle, 
				       struct lsa_DomainListEx *domains) 
{
	NTSTATUS status;
	int i,j;
	BOOL ret = True;

	for (i=0; i< domains->count; i++) {

		if (domains->domains[i].trust_attributes & NETR_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			ret &= test_QueryForestTrustInformation(p, mem_ctx, handle, 
								domains->domains[i].domain_name.string);
		}
	}

	return ret;
}

static BOOL test_query_each_TrustDom(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle, 
				     struct lsa_DomainList *domains) 
{
	NTSTATUS status;
	int i,j;
	BOOL ret = True;
		
	printf("\nTesting OpenTrustedDomain, OpenTrustedDomainByName and QueryInfoTrustedDomain\n");
	for (i=0; i< domains->count; i++) {
		struct lsa_OpenTrustedDomain trust;
		struct lsa_OpenTrustedDomainByName trust_by_name;
		struct policy_handle trustdom_handle;
		struct policy_handle handle2;
		struct lsa_Close c;
		struct lsa_CloseTrustedDomainEx c_trust;
		int levels [] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
		int ok[]      = {1, 0, 1, 0, 0, 1, 0, 1, 0,  0,  0,  1};

		if (domains->domains[i].sid) {
			trust.in.handle = handle;
			trust.in.sid = domains->domains[i].sid;
			trust.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			trust.out.trustdom_handle = &trustdom_handle;
			
			status = dcerpc_lsa_OpenTrustedDomain(p, mem_ctx, &trust);
			
			if (!NT_STATUS_IS_OK(status)) {
				printf("OpenTrustedDomain failed - %s\n", nt_errstr(status));
				return False;
			}
			
			c.in.handle = &trustdom_handle;
			c.out.handle = &handle2;
			
			c_trust.in.handle = &trustdom_handle;
			c_trust.out.handle = &handle2;
			
			for (j=0; j < ARRAY_SIZE(levels); j++) {
				struct lsa_QueryTrustedDomainInfo q;
				union lsa_TrustedDomainInfo info;
				q.in.trustdom_handle = &trustdom_handle;
				q.in.level = levels[j];
				q.out.info = &info;
				status = dcerpc_lsa_QueryTrustedDomainInfo(p, mem_ctx, &q);
				if (!NT_STATUS_IS_OK(status) && ok[j]) {
					printf("QueryTrustedDomainInfo level %d failed - %s\n", 
					       levels[j], nt_errstr(status));
					ret = False;
				} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
					printf("QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n", 
					       levels[j], nt_errstr(status));
					ret = False;
				}
			}
			
			status = dcerpc_lsa_CloseTrustedDomainEx(p, mem_ctx, &c_trust);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
				printf("Expected CloseTrustedDomainEx to return NT_STATUS_NOT_IMPLEMENTED, instead - %s\n", nt_errstr(status));
				return False;
			}
			
			c.in.handle = &trustdom_handle;
			c.out.handle = &handle2;
			
			status = dcerpc_lsa_Close(p, mem_ctx, &c);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close of trusted domain failed - %s\n", nt_errstr(status));
				return False;
			}

			for (j=0; j < ARRAY_SIZE(levels); j++) {
				struct lsa_QueryTrustedDomainInfoBySid q;
				union lsa_TrustedDomainInfo info;
				
				if (!domains->domains[i].sid) {
					continue;
				}
				
				q.in.handle  = handle;
				q.in.dom_sid = domains->domains[i].sid;
				q.in.level   = levels[j];
				q.out.info   = &info;
				status = dcerpc_lsa_QueryTrustedDomainInfoBySid(p, mem_ctx, &q);
				if (!NT_STATUS_IS_OK(status) && ok[j]) {
					printf("QueryTrustedDomainInfoBySid level %d failed - %s\n", 
					       levels[j], nt_errstr(status));
					ret = False;
				} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
					printf("QueryTrustedDomainInfoBySid level %d unexpectedly succeeded - %s\n", 
					       levels[j], nt_errstr(status));
					ret = False;
				}
			}
		}

		trust_by_name.in.handle = handle;
		trust_by_name.in.name.string = domains->domains[i].name.string;
		trust_by_name.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		trust_by_name.out.trustdom_handle = &trustdom_handle;
			
		status = dcerpc_lsa_OpenTrustedDomainByName(p, mem_ctx, &trust_by_name);
			
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenTrustedDomainByName failed - %s\n", nt_errstr(status));
			return False;
		}

		for (j=0; j < ARRAY_SIZE(levels); j++) {
			struct lsa_QueryTrustedDomainInfo q;
			union lsa_TrustedDomainInfo info;
			q.in.trustdom_handle = &trustdom_handle;
			q.in.level = levels[j];
			q.out.info = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfo(p, mem_ctx, &q);
			if (!NT_STATUS_IS_OK(status) && ok[j]) {
				printf("QueryTrustedDomainInfo level %d failed - %s\n", 
				       levels[j], nt_errstr(status));
				ret = False;
			} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
				printf("QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n", 
				       levels[j], nt_errstr(status));
				ret = False;
			}
		}
		
		c.in.handle = &trustdom_handle;
		c.out.handle = &handle2;

		status = dcerpc_lsa_Close(p, mem_ctx, &c);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Close of trusted domain failed - %s\n", nt_errstr(status));
			return False;
		}

		for (j=0; j < ARRAY_SIZE(levels); j++) {
			struct lsa_QueryTrustedDomainInfoByName q;
			union lsa_TrustedDomainInfo info;
			q.in.handle         = handle;
			q.in.trusted_domain.string = domains->domains[i].name.string;
			q.in.level          = levels[j];
			q.out.info          = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfoByName(p, mem_ctx, &q);
			if (!NT_STATUS_IS_OK(status) && ok[j]) {
				printf("QueryTrustedDomainInfoByName level %d failed - %s\n", 
				       levels[j], nt_errstr(status));
				ret = False;
			} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
				printf("QueryTrustedDomainInfoByName level %d unexpectedly succeeded - %s\n", 
				       levels[j], nt_errstr(status));
				ret = False;
			}
		}
	}
	return ret;
}

static BOOL test_EnumTrustDom(struct dcerpc_pipe *p, 
			      TALLOC_CTX *mem_ctx, 
			      struct policy_handle *handle)
{
	struct lsa_EnumTrustDom r;
	struct lsa_EnumTrustedDomainsEx r_ex;
	NTSTATUS enum_status;
	uint32_t resume_handle = 0;
	struct lsa_DomainList domains;
	struct lsa_DomainListEx domains_ex;
	BOOL ret = True;

	printf("\nTesting EnumTrustDom\n");

	do {
		r.in.handle = handle;
		r.in.resume_handle = &resume_handle;
		r.in.max_size = LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3;
		r.out.domains = &domains;
		r.out.resume_handle = &resume_handle;
		
		enum_status = dcerpc_lsa_EnumTrustDom(p, mem_ctx, &r);
		
		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES)) {
			return True;
		} else if (NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r.out.domains->count < 3 || r.out.domains->count > 4) {
				printf("EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r.out.domains->count, LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3, 
				       LSA_ENUM_TRUST_DOMAIN_MULTIPLIER, r.in.max_size);
				ret = False;
			}
		} else if (!NT_STATUS_IS_OK(enum_status)) {
			printf("EnumTrustDom failed - %s\n", nt_errstr(enum_status));
			return False;
		}
		
		ret &= test_query_each_TrustDom(p, mem_ctx, handle, &domains);
		
	} while ((NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)));

	printf("\nTesting EnumTrustedDomainsEx\n");

	resume_handle = 0;
	do {
		r_ex.in.handle = handle;
		r_ex.in.resume_handle = &resume_handle;
		r_ex.in.max_size = LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER * 3;
		r_ex.out.domains = &domains_ex;
		r_ex.out.resume_handle = &resume_handle;
		
		enum_status = dcerpc_lsa_EnumTrustedDomainsEx(p, mem_ctx, &r_ex);
		
		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES)) {
			return True;
		} else if (NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r_ex.out.domains->count < 3 || r_ex.out.domains->count > 4) {
				printf("EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r_ex.out.domains->count, 
				       r_ex.in.max_size,
				       LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER, 
				       r_ex.in.max_size / LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER);
				ret = False;
				exit(1);
			}
		} else if (!NT_STATUS_IS_OK(enum_status)) {
			printf("EnumTrustedDomainEx failed - %s\n", nt_errstr(enum_status));
			return False;
		}

		ret &= test_query_each_TrustDomEx(p, mem_ctx, handle, &domains_ex);
		
	} while ((NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)));

	return ret;
}

static BOOL test_CreateTrustedDomain(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx, 
				     struct policy_handle *handle)
{
	NTSTATUS status;
	BOOL ret = True;
	struct lsa_CreateTrustedDomain r;
	struct lsa_DomainInfo trustinfo;
	struct dom_sid *domsid[12];
	struct policy_handle trustdom_handle[12];
	struct lsa_QueryTrustedDomainInfo q;
	int i;

	printf("Testing CreateTrustedDomain for 12 domains\n");

	for (i=0; i< 12; i++) {
		char *trust_name = talloc_asprintf(mem_ctx, "torturedom%02d", i);
		char *trust_sid = talloc_asprintf(mem_ctx, "S-1-5-21-97398-379795-100%02d", i);
		
		domsid[i] = dom_sid_parse_talloc(mem_ctx, trust_sid);

		trustinfo.sid = domsid[i];
		init_lsa_String((struct lsa_String *)&trustinfo.name, trust_name);

		r.in.handle = handle;
		r.in.info = &trustinfo;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.trustdom_handle = &trustdom_handle[i];
		
		status = dcerpc_lsa_CreateTrustedDomain(p, mem_ctx, &r);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			test_DeleteTrustedDomain(p, mem_ctx, handle, trustinfo.name);
			status = dcerpc_lsa_CreateTrustedDomain(p, mem_ctx, &r);
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("CreateTrustedDomain failed - %s\n", nt_errstr(status));
			ret = False;
		} else {
		
			q.in.trustdom_handle = &trustdom_handle[i];
			q.in.level = LSA_TRUSTED_DOMAIN_INFO_NAME;
			status = dcerpc_lsa_QueryTrustedDomainInfo(p, mem_ctx, &q);
			if (!NT_STATUS_IS_OK(status)) {
				printf("QueryTrustedDomainInfo level 1 failed - %s\n", nt_errstr(status));
				ret = False;
			} else if (!q.out.info) {
				ret = False;
			} else {
				if (strcmp(q.out.info->name.netbios_name.string, trustinfo.name.string) != 0) {
					printf("QueryTrustedDomainInfo returned inconsistant short name: %s != %s\n",
					       q.out.info->name.netbios_name.string, trustinfo.name.string);
					ret = False;
				}
			}
		}
	}

	/* now that we have some domains to look over, we can test the enum calls */
	if (!test_EnumTrustDom(p, mem_ctx, handle)) {
		ret = False;
	}
	
	for (i=0; i<12; i++) {
		if (!test_DeleteTrustedDomainBySid(p, mem_ctx, handle, domsid[i])) {
			ret = False;
		}
	}

	return ret;
}

static BOOL test_QueryDomainInfoPolicy(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx, 
				 struct policy_handle *handle)
{
	struct lsa_QueryDomainInformationPolicy r;
	NTSTATUS status;
	int i;
	BOOL ret = True;
	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping QueryDomainInformationPolicy test against Samba4\n");
		return True;
	}

	printf("\nTesting QueryDomainInformationPolicy\n");

	for (i=2;i<4;i++) {
		r.in.handle = handle;
		r.in.level = i;

		printf("\ntrying QueryDomainInformationPolicy level %d\n", i);

		status = dcerpc_lsa_QueryDomainInformationPolicy(p, mem_ctx, &r);

		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDomainInformationPolicy failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return ret;
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

	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping QueryInfoPolicy against Samba4\n");
		return True;
	}

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

static BOOL test_QueryInfoPolicy2(struct dcerpc_pipe *p, 
				  TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy2 r;
	NTSTATUS status;
	int i;
	BOOL ret = True;
	printf("\nTesting QueryInfoPolicy2\n");
	if (lp_parm_bool(-1, "torture", "samba4", False)) {
		printf("skipping QueryInfoPolicy2 against Samba4\n");
		return True;
	}

	for (i=1;i<13;i++) {
		r.in.handle = handle;
		r.in.level = i;

		printf("\ntrying QueryInfoPolicy2 level %d\n", i);

		status = dcerpc_lsa_QueryInfoPolicy2(p, mem_ctx, &r);

		if ((i == 9 || i == 10 || i == 11) &&
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			printf("server failed level %u (OK)\n", i);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			printf("QueryInfoPolicy2 failed - %s\n", nt_errstr(status));
			ret = False;
			continue;
		}
	}

	return ret;
}

static BOOL test_GetUserName(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx)
{
	struct lsa_GetUserName r;
	NTSTATUS status;
	BOOL ret = True;
	struct lsa_StringPointer authority_name_p;

	printf("\nTesting GetUserName\n");

	r.in.system_name = "\\";
	r.in.account_name = NULL;
	r.in.authority_name = &authority_name_p;
	authority_name_p.string = NULL;

	status = dcerpc_lsa_GetUserName(p, mem_ctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		ret = False;
	}

	return ret;
}

BOOL test_lsa_Close(struct dcerpc_pipe *p, 
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

BOOL torture_rpc_lsa(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle *handle;

	mem_ctx = talloc_init("torture_rpc_lsa");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_OpenPolicy(p, mem_ctx)) {
		ret = False;
	}

	if (!test_lsa_OpenPolicy2(p, mem_ctx, &handle)) {
		ret = False;
	}

	if (handle) {
		if (!test_LookupSids_async(p, mem_ctx, handle)) {
			ret = False;
		}

		if (!test_QueryDomainInfoPolicy(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_CreateAccount(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_CreateSecret(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_CreateTrustedDomain(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_EnumAccounts(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_EnumPrivs(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_QueryInfoPolicy(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_QueryInfoPolicy2(p, mem_ctx, handle)) {
			ret = False;
		}
		
#if 0
		if (!test_Delete(p, mem_ctx, handle)) {
			ret = False;
		}
#endif
		
		if (!test_many_LookupSids(p, mem_ctx, handle)) {
			ret = False;
		}
		
		if (!test_lsa_Close(p, mem_ctx, handle)) {
			ret = False;
		}
	} else {
		if (!test_many_LookupSids(p, mem_ctx, handle)) {
			ret = False;
		}
	}

	if (!test_GetUserName(p, mem_ctx)) {
		ret = False;
	}
		
	talloc_free(mem_ctx);

	return ret;
}

BOOL torture_rpc_lsa_get_user(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;

	mem_ctx = talloc_init("torture_rpc_lsa_get_user");

	status = torture_rpc_connection(mem_ctx, &p, &ndr_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return False;
	}

	if (!test_GetUserName(p, mem_ctx)) {
		ret = False;
	}
		
	talloc_free(mem_ctx);

	return ret;
}
