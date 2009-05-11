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
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "lib/events/events.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "torture/rpc/rpc.h"
#include "param/param.h"
#include "../lib/crypto/crypto.h"
#define TEST_MACHINENAME "lsatestmach"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static bool test_OpenPolicy(struct dcerpc_pipe *p,
			    struct torture_context *tctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	NTSTATUS status;
	uint16_t system_name = '\\';

	printf("\nTesting OpenPolicy\n");

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

	status = dcerpc_lsa_OpenPolicy(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			return true;
		}
		printf("OpenPolicy failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}


bool test_lsa_OpenPolicy2(struct dcerpc_pipe *p,
			  struct torture_context *tctx,
			  struct policy_handle **handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	printf("\nTesting OpenPolicy2\n");

	*handle = talloc(tctx, struct policy_handle);
	if (!*handle) {
		return false;
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

	status = dcerpc_lsa_OpenPolicy2(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			talloc_free(*handle);
			*handle = NULL;
			return true;
		}
		printf("OpenPolicy2 failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}


static const char *sid_type_lookup(enum lsa_SidType r)
{
	switch (r) {
		case SID_NAME_USE_NONE: return "SID_NAME_USE_NONE"; break;
		case SID_NAME_USER: return "SID_NAME_USER"; break;
		case SID_NAME_DOM_GRP: return "SID_NAME_DOM_GRP"; break;
		case SID_NAME_DOMAIN: return "SID_NAME_DOMAIN"; break;
		case SID_NAME_ALIAS: return "SID_NAME_ALIAS"; break;
		case SID_NAME_WKN_GRP: return "SID_NAME_WKN_GRP"; break;
		case SID_NAME_DELETED: return "SID_NAME_DELETED"; break;
		case SID_NAME_INVALID: return "SID_NAME_INVALID"; break;
		case SID_NAME_UNKNOWN: return "SID_NAME_UNKNOWN"; break;
		case SID_NAME_COMPUTER: return "SID_NAME_COMPUTER"; break;
	}
	return "Invalid sid type\n";
}

static bool test_LookupNames(struct dcerpc_pipe *p,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     struct lsa_TransNameArray *tnames)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(tctx, struct lsa_String, tnames->count);
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
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames(p, tctx, &r);

	if (NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		for (i=0;i< tnames->count;i++) {
			if (i < count && sids.sids[i].sid_type == SID_NAME_UNKNOWN) {
				printf("LookupName of %s was unmapped\n",
				       tnames->names[i].name.string);
			} else if (i >=count) {
				printf("LookupName of %s failed to return a result\n",
				       tnames->names[i].name.string);
			}
		}
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return false;
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return false;
	}

	for (i=0;i< tnames->count;i++) {
		if (i < count && sids.sids[i].sid_type != tnames->names[i].sid_type) {
			printf("LookupName of %s got unexpected name type: %s\n",
			       tnames->names[i].name.string, sid_type_lookup(sids.sids[i].sid_type));
		} else if (i >=count) {
			printf("LookupName of %s failed to return a result\n",
			       tnames->names[i].name.string);
		}
	}
	printf("\n");

	return true;
}

static bool test_LookupNames_bogus(struct dcerpc_pipe *p,
				   struct torture_context *tctx,
				   struct policy_handle *handle)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	struct lsa_TranslatedName name[2];
	struct lsa_TransNameArray tnames;

	tnames.names = name;
	tnames.count = 2;
	name[0].name.string = "NT AUTHORITY\\BOGUS";
	name[1].name.string = NULL;

	printf("\nTesting LookupNames with bogus names\n");

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(tctx, struct lsa_String, tnames.count);
	for (i=0;i<tnames.count;i++) {
		init_lsa_String(&names[i], tnames.names[i].name.string);
	}

	r.in.handle = handle;
	r.in.num_names = tnames.count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames(p, tctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		printf("LookupNames failed - %s\n", nt_errstr(status));
		return false;
	}

	printf("\n");

	return true;
}

static bool test_LookupNames_wellknown(struct dcerpc_pipe *p,
				       struct torture_context *tctx,
				       struct policy_handle *handle)
{
	struct lsa_TranslatedName name;
	struct lsa_TransNameArray tnames;
	bool ret = true;

	printf("Testing LookupNames with well known names\n");

	tnames.names = &name;
	tnames.count = 1;
	name.name.string = "NT AUTHORITY\\SYSTEM";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "NT AUTHORITY\\ANONYMOUS LOGON";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "NT AUTHORITY\\Authenticated Users";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

#if 0
	name.name.string = "NT AUTHORITY";
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "NT AUTHORITY\\";
	ret &= test_LookupNames(p, tctx, handle, &tnames);
#endif

	name.name.string = "BUILTIN\\";
	name.sid_type = SID_NAME_DOMAIN;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "BUILTIN\\Administrators";
	name.sid_type = SID_NAME_ALIAS;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "SYSTEM";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(p, tctx, handle, &tnames);

	name.name.string = "Everyone";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(p, tctx, handle, &tnames);
	return ret;
}

static bool test_LookupNames2(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames2 r;
	struct lsa_TransSidArray2 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames2 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(tctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames2(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames2 failed - %s\n", nt_errstr(status));
		return false;
	}

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	printf("\n");

	return true;
}


static bool test_LookupNames3(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames3 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames3 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(tctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.handle = handle;
	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames3(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames3 failed - %s\n", nt_errstr(status));
		return false;
	}

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	printf("\n");

	return true;
}

static bool test_LookupNames4(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames4 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	NTSTATUS status;
	int i;

	printf("\nTesting LookupNames4 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	names = talloc_array(tctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		init_lsa_String(&names[i], tnames->names[i].name.string);
	}

	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = 1;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames4(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupNames4 failed - %s\n", nt_errstr(status));
		return false;
	}

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	printf("\n");

	return true;
}


static bool test_LookupSids(struct dcerpc_pipe *p,
			    struct torture_context *tctx,
			    struct policy_handle *handle,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray names;
	struct lsa_RefDomainList *domains = NULL;
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
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupSids(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupSids failed - %s\n", nt_errstr(status));
		return false;
	}

	printf("\n");

	if (!test_LookupNames(p, tctx, handle, &names)) {
		return false;
	}

	return true;
}


static bool test_LookupSids2(struct dcerpc_pipe *p,
			    struct torture_context *tctx,
			    struct policy_handle *handle,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids2 r;
	struct lsa_TransNameArray2 names;
	struct lsa_RefDomainList *domains = NULL;
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
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupSids2(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupSids2 failed - %s\n", nt_errstr(status));
		return false;
	}

	printf("\n");

	if (!test_LookupNames2(p, tctx, handle, &names, false)) {
		return false;
	}

	if (!test_LookupNames3(p, tctx, handle, &names, false)) {
		return false;
	}

	return true;
}

static bool test_LookupSids3(struct dcerpc_pipe *p,
			    struct torture_context *tctx,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids3 r;
	struct lsa_TransNameArray2 names;
	struct lsa_RefDomainList *domains = NULL;
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
	r.out.domains = &domains;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids3(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			printf("not considering %s to be an error\n", nt_errstr(status));
			return true;
		}
		printf("LookupSids3 failed - %s - not considered an error\n",
		       nt_errstr(status));
		return false;
	}

	printf("\n");

	if (!test_LookupNames4(p, tctx, &names, false)) {
		return false;
	}

	return true;
}

bool test_many_LookupSids(struct dcerpc_pipe *p,
			  struct torture_context *tctx,
			  struct policy_handle *handle)
{
	uint32_t count;
	NTSTATUS status;
	struct lsa_SidArray sids;
	int i;

	printf("\nTesting LookupSids with lots of SIDs\n");

	sids.num_sids = 100;

	sids.sids = talloc_array(tctx, struct lsa_SidPtr, sids.num_sids);

	for (i=0; i<sids.num_sids; i++) {
		const char *sidstr = "S-1-5-32-545";
		sids.sids[i].sid = dom_sid_parse_talloc(tctx, sidstr);
	}

	count = sids.num_sids;

	if (handle) {
		struct lsa_LookupSids r;
		struct lsa_TransNameArray names;
		struct lsa_RefDomainList *domains = NULL;
		names.count = 0;
		names.names = NULL;

		r.in.handle = handle;
		r.in.sids = &sids;
		r.in.names = &names;
		r.in.level = 1;
		r.in.count = &names.count;
		r.out.count = &count;
		r.out.names = &names;
		r.out.domains = &domains;

		status = dcerpc_lsa_LookupSids(p, tctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("LookupSids failed - %s\n", nt_errstr(status));
			return false;
		}

		printf("\n");

		if (!test_LookupNames(p, tctx, handle, &names)) {
			return false;
		}
	} else if (p->conn->security_state.auth_info->auth_type == DCERPC_AUTH_TYPE_SCHANNEL &&
		   p->conn->security_state.auth_info->auth_level >= DCERPC_AUTH_LEVEL_INTEGRITY) {
		struct lsa_LookupSids3 r;
		struct lsa_RefDomainList *domains = NULL;
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
		r.out.domains = &domains;

		status = dcerpc_lsa_LookupSids3(p, tctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
			    NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
				printf("not considering %s to be an error\n", nt_errstr(status));
				return true;
			}
			printf("LookupSids3 failed - %s\n",
			       nt_errstr(status));
			return false;
		}
		if (!test_LookupNames4(p, tctx, &names, false)) {
			return false;
		}
	}

	printf("\n");



	return true;
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

static bool test_LookupSids_async(struct dcerpc_pipe *p,
				  struct torture_context *tctx,
				  struct policy_handle *handle)
{
	struct lsa_SidArray sids;
	struct lsa_SidPtr sidptr;
	uint32_t *count;
	struct lsa_TransNameArray *names;
	struct lsa_LookupSids *r;
	struct lsa_RefDomainList *domains = NULL;
	struct rpc_request **req;
	int i, replies;
	bool ret = true;
	const int num_async_requests = 50;

	count = talloc_array(tctx, uint32_t, num_async_requests);
	names = talloc_array(tctx, struct lsa_TransNameArray, num_async_requests);
	r = talloc_array(tctx, struct lsa_LookupSids, num_async_requests);

	printf("\nTesting %d async lookupsids request\n", num_async_requests);

	req = talloc_array(tctx, struct rpc_request *, num_async_requests);

	sids.num_sids = 1;
	sids.sids = &sidptr;
	sidptr.sid = dom_sid_parse_talloc(tctx, "S-1-5-32-545");

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
		r[i].out.domains = &domains;

		req[i] = dcerpc_lsa_LookupSids_send(p, req, &r[i]);
		if (req[i] == NULL) {
			ret = false;
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
		ret = false;
	}

	return ret;
}

static bool test_LookupPrivValue(struct dcerpc_pipe *p,
				 struct torture_context *tctx,
				 struct policy_handle *handle,
				 struct lsa_String *name)
{
	NTSTATUS status;
	struct lsa_LookupPrivValue r;
	struct lsa_LUID luid;

	r.in.handle = handle;
	r.in.name = name;
	r.out.luid = &luid;

	status = dcerpc_lsa_LookupPrivValue(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("\nLookupPrivValue failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

static bool test_LookupPrivName(struct dcerpc_pipe *p,
				struct torture_context *tctx,
				struct policy_handle *handle,
				struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_LookupPrivName r;
	struct lsa_StringLarge *name = NULL;

	r.in.handle = handle;
	r.in.luid = luid;
	r.out.name = &name;

	status = dcerpc_lsa_LookupPrivName(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("\nLookupPrivName failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

static bool test_RemovePrivilegesFromAccount(struct dcerpc_pipe *p,
					     struct torture_context *tctx,
					     struct policy_handle *handle,
					     struct policy_handle *acct_handle,
					     struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_RemovePrivilegesFromAccount r;
	struct lsa_PrivilegeSet privs;
	bool ret = true;

	printf("\nTesting RemovePrivilegesFromAccount\n");

	r.in.handle = acct_handle;
	r.in.remove_all = 0;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(tctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	status = dcerpc_lsa_RemovePrivilegesFromAccount(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {

		struct lsa_LookupPrivName r_name;
		struct lsa_StringLarge *name = NULL;

		r_name.in.handle = handle;
		r_name.in.luid = luid;
		r_name.out.name = &name;

		status = dcerpc_lsa_LookupPrivName(p, tctx, &r_name);
		if (!NT_STATUS_IS_OK(status)) {
			printf("\nLookupPrivName failed - %s\n", nt_errstr(status));
			return false;
		}
		/* Windows 2008 does not allow this to be removed */
		if (strcmp("SeAuditPrivilege", name->string) == 0) {
			return ret;
		}

		printf("RemovePrivilegesFromAccount failed to remove %s - %s\n",
		       name->string,
		       nt_errstr(status));
		return false;
	}

	return ret;
}

static bool test_AddPrivilegesToAccount(struct dcerpc_pipe *p,
					struct torture_context *tctx,
					struct policy_handle *acct_handle,
					struct lsa_LUID *luid)
{
	NTSTATUS status;
	struct lsa_AddPrivilegesToAccount r;
	struct lsa_PrivilegeSet privs;
	bool ret = true;

	printf("\nTesting AddPrivilegesToAccount\n");

	r.in.handle = acct_handle;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(tctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	status = dcerpc_lsa_AddPrivilegesToAccount(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("AddPrivilegesToAccount failed - %s\n", nt_errstr(status));
		return false;
	}

	return ret;
}

static bool test_EnumPrivsAccount(struct dcerpc_pipe *p,
				  struct torture_context *tctx,
				  struct policy_handle *handle,
				  struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivsAccount r;
	struct lsa_PrivilegeSet *privs = NULL;
	bool ret = true;

	printf("\nTesting EnumPrivsAccount\n");

	r.in.handle = acct_handle;
	r.out.privs = &privs;

	status = dcerpc_lsa_EnumPrivsAccount(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivsAccount failed - %s\n", nt_errstr(status));
		return false;
	}

	if (privs && privs->count > 0) {
		int i;
		for (i=0;i<privs->count;i++) {
			test_LookupPrivName(p, tctx, handle,
					    &privs->set[i].luid);
		}

		ret &= test_RemovePrivilegesFromAccount(p, tctx, handle, acct_handle,
							&privs->set[0].luid);
		ret &= test_AddPrivilegesToAccount(p, tctx, acct_handle,
						   &privs->set[0].luid);
	}

	return ret;
}

static bool test_GetSystemAccessAccount(struct dcerpc_pipe *p,
					struct torture_context *tctx,
					struct policy_handle *handle,
					struct policy_handle *acct_handle)
{
	NTSTATUS status;
	uint32_t access_mask;
	struct lsa_GetSystemAccessAccount r;

	printf("\nTesting GetSystemAccessAccount\n");

	r.in.handle = acct_handle;
	r.out.access_mask = &access_mask;

	status = dcerpc_lsa_GetSystemAccessAccount(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("GetSystemAccessAccount failed - %s\n", nt_errstr(status));
		return false;
	}

	if (r.out.access_mask != NULL) {
		printf("Rights:");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_INTERACTIVE)
			printf(" LSA_POLICY_MODE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_NETWORK)
			printf(" LSA_POLICY_MODE_NETWORK");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_BATCH)
			printf(" LSA_POLICY_MODE_BATCH");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_SERVICE)
			printf(" LSA_POLICY_MODE_SERVICE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_PROXY)
			printf(" LSA_POLICY_MODE_PROXY");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_INTERACTIVE)
			printf(" LSA_POLICY_MODE_DENY_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_NETWORK)
			printf(" LSA_POLICY_MODE_DENY_NETWORK");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_BATCH)
			printf(" LSA_POLICY_MODE_DENY_BATCH");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_SERVICE)
			printf(" LSA_POLICY_MODE_DENY_SERVICE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_REMOTE_INTERACTIVE)
			printf(" LSA_POLICY_MODE_REMOTE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE)
			printf(" LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_ALL)
			printf(" LSA_POLICY_MODE_ALL");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_ALL_NT4)
			printf(" LSA_POLICY_MODE_ALL_NT4");
		printf("\n");
	}

	return true;
}

static bool test_Delete(struct dcerpc_pipe *p,
			struct torture_context *tctx,
			struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Delete r;

	printf("\nTesting Delete\n");

	r.in.handle = handle;
	status = dcerpc_lsa_Delete(p, tctx, &r);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		printf("Delete should have failed NT_STATUS_NOT_SUPPORTED - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

static bool test_DeleteObject(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_DeleteObject r;

	printf("\nTesting DeleteObject\n");

	r.in.handle = handle;
	r.out.handle = handle;
	status = dcerpc_lsa_DeleteObject(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteObject failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}


static bool test_CreateAccount(struct dcerpc_pipe *p,
			       struct torture_context *tctx,
			       struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_CreateAccount r;
	struct dom_sid2 *newsid;
	struct policy_handle acct_handle;

	newsid = dom_sid_parse_talloc(tctx, "S-1-5-12349876-4321-2854");

	printf("\nTesting CreateAccount\n");

	r.in.handle = handle;
	r.in.sid = newsid;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_CreateAccount(p, tctx, &r);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
		struct lsa_OpenAccount r_o;
		r_o.in.handle = handle;
		r_o.in.sid = newsid;
		r_o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r_o.out.acct_handle = &acct_handle;

		status = dcerpc_lsa_OpenAccount(p, tctx, &r_o);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenAccount failed - %s\n", nt_errstr(status));
			return false;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		printf("CreateAccount failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!test_Delete(p, tctx, &acct_handle)) {
		return false;
	}

	if (!test_DeleteObject(p, tctx, &acct_handle)) {
		return false;
	}

	return true;
}

static bool test_DeleteTrustedDomain(struct dcerpc_pipe *p,
				     struct torture_context *tctx,
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

	status = dcerpc_lsa_OpenTrustedDomainByName(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenTrustedDomainByName failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!test_Delete(p, tctx, &trustdom_handle)) {
		return false;
	}

	if (!test_DeleteObject(p, tctx, &trustdom_handle)) {
		return false;
	}

	return true;
}

static bool test_DeleteTrustedDomainBySid(struct dcerpc_pipe *p,
					  struct torture_context *tctx,
					  struct policy_handle *handle,
					  struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_DeleteTrustedDomain r;

	r.in.handle = handle;
	r.in.dom_sid = sid;

	status = dcerpc_lsa_DeleteTrustedDomain(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("DeleteTrustedDomain failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}


static bool test_CreateSecret(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
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
	struct lsa_DeleteObject d_o;
	struct lsa_DATA_BUF buf1;
	struct lsa_DATA_BUF_PTR bufp1;
	struct lsa_DATA_BUF_PTR bufp2;
	DATA_BLOB enc_key;
	bool ret = true;
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

	secname[LOCAL] = talloc_asprintf(tctx, "torturesecret-%u", (uint_t)random());
	secname[GLOBAL] = talloc_asprintf(tctx, "G$torturesecret-%u", (uint_t)random());

	for (i=0; i< 2; i++) {
		printf("\nTesting CreateSecret of %s\n", secname[i]);

		init_lsa_String(&r.in.name, secname[i]);

		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle;

		status = dcerpc_lsa_CreateSecret(p, tctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			printf("CreateSecret failed - %s\n", nt_errstr(status));
			return false;
		}

		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle3;

		status = dcerpc_lsa_CreateSecret(p, tctx, &r);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			printf("CreateSecret should have failed OBJECT_NAME_COLLISION - %s\n", nt_errstr(status));
			return false;
		}

		r2.in.handle = handle;
		r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r2.in.name = r.in.name;
		r2.out.sec_handle = &sec_handle2;

		printf("Testing OpenSecret\n");

		status = dcerpc_lsa_OpenSecret(p, tctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenSecret failed - %s\n", nt_errstr(status));
			return false;
		}

		status = dcerpc_fetch_session_key(p, &session_key);
		if (!NT_STATUS_IS_OK(status)) {
			printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
			return false;
		}

		enc_key = sess_encrypt_string(secret1, &session_key);

		r3.in.sec_handle = &sec_handle;
		r3.in.new_val = &buf1;
		r3.in.old_val = NULL;
		r3.in.new_val->data = enc_key.data;
		r3.in.new_val->length = enc_key.length;
		r3.in.new_val->size = enc_key.length;

		printf("Testing SetSecret\n");

		status = dcerpc_lsa_SetSecret(p, tctx, &r3);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			return false;
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

		status = dcerpc_lsa_SetSecret(p, tctx, &r3);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_UNKNOWN_REVISION)) {
			printf("SetSecret should have failed UNKNOWN_REVISION - %s\n", nt_errstr(status));
			ret = false;
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
		status = dcerpc_lsa_QuerySecret(p, tctx, &r4);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = false;
		} else {
			if (r4.out.new_val == NULL || r4.out.new_val->buf == NULL) {
				printf("No secret buffer returned\n");
				ret = false;
			} else {
				blob1.data = r4.out.new_val->buf->data;
				blob1.length = r4.out.new_val->buf->size;

				blob2 = data_blob_talloc(tctx, NULL, blob1.length);

				secret2 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret1, secret2) != 0) {
					printf("Returned secret (r4) '%s' doesn't match '%s'\n",
					       secret2, secret1);
					ret = false;
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


		msleep(200);
		printf("Testing SetSecret (existing value should move to old)\n");

		status = dcerpc_lsa_SetSecret(p, tctx, &r5);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			ret = false;
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

		status = dcerpc_lsa_QuerySecret(p, tctx, &r6);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = false;
			secret4 = NULL;
		} else {

			if (r6.out.new_val->buf == NULL || r6.out.old_val->buf == NULL
				|| r6.out.new_mtime == NULL || r6.out.old_mtime == NULL) {
				printf("Both secret buffers and both times not returned\n");
				ret = false;
				secret4 = NULL;
			} else {
				blob1.data = r6.out.new_val->buf->data;
				blob1.length = r6.out.new_val->buf->size;

				blob2 = data_blob_talloc(tctx, NULL, blob1.length);

				secret4 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret3, secret4) != 0) {
					printf("Returned NEW secret %s doesn't match %s\n", secret4, secret3);
					ret = false;
				}

				blob1.data = r6.out.old_val->buf->data;
				blob1.length = r6.out.old_val->buf->length;

				blob2 = data_blob_talloc(tctx, NULL, blob1.length);

				secret2 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret1, secret2) != 0) {
					printf("Returned OLD secret %s doesn't match %s\n", secret2, secret1);
					ret = false;
				}

				if (*r6.out.new_mtime == *r6.out.old_mtime) {
					printf("Returned secret (r6-%d) %s must not have same mtime for both secrets: %s != %s\n",
					       i,
					       secname[i],
					       nt_time_string(tctx, *r6.out.old_mtime),
					       nt_time_string(tctx, *r6.out.new_mtime));
					ret = false;
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

		status = dcerpc_lsa_SetSecret(p, tctx, &r7);
		if (!NT_STATUS_IS_OK(status)) {
			printf("SetSecret failed - %s\n", nt_errstr(status));
			ret = false;
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

		status = dcerpc_lsa_QuerySecret(p, tctx, &r8);
		if (!NT_STATUS_IS_OK(status)) {
			printf("QuerySecret failed - %s\n", nt_errstr(status));
			ret = false;
		} else {
			if (!r8.out.new_val || !r8.out.old_val) {
				printf("in/out pointers not returned, despite being set on in for QuerySecret\n");
				ret = false;
			} else if (r8.out.new_val->buf != NULL) {
				printf("NEW secret buffer must not be returned after OLD set\n");
				ret = false;
			} else if (r8.out.old_val->buf == NULL) {
				printf("OLD secret buffer was not returned after OLD set\n");
				ret = false;
			} else if (r8.out.new_mtime == NULL || r8.out.old_mtime == NULL) {
				printf("Both times not returned after OLD set\n");
				ret = false;
			} else {
				blob1.data = r8.out.old_val->buf->data;
				blob1.length = r8.out.old_val->buf->size;

				blob2 = data_blob_talloc(tctx, NULL, blob1.length);

				secret6 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret5, secret6) != 0) {
					printf("Returned OLD secret %s doesn't match %s\n", secret5, secret6);
					ret = false;
				}

				if (*r8.out.new_mtime != *r8.out.old_mtime) {
					printf("Returned secret (r8) %s did not had same mtime for both secrets: %s != %s\n",
					       secname[i],
					       nt_time_string(tctx, *r8.out.old_mtime),
					       nt_time_string(tctx, *r8.out.new_mtime));
					ret = false;
				}
			}
		}

		if (!test_Delete(p, tctx, &sec_handle)) {
			ret = false;
		}

		if (!test_DeleteObject(p, tctx, &sec_handle)) {
			return false;
		}

		d_o.in.handle = &sec_handle2;
		d_o.out.handle = &sec_handle2;
		status = dcerpc_lsa_DeleteObject(p, tctx, &d_o);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_HANDLE)) {
			printf("Second delete expected INVALID_HANDLE - %s\n", nt_errstr(status));
			ret = false;
		} else {

			printf("Testing OpenSecret of just-deleted secret\n");

			status = dcerpc_lsa_OpenSecret(p, tctx, &r2);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
				printf("OpenSecret expected OBJECT_NAME_NOT_FOUND - %s\n", nt_errstr(status));
				ret = false;
			}
		}

	}

	return ret;
}


static bool test_EnumAccountRights(struct dcerpc_pipe *p,
				   struct torture_context *tctx,
				   struct policy_handle *acct_handle,
				   struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_EnumAccountRights r;
	struct lsa_RightSet rights;

	printf("\nTesting EnumAccountRights\n");

	r.in.handle = acct_handle;
	r.in.sid = sid;
	r.out.rights = &rights;

	status = dcerpc_lsa_EnumAccountRights(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccountRights of %s failed - %s\n",
		       dom_sid_string(tctx, sid), nt_errstr(status));
		return false;
	}

	return true;
}


static bool test_QuerySecurity(struct dcerpc_pipe *p,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     struct policy_handle *acct_handle)
{
	NTSTATUS status;
	struct lsa_QuerySecurity r;
	struct sec_desc_buf *sdbuf = NULL;

	if (torture_setting_bool(tctx, "samba4", false)) {
		printf("\nskipping QuerySecurity test against Samba4\n");
		return true;
	}

	printf("\nTesting QuerySecurity\n");

	r.in.handle = acct_handle;
	r.in.sec_info = 7;
	r.out.sdbuf = &sdbuf;

	status = dcerpc_lsa_QuerySecurity(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}

static bool test_OpenAccount(struct dcerpc_pipe *p,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     struct dom_sid *sid)
{
	NTSTATUS status;
	struct lsa_OpenAccount r;
	struct policy_handle acct_handle;

	printf("\nTesting OpenAccount\n");

	r.in.handle = handle;
	r.in.sid = sid;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	status = dcerpc_lsa_OpenAccount(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenAccount failed - %s\n", nt_errstr(status));
		return false;
	}

	if (!test_EnumPrivsAccount(p, tctx, handle, &acct_handle)) {
		return false;
	}

	if (!test_GetSystemAccessAccount(p, tctx, handle, &acct_handle)) {
		return false;
	}

	if (!test_QuerySecurity(p, tctx, handle, &acct_handle)) {
		return false;
	}

	return true;
}

static bool test_EnumAccounts(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumAccounts r;
	struct lsa_SidArray sids1, sids2;
	uint32_t resume_handle = 0;
	int i;
	bool ret = true;

	printf("\nTesting EnumAccounts\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 100;
	r.out.resume_handle = &resume_handle;
	r.out.sids = &sids1;

	resume_handle = 0;
	while (true) {
		status = dcerpc_lsa_EnumAccounts(p, tctx, &r);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
			break;
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("EnumAccounts failed - %s\n", nt_errstr(status));
			return false;
		}

		if (!test_LookupSids(p, tctx, handle, &sids1)) {
			return false;
		}

		if (!test_LookupSids2(p, tctx, handle, &sids1)) {
			return false;
		}

		/* Can't test lookupSids3 here, as clearly we must not
		 * be on schannel, or we would not be able to do the
		 * rest */

		printf("Testing all accounts\n");
		for (i=0;i<sids1.num_sids;i++) {
			ret &= test_OpenAccount(p, tctx, handle, sids1.sids[i].sid);
			ret &= test_EnumAccountRights(p, tctx, handle, sids1.sids[i].sid);
		}
		printf("\n");
	}

	if (sids1.num_sids < 3) {
		return ret;
	}

	printf("Trying EnumAccounts partial listing (asking for 1 at 2)\n");
	resume_handle = 2;
	r.in.num_entries = 1;
	r.out.sids = &sids2;

	status = dcerpc_lsa_EnumAccounts(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccounts failed - %s\n", nt_errstr(status));
		return false;
	}

	if (sids2.num_sids != 1) {
		printf("Returned wrong number of entries (%d)\n", sids2.num_sids);
		return false;
	}

	return true;
}

static bool test_LookupPrivDisplayName(struct dcerpc_pipe *p,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       struct lsa_String *priv_name)
{
	struct lsa_LookupPrivDisplayName r;
	NTSTATUS status;
	/* produce a reasonable range of language output without screwing up
	   terminals */
	uint16_t language_id = (random() % 4) + 0x409;
	uint16_t returned_language_id = 0;
	struct lsa_StringLarge *disp_name = NULL;

	printf("\nTesting LookupPrivDisplayName(%s)\n", priv_name->string);

	r.in.handle = handle;
	r.in.name = priv_name;
	r.in.language_id = language_id;
	r.in.language_id_sys = 0;
	r.out.returned_language_id = &returned_language_id;
	r.out.disp_name = &disp_name;

	status = dcerpc_lsa_LookupPrivDisplayName(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupPrivDisplayName failed - %s\n", nt_errstr(status));
		return false;
	}
	printf("%s -> \"%s\"  (language 0x%x/0x%x)\n",
	       priv_name->string, disp_name->string,
	       r.in.language_id, *r.out.returned_language_id);

	return true;
}

static bool test_EnumAccountsWithUserRight(struct dcerpc_pipe *p,
					   struct torture_context *tctx,
					   struct policy_handle *handle,
					   struct lsa_String *priv_name)
{
	struct lsa_EnumAccountsWithUserRight r;
	struct lsa_SidArray sids;
	NTSTATUS status;

	ZERO_STRUCT(sids);

	printf("\nTesting EnumAccountsWithUserRight(%s)\n", priv_name->string);

	r.in.handle = handle;
	r.in.name = priv_name;
	r.out.sids = &sids;

	status = dcerpc_lsa_EnumAccountsWithUserRight(p, tctx, &r);

	/* NT_STATUS_NO_MORE_ENTRIES means noone has this privilege */
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		return true;
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumAccountsWithUserRight failed - %s\n", nt_errstr(status));
		return false;
	}

	return true;
}


static bool test_EnumPrivs(struct dcerpc_pipe *p,
			   struct torture_context *tctx,
			   struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_EnumPrivs r;
	struct lsa_PrivArray privs1;
	uint32_t resume_handle = 0;
	int i;
	bool ret = true;

	printf("\nTesting EnumPrivs\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_count = 100;
	r.out.resume_handle = &resume_handle;
	r.out.privs = &privs1;

	resume_handle = 0;
	status = dcerpc_lsa_EnumPrivs(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("EnumPrivs failed - %s\n", nt_errstr(status));
		return false;
	}

	for (i = 0; i< privs1.count; i++) {
		test_LookupPrivDisplayName(p, tctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		test_LookupPrivValue(p, tctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		if (!test_EnumAccountsWithUserRight(p, tctx, handle, (struct lsa_String *)&privs1.privs[i].name)) {
			ret = false;
		}
	}

	return ret;
}

static bool test_QueryForestTrustInformation(struct dcerpc_pipe *p,
					     struct torture_context *tctx,
					     struct policy_handle *handle,
					     const char *trusted_domain_name)
{
	bool ret = true;
	struct lsa_lsaRQueryForestTrustInformation r;
	NTSTATUS status;
	struct lsa_String string;
	struct lsa_ForestTrustInformation info, *info_ptr;

	printf("\nTesting lsaRQueryForestTrustInformation\n");

	if (torture_setting_bool(tctx, "samba4", false)) {
		printf("skipping QueryForestTrustInformation against Samba4\n");
		return true;
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

	status = dcerpc_lsa_lsaRQueryForestTrustInformation(p, tctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("lsaRQueryForestTrustInformation of %s failed - %s\n", trusted_domain_name, nt_errstr(status));
		ret = false;
	}

	return ret;
}

static bool test_query_each_TrustDomEx(struct dcerpc_pipe *p,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       struct lsa_DomainListEx *domains)
{
	int i;
	bool ret = true;

	for (i=0; i< domains->count; i++) {

		if (domains->domains[i].trust_attributes & NETR_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			ret &= test_QueryForestTrustInformation(p, tctx, handle,
								domains->domains[i].domain_name.string);
		}
	}

	return ret;
}

static bool test_query_each_TrustDom(struct dcerpc_pipe *p,
				     struct torture_context *tctx,
				     struct policy_handle *handle,
				     struct lsa_DomainList *domains)
{
	NTSTATUS status;
	int i,j;
	bool ret = true;

	printf("\nTesting OpenTrustedDomain, OpenTrustedDomainByName and QueryInfoTrustedDomain\n");
	for (i=0; i< domains->count; i++) {
		struct lsa_OpenTrustedDomain trust;
		struct lsa_OpenTrustedDomainByName trust_by_name;
		struct policy_handle trustdom_handle;
		struct policy_handle handle2;
		struct lsa_Close c;
		struct lsa_CloseTrustedDomainEx c_trust;
		int levels [] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
		int ok[]      = {1, 0, 1, 0, 0, 1, 0, 1, 0,  0,  0,  1, 1};

		if (domains->domains[i].sid) {
			trust.in.handle = handle;
			trust.in.sid = domains->domains[i].sid;
			trust.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			trust.out.trustdom_handle = &trustdom_handle;

			status = dcerpc_lsa_OpenTrustedDomain(p, tctx, &trust);

			if (!NT_STATUS_IS_OK(status)) {
				printf("OpenTrustedDomain failed - %s\n", nt_errstr(status));
				return false;
			}

			c.in.handle = &trustdom_handle;
			c.out.handle = &handle2;

			c_trust.in.handle = &trustdom_handle;
			c_trust.out.handle = &handle2;

			for (j=0; j < ARRAY_SIZE(levels); j++) {
				struct lsa_QueryTrustedDomainInfo q;
				union lsa_TrustedDomainInfo *info = NULL;
				q.in.trustdom_handle = &trustdom_handle;
				q.in.level = levels[j];
				q.out.info = &info;
				status = dcerpc_lsa_QueryTrustedDomainInfo(p, tctx, &q);
				if (!NT_STATUS_IS_OK(status) && ok[j]) {
					printf("QueryTrustedDomainInfo level %d failed - %s\n",
					       levels[j], nt_errstr(status));
					ret = false;
				} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
					printf("QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n",
					       levels[j], nt_errstr(status));
					ret = false;
				}
			}

			status = dcerpc_lsa_CloseTrustedDomainEx(p, tctx, &c_trust);
			if (!NT_STATUS_EQUAL(status, NT_STATUS_NOT_IMPLEMENTED)) {
				printf("Expected CloseTrustedDomainEx to return NT_STATUS_NOT_IMPLEMENTED, instead - %s\n", nt_errstr(status));
				return false;
			}

			c.in.handle = &trustdom_handle;
			c.out.handle = &handle2;

			status = dcerpc_lsa_Close(p, tctx, &c);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close of trusted domain failed - %s\n", nt_errstr(status));
				return false;
			}

			for (j=0; j < ARRAY_SIZE(levels); j++) {
				struct lsa_QueryTrustedDomainInfoBySid q;
				union lsa_TrustedDomainInfo *info = NULL;

				if (!domains->domains[i].sid) {
					continue;
				}

				q.in.handle  = handle;
				q.in.dom_sid = domains->domains[i].sid;
				q.in.level   = levels[j];
				q.out.info   = &info;

				status = dcerpc_lsa_QueryTrustedDomainInfoBySid(p, tctx, &q);
				if (!NT_STATUS_IS_OK(status) && ok[j]) {
					printf("QueryTrustedDomainInfoBySid level %d failed - %s\n",
					       levels[j], nt_errstr(status));
					ret = false;
				} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
					printf("QueryTrustedDomainInfoBySid level %d unexpectedly succeeded - %s\n",
					       levels[j], nt_errstr(status));
					ret = false;
				}
			}
		}

		trust_by_name.in.handle = handle;
		trust_by_name.in.name.string = domains->domains[i].name.string;
		trust_by_name.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		trust_by_name.out.trustdom_handle = &trustdom_handle;

		status = dcerpc_lsa_OpenTrustedDomainByName(p, tctx, &trust_by_name);

		if (!NT_STATUS_IS_OK(status)) {
			printf("OpenTrustedDomainByName failed - %s\n", nt_errstr(status));
			return false;
		}

		for (j=0; j < ARRAY_SIZE(levels); j++) {
			struct lsa_QueryTrustedDomainInfo q;
			union lsa_TrustedDomainInfo *info = NULL;
			q.in.trustdom_handle = &trustdom_handle;
			q.in.level = levels[j];
			q.out.info = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfo(p, tctx, &q);
			if (!NT_STATUS_IS_OK(status) && ok[j]) {
				printf("QueryTrustedDomainInfo level %d failed - %s\n",
				       levels[j], nt_errstr(status));
				ret = false;
			} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
				printf("QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n",
				       levels[j], nt_errstr(status));
				ret = false;
			}
		}

		c.in.handle = &trustdom_handle;
		c.out.handle = &handle2;

		status = dcerpc_lsa_Close(p, tctx, &c);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Close of trusted domain failed - %s\n", nt_errstr(status));
			return false;
		}

		for (j=0; j < ARRAY_SIZE(levels); j++) {
			struct lsa_QueryTrustedDomainInfoByName q;
			union lsa_TrustedDomainInfo *info = NULL;
			struct lsa_String name;

			name.string = domains->domains[i].name.string;

			q.in.handle         = handle;
			q.in.trusted_domain = &name;
			q.in.level          = levels[j];
			q.out.info          = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfoByName(p, tctx, &q);
			if (!NT_STATUS_IS_OK(status) && ok[j]) {
				printf("QueryTrustedDomainInfoByName level %d failed - %s\n",
				       levels[j], nt_errstr(status));
				ret = false;
			} else if (NT_STATUS_IS_OK(status) && !ok[j]) {
				printf("QueryTrustedDomainInfoByName level %d unexpectedly succeeded - %s\n",
				       levels[j], nt_errstr(status));
				ret = false;
			}
		}
	}
	return ret;
}

static bool test_EnumTrustDom(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	struct lsa_EnumTrustDom r;
	struct lsa_EnumTrustedDomainsEx r_ex;
	NTSTATUS enum_status;
	uint32_t resume_handle = 0;
	struct lsa_DomainList domains;
	struct lsa_DomainListEx domains_ex;
	bool ret = true;

	printf("\nTesting EnumTrustDom\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_size = 0;
	r.out.domains = &domains;
	r.out.resume_handle = &resume_handle;

	enum_status = dcerpc_lsa_EnumTrustDom(p, tctx, &r);

	if (NT_STATUS_IS_OK(enum_status)) {
		if (domains.count == 0) {
			printf("EnumTrustDom failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}
	} else if (!(NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES) || NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES))) {
		printf("EnumTrustDom of zero size failed - %s\n", nt_errstr(enum_status));
		return false;
	}

	/* Start from the bottom again */
	resume_handle = 0;

	do {
		r.in.handle = handle;
		r.in.resume_handle = &resume_handle;
		r.in.max_size = LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3;
		r.out.domains = &domains;
		r.out.resume_handle = &resume_handle;

		enum_status = dcerpc_lsa_EnumTrustDom(p, tctx, &r);

		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES)) {
			if (domains.count == 0) {
				return true;
			}
			printf("EnumTrustDom failed - should have returned 0 trusted domains with 'NT_STATUS_NO_MORE_ENTRIES'\n");
			return false;
		} else if (NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r.out.domains->count < 3 || r.out.domains->count > 4) {
				printf("EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r.out.domains->count, LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3,
				       LSA_ENUM_TRUST_DOMAIN_MULTIPLIER, r.in.max_size);
				ret = false;
			}
		} else if (!NT_STATUS_IS_OK(enum_status)) {
			printf("EnumTrustDom failed - %s\n", nt_errstr(enum_status));
			return false;
		}

		if (domains.count == 0) {
			printf("EnumTrustDom failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}

		ret &= test_query_each_TrustDom(p, tctx, handle, &domains);

	} while ((NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)));

	printf("\nTesting EnumTrustedDomainsEx\n");

	r_ex.in.handle = handle;
	r_ex.in.resume_handle = &resume_handle;
	r_ex.in.max_size = LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER * 3;
	r_ex.out.domains = &domains_ex;
	r_ex.out.resume_handle = &resume_handle;

	enum_status = dcerpc_lsa_EnumTrustedDomainsEx(p, tctx, &r_ex);

	if (!(NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES) || NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES))) {
		printf("EnumTrustedDomainEx of zero size failed - %s\n", nt_errstr(enum_status));
		return false;
	}

	resume_handle = 0;
	do {
		r_ex.in.handle = handle;
		r_ex.in.resume_handle = &resume_handle;
		r_ex.in.max_size = LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER * 3;
		r_ex.out.domains = &domains_ex;
		r_ex.out.resume_handle = &resume_handle;

		enum_status = dcerpc_lsa_EnumTrustedDomainsEx(p, tctx, &r_ex);

		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(enum_status, NT_STATUS_NO_MORE_ENTRIES)) {
			if (domains_ex.count == 0) {
				return true;
			}
			printf("EnumTrustDomainsEx failed - should have returned 0 trusted domains with 'NT_STATUS_NO_MORE_ENTRIES'\n");
			return false;
		} else if (NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r_ex.out.domains->count < 3 || r_ex.out.domains->count > 4) {
				printf("EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r_ex.out.domains->count,
				       r_ex.in.max_size,
				       LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER,
				       r_ex.in.max_size / LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER);
			}
		} else if (!NT_STATUS_IS_OK(enum_status)) {
			printf("EnumTrustedDomainEx failed - %s\n", nt_errstr(enum_status));
			return false;
		}

		if (domains_ex.count == 0) {
			printf("EnumTrustDomainEx failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}

		ret &= test_query_each_TrustDomEx(p, tctx, handle, &domains_ex);

	} while ((NT_STATUS_EQUAL(enum_status, STATUS_MORE_ENTRIES)));

	return ret;
}

static bool test_CreateTrustedDomain(struct dcerpc_pipe *p,
				     struct torture_context *tctx,
				     struct policy_handle *handle)
{
	NTSTATUS status;
	bool ret = true;
	struct lsa_CreateTrustedDomain r;
	struct lsa_DomainInfo trustinfo;
	struct dom_sid *domsid[12];
	struct policy_handle trustdom_handle[12];
	struct lsa_QueryTrustedDomainInfo q;
	union lsa_TrustedDomainInfo *info = NULL;
	int i;

	printf("\nTesting CreateTrustedDomain for 12 domains\n");

	if (!test_EnumTrustDom(p, tctx, handle)) {
		ret = false;
	}

	for (i=0; i< 12; i++) {
		char *trust_name = talloc_asprintf(tctx, "torturedom%02d", i);
		char *trust_sid = talloc_asprintf(tctx, "S-1-5-21-97398-379795-100%02d", i);

		domsid[i] = dom_sid_parse_talloc(tctx, trust_sid);

		trustinfo.sid = domsid[i];
		init_lsa_String((struct lsa_String *)&trustinfo.name, trust_name);

		r.in.policy_handle = handle;
		r.in.info = &trustinfo;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.trustdom_handle = &trustdom_handle[i];

		status = dcerpc_lsa_CreateTrustedDomain(p, tctx, &r);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			test_DeleteTrustedDomain(p, tctx, handle, trustinfo.name);
			status = dcerpc_lsa_CreateTrustedDomain(p, tctx, &r);
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("CreateTrustedDomain failed - %s\n", nt_errstr(status));
			ret = false;
		} else {

			q.in.trustdom_handle = &trustdom_handle[i];
			q.in.level = LSA_TRUSTED_DOMAIN_INFO_INFO_EX;
			q.out.info = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfo(p, tctx, &q);
			if (!NT_STATUS_IS_OK(status)) {
				printf("QueryTrustedDomainInfo level 1 failed - %s\n", nt_errstr(status));
				ret = false;
			} else if (!q.out.info) {
				ret = false;
			} else {
				if (strcmp(info->info_ex.netbios_name.string, trustinfo.name.string) != 0) {
					printf("QueryTrustedDomainInfo returned inconsistant short name: %s != %s\n",
					       info->info_ex.netbios_name.string, trustinfo.name.string);
					ret = false;
				}
				if (info->info_ex.trust_type != LSA_TRUST_TYPE_DOWNLEVEL) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust type %d != %d\n",
					       trust_name, info->info_ex.trust_type, LSA_TRUST_TYPE_DOWNLEVEL);
					ret = false;
				}
				if (info->info_ex.trust_attributes != 0) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust attributes %d != %d\n",
					       trust_name, info->info_ex.trust_attributes, 0);
					ret = false;
				}
				if (info->info_ex.trust_direction != LSA_TRUST_DIRECTION_OUTBOUND) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust direction %d != %d\n",
					       trust_name, info->info_ex.trust_direction, LSA_TRUST_DIRECTION_OUTBOUND);
					ret = false;
				}
			}
		}
	}

	/* now that we have some domains to look over, we can test the enum calls */
	if (!test_EnumTrustDom(p, tctx, handle)) {
		ret = false;
	}

	for (i=0; i<12; i++) {
		if (!test_DeleteTrustedDomainBySid(p, tctx, handle, domsid[i])) {
			ret = false;
		}
	}

	return ret;
}

static bool test_CreateTrustedDomainEx2(struct dcerpc_pipe *p,
					struct torture_context *tctx,
					struct policy_handle *handle)
{
	NTSTATUS status;
	bool ret = true;
	struct lsa_CreateTrustedDomainEx2 r;
	struct lsa_TrustDomainInfoInfoEx trustinfo;
	struct lsa_TrustDomainInfoAuthInfoInternal authinfo;
	struct trustDomainPasswords auth_struct;
	DATA_BLOB auth_blob;
	struct dom_sid *domsid[12];
	struct policy_handle trustdom_handle[12];
	struct lsa_QueryTrustedDomainInfo q;
	union lsa_TrustedDomainInfo *info = NULL;
	DATA_BLOB session_key;
	enum ndr_err_code ndr_err;
	int i;

	printf("\nTesting CreateTrustedDomainEx2 for 12 domains\n");

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		return false;
	}

	for (i=0; i< 12; i++) {
		char *trust_name = talloc_asprintf(tctx, "torturedom%02d", i);
		char *trust_name_dns = talloc_asprintf(tctx, "torturedom%02d.samba.example.com", i);
		char *trust_sid = talloc_asprintf(tctx, "S-1-5-21-97398-379795-100%02d", i);

		domsid[i] = dom_sid_parse_talloc(tctx, trust_sid);

		trustinfo.sid = domsid[i];
		trustinfo.netbios_name.string = trust_name;
		trustinfo.domain_name.string = trust_name_dns;

		/* Create inbound, some outbound, and some
		 * bi-directional trusts in a repeating pattern based
		 * on i */

		/* 1 == inbound, 2 == outbound, 3 == both */
		trustinfo.trust_direction = (i % 3) + 1;

		/* Try different trust types too */

		/* 1 == downlevel (NT4), 2 == uplevel (ADS), 3 == MIT (kerberos but not AD) */
		trustinfo.trust_type = (((i / 3) + 1) % 3) + 1;

		trustinfo.trust_attributes = LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION;

		generate_random_buffer(auth_struct.confounder, sizeof(auth_struct.confounder));

		auth_struct.outgoing.count = 0;
		auth_struct.incoming.count = 0;

		ndr_err = ndr_push_struct_blob(&auth_blob, tctx, lp_iconv_convenience(tctx->lp_ctx), &auth_struct,
					       (ndr_push_flags_fn_t)ndr_push_trustDomainPasswords);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			printf("ndr_push_struct_blob of trustDomainPasswords structure failed");
			ret = false;
		}

		arcfour_crypt_blob(auth_blob.data, auth_blob.length, &session_key);

		authinfo.auth_blob.size = auth_blob.length;
		authinfo.auth_blob.data = auth_blob.data;

		r.in.policy_handle = handle;
		r.in.info = &trustinfo;
		r.in.auth_info = &authinfo;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.trustdom_handle = &trustdom_handle[i];

		status = dcerpc_lsa_CreateTrustedDomainEx2(p, tctx, &r);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			test_DeleteTrustedDomain(p, tctx, handle, trustinfo.netbios_name);
			status = dcerpc_lsa_CreateTrustedDomainEx2(p, tctx, &r);
		}
		if (!NT_STATUS_IS_OK(status)) {
			printf("CreateTrustedDomainEx failed2 - %s\n", nt_errstr(status));
			ret = false;
		} else {

			q.in.trustdom_handle = &trustdom_handle[i];
			q.in.level = LSA_TRUSTED_DOMAIN_INFO_INFO_EX;
			q.out.info = &info;
			status = dcerpc_lsa_QueryTrustedDomainInfo(p, tctx, &q);
			if (!NT_STATUS_IS_OK(status)) {
				printf("QueryTrustedDomainInfo level 1 failed - %s\n", nt_errstr(status));
				ret = false;
			} else if (!q.out.info) {
				printf("QueryTrustedDomainInfo level 1 failed to return an info pointer\n");
				ret = false;
			} else {
				if (strcmp(info->info_ex.netbios_name.string, trustinfo.netbios_name.string) != 0) {
					printf("QueryTrustedDomainInfo returned inconsistant short name: %s != %s\n",
					       info->info_ex.netbios_name.string, trustinfo.netbios_name.string);
					ret = false;
				}
				if (info->info_ex.trust_type != trustinfo.trust_type) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust type %d != %d\n",
					       trust_name, info->info_ex.trust_type, trustinfo.trust_type);
					ret = false;
				}
				if (info->info_ex.trust_attributes != LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust attributes %d != %d\n",
					       trust_name, info->info_ex.trust_attributes, LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION);
					ret = false;
				}
				if (info->info_ex.trust_direction != trustinfo.trust_direction) {
					printf("QueryTrustedDomainInfo of %s returned incorrect trust direction %d != %d\n",
					       trust_name, info->info_ex.trust_direction, trustinfo.trust_direction);
					ret = false;
				}
			}
		}
	}

	/* now that we have some domains to look over, we can test the enum calls */
	if (!test_EnumTrustDom(p, tctx, handle)) {
		printf("test_EnumTrustDom failed\n");
		ret = false;
	}

	for (i=0; i<12; i++) {
		if (!test_DeleteTrustedDomainBySid(p, tctx, handle, domsid[i])) {
			printf("test_DeleteTrustedDomainBySid failed\n");
			ret = false;
		}
	}

	return ret;
}

static bool test_QueryDomainInfoPolicy(struct dcerpc_pipe *p,
				 struct torture_context *tctx,
				 struct policy_handle *handle)
{
	struct lsa_QueryDomainInformationPolicy r;
	union lsa_DomainInformationPolicy *info = NULL;
	NTSTATUS status;
	int i;
	bool ret = true;

	printf("\nTesting QueryDomainInformationPolicy\n");

	for (i=2;i<4;i++) {
		r.in.handle = handle;
		r.in.level = i;
		r.out.info = &info;

		printf("\nTrying QueryDomainInformationPolicy level %d\n", i);

		status = dcerpc_lsa_QueryDomainInformationPolicy(p, tctx, &r);

		/* If the server does not support EFS, then this is the correct return */
		if (i == LSA_DOMAIN_INFO_POLICY_EFS && NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			continue;
		} else if (!NT_STATUS_IS_OK(status)) {
			printf("QueryDomainInformationPolicy failed - %s\n", nt_errstr(status));
			ret = false;
			continue;
		}
	}

	return ret;
}


static bool test_QueryInfoPolicyCalls(	bool version2,
					struct dcerpc_pipe *p,
					struct torture_context *tctx,
					struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy r;
	union lsa_PolicyInformation *info = NULL;
	NTSTATUS status;
	int i;
	bool ret = true;

	if (version2)
		printf("\nTesting QueryInfoPolicy2\n");
	else
		printf("\nTesting QueryInfoPolicy\n");

	for (i=1;i<=14;i++) {
		r.in.handle = handle;
		r.in.level = i;
		r.out.info = &info;

		if (version2)
			printf("\nTrying QueryInfoPolicy2 level %d\n", i);
		else
			printf("\nTrying QueryInfoPolicy level %d\n", i);

		if (version2)
			/* We can perform the cast, because both types are
			   structurally equal */
			status = dcerpc_lsa_QueryInfoPolicy2(p, tctx,
				 (struct lsa_QueryInfoPolicy2*) &r);
		else
			status = dcerpc_lsa_QueryInfoPolicy(p, tctx, &r);

		switch (i) {
		case LSA_POLICY_INFO_MOD:
		case LSA_POLICY_INFO_AUDIT_FULL_SET:
		case LSA_POLICY_INFO_AUDIT_FULL_QUERY:
			if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
				printf("Server should have failed level %u: %s\n", i, nt_errstr(status));
				ret = false;
			}
			break;
		case LSA_POLICY_INFO_DOMAIN:
		case LSA_POLICY_INFO_ACCOUNT_DOMAIN:
		case LSA_POLICY_INFO_L_ACCOUNT_DOMAIN:
		case LSA_POLICY_INFO_DNS_INT:
		case LSA_POLICY_INFO_DNS:
		case LSA_POLICY_INFO_REPLICA:
		case LSA_POLICY_INFO_QUOTA:
		case LSA_POLICY_INFO_ROLE:
		case LSA_POLICY_INFO_AUDIT_LOG:
		case LSA_POLICY_INFO_AUDIT_EVENTS:
		case LSA_POLICY_INFO_PD:
			if (!NT_STATUS_IS_OK(status)) {
				if (version2)
					printf("QueryInfoPolicy2 failed - %s\n", nt_errstr(status));
				else
					printf("QueryInfoPolicy failed - %s\n", nt_errstr(status));
				ret = false;
			}
			break;
		default:
			if (torture_setting_bool(tctx, "samba4", false)) {
				/* Other levels not implemented yet */
				if (!NT_STATUS_EQUAL(status, NT_STATUS_INVALID_INFO_CLASS)) {
					if (version2)
						printf("QueryInfoPolicy2 failed - %s\n", nt_errstr(status));
					else
						printf("QueryInfoPolicy failed - %s\n", nt_errstr(status));
					ret = false;
				}
			} else if (!NT_STATUS_IS_OK(status)) {
				if (version2)
					printf("QueryInfoPolicy2 failed - %s\n", nt_errstr(status));
				else
					printf("QueryInfoPolicy failed - %s\n", nt_errstr(status));
				ret = false;
			}
			break;
		}

		if (NT_STATUS_IS_OK(status) && (i == LSA_POLICY_INFO_DNS
			|| i == LSA_POLICY_INFO_DNS_INT)) {
			/* Let's look up some of these names */

			struct lsa_TransNameArray tnames;
			tnames.count = 14;
			tnames.names = talloc_zero_array(tctx, struct lsa_TranslatedName, tnames.count);
			tnames.names[0].name.string = info->dns.name.string;
			tnames.names[0].sid_type = SID_NAME_DOMAIN;
			tnames.names[1].name.string = info->dns.dns_domain.string;
			tnames.names[1].sid_type = SID_NAME_DOMAIN;
			tnames.names[2].name.string = talloc_asprintf(tctx, "%s\\", info->dns.name.string);
			tnames.names[2].sid_type = SID_NAME_DOMAIN;
			tnames.names[3].name.string = talloc_asprintf(tctx, "%s\\", info->dns.dns_domain.string);
			tnames.names[3].sid_type = SID_NAME_DOMAIN;
			tnames.names[4].name.string = talloc_asprintf(tctx, "%s\\guest", info->dns.name.string);
			tnames.names[4].sid_type = SID_NAME_USER;
			tnames.names[5].name.string = talloc_asprintf(tctx, "%s\\krbtgt", info->dns.name.string);
			tnames.names[5].sid_type = SID_NAME_USER;
			tnames.names[6].name.string = talloc_asprintf(tctx, "%s\\guest", info->dns.dns_domain.string);
			tnames.names[6].sid_type = SID_NAME_USER;
			tnames.names[7].name.string = talloc_asprintf(tctx, "%s\\krbtgt", info->dns.dns_domain.string);
			tnames.names[7].sid_type = SID_NAME_USER;
			tnames.names[8].name.string = talloc_asprintf(tctx, "krbtgt@%s", info->dns.name.string);
			tnames.names[8].sid_type = SID_NAME_USER;
			tnames.names[9].name.string = talloc_asprintf(tctx, "krbtgt@%s", info->dns.dns_domain.string);
			tnames.names[9].sid_type = SID_NAME_USER;
			tnames.names[10].name.string = talloc_asprintf(tctx, "%s\\"TEST_MACHINENAME "$", info->dns.name.string);
			tnames.names[10].sid_type = SID_NAME_USER;
			tnames.names[11].name.string = talloc_asprintf(tctx, "%s\\"TEST_MACHINENAME "$", info->dns.dns_domain.string);
			tnames.names[11].sid_type = SID_NAME_USER;
			tnames.names[12].name.string = talloc_asprintf(tctx, TEST_MACHINENAME "$@%s", info->dns.name.string);
			tnames.names[12].sid_type = SID_NAME_USER;
			tnames.names[13].name.string = talloc_asprintf(tctx, TEST_MACHINENAME "$@%s", info->dns.dns_domain.string);
			tnames.names[13].sid_type = SID_NAME_USER;
			ret &= test_LookupNames(p, tctx, handle, &tnames);

		}
	}

	return ret;
}

static bool test_QueryInfoPolicy(struct dcerpc_pipe *p,
				 struct torture_context *tctx,
				 struct policy_handle *handle)
{
	return test_QueryInfoPolicyCalls(false, p, tctx, handle);
}

static bool test_QueryInfoPolicy2(struct dcerpc_pipe *p,
				  struct torture_context *tctx,
				  struct policy_handle *handle)
{
	return test_QueryInfoPolicyCalls(true, p, tctx, handle);
}

static bool test_GetUserName(struct dcerpc_pipe *p,
			     struct torture_context *tctx)
{
	struct lsa_GetUserName r;
	NTSTATUS status;
	bool ret = true;
	struct lsa_String *authority_name_p = NULL;
	struct lsa_String *account_name_p = NULL;

	printf("\nTesting GetUserName\n");

	r.in.system_name	= "\\";
	r.in.account_name	= &account_name_p;
	r.in.authority_name	= NULL;
	r.out.account_name	= &account_name_p;

	status = dcerpc_lsa_GetUserName(p, tctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		ret = false;
	}

	account_name_p = NULL;
	r.in.account_name	= &account_name_p;
	r.in.authority_name	= &authority_name_p;
	r.out.account_name	= &account_name_p;

	status = dcerpc_lsa_GetUserName(p, tctx, &r);

	if (!NT_STATUS_IS_OK(status)) {
		printf("GetUserName failed - %s\n", nt_errstr(status));
		ret = false;
	}

	return ret;
}

bool test_lsa_Close(struct dcerpc_pipe *p,
		    struct torture_context *tctx,
		    struct policy_handle *handle)
{
	NTSTATUS status;
	struct lsa_Close r;
	struct policy_handle handle2;

	printf("\nTesting Close\n");

	r.in.handle = handle;
	r.out.handle = &handle2;

	status = dcerpc_lsa_Close(p, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return false;
	}

	status = dcerpc_lsa_Close(p, tctx, &r);
	/* its really a fault - we need a status code for rpc fault */
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		printf("Close failed - %s\n", nt_errstr(status));
		return false;
	}

	printf("\n");

	return true;
}

bool torture_rpc_lsa(struct torture_context *tctx)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	bool ret = true;
	struct policy_handle *handle;
	struct test_join *join = NULL;
	struct cli_credentials *machine_creds;

	status = torture_rpc_connection(tctx, &p, &ndr_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (!test_OpenPolicy(p, tctx)) {
		ret = false;
	}

	if (!test_lsa_OpenPolicy2(p, tctx, &handle)) {
		ret = false;
	}

	if (handle) {
		join = torture_join_domain(tctx, TEST_MACHINENAME, ACB_WSTRUST, &machine_creds);
		if (!join) {
			ret = false;
		}
		if (!test_LookupNames_wellknown(p, tctx, handle)) {
			ret = false;
		}

		if (!test_LookupNames_bogus(p, tctx, handle)) {
			ret = false;
		}

		if (!test_LookupSids_async(p, tctx, handle)) {
			ret = false;
		}

		if (!test_QueryDomainInfoPolicy(p, tctx, handle)) {
			ret = false;
		}

		if (!test_CreateAccount(p, tctx, handle)) {
			ret = false;
		}

		if (!test_CreateSecret(p, tctx, handle)) {
			ret = false;
		}
		if (!test_CreateTrustedDomain(p, tctx, handle)) {
			ret = false;
		}

		if (!test_CreateTrustedDomainEx2(p, tctx, handle)) {
			ret = false;
		}

		if (!test_EnumAccounts(p, tctx, handle)) {
			ret = false;
		}

		if (!test_EnumPrivs(p, tctx, handle)) {
			ret = false;
		}

		if (!test_QueryInfoPolicy(p, tctx, handle)) {
			ret = false;
		}

		if (!test_QueryInfoPolicy2(p, tctx, handle)) {
			ret = false;
		}

		if (!test_Delete(p, tctx, handle)) {
			ret = false;
		}

		if (!test_many_LookupSids(p, tctx, handle)) {
			ret = false;
		}

		if (!test_lsa_Close(p, tctx, handle)) {
			ret = false;
		}

		torture_leave_domain(tctx, join);

	} else {
		if (!test_many_LookupSids(p, tctx, handle)) {
			ret = false;
		}
	}

	if (!test_GetUserName(p, tctx)) {
		ret = false;
	}

	return ret;
}

bool torture_rpc_lsa_get_user(struct torture_context *tctx)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	bool ret = true;

	status = torture_rpc_connection(tctx, &p, &ndr_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (!test_GetUserName(p, tctx)) {
		ret = false;
	}

	return ret;
}

static bool testcase_LookupNames(struct torture_context *tctx,
				 struct dcerpc_pipe *p)
{
	bool ret = true;
	struct policy_handle *handle;
	struct lsa_TransNameArray tnames;
	struct lsa_TransNameArray2 tnames2;

	if (!test_OpenPolicy(p, tctx)) {
		ret = false;
	}

	if (!test_lsa_OpenPolicy2(p, tctx, &handle)) {
		ret = false;
	}

	if (!handle) {
		ret = false;
	}

	tnames.count = 1;
	tnames.names = talloc_array(tctx, struct lsa_TranslatedName, tnames.count);
	ZERO_STRUCT(tnames.names[0]);
	tnames.names[0].name.string = "BUILTIN";
	tnames.names[0].sid_type = SID_NAME_DOMAIN;

	if (!test_LookupNames(p, tctx, handle, &tnames)) {
		ret = false;
	}

	tnames2.count = 1;
	tnames2.names = talloc_array(tctx, struct lsa_TranslatedName2, tnames2.count);
	ZERO_STRUCT(tnames2.names[0]);
	tnames2.names[0].name.string = "BUILTIN";
	tnames2.names[0].sid_type = SID_NAME_DOMAIN;

	if (!test_LookupNames2(p, tctx, handle, &tnames2, true)) {
		ret = false;
	}

	if (!test_LookupNames3(p, tctx, handle, &tnames2, true)) {
		ret = false;
	}

	if (!test_lsa_Close(p, tctx, handle)) {
		ret = false;
	}

	return ret;
}

struct torture_suite *torture_rpc_lsa_lookup_names(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;

	suite = torture_suite_create(mem_ctx, "LSA-LOOKUPNAMES");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "lsa",
						  &ndr_table_lsarpc);
	torture_rpc_tcase_add_test(tcase, "LookupNames",
				   testcase_LookupNames);

	return suite;
}
