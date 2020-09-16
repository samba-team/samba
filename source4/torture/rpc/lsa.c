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
#include "libcli/cldap/cldap.h"
#include "../lib/tsocket/tsocket.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "librpc/gen_ndr/netlogon.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_netlogon_c.h"
#include "lib/events/events.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"
#include "source4/auth/kerberos/kerberos.h"
#include "source4/auth/kerberos/kerberos_util.h"
#include "lib/util/util_net.h"
#include "libcli/resolve/resolve.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#define TEST_MACHINENAME "lsatestmach"
#define TRUSTPW "12345678"

static void init_lsa_String(struct lsa_String *name, const char *s)
{
	name->string = s;
}

static bool test_OpenPolicy(struct dcerpc_binding_handle *b,
			    struct torture_context *tctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	uint16_t system_name = '\\';

	torture_comment(tctx, "\nTesting OpenPolicy\n");

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

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenPolicy_r(b, tctx, &r),
				   "OpenPolicy failed");

	torture_assert_ntstatus_ok(tctx,
				   r.out.result,
				   "OpenPolicy failed");

	return true;
}

static bool test_OpenPolicy_fail(struct dcerpc_binding_handle *b,
				 struct torture_context *tctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy r;
	uint16_t system_name = '\\';
	NTSTATUS status;

	torture_comment(tctx, "\nTesting OpenPolicy_fail\n");

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

	status = dcerpc_lsa_OpenPolicy_r(b, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			torture_comment(tctx,
					"OpenPolicy correctly returned with "
					"status: %s\n",
					nt_errstr(status));
			return true;
		}

		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_ACCESS_DENIED,
					      "OpenPolicy return value should "
					      "be ACCESS_DENIED");
		return true;
	}

	if (!NT_STATUS_IS_OK(r.out.result)) {
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(r.out.result, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			torture_comment(tctx,
					"OpenPolicy correctly returned with "
					"result: %s\n",
					nt_errstr(r.out.result));
			return true;
		}
	}

	torture_assert_ntstatus_equal(tctx,
				      r.out.result,
				      NT_STATUS_OK,
				      "OpenPolicy return value should be "
				      "ACCESS_DENIED");

	return false;
}


bool test_lsa_OpenPolicy2_ex(struct dcerpc_binding_handle *b,
			     struct torture_context *tctx,
			     struct policy_handle **handle,
			     NTSTATUS expected_status,
			     NTSTATUS expected_status2)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	torture_comment(tctx, "\nTesting OpenPolicy2\n");

	*handle = talloc(tctx, struct policy_handle);
	torture_assert(tctx, *handle != NULL, "talloc(tctx, struct policy_handle)");

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

	status = dcerpc_lsa_OpenPolicy2_r(b, tctx, &r);

	/* Allow two possible failure status codes */
	if (!NT_STATUS_EQUAL(status, expected_status2)) {
		torture_assert_ntstatus_equal(tctx, status,
					      expected_status,
					      "OpenPolicy2 failed");
	}
	if (!NT_STATUS_IS_OK(expected_status) ||
	    !NT_STATUS_IS_OK(expected_status2)) {
		return true;
	}

	torture_assert_ntstatus_ok(tctx,
				   r.out.result,
				   "OpenPolicy2 failed");

	return true;
}


bool test_lsa_OpenPolicy2(struct dcerpc_binding_handle *b,
			  struct torture_context *tctx,
			  struct policy_handle **handle)
{
	return test_lsa_OpenPolicy2_ex(b, tctx, handle,
				       NT_STATUS_OK, NT_STATUS_OK);
}

static bool test_OpenPolicy2_fail(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx)
{
	struct lsa_ObjectAttribute attr;
	struct policy_handle handle;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

	torture_comment(tctx, "\nTesting OpenPolicy2_fail\n");

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
	r.out.handle = &handle;

	status = dcerpc_lsa_OpenPolicy2_r(b, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			torture_comment(tctx,
					"OpenPolicy2 correctly returned with "
					"status: %s\n",
					nt_errstr(status));
			return true;
		}

		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_ACCESS_DENIED,
					      "OpenPolicy2 return value should "
					      "be ACCESS_DENIED");
		return true;
	}

	if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_ACCESS_DENIED) ||
	    NT_STATUS_EQUAL(r.out.result, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
		torture_comment(tctx,
				"OpenPolicy2 correctly returned with "
				"result: %s\n",
				nt_errstr(r.out.result));
		return true;
	}

	torture_fail(tctx,
		     "OpenPolicy2 return value should be "
		     "ACCESS_DENIED or RPC_PROTSEQ_NOT_SUPPORTED");

	return false;
}

static bool test_LookupNames(struct dcerpc_binding_handle *b,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     enum lsa_LookupNamesLevel level,
			     struct lsa_TransNameArray *tnames)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	int i;
	uint32_t *input_idx;

	torture_comment(tctx, "\nTesting LookupNames with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;


	r.in.num_names = 0;

	input_idx = talloc_array(tctx, uint32_t, tnames->count);
	names = talloc_array(tctx, struct lsa_String, tnames->count);

	for (i=0;i<tnames->count;i++) {
		if (tnames->names[i].sid_type != SID_NAME_UNKNOWN) {
			init_lsa_String(&names[r.in.num_names], tnames->names[i].name.string);
			input_idx[r.in.num_names] = i;
			r.in.num_names++;
		}
	}

	r.in.handle = handle;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames_r(b, tctx, &r),
				   "LookupNames failed");
	if (NT_STATUS_EQUAL(r.out.result, STATUS_SOME_UNMAPPED) ||
	    NT_STATUS_EQUAL(r.out.result, NT_STATUS_NONE_MAPPED)) {
		for (i=0;i< r.in.num_names;i++) {
			if (i < count && sids.sids[i].sid_type == SID_NAME_UNKNOWN) {
				torture_comment(tctx, "LookupName of %s was unmapped\n",
				       tnames->names[i].name.string);
			} else if (i >=count) {
				torture_comment(tctx, "LookupName of %s failed to return a result\n",
				       tnames->names[i].name.string);
			}
		}
		torture_assert_ntstatus_ok(tctx, r.out.result,
					   "LookupNames failed");
	} else if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_assert_ntstatus_ok(tctx, r.out.result,
					   "LookupNames failed");
	}

	for (i=0;i< r.in.num_names;i++) {
		torture_assert(tctx, (i < count),
			       talloc_asprintf(tctx,
			       "LookupName of %s failed to return a result\n",
			       tnames->names[input_idx[i]].name.string));

		torture_assert_int_equal(tctx,
					 sids.sids[i].sid_type,
					 tnames->names[input_idx[i]].sid_type,
					 talloc_asprintf(tctx,
					 "LookupName of %s got unexpected name type: %s\n",
					 tnames->names[input_idx[i]].name.string,
					 sid_type_lookup(sids.sids[i].sid_type)));
		if (sids.sids[i].sid_type != SID_NAME_DOMAIN) {
			continue;
		}
		torture_assert_int_equal(tctx,
					 sids.sids[i].rid,
					 UINT32_MAX,
					 talloc_asprintf(tctx,
					 "LookupName of %s got unexpected rid: %d\n",
					 tnames->names[input_idx[i]].name.string,
					 sids.sids[i].rid));
	}

	return true;
}

static bool test_LookupNames_bogus(struct dcerpc_binding_handle *b,
				   struct torture_context *tctx,
				   struct policy_handle *handle,
				   enum lsa_LookupNamesLevel level)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String names[1];
	uint32_t count = 0;

	torture_comment(tctx, "\nTesting LookupNames with bogus name\n");

	sids.count = 0;
	sids.sids = NULL;

	init_lsa_String(&names[0], "NT AUTHORITY\\BOGUS");

	r.in.handle = handle;
	r.in.num_names = 1;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames_r(b, tctx, &r),
				   "LookupNames bogus failed");
	if (!NT_STATUS_EQUAL(r.out.result, NT_STATUS_NONE_MAPPED)) {
		torture_comment(tctx, "LookupNames failed - %s\n",
				nt_errstr(r.out.result));
		return false;
	}

	torture_comment(tctx, "\n");

	return true;
}

static bool test_LookupNames_NULL(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx,
				  struct policy_handle *handle,
				  enum lsa_LookupNamesLevel level)
{
	struct lsa_LookupNames r;
	struct lsa_TransSidArray sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String names[1];
	uint32_t count = 0;

	torture_comment(tctx, "\nTesting LookupNames with NULL name\n");

	sids.count = 0;
	sids.sids = NULL;

	names[0].string = NULL;

	r.in.handle = handle;
	r.in.num_names = 1;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	/* nt4 returns NT_STATUS_NONE_MAPPED with sid_type
	 * SID_NAME_UNKNOWN, rid 0, and sid_index -1;
	 *
	 * w2k3/w2k8 return NT_STATUS_OK with sid_type
	 * SID_NAME_DOMAIN, rid -1 and sid_index 0 and BUILTIN domain
	 */

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames_r(b, tctx, &r),
		"LookupNames with NULL name failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"LookupNames with NULL name failed");

	torture_comment(tctx, "\n");

	return true;
}

static bool test_LookupNames_wellknown(struct dcerpc_binding_handle *b,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       enum lsa_LookupNamesLevel level)
{
	struct lsa_TranslatedName name;
	struct lsa_TransNameArray tnames;
	bool ret = true;

	torture_comment(tctx, "Testing LookupNames with well known names\n");

	tnames.names = &name;
	tnames.count = 1;
	name.name.string = "NT AUTHORITY\\SYSTEM";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "NT AUTHORITY\\ANONYMOUS LOGON";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "NT AUTHORITY\\Authenticated Users";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

#if 0
	name.name.string = "NT AUTHORITY";
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "NT AUTHORITY\\";
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);
#endif

	name.name.string = "BUILTIN\\";
	name.sid_type = SID_NAME_DOMAIN;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "BUILTIN\\Administrators";
	name.sid_type = SID_NAME_ALIAS;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "SYSTEM";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);

	name.name.string = "Everyone";
	name.sid_type = SID_NAME_WKN_GRP;
	ret &= test_LookupNames(b, tctx, handle, level, &tnames);
	return ret;
}

static bool test_LookupNames2(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      struct policy_handle *handle,
			      enum lsa_LookupNamesLevel level,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames2 r;
	struct lsa_TransSidArray2 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t *input_idx;
	uint32_t count = 0;
	int i;

	torture_comment(tctx, "\nTesting LookupNames2 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	r.in.num_names = 0;

	input_idx = talloc_array(tctx, uint32_t, tnames->count);
	names = talloc_array(tctx, struct lsa_String, tnames->count);

	for (i=0;i<tnames->count;i++) {
		if (tnames->names[i].sid_type != SID_NAME_UNKNOWN) {
			init_lsa_String(&names[r.in.num_names], tnames->names[i].name.string);
			input_idx[r.in.num_names] = i;
			r.in.num_names++;
		}
	}

	r.in.handle = handle;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames2_r(b, tctx, &r),
		"LookupNames2 failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "LookupNames2 failed");

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	torture_comment(tctx, "\n");

	return true;
}


static bool test_LookupNames3(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      struct policy_handle *handle,
			      enum lsa_LookupNamesLevel level,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames3 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	int i;
	uint32_t *input_idx;

	torture_comment(tctx, "\nTesting LookupNames3 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	r.in.num_names = 0;

	input_idx = talloc_array(tctx, uint32_t, tnames->count);
	names = talloc_array(tctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		if (tnames->names[i].sid_type != SID_NAME_UNKNOWN) {
			init_lsa_String(&names[r.in.num_names], tnames->names[i].name.string);
			input_idx[r.in.num_names] = i;
			r.in.num_names++;
		}
	}

	r.in.handle = handle;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames3_r(b, tctx, &r),
		"LookupNames3 failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"LookupNames3 failed");

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	torture_comment(tctx, "\n");

	return true;
}

static bool test_LookupNames4(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      enum lsa_LookupNamesLevel level,
			      struct lsa_TransNameArray2 *tnames,
			      bool check_result)
{
	struct lsa_LookupNames4 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names;
	uint32_t count = 0;
	int i;
	uint32_t *input_idx;

	torture_comment(tctx, "\nTesting LookupNames4 with %d names\n", tnames->count);

	sids.count = 0;
	sids.sids = NULL;

	r.in.num_names = 0;

	input_idx = talloc_array(tctx, uint32_t, tnames->count);
	names = talloc_array(tctx, struct lsa_String, tnames->count);
	for (i=0;i<tnames->count;i++) {
		if (tnames->names[i].sid_type != SID_NAME_UNKNOWN) {
			init_lsa_String(&names[r.in.num_names], tnames->names[i].name.string);
			input_idx[r.in.num_names] = i;
			r.in.num_names++;
		}
	}

	r.in.num_names = tnames->count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupNames4_r(b, tctx, &r),
		"LookupNames4 failed");

	if (!NT_STATUS_IS_OK(r.out.result)) {
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_NONE_MAPPED)) {
			torture_comment(tctx,
					"LookupNames4 failed: %s - not considered as an error",
					nt_errstr(r.out.result));

			return true;
		}
	}
	torture_assert_ntstatus_ok(tctx,
				   r.out.result,
				   "LookupNames4 failed");

	if (check_result) {
		torture_assert_int_equal(tctx, count, sids.count,
			"unexpected number of results returned");
		if (sids.count > 0) {
			torture_assert(tctx, sids.sids, "invalid sid buffer");
		}
	}

	torture_comment(tctx, "\n");

	return true;
}

static bool test_LookupNames4_fail(struct dcerpc_binding_handle *b,
				   struct torture_context *tctx,
				   enum lsa_LookupNamesLevel level)
{
	struct lsa_LookupNames4 r;
	struct lsa_TransSidArray3 sids;
	struct lsa_RefDomainList *domains = NULL;
	struct lsa_String *names = NULL;
	uint32_t count = 0;
	NTSTATUS status;

	torture_comment(tctx, "\nTesting LookupNames4_fail");

	sids.count = 0;
	sids.sids = NULL;

	r.in.num_names = 0;

	r.in.num_names = count;
	r.in.names = names;
	r.in.sids = &sids;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.sids = &sids;
	r.out.domains = &domains;

	status = dcerpc_lsa_LookupNames4_r(b, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			torture_comment(tctx,
					"LookupNames4 correctly returned with "
					"status: %s\n",
					nt_errstr(status));
			return true;
		}

		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_ACCESS_DENIED,
					      "LookupNames4 return value should "
					      "be ACCESS_DENIED");
		return true;
	}

	if (!NT_STATUS_IS_OK(r.out.result)) {
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(r.out.result, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			torture_comment(tctx,
					"LookupSids3 correctly returned with "
					"result: %s\n",
					nt_errstr(r.out.result));
			return true;
		}
	}

	torture_fail(tctx,
		     "LookupNames4 return value should be "
		     "ACCESS_DENIED or RPC_PROTSEQ_NOT_SUPPORTED");

	return false;
}


static bool test_LookupSids(struct dcerpc_binding_handle *b,
			    struct torture_context *tctx,
			    struct policy_handle *handle,
			    enum lsa_LookupNamesLevel level,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids r;
	struct lsa_TransNameArray names;
	struct lsa_RefDomainList *domains = NULL;
	uint32_t count = sids->num_sids;

	torture_comment(tctx, "\nTesting LookupSids\n");

	names.count = 0;
	names.names = NULL;

	r.in.handle = handle;
	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = level;
	r.in.count = &count;
	r.out.count = &count;
	r.out.names = &names;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupSids_r(b, tctx, &r),
		"LookupSids failed");
	if (!NT_STATUS_EQUAL(r.out.result, STATUS_SOME_UNMAPPED)) {
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"LookupSids failed");
	}

	torture_comment(tctx, "\n");

	if (!test_LookupNames(b, tctx, handle, level, &names)) {
		return false;
	}

	return true;
}


static bool test_LookupSids2(struct dcerpc_binding_handle *b,
			    struct torture_context *tctx,
			    struct policy_handle *handle,
			    enum lsa_LookupNamesLevel level,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids2 r;
	struct lsa_TransNameArray2 names;
	struct lsa_RefDomainList *domains = NULL;
	uint32_t count = sids->num_sids;

	torture_comment(tctx, "\nTesting LookupSids2\n");

	names.count = 0;
	names.names = NULL;

	r.in.handle = handle;
	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.count = &count;
	r.out.names = &names;
	r.out.domains = &domains;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupSids2_r(b, tctx, &r),
		"LookupSids2 failed");
	if (!NT_STATUS_IS_OK(r.out.result) &&
	    !NT_STATUS_EQUAL(r.out.result, STATUS_SOME_UNMAPPED)) {
		torture_comment(tctx, "LookupSids2 failed - %s\n",
				nt_errstr(r.out.result));
		return false;
	}

	torture_comment(tctx, "\n");

	if (!test_LookupNames2(b, tctx, handle, level, &names, false)) {
		return false;
	}

	if (!test_LookupNames3(b, tctx, handle, level, &names, false)) {
		return false;
	}

	return true;
}

static bool test_LookupSids3(struct dcerpc_binding_handle *b,
			    struct torture_context *tctx,
			    enum lsa_LookupNamesLevel level,
			    struct lsa_SidArray *sids)
{
	struct lsa_LookupSids3 r;
	struct lsa_TransNameArray2 names;
	struct lsa_RefDomainList *domains = NULL;
	uint32_t count = sids->num_sids;

	torture_comment(tctx, "\nTesting LookupSids3\n");

	names.count = 0;
	names.names = NULL;

	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.domains = &domains;
	r.out.count = &count;
	r.out.names = &names;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupSids3_r(b, tctx, &r),
		"LookupSids3 failed");

	if (!NT_STATUS_IS_OK(r.out.result)) {
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_NONE_MAPPED)) {
			torture_comment(tctx,
					"LookupSids3 failed: %s - not considered as an error",
					nt_errstr(r.out.result));

			return true;
		}

		torture_assert_ntstatus_ok(tctx,
					   r.out.result,
					   "LookupSids3 failed");

		return false;
	}

	torture_comment(tctx, "\n");

	if (!test_LookupNames4(b, tctx, level, &names, true)) {
		return false;
	}

	return true;
}

static bool test_LookupSids3_fail(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx,
				  enum lsa_LookupNamesLevel level,
				  struct lsa_SidArray *sids)
{
	struct lsa_LookupSids3 r;
	struct lsa_TransNameArray2 names;
	struct lsa_RefDomainList *domains = NULL;
	uint32_t count = sids->num_sids;
	NTSTATUS status;

	torture_comment(tctx, "\nTesting LookupSids3\n");

	names.count = 0;
	names.names = NULL;

	r.in.sids = sids;
	r.in.names = &names;
	r.in.level = level;
	r.in.count = &count;
	r.in.lookup_options = 0;
	r.in.client_revision = 0;
	r.out.domains = &domains;
	r.out.count = &count;
	r.out.names = &names;

	status = dcerpc_lsa_LookupSids3_r(b, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			torture_comment(tctx,
					"LookupSids3 correctly returned with "
					"status: %s\n",
					nt_errstr(status));
			return true;
		}

		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_ACCESS_DENIED,
					      "LookupSids3 return value should "
					      "be ACCESS_DENIED");
		return true;
	}

	if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_ACCESS_DENIED) ||
	    NT_STATUS_EQUAL(r.out.result, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
		torture_comment(tctx,
				"LookupNames4 correctly returned with "
				"result: %s\n",
				nt_errstr(r.out.result));
		return true;
	}

	torture_fail(tctx,
		     "LookupSids3 return value should be "
		     "ACCESS_DENIED or RPC_PROTSEQ_NOT_SUPPORTED");

	return false;
}

bool test_many_LookupSids(struct dcerpc_pipe *p,
			  struct torture_context *tctx,
			  struct policy_handle *handle,
			  enum lsa_LookupNamesLevel level)
{
	uint32_t count;
	struct lsa_SidArray sids;
	int i;
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(p->binding);

	torture_comment(tctx, "\nTesting LookupSids with lots of SIDs\n");

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
		r.in.level = level;
		r.in.count = &names.count;
		r.out.count = &count;
		r.out.names = &names;
		r.out.domains = &domains;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupSids_r(b, tctx, &r),
			"LookupSids failed");
		if (!NT_STATUS_IS_OK(r.out.result)) {
			torture_comment(tctx, "LookupSids failed - %s\n",
					nt_errstr(r.out.result));
			return false;
		}

		torture_comment(tctx, "\n");

		if (!test_LookupNames(b, tctx, handle, level, &names)) {
			return false;
		}
	}

	if (transport == NCACN_NP) {
		if (!test_LookupSids3_fail(b, tctx, level, &sids)) {
			return false;
		}
		if (!test_LookupNames4_fail(b, tctx, level)) {
			return false;
		}
	} else if (transport == NCACN_IP_TCP) {
		struct lsa_TransNameArray2 names;
		enum dcerpc_AuthType auth_type;
		enum dcerpc_AuthLevel auth_level;

		names.count = 0;
		names.names = NULL;

		dcerpc_binding_handle_auth_info(p->binding_handle,
						&auth_type, &auth_level);

		if (auth_type == DCERPC_AUTH_TYPE_SCHANNEL &&
		    auth_level >= DCERPC_AUTH_LEVEL_INTEGRITY) {
			if (!test_LookupSids3(b, tctx, level, &sids)) {
				return false;
			}
			if (!test_LookupNames4(b, tctx, level, &names, true)) {
				return false;
			}
		} else {
			/*
			 * If we don't have a secure channel these tests must
			 * fail with ACCESS_DENIED.
			 */
			if (!test_LookupSids3_fail(b, tctx, level, &sids)) {
				return false;
			}
			if (!test_LookupNames4_fail(b, tctx, level)) {
				return false;
			}
		}
	}

	torture_comment(tctx, "\n");



	return true;
}

static void lookupsids_cb(struct tevent_req *subreq)
{
	int *replies = (int *)tevent_req_callback_data_void(subreq);
	NTSTATUS status;

	status = dcerpc_lsa_LookupSids_r_recv(subreq, subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		printf("lookupsids returned %s\n", nt_errstr(status));
		*replies = -1;
	}

	if (*replies >= 0) {
		*replies += 1;
	}
}

static bool test_LookupSids_async(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx,
				  struct policy_handle *handle,
				  enum lsa_LookupNamesLevel level)
{
	struct lsa_SidArray sids;
	struct lsa_SidPtr sidptr;
	uint32_t *count;
	struct lsa_TransNameArray *names;
	struct lsa_LookupSids *r;
	struct lsa_RefDomainList *domains = NULL;
	struct tevent_req **req;
	int i, replies;
	bool ret = true;
	const int num_async_requests = 50;

	count = talloc_array(tctx, uint32_t, num_async_requests);
	names = talloc_array(tctx, struct lsa_TransNameArray, num_async_requests);
	r = talloc_array(tctx, struct lsa_LookupSids, num_async_requests);

	torture_comment(tctx, "\nTesting %d async lookupsids request\n", num_async_requests);

	req = talloc_array(tctx, struct tevent_req *, num_async_requests);

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
		r[i].in.level = level;
		r[i].in.count = &names[i].count;
		r[i].out.count = &count[i];
		r[i].out.names = &names[i];
		r[i].out.domains = &domains;

		req[i] = dcerpc_lsa_LookupSids_r_send(tctx, tctx->ev, b, &r[i]);
		if (req[i] == NULL) {
			ret = false;
			break;
		}

		tevent_req_set_callback(req[i], lookupsids_cb, &replies);
	}

	while (replies >= 0 && replies < num_async_requests) {
		tevent_loop_once(tctx->ev);
	}

	talloc_free(req);

	if (replies < 0) {
		ret = false;
	}

	return ret;
}

static bool test_LookupPrivValue(struct dcerpc_binding_handle *b,
				 struct torture_context *tctx,
				 struct policy_handle *handle,
				 struct lsa_String *name)
{
	struct lsa_LookupPrivValue r;
	struct lsa_LUID luid;

	r.in.handle = handle;
	r.in.name = name;
	r.out.luid = &luid;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupPrivValue_r(b, tctx, &r),
		"LookupPrivValue failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"LookupPrivValue failed");

	return true;
}

static bool test_LookupPrivName(struct dcerpc_binding_handle *b,
				struct torture_context *tctx,
				struct policy_handle *handle,
				struct lsa_LUID *luid)
{
	struct lsa_LookupPrivName r;
	struct lsa_StringLarge *name = NULL;

	r.in.handle = handle;
	r.in.luid = luid;
	r.out.name = &name;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupPrivName_r(b, tctx, &r),
		"LookupPrivName failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "LookupPrivName failed");

	return true;
}

static bool test_RemovePrivilegesFromAccount(struct dcerpc_binding_handle *b,
					     struct torture_context *tctx,
					     struct policy_handle *handle,
					     struct policy_handle *acct_handle,
					     struct lsa_LUID *luid)
{
	struct lsa_RemovePrivilegesFromAccount r;
	struct lsa_PrivilegeSet privs;
	bool ret = true;

	torture_comment(tctx, "\nTesting RemovePrivilegesFromAccount\n");

	r.in.handle = acct_handle;
	r.in.remove_all = 0;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(tctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_RemovePrivilegesFromAccount_r(b, tctx, &r),
		"RemovePrivilegesFromAccount failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {

		struct lsa_LookupPrivName r_name;
		struct lsa_StringLarge *name = NULL;

		r_name.in.handle = handle;
		r_name.in.luid = luid;
		r_name.out.name = &name;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupPrivName_r(b, tctx, &r_name),
			"LookupPrivName failed");
		if (!NT_STATUS_IS_OK(r_name.out.result)) {
			torture_comment(tctx, "\nLookupPrivName failed - %s\n",
					nt_errstr(r_name.out.result));
			return false;
		}
		/* Windows 2008 does not allow this to be removed */
		if (strcmp("SeAuditPrivilege", name->string) == 0) {
			return ret;
		}

		torture_comment(tctx, "RemovePrivilegesFromAccount failed to remove %s - %s\n",
		       name->string,
		       nt_errstr(r.out.result));
		return false;
	}

	return ret;
}

static bool test_AddPrivilegesToAccount(struct dcerpc_binding_handle *b,
					struct torture_context *tctx,
					struct policy_handle *acct_handle,
					struct lsa_LUID *luid)
{
	struct lsa_AddPrivilegesToAccount r;
	struct lsa_PrivilegeSet privs;
	bool ret = true;

	torture_comment(tctx, "\nTesting AddPrivilegesToAccount\n");

	r.in.handle = acct_handle;
	r.in.privs = &privs;

	privs.count = 1;
	privs.unknown = 0;
	privs.set = talloc_array(tctx, struct lsa_LUIDAttribute, 1);
	privs.set[0].luid = *luid;
	privs.set[0].attribute = 0;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_AddPrivilegesToAccount_r(b, tctx, &r),
		"AddPrivilegesToAccount failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"AddPrivilegesToAccount failed");
	return ret;
}

static bool test_EnumPrivsAccount(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx,
				  struct policy_handle *handle,
				  struct policy_handle *acct_handle)
{
	struct lsa_EnumPrivsAccount r;
	struct lsa_PrivilegeSet *privs = NULL;
	bool ret = true;

	torture_comment(tctx, "\nTesting EnumPrivsAccount\n");

	r.in.handle = acct_handle;
	r.out.privs = &privs;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumPrivsAccount_r(b, tctx, &r),
		"EnumPrivsAccount failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"EnumPrivsAccount failed");

	if (privs && privs->count > 0) {
		int i;
		for (i=0;i<privs->count;i++) {
			test_LookupPrivName(b, tctx, handle,
					    &privs->set[i].luid);
		}

		ret &= test_RemovePrivilegesFromAccount(b, tctx, handle, acct_handle,
							&privs->set[0].luid);
		ret &= test_AddPrivilegesToAccount(b, tctx, acct_handle,
						   &privs->set[0].luid);
	}

	return ret;
}

static bool test_GetSystemAccessAccount(struct dcerpc_binding_handle *b,
					struct torture_context *tctx,
					struct policy_handle *handle,
					struct policy_handle *acct_handle)
{
	uint32_t access_mask;
	struct lsa_GetSystemAccessAccount r;

	torture_comment(tctx, "\nTesting GetSystemAccessAccount\n");

	r.in.handle = acct_handle;
	r.out.access_mask = &access_mask;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_GetSystemAccessAccount_r(b, tctx, &r),
		"GetSystemAccessAccount failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"GetSystemAccessAccount failed");

	if (r.out.access_mask != NULL) {
		torture_comment(tctx, "Rights:");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_INTERACTIVE)
			torture_comment(tctx, " LSA_POLICY_MODE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_NETWORK)
			torture_comment(tctx, " LSA_POLICY_MODE_NETWORK");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_BATCH)
			torture_comment(tctx, " LSA_POLICY_MODE_BATCH");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_SERVICE)
			torture_comment(tctx, " LSA_POLICY_MODE_SERVICE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_PROXY)
			torture_comment(tctx, " LSA_POLICY_MODE_PROXY");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_INTERACTIVE)
			torture_comment(tctx, " LSA_POLICY_MODE_DENY_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_NETWORK)
			torture_comment(tctx, " LSA_POLICY_MODE_DENY_NETWORK");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_BATCH)
			torture_comment(tctx, " LSA_POLICY_MODE_DENY_BATCH");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_SERVICE)
			torture_comment(tctx, " LSA_POLICY_MODE_DENY_SERVICE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_REMOTE_INTERACTIVE)
			torture_comment(tctx, " LSA_POLICY_MODE_REMOTE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE)
			torture_comment(tctx, " LSA_POLICY_MODE_DENY_REMOTE_INTERACTIVE");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_ALL)
			torture_comment(tctx, " LSA_POLICY_MODE_ALL");
		if (*(r.out.access_mask) & LSA_POLICY_MODE_ALL_NT4)
			torture_comment(tctx, " LSA_POLICY_MODE_ALL_NT4");
		torture_comment(tctx, "\n");
	}

	return true;
}

static bool test_Delete(struct dcerpc_binding_handle *b,
			struct torture_context *tctx,
			struct policy_handle *handle)
{
	struct lsa_Delete r;

	torture_comment(tctx, "\nTesting Delete\n");

	r.in.handle = handle;
	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_Delete_r(b, tctx, &r),
		"Delete failed");
	torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_NOT_SUPPORTED,
		"Delete should have failed NT_STATUS_NOT_SUPPORTED");

	return true;
}

static bool test_DeleteObject(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	struct lsa_DeleteObject r;

	torture_comment(tctx, "\nTesting DeleteObject\n");

	r.in.handle = handle;
	r.out.handle = handle;
	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_DeleteObject_r(b, tctx, &r),
		"DeleteObject failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"DeleteObject failed");

	return true;
}


static bool test_CreateAccount(struct dcerpc_binding_handle *b,
			       struct torture_context *tctx,
			       struct policy_handle *handle)
{
	struct lsa_CreateAccount r;
	struct dom_sid2 *newsid;
	struct policy_handle acct_handle;

	newsid = dom_sid_parse_talloc(tctx, "S-1-5-12349876-4321-2854");

	torture_comment(tctx, "\nTesting CreateAccount\n");

	r.in.handle = handle;
	r.in.sid = newsid;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CreateAccount_r(b, tctx, &r),
		"CreateAccount failed");
	if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_OBJECT_NAME_COLLISION)) {
		struct lsa_OpenAccount r_o;
		r_o.in.handle = handle;
		r_o.in.sid = newsid;
		r_o.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r_o.out.acct_handle = &acct_handle;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenAccount_r(b, tctx, &r_o),
			"OpenAccount failed");
		torture_assert_ntstatus_ok(tctx, r_o.out.result,
			"OpenAccount failed");
	} else {
		torture_assert_ntstatus_ok(tctx, r.out.result,
					   "CreateAccount failed");
	}

	if (!test_Delete(b, tctx, &acct_handle)) {
		return false;
	}

	if (!test_DeleteObject(b, tctx, &acct_handle)) {
		return false;
	}

	return true;
}

static bool test_DeleteTrustedDomain(struct dcerpc_binding_handle *b,
				     struct torture_context *tctx,
				     struct policy_handle *handle,
				     struct lsa_StringLarge name)
{
	struct lsa_OpenTrustedDomainByName r;
	struct policy_handle trustdom_handle;

	r.in.handle = handle;
	r.in.name.string = name.string;
	r.in.access_mask = SEC_STD_DELETE;
	r.out.trustdom_handle = &trustdom_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenTrustedDomainByName_r(b, tctx, &r),
		"OpenTrustedDomainByName failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"OpenTrustedDomainByName failed");

	if (!test_Delete(b, tctx, &trustdom_handle)) {
		return false;
	}

	if (!test_DeleteObject(b, tctx, &trustdom_handle)) {
		return false;
	}

	return true;
}

static bool test_DeleteTrustedDomainBySid(struct dcerpc_binding_handle *b,
					  struct torture_context *tctx,
					  struct policy_handle *handle,
					  struct dom_sid *sid)
{
	struct lsa_DeleteTrustedDomain r;

	r.in.handle = handle;
	r.in.dom_sid = sid;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_DeleteTrustedDomain_r(b, tctx, &r),
		"DeleteTrustedDomain failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"DeleteTrustedDomain failed");

	return true;
}


static bool test_CreateSecret(struct dcerpc_pipe *p,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
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
	DATA_BLOB blob1;
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
	struct dcerpc_binding_handle *b = p->binding_handle;

	secname[LOCAL] = talloc_asprintf(tctx, "torturesecret-%u", (unsigned int)random());
	secname[GLOBAL] = talloc_asprintf(tctx, "G$torturesecret-%u", (unsigned int)random());

	for (i=0; i< 2; i++) {
		torture_comment(tctx, "\nTesting CreateSecret of %s\n", secname[i]);

		init_lsa_String(&r.in.name, secname[i]);

		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CreateSecret_r(b, tctx, &r),
			"CreateSecret failed");
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"CreateSecret failed");

		r.in.handle = handle;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.sec_handle = &sec_handle3;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CreateSecret_r(b, tctx, &r),
			"CreateSecret failed");
		torture_assert_ntstatus_equal(tctx, r.out.result, NT_STATUS_OBJECT_NAME_COLLISION,
					      "CreateSecret should have failed OBJECT_NAME_COLLISION");

		r2.in.handle = handle;
		r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r2.in.name = r.in.name;
		r2.out.sec_handle = &sec_handle2;

		torture_comment(tctx, "Testing OpenSecret\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenSecret_r(b, tctx, &r2),
			"OpenSecret failed");
		torture_assert_ntstatus_ok(tctx, r2.out.result,
					   "OpenSecret failed");

		torture_assert_ntstatus_ok(tctx, dcerpc_fetch_session_key(p, &session_key),
					   "dcerpc_fetch_session_key failed");

		enc_key = sess_encrypt_string(secret1, &session_key);

		r3.in.sec_handle = &sec_handle;
		r3.in.new_val = &buf1;
		r3.in.old_val = NULL;
		r3.in.new_val->data = enc_key.data;
		r3.in.new_val->length = enc_key.length;
		r3.in.new_val->size = enc_key.length;

		torture_comment(tctx, "Testing SetSecret\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_SetSecret_r(b, tctx, &r3),
			"SetSecret failed");
		torture_assert_ntstatus_ok(tctx, r3.out.result,
			"SetSecret failed");

		r3.in.sec_handle = &sec_handle;
		r3.in.new_val = &buf1;
		r3.in.old_val = NULL;
		r3.in.new_val->data = enc_key.data;
		r3.in.new_val->length = enc_key.length;
		r3.in.new_val->size = enc_key.length;

		/* break the encrypted data */
		enc_key.data[0]++;

		torture_comment(tctx, "Testing SetSecret with broken key\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_SetSecret_r(b, tctx, &r3),
					   "SetSecret failed");
		torture_assert_ntstatus_equal(tctx, r3.out.result, NT_STATUS_UNKNOWN_REVISION,
					      "SetSecret should have failed UNKNOWN_REVISION");

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

		torture_comment(tctx, "Testing QuerySecret\n");
		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecret_r(b, tctx, &r4),
			"QuerySecret failed");
		if (!NT_STATUS_IS_OK(r4.out.result)) {
			torture_comment(tctx, "QuerySecret failed - %s\n", nt_errstr(r4.out.result));
			ret = false;
		} else {
			if (r4.out.new_val == NULL || r4.out.new_val->buf == NULL) {
				torture_comment(tctx, "No secret buffer returned\n");
				ret = false;
			} else {
				blob1.data = r4.out.new_val->buf->data;
				blob1.length = r4.out.new_val->buf->size;

				secret2 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret1, secret2) != 0) {
					torture_comment(tctx, "Returned secret (r4) '%s' doesn't match '%s'\n",
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


		smb_msleep(200);
		torture_comment(tctx, "Testing SetSecret (existing value should move to old)\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_SetSecret_r(b, tctx, &r5),
			"SetSecret failed");
		if (!NT_STATUS_IS_OK(r5.out.result)) {
			torture_comment(tctx, "SetSecret failed - %s\n", nt_errstr(r5.out.result));
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

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecret_r(b, tctx, &r6),
			"QuerySecret failed");
		if (!NT_STATUS_IS_OK(r6.out.result)) {
			torture_comment(tctx, "QuerySecret failed - %s\n", nt_errstr(r6.out.result));
			ret = false;
			secret4 = NULL;
		} else {

			if (r6.out.new_val->buf == NULL || r6.out.old_val->buf == NULL
				|| r6.out.new_mtime == NULL || r6.out.old_mtime == NULL) {
				torture_comment(tctx, "Both secret buffers and both times not returned\n");
				ret = false;
				secret4 = NULL;
			} else {
				blob1.data = r6.out.new_val->buf->data;
				blob1.length = r6.out.new_val->buf->size;

				secret4 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret3, secret4) != 0) {
					torture_comment(tctx, "Returned NEW secret %s doesn't match %s\n", secret4, secret3);
					ret = false;
				}

				blob1.data = r6.out.old_val->buf->data;
				blob1.length = r6.out.old_val->buf->length;

				secret2 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret1, secret2) != 0) {
					torture_comment(tctx, "Returned OLD secret %s doesn't match %s\n", secret2, secret1);
					ret = false;
				}

				if (*r6.out.new_mtime == *r6.out.old_mtime) {
					torture_comment(tctx, "Returned secret (r6-%d) %s must not have same mtime for both secrets: %s != %s\n",
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

		torture_comment(tctx, "Testing SetSecret of old Secret only\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_SetSecret_r(b, tctx, &r7),
			"SetSecret failed");
		if (!NT_STATUS_IS_OK(r7.out.result)) {
			torture_comment(tctx, "SetSecret failed - %s\n", nt_errstr(r7.out.result));
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

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecret_r(b, tctx, &r8),
			"QuerySecret failed");
		if (!NT_STATUS_IS_OK(r8.out.result)) {
			torture_comment(tctx, "QuerySecret failed - %s\n", nt_errstr(r8.out.result));
			ret = false;
		} else {
			if (!r8.out.new_val || !r8.out.old_val) {
				torture_comment(tctx, "in/out pointers not returned, despite being set on in for QuerySecret\n");
				ret = false;
			} else if (r8.out.new_val->buf != NULL) {
				torture_comment(tctx, "NEW secret buffer must not be returned after OLD set\n");
				ret = false;
			} else if (r8.out.old_val->buf == NULL) {
				torture_comment(tctx, "OLD secret buffer was not returned after OLD set\n");
				ret = false;
			} else if (r8.out.new_mtime == NULL || r8.out.old_mtime == NULL) {
				torture_comment(tctx, "Both times not returned after OLD set\n");
				ret = false;
			} else {
				blob1.data = r8.out.old_val->buf->data;
				blob1.length = r8.out.old_val->buf->size;

				secret6 = sess_decrypt_string(tctx,
							      &blob1, &session_key);

				if (strcmp(secret5, secret6) != 0) {
					torture_comment(tctx, "Returned OLD secret %s doesn't match %s\n", secret5, secret6);
					ret = false;
				}

				if (*r8.out.new_mtime != *r8.out.old_mtime) {
					torture_comment(tctx, "Returned secret (r8) %s did not had same mtime for both secrets: %s != %s\n",
					       secname[i],
					       nt_time_string(tctx, *r8.out.old_mtime),
					       nt_time_string(tctx, *r8.out.new_mtime));
					ret = false;
				}
			}
		}

		if (!test_Delete(b, tctx, &sec_handle)) {
			ret = false;
		}

		if (!test_DeleteObject(b, tctx, &sec_handle)) {
			return false;
		}

		d_o.in.handle = &sec_handle2;
		d_o.out.handle = &sec_handle2;
		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_DeleteObject_r(b, tctx, &d_o),
			"DeleteObject failed");
		torture_assert_ntstatus_equal(tctx, d_o.out.result, NT_STATUS_INVALID_HANDLE,
					      "OpenSecret expected INVALID_HANDLE");

		torture_comment(tctx, "Testing OpenSecret of just-deleted secret\n");

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenSecret_r(b, tctx, &r2),
					   "OpenSecret failed");
		torture_assert_ntstatus_equal(tctx, r2.out.result, NT_STATUS_OBJECT_NAME_NOT_FOUND,
					      "OpenSecret expected OBJECT_NAME_NOT_FOUND");
	}
	return ret;
}


static bool test_EnumAccountRights(struct dcerpc_binding_handle *b,
				   struct torture_context *tctx,
				   struct policy_handle *acct_handle,
				   struct dom_sid *sid)
{
	struct lsa_EnumAccountRights r;
	struct lsa_RightSet rights;

	torture_comment(tctx, "\nTesting EnumAccountRights\n");

	r.in.handle = acct_handle;
	r.in.sid = sid;
	r.out.rights = &rights;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumAccountRights_r(b, tctx, &r),
		"EnumAccountRights failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "EnumAccountRights of %s failed - %s\n",
		       dom_sid_string(tctx, sid), nt_errstr(r.out.result));
	}
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"EnumAccountRights failed");

	return true;
}


static bool test_QuerySecurity(struct dcerpc_binding_handle *b,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     struct policy_handle *acct_handle)
{
	struct lsa_QuerySecurity r;
	struct sec_desc_buf *sdbuf = NULL;

	if (torture_setting_bool(tctx, "samba4", false)) {
		torture_comment(tctx, "\nskipping QuerySecurity test against Samba4\n");
		return true;
	}

	torture_comment(tctx, "\nTesting QuerySecurity\n");

	r.in.handle = acct_handle;
	r.in.sec_info = SECINFO_OWNER |
			SECINFO_GROUP |
			SECINFO_DACL;
	r.out.sdbuf = &sdbuf;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QuerySecurity_r(b, tctx, &r),
		"QuerySecurity failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "QuerySecurity failed - %s\n", nt_errstr(r.out.result));
		return false;
	}

	return true;
}

static bool test_OpenAccount(struct dcerpc_binding_handle *b,
			     struct torture_context *tctx,
			     struct policy_handle *handle,
			     struct dom_sid *sid)
{
	struct lsa_OpenAccount r;
	struct policy_handle acct_handle;

	torture_comment(tctx, "\nTesting OpenAccount\n");

	r.in.handle = handle;
	r.in.sid = sid;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.acct_handle = &acct_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenAccount_r(b, tctx, &r),
		"OpenAccount failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"OpenAccount failed");

	if (!test_EnumPrivsAccount(b, tctx, handle, &acct_handle)) {
		return false;
	}

	if (!test_GetSystemAccessAccount(b, tctx, handle, &acct_handle)) {
		return false;
	}

	if (!test_QuerySecurity(b, tctx, handle, &acct_handle)) {
		return false;
	}

	return true;
}

static bool test_EnumAccounts(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	struct lsa_EnumAccounts r;
	struct lsa_SidArray sids1, sids2;
	uint32_t resume_handle = 0;
	int i;
	bool ret = true;

	torture_comment(tctx, "\nTesting EnumAccounts\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.num_entries = 100;
	r.out.resume_handle = &resume_handle;
	r.out.sids = &sids1;

	resume_handle = 0;
	while (true) {
		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumAccounts_r(b, tctx, &r),
			"EnumAccounts failed");
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES)) {
			break;
		}
		torture_assert_ntstatus_ok(tctx, r.out.result,
			"EnumAccounts failed");

		if (!test_LookupSids(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &sids1)) {
			return false;
		}

		if (!test_LookupSids2(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &sids1)) {
			return false;
		}

		/* Can't test lookupSids3 here, as clearly we must not
		 * be on schannel, or we would not be able to do the
		 * rest */

		torture_comment(tctx, "Testing all accounts\n");
		for (i=0;i<sids1.num_sids;i++) {
			ret &= test_OpenAccount(b, tctx, handle, sids1.sids[i].sid);
			ret &= test_EnumAccountRights(b, tctx, handle, sids1.sids[i].sid);
		}
		torture_comment(tctx, "\n");
	}

	if (sids1.num_sids < 3) {
		return ret;
	}

	torture_comment(tctx, "Trying EnumAccounts partial listing (asking for 1 at 2)\n");
	resume_handle = 2;
	r.in.num_entries = 1;
	r.out.sids = &sids2;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumAccounts_r(b, tctx, &r),
		"EnumAccounts failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"EnumAccounts failed");

	if (sids2.num_sids != 1) {
		torture_comment(tctx, "Returned wrong number of entries (%d)\n", sids2.num_sids);
		return false;
	}

	return true;
}

static bool test_LookupPrivDisplayName(struct dcerpc_binding_handle *b,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       struct lsa_String *priv_name)
{
	struct lsa_LookupPrivDisplayName r;
	/* produce a reasonable range of language output without screwing up
	   terminals */
	uint16_t language_id = (random() % 4) + 0x409;
	uint16_t returned_language_id = 0;
	struct lsa_StringLarge *disp_name = NULL;

	torture_comment(tctx, "\nTesting LookupPrivDisplayName(%s)\n", priv_name->string);

	r.in.handle = handle;
	r.in.name = priv_name;
	r.in.language_id = language_id;
	r.in.language_id_sys = 0;
	r.out.returned_language_id = &returned_language_id;
	r.out.disp_name = &disp_name;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_LookupPrivDisplayName_r(b, tctx, &r),
		"LookupPrivDisplayName failed");
	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "LookupPrivDisplayName failed - %s\n", nt_errstr(r.out.result));
		return false;
	}
	torture_comment(tctx, "%s -> \"%s\"  (language 0x%x/0x%x)\n",
	       priv_name->string, disp_name->string,
	       r.in.language_id, *r.out.returned_language_id);

	return true;
}

static bool test_EnumAccountsWithUserRight(struct dcerpc_binding_handle *b,
					   struct torture_context *tctx,
					   struct policy_handle *handle,
					   struct lsa_String *priv_name)
{
	struct lsa_EnumAccountsWithUserRight r;
	struct lsa_SidArray sids;

	ZERO_STRUCT(sids);

	torture_comment(tctx, "\nTesting EnumAccountsWithUserRight(%s)\n", priv_name->string);

	r.in.handle = handle;
	r.in.name = priv_name;
	r.out.sids = &sids;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumAccountsWithUserRight_r(b, tctx, &r),
		"EnumAccountsWithUserRight failed");

	/* NT_STATUS_NO_MORE_ENTRIES means no one has this privilege */
	if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES)) {
		return true;
	}

	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "EnumAccountsWithUserRight failed - %s\n", nt_errstr(r.out.result));
		return false;
	}

	return true;
}


static bool test_EnumPrivs(struct dcerpc_binding_handle *b,
			   struct torture_context *tctx,
			   struct policy_handle *handle)
{
	struct lsa_EnumPrivs r;
	struct lsa_PrivArray privs1;
	uint32_t resume_handle = 0;
	int i;
	bool ret = true;

	torture_comment(tctx, "\nTesting EnumPrivs\n");

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_count = 100;
	r.out.resume_handle = &resume_handle;
	r.out.privs = &privs1;

	resume_handle = 0;
	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumPrivs_r(b, tctx, &r),
		"EnumPrivs failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"EnumPrivs failed");

	for (i = 0; i< privs1.count; i++) {
		test_LookupPrivDisplayName(b, tctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		test_LookupPrivValue(b, tctx, handle, (struct lsa_String *)&privs1.privs[i].name);
		if (!test_EnumAccountsWithUserRight(b, tctx, handle, (struct lsa_String *)&privs1.privs[i].name)) {
			ret = false;
		}
	}

	return ret;
}

static bool test_QueryForestTrustInformation(struct dcerpc_binding_handle *b,
					     struct torture_context *tctx,
					     struct policy_handle *handle,
					     const char *trusted_domain_name)
{
	bool ret = true;
	struct lsa_lsaRQueryForestTrustInformation r;
	struct lsa_String string;
	struct lsa_ForestTrustInformation info, *info_ptr;

	torture_comment(tctx, "\nTesting lsaRQueryForestTrustInformation\n");

	if (torture_setting_bool(tctx, "samba4", false)) {
		torture_comment(tctx, "skipping QueryForestTrustInformation against Samba4\n");
		return true;
	}

	ZERO_STRUCT(string);

	if (trusted_domain_name) {
		init_lsa_String(&string, trusted_domain_name);
	}

	info_ptr = &info;

	r.in.handle = handle;
	r.in.trusted_domain_name = &string;
	r.in.highest_record_type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
	r.out.forest_trust_info = &info_ptr;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_lsaRQueryForestTrustInformation_r(b, tctx, &r),
		"lsaRQueryForestTrustInformation failed");

	if (!NT_STATUS_IS_OK(r.out.result)) {
		torture_comment(tctx, "lsaRQueryForestTrustInformation of %s failed - %s\n", trusted_domain_name, nt_errstr(r.out.result));
		ret = false;
	}

	return ret;
}

static bool test_query_each_TrustDomEx(struct dcerpc_binding_handle *b,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       struct lsa_DomainListEx *domains)
{
	int i;
	bool ret = true;

	for (i=0; i< domains->count; i++) {

		if (domains->domains[i].trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			ret &= test_QueryForestTrustInformation(b, tctx, handle,
								domains->domains[i].domain_name.string);
		}
	}

	return ret;
}

static bool test_query_each_TrustDom(struct dcerpc_binding_handle *b,
				     struct torture_context *tctx,
				     struct policy_handle *handle,
				     struct lsa_DomainList *domains)
{
	int i,j;
	bool ret = true;

	torture_comment(tctx, "\nTesting OpenTrustedDomain, OpenTrustedDomainByName and QueryInfoTrustedDomain\n");
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

			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenTrustedDomain_r(b, tctx, &trust),
				"OpenTrustedDomain failed");

			if (NT_STATUS_EQUAL(trust.out.result, NT_STATUS_NO_SUCH_DOMAIN)) {
				torture_comment(tctx, "DOMAIN(%s, %s) not a direct trust?\n",
						domains->domains[i].name.string,
						dom_sid_string(tctx, domains->domains[i].sid));
				continue;
			}
			if (!NT_STATUS_IS_OK(trust.out.result)) {
				torture_comment(tctx, "OpenTrustedDomain failed - %s\n", nt_errstr(trust.out.result));
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
				torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfo_r(b, tctx, &q),
					"QueryTrustedDomainInfo failed");
				if (!NT_STATUS_IS_OK(q.out.result) && ok[j]) {
					torture_comment(tctx, "QueryTrustedDomainInfo level %d failed - %s\n",
					       levels[j], nt_errstr(q.out.result));
					ret = false;
				} else if (NT_STATUS_IS_OK(q.out.result) && !ok[j]) {
					torture_comment(tctx, "QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n",
					       levels[j], nt_errstr(q.out.result));
					ret = false;
				}
			}

			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CloseTrustedDomainEx_r(b, tctx, &c_trust),
				"CloseTrustedDomainEx failed");
			if (!NT_STATUS_EQUAL(c_trust.out.result, NT_STATUS_NOT_IMPLEMENTED)) {
				torture_comment(tctx, "Expected CloseTrustedDomainEx to return NT_STATUS_NOT_IMPLEMENTED, instead - %s\n", nt_errstr(c_trust.out.result));
				return false;
			}

			c.in.handle = &trustdom_handle;
			c.out.handle = &handle2;

			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_Close_r(b, tctx, &c),
				"Close failed");
			if (!NT_STATUS_IS_OK(c.out.result)) {
				torture_comment(tctx, "Close of trusted domain failed - %s\n", nt_errstr(c.out.result));
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

				torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfoBySid_r(b, tctx, &q),
					"lsa_QueryTrustedDomainInfoBySid failed");
				if (!NT_STATUS_IS_OK(q.out.result) && ok[j]) {
					torture_comment(tctx, "QueryTrustedDomainInfoBySid level %d failed - %s\n",
					       levels[j], nt_errstr(q.out.result));
					ret = false;
				} else if (NT_STATUS_IS_OK(q.out.result) && !ok[j]) {
					torture_comment(tctx, "QueryTrustedDomainInfoBySid level %d unexpectedly succeeded - %s\n",
					       levels[j], nt_errstr(q.out.result));
					ret = false;
				}
			}
		}

		trust_by_name.in.handle = handle;
		trust_by_name.in.name.string = domains->domains[i].name.string;
		trust_by_name.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		trust_by_name.out.trustdom_handle = &trustdom_handle;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_OpenTrustedDomainByName_r(b, tctx, &trust_by_name),
			"OpenTrustedDomainByName failed");

		if (NT_STATUS_EQUAL(trust_by_name.out.result, NT_STATUS_NO_SUCH_DOMAIN)) {
			torture_comment(tctx, "DOMAIN(%s, %s) not a direct trust?\n",
					domains->domains[i].name.string,
					dom_sid_string(tctx, domains->domains[i].sid));
			continue;
		}
		if (!NT_STATUS_IS_OK(trust_by_name.out.result)) {
			torture_comment(tctx, "OpenTrustedDomainByName failed - %s\n", nt_errstr(trust_by_name.out.result));
			return false;
		}

		for (j=0; j < ARRAY_SIZE(levels); j++) {
			struct lsa_QueryTrustedDomainInfo q;
			union lsa_TrustedDomainInfo *info = NULL;
			q.in.trustdom_handle = &trustdom_handle;
			q.in.level = levels[j];
			q.out.info = &info;
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfo_r(b, tctx, &q),
				"QueryTrustedDomainInfo failed");
			if (!NT_STATUS_IS_OK(q.out.result) && ok[j]) {
				torture_comment(tctx, "QueryTrustedDomainInfo level %d failed - %s\n",
				       levels[j], nt_errstr(q.out.result));
				ret = false;
			} else if (NT_STATUS_IS_OK(q.out.result) && !ok[j]) {
				torture_comment(tctx, "QueryTrustedDomainInfo level %d unexpectedly succeeded - %s\n",
				       levels[j], nt_errstr(q.out.result));
				ret = false;
			}
		}

		c.in.handle = &trustdom_handle;
		c.out.handle = &handle2;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_Close_r(b, tctx, &c),
			"Close failed");
		if (!NT_STATUS_IS_OK(c.out.result)) {
			torture_comment(tctx, "Close of trusted domain failed - %s\n", nt_errstr(c.out.result));
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
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfoByName_r(b, tctx, &q),
				"QueryTrustedDomainInfoByName failed");
			if (!NT_STATUS_IS_OK(q.out.result) && ok[j]) {
				torture_comment(tctx, "QueryTrustedDomainInfoByName level %d failed - %s\n",
				       levels[j], nt_errstr(q.out.result));
				ret = false;
			} else if (NT_STATUS_IS_OK(q.out.result) && !ok[j]) {
				torture_comment(tctx, "QueryTrustedDomainInfoByName level %d unexpectedly succeeded - %s\n",
				       levels[j], nt_errstr(q.out.result));
				ret = false;
			}
		}
	}
	return ret;
}

static bool test_EnumTrustDom(struct dcerpc_binding_handle *b,
			      struct torture_context *tctx,
			      struct policy_handle *handle)
{
	struct lsa_EnumTrustDom r;
	uint32_t in_resume_handle = 0;
	uint32_t out_resume_handle;
	struct lsa_DomainList domains;
	bool ret = true;

	torture_comment(tctx, "\nTesting EnumTrustDom\n");

	r.in.handle = handle;
	r.in.resume_handle = &in_resume_handle;
	r.in.max_size = 0;
	r.out.domains = &domains;
	r.out.resume_handle = &out_resume_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumTrustDom_r(b, tctx, &r),
		"lsa_EnumTrustDom failed");

	/* according to MS-LSAD 3.1.4.7.8 output resume handle MUST
	 * always be larger than the previous input resume handle, in
	 * particular when hitting the last query it is vital to set the
	 * resume handle correctly to avoid infinite client loops, as
	 * seen e.g.  with Windows XP SP3 when resume handle is 0 and
	 * status is NT_STATUS_OK - gd */

	if (NT_STATUS_IS_OK(r.out.result) ||
	    NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES) ||
	    NT_STATUS_EQUAL(r.out.result, STATUS_MORE_ENTRIES))
	{
		if (out_resume_handle <= in_resume_handle) {
			torture_comment(tctx, "EnumTrustDom failed - should have returned output resume_handle (0x%08x) larger than input resume handle (0x%08x)\n",
				out_resume_handle, in_resume_handle);
			return false;
		}
	}

	if (NT_STATUS_IS_OK(r.out.result)) {
		if (domains.count == 0) {
			torture_comment(tctx, "EnumTrustDom failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}
	} else if (!(NT_STATUS_EQUAL(r.out.result, STATUS_MORE_ENTRIES) || NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES))) {
		torture_comment(tctx, "EnumTrustDom of zero size failed - %s\n", nt_errstr(r.out.result));
		return false;
	}

	/* Start from the bottom again */
	in_resume_handle = 0;

	do {
		r.in.handle = handle;
		r.in.resume_handle = &in_resume_handle;
		r.in.max_size = LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3;
		r.out.domains = &domains;
		r.out.resume_handle = &out_resume_handle;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumTrustDom_r(b, tctx, &r),
			"EnumTrustDom failed");

		/* according to MS-LSAD 3.1.4.7.8 output resume handle MUST
		 * always be larger than the previous input resume handle, in
		 * particular when hitting the last query it is vital to set the
		 * resume handle correctly to avoid infinite client loops, as
		 * seen e.g.  with Windows XP SP3 when resume handle is 0 and
		 * status is NT_STATUS_OK - gd */

		if (NT_STATUS_IS_OK(r.out.result) ||
		    NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES) ||
		    NT_STATUS_EQUAL(r.out.result, STATUS_MORE_ENTRIES))
		{
			if (out_resume_handle <= in_resume_handle) {
				torture_comment(tctx, "EnumTrustDom failed - should have returned output resume_handle (0x%08x) larger than input resume handle (0x%08x)\n",
					out_resume_handle, in_resume_handle);
				return false;
			}
		}

		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_NO_MORE_ENTRIES)) {
			if (domains.count == 0) {
				return true;
			}
			torture_comment(tctx, "EnumTrustDom failed - should have returned 0 trusted domains with 'NT_STATUS_NO_MORE_ENTRIES'\n");
			return false;
		} else if (NT_STATUS_EQUAL(r.out.result, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r.out.domains->count < 3 || r.out.domains->count > 4) {
				torture_comment(tctx, "EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r.out.domains->count, LSA_ENUM_TRUST_DOMAIN_MULTIPLIER * 3,
				       LSA_ENUM_TRUST_DOMAIN_MULTIPLIER, r.in.max_size);
				ret = false;
			}
		} else if (!NT_STATUS_IS_OK(r.out.result)) {
			torture_comment(tctx, "EnumTrustDom failed - %s\n", nt_errstr(r.out.result));
			return false;
		}

		if (domains.count == 0) {
			torture_comment(tctx, "EnumTrustDom failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}

		ret &= test_query_each_TrustDom(b, tctx, handle, &domains);

		in_resume_handle = out_resume_handle;

	} while (NT_STATUS_EQUAL(r.out.result, STATUS_MORE_ENTRIES));

	return ret;
}

static bool test_EnumTrustDomEx(struct dcerpc_binding_handle *b,
				struct torture_context *tctx,
				struct policy_handle *handle)
{
	struct lsa_EnumTrustedDomainsEx r_ex;
	uint32_t in_resume_handle = 0;
	uint32_t out_resume_handle;
	struct lsa_DomainListEx domains_ex;
	bool ret = true;

	torture_comment(tctx, "\nTesting EnumTrustedDomainsEx\n");

	r_ex.in.handle = handle;
	r_ex.in.resume_handle = &in_resume_handle;
	r_ex.in.max_size = 0;
	r_ex.out.domains = &domains_ex;
	r_ex.out.resume_handle = &out_resume_handle;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumTrustedDomainsEx_r(b, tctx, &r_ex),
		"EnumTrustedDomainsEx failed");

	/* according to MS-LSAD 3.1.4.7.8 output resume handle MUST
	 * always be larger than the previous input resume handle, in
	 * particular when hitting the last query it is vital to set the
	 * resume handle correctly to avoid infinite client loops, as
	 * seen e.g.  with Windows XP SP3 when resume handle is 0 and
	 * status is NT_STATUS_OK - gd */

	if (NT_STATUS_IS_OK(r_ex.out.result) ||
	    NT_STATUS_EQUAL(r_ex.out.result, NT_STATUS_NO_MORE_ENTRIES) ||
	    NT_STATUS_EQUAL(r_ex.out.result, STATUS_MORE_ENTRIES))
	{
		if (out_resume_handle <= in_resume_handle) {
			torture_comment(tctx, "EnumTrustDomEx failed - should have returned output resume_handle (0x%08x) larger than input resume handle (0x%08x)\n",
				out_resume_handle, in_resume_handle);
			return false;
		}
	}

	if (NT_STATUS_IS_OK(r_ex.out.result)) {
		if (domains_ex.count == 0) {
			torture_comment(tctx, "EnumTrustDom failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}
	} else if (!(NT_STATUS_EQUAL(r_ex.out.result, STATUS_MORE_ENTRIES) ||
		    NT_STATUS_EQUAL(r_ex.out.result, NT_STATUS_NO_MORE_ENTRIES))) {
		torture_comment(tctx, "EnumTrustDom of zero size failed - %s\n",
				nt_errstr(r_ex.out.result));
		return false;
	}

	in_resume_handle = 0;
	do {
		r_ex.in.handle = handle;
		r_ex.in.resume_handle = &in_resume_handle;
		r_ex.in.max_size = LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER * 3;
		r_ex.out.domains = &domains_ex;
		r_ex.out.resume_handle = &out_resume_handle;

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_EnumTrustedDomainsEx_r(b, tctx, &r_ex),
			"EnumTrustedDomainsEx failed");

		in_resume_handle = out_resume_handle;

		/* NO_MORE_ENTRIES is allowed */
		if (NT_STATUS_EQUAL(r_ex.out.result, NT_STATUS_NO_MORE_ENTRIES)) {
			if (domains_ex.count == 0) {
				return true;
			}
			torture_comment(tctx, "EnumTrustDomainsEx failed - should have returned 0 trusted domains with 'NT_STATUS_NO_MORE_ENTRIES'\n");
			return false;
		} else if (NT_STATUS_EQUAL(r_ex.out.result, STATUS_MORE_ENTRIES)) {
			/* Windows 2003 gets this off by one on the first run */
			if (r_ex.out.domains->count < 3 || r_ex.out.domains->count > 4) {
				torture_comment(tctx, "EnumTrustDom didn't fill the buffer we "
				       "asked it to (got %d, expected %d / %d == %d entries)\n",
				       r_ex.out.domains->count,
				       r_ex.in.max_size,
				       LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER,
				       r_ex.in.max_size / LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER);
			}
		} else if (!NT_STATUS_IS_OK(r_ex.out.result)) {
			torture_comment(tctx, "EnumTrustedDomainEx failed - %s\n", nt_errstr(r_ex.out.result));
			return false;
		}

		if (domains_ex.count == 0) {
			torture_comment(tctx, "EnumTrustDomainEx failed - should have returned 'NT_STATUS_NO_MORE_ENTRIES' for 0 trusted domains\n");
			return false;
		}

		ret &= test_query_each_TrustDomEx(b, tctx, handle, &domains_ex);

	} while (NT_STATUS_EQUAL(r_ex.out.result, STATUS_MORE_ENTRIES));

	return ret;
}


static bool test_CreateTrustedDomain(struct dcerpc_binding_handle *b,
				     struct torture_context *tctx,
				     struct policy_handle *handle,
				     uint32_t num_trusts)
{
	bool ret = true;
	struct lsa_CreateTrustedDomain r;
	struct lsa_DomainInfo trustinfo;
	struct dom_sid **domsid;
	struct policy_handle *trustdom_handle;
	struct lsa_QueryTrustedDomainInfo q;
	union lsa_TrustedDomainInfo *info = NULL;
	int i;

	torture_comment(tctx, "\nTesting CreateTrustedDomain for %d domains\n", num_trusts);

	if (!test_EnumTrustDom(b, tctx, handle)) {
		ret = false;
	}

	if (!test_EnumTrustDomEx(b, tctx, handle)) {
		ret = false;
	}

	domsid = talloc_array(tctx, struct dom_sid *, num_trusts);
	trustdom_handle = talloc_array(tctx, struct policy_handle, num_trusts);

	for (i=0; i< num_trusts; i++) {
		char *trust_name = talloc_asprintf(tctx, "TORTURE1%02d", i);
		char *trust_sid = talloc_asprintf(tctx, "S-1-5-21-97398-379795-1%02d", i);

		domsid[i] = dom_sid_parse_talloc(tctx, trust_sid);

		trustinfo.sid = domsid[i];
		init_lsa_String((struct lsa_String *)&trustinfo.name, trust_name);

		r.in.policy_handle = handle;
		r.in.info = &trustinfo;
		r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		r.out.trustdom_handle = &trustdom_handle[i];

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CreateTrustedDomain_r(b, tctx, &r),
			"CreateTrustedDomain failed");
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_OBJECT_NAME_COLLISION)) {
			test_DeleteTrustedDomain(b, tctx, handle, trustinfo.name);
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_CreateTrustedDomain_r(b, tctx, &r),
				"CreateTrustedDomain failed");
		}
		if (!NT_STATUS_IS_OK(r.out.result)) {
			torture_comment(tctx, "CreateTrustedDomain failed - %s\n", nt_errstr(r.out.result));
			ret = false;
		} else {

			q.in.trustdom_handle = &trustdom_handle[i];
			q.in.level = LSA_TRUSTED_DOMAIN_INFO_INFO_EX;
			q.out.info = &info;
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfo_r(b, tctx, &q),
				"QueryTrustedDomainInfo failed");
			if (!NT_STATUS_IS_OK(q.out.result)) {
				torture_comment(tctx, "QueryTrustedDomainInfo level %d failed - %s\n", q.in.level, nt_errstr(q.out.result));
				ret = false;
			} else if (!q.out.info) {
				ret = false;
			} else {
				if (strcmp(info->info_ex.domain_name.string, trustinfo.name.string) != 0) {
					torture_comment(tctx, "QueryTrustedDomainInfo returned inconsistent long name: %s != %s\n",
					       info->info_ex.domain_name.string, trustinfo.name.string);
					ret = false;
				}
				if (strcmp(info->info_ex.netbios_name.string, trustinfo.name.string) != 0) {
					torture_comment(tctx, "QueryTrustedDomainInfo returned inconsistent short name: %s != %s\n",
					       info->info_ex.netbios_name.string, trustinfo.name.string);
					ret = false;
				}
				if (info->info_ex.trust_type != LSA_TRUST_TYPE_DOWNLEVEL) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust type %d != %d\n",
					       trust_name, info->info_ex.trust_type, LSA_TRUST_TYPE_DOWNLEVEL);
					ret = false;
				}
				if (info->info_ex.trust_attributes != 0) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust attributes %d != %d\n",
					       trust_name, info->info_ex.trust_attributes, 0);
					ret = false;
				}
				if (info->info_ex.trust_direction != LSA_TRUST_DIRECTION_OUTBOUND) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust direction %d != %d\n",
					       trust_name, info->info_ex.trust_direction, LSA_TRUST_DIRECTION_OUTBOUND);
					ret = false;
				}
			}
		}
	}

	/* now that we have some domains to look over, we can test the enum calls */
	if (!test_EnumTrustDom(b, tctx, handle)) {
		ret = false;
	}

	if (!test_EnumTrustDomEx(b, tctx, handle)) {
		ret = false;
	}

	for (i=0; i<num_trusts; i++) {
		if (!test_DeleteTrustedDomainBySid(b, tctx, handle, domsid[i])) {
			ret = false;
		}
	}

	return ret;
}

static bool gen_authinfo_internal(TALLOC_CTX *mem_ctx,
				  const char *incoming_old, const char *incoming_new,
				  const char *outgoing_old, const char *outgoing_new,
				  DATA_BLOB session_key,
				  struct lsa_TrustDomainInfoAuthInfoInternal **_authinfo_internal)
{
	struct lsa_TrustDomainInfoAuthInfoInternal *authinfo_internal;
	struct trustDomainPasswords auth_struct;
	struct AuthenticationInformation in_info;
	struct AuthenticationInformation io_info;
	struct AuthenticationInformation on_info;
	struct AuthenticationInformation oo_info;
	size_t converted_size;
	DATA_BLOB auth_blob;
	enum ndr_err_code ndr_err;
	bool ok;
	gnutls_cipher_hd_t cipher_hnd = NULL;
	gnutls_datum_t _session_key;

	authinfo_internal = talloc_zero(mem_ctx, struct lsa_TrustDomainInfoAuthInfoInternal);
	if (authinfo_internal == NULL) {
		return false;
	}

	in_info.AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16,
				   incoming_new,
				   strlen(incoming_new),
				   &in_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_info.AuthInfo.clear.size = converted_size;

	io_info.AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16,
				   incoming_old,
				   strlen(incoming_old),
				   &io_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	io_info.AuthInfo.clear.size = converted_size;

	on_info.AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16,
				   outgoing_new,
				   strlen(outgoing_new),
				   &on_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	on_info.AuthInfo.clear.size = converted_size;

	oo_info.AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16,
				   outgoing_old,
				   strlen(outgoing_old),
				   &oo_info.AuthInfo.clear.password,
				   &converted_size);
	if (!ok) {
		return false;
	}
	oo_info.AuthInfo.clear.size = converted_size;

	generate_random_buffer(auth_struct.confounder, sizeof(auth_struct.confounder));
	auth_struct.outgoing.count = 1;
	auth_struct.outgoing.current.count = 1;
	auth_struct.outgoing.current.array = &on_info;
	auth_struct.outgoing.previous.count = 1;
	auth_struct.outgoing.previous.array = &oo_info;

	auth_struct.incoming.count = 1;
	auth_struct.incoming.current.count = 1;
	auth_struct.incoming.current.array = &in_info;
	auth_struct.incoming.previous.count = 1;
	auth_struct.incoming.previous.array = &io_info;

	ndr_err = ndr_push_struct_blob(&auth_blob, mem_ctx, &auth_struct,
				       (ndr_push_flags_fn_t)ndr_push_trustDomainPasswords);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return false;
	}

	_session_key = (gnutls_datum_t) {
		.data = session_key.data,
		.size = session_key.length,
	};

	gnutls_cipher_init(&cipher_hnd,
			   GNUTLS_CIPHER_ARCFOUR_128,
			   &_session_key,
			   NULL);
	gnutls_cipher_encrypt(cipher_hnd,
			      auth_blob.data,
			      auth_blob.length);
	gnutls_cipher_deinit(cipher_hnd);

	authinfo_internal->auth_blob.size = auth_blob.length;
	authinfo_internal->auth_blob.data = auth_blob.data;

	*_authinfo_internal = authinfo_internal;

	return true;
}

static bool gen_authinfo(TALLOC_CTX *mem_ctx,
			 const char *incoming_old, const char *incoming_new,
			 const char *outgoing_old, const char *outgoing_new,
			 struct lsa_TrustDomainInfoAuthInfo **_authinfo)
{
	struct lsa_TrustDomainInfoAuthInfo *authinfo;
	struct lsa_TrustDomainInfoBuffer *in_buffer;
	struct lsa_TrustDomainInfoBuffer *io_buffer;
	struct lsa_TrustDomainInfoBuffer *on_buffer;
	struct lsa_TrustDomainInfoBuffer *oo_buffer;
	size_t converted_size;
	bool ok;

	authinfo = talloc_zero(mem_ctx, struct lsa_TrustDomainInfoAuthInfo);
	if (authinfo == NULL) {
		return false;
	}

	in_buffer = talloc_zero(authinfo, struct lsa_TrustDomainInfoBuffer);
	if (in_buffer == NULL) {
		return false;
	}
	in_buffer->AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(in_buffer, CH_UNIX, CH_UTF16,
				   incoming_new,
				   strlen(incoming_new),
				   &in_buffer->data.data,
				   &converted_size);
	if (!ok) {
		return false;
	}
	in_buffer->data.size = converted_size;

	io_buffer = talloc_zero(authinfo, struct lsa_TrustDomainInfoBuffer);
	if (io_buffer == NULL) {
		return false;
	}
	io_buffer->AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(io_buffer, CH_UNIX, CH_UTF16,
				   incoming_old,
				   strlen(incoming_old),
				   &io_buffer->data.data,
				   &converted_size);
	if (!ok) {
		return false;
	}
	io_buffer->data.size = converted_size;

	on_buffer = talloc_zero(authinfo, struct lsa_TrustDomainInfoBuffer);
	if (on_buffer == NULL) {
		return false;
	}
	on_buffer->AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(on_buffer, CH_UNIX, CH_UTF16,
				   outgoing_new,
				   strlen(outgoing_new),
				   &on_buffer->data.data,
				   &converted_size);
	if (!ok) {
		return false;
	}
	on_buffer->data.size = converted_size;

	oo_buffer = talloc_zero(authinfo, struct lsa_TrustDomainInfoBuffer);
	if (oo_buffer == NULL) {
		return false;
	}
	oo_buffer->AuthType = TRUST_AUTH_TYPE_CLEAR;
	ok = convert_string_talloc(oo_buffer, CH_UNIX, CH_UTF16,
				   outgoing_old,
				   strlen(outgoing_old),
				   &oo_buffer->data.data,
				   &converted_size);
	if (!ok) {
		return false;
	}
	oo_buffer->data.size = converted_size;

	authinfo->incoming_count = 1;
	authinfo->incoming_current_auth_info = in_buffer;
	authinfo->incoming_previous_auth_info = io_buffer;
	authinfo->outgoing_count = 1;
	authinfo->outgoing_current_auth_info = on_buffer;
	authinfo->outgoing_previous_auth_info = oo_buffer;

	*_authinfo = authinfo;

	return true;
}

static bool check_pw_with_ServerAuthenticate3(struct dcerpc_pipe *p,
					     struct torture_context *tctx,
					     uint32_t negotiate_flags,
					     const char *server_name,
					     struct cli_credentials *machine_credentials,
					     struct netlogon_creds_CredentialState **creds_out)
{
	struct netr_ServerReqChallenge r;
	struct netr_ServerAuthenticate3 a;
	struct netr_Credential credentials1, credentials2, credentials3;
	struct netlogon_creds_CredentialState *creds;
	const struct samr_Password *new_password = NULL;
	const struct samr_Password *old_password = NULL;
	uint32_t rid;
	struct dcerpc_binding_handle *b = p->binding_handle;

	new_password = cli_credentials_get_nt_hash(machine_credentials, tctx);
	old_password = cli_credentials_get_old_nt_hash(machine_credentials, tctx);

	r.in.server_name = server_name;
	r.in.computer_name = cli_credentials_get_workstation(machine_credentials);
	r.in.credentials = &credentials1;
	r.out.return_credentials = &credentials2;

	netlogon_creds_random_challenge(&credentials1);

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerReqChallenge_r(b, tctx, &r),
		"ServerReqChallenge failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "ServerReqChallenge failed");

	a.in.server_name = server_name;
	a.in.account_name = cli_credentials_get_username(machine_credentials);
	a.in.secure_channel_type = cli_credentials_get_secure_channel_type(machine_credentials);
	a.in.computer_name = cli_credentials_get_workstation(machine_credentials);
	a.in.negotiate_flags = &negotiate_flags;
	a.in.credentials = &credentials3;
	a.out.return_credentials = &credentials3;
	a.out.negotiate_flags = &negotiate_flags;
	a.out.rid = &rid;

	creds = netlogon_creds_client_init(tctx, a.in.account_name,
					   a.in.computer_name,
					   a.in.secure_channel_type,
					   &credentials1, &credentials2,
					   new_password, &credentials3,
					   negotiate_flags);

	torture_assert(tctx, creds != NULL, "memory allocation");

	torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerAuthenticate3_r(b, tctx, &a),
		"ServerAuthenticate3 failed");
	if (!NT_STATUS_IS_OK(a.out.result)) {
		if (!NT_STATUS_EQUAL(a.out.result, NT_STATUS_ACCESS_DENIED)) {
			torture_assert_ntstatus_ok(tctx, a.out.result,
						   "ServerAuthenticate3 failed");
		}
		return false;
	}
	torture_assert(tctx, netlogon_creds_client_check(creds, &credentials3), "Credential chaining failed");

	if (old_password != NULL) {
		torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerReqChallenge_r(b, tctx, &r),
			"ServerReqChallenge failed");
		torture_assert_ntstatus_ok(tctx, r.out.result, "ServerReqChallenge failed");

		creds = netlogon_creds_client_init(tctx, a.in.account_name,
						   a.in.computer_name,
						   a.in.secure_channel_type,
						   &credentials1, &credentials2,
						   old_password, &credentials3,
						   negotiate_flags);

		torture_assert(tctx, creds != NULL, "memory allocation");

		torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerAuthenticate3_r(b, tctx, &a),
			"ServerAuthenticate3 failed");
		if (!NT_STATUS_IS_OK(a.out.result)) {
			if (!NT_STATUS_EQUAL(a.out.result, NT_STATUS_ACCESS_DENIED)) {
				torture_assert_ntstatus_ok(tctx, a.out.result,
							   "ServerAuthenticate3 (old) failed");
			}
			return false;
		}
		torture_assert(tctx, netlogon_creds_client_check(creds, &credentials3), "Credential (old) chaining failed");
	}

	/* Prove that requesting a challenge again won't break it */
	torture_assert_ntstatus_ok(tctx, dcerpc_netr_ServerReqChallenge_r(b, tctx, &r),
		"ServerReqChallenge failed");
	torture_assert_ntstatus_ok(tctx, r.out.result, "ServerReqChallenge failed");

	*creds_out = creds;
	return true;
}

#ifdef SAMBA4_USES_HEIMDAL

/*
 * This function is set in torture_krb5_init_context as krb5
 * send_and_recv function.  This allows us to override what server the
 * test is aimed at, and to inspect the packets just before they are
 * sent to the network, and before they are processed on the recv
 * side.
 *
 * The torture_krb5_pre_send_test() and torture_krb5_post_recv_test()
 * functions are implement the actual tests.
 *
 * When this asserts, the caller will get a spurious 'cannot contact
 * any KDC' message.
 *
 */
struct check_pw_with_krb5_ctx {
	struct addrinfo *server;
	struct {
		unsigned io;
		unsigned fail;
		unsigned errors;
		unsigned error_io;
		unsigned ok;
	} counts;
	krb5_error error;
	struct smb_krb5_context *smb_krb5_context;
	krb5_get_init_creds_opt *krb_options;
	krb5_creds my_creds;
	krb5_get_creds_opt opt_canon;
	krb5_get_creds_opt opt_nocanon;
	krb5_principal upn_realm;
	krb5_principal upn_dns;
	krb5_principal upn_netbios;
	krb5_ccache krbtgt_ccache;
	krb5_principal krbtgt_trust_realm;
	krb5_creds *krbtgt_trust_realm_creds;
	krb5_principal krbtgt_trust_dns;
	krb5_creds *krbtgt_trust_dns_creds;
	krb5_principal krbtgt_trust_netbios;
	krb5_creds *krbtgt_trust_netbios_creds;
	krb5_principal cifs_trust_dns;
	krb5_creds *cifs_trust_dns_creds;
	krb5_principal cifs_trust_netbios;
	krb5_creds *cifs_trust_netbios_creds;
	krb5_principal drs_trust_dns;
	krb5_creds *drs_trust_dns_creds;
	krb5_principal drs_trust_netbios;
	krb5_creds *drs_trust_netbios_creds;
	krb5_principal four_trust_dns;
	krb5_creds *four_trust_dns_creds;
	krb5_creds krbtgt_referral_creds;
	Ticket krbtgt_referral_ticket;
	krb5_keyblock krbtgt_referral_keyblock;
	EncTicketPart krbtgt_referral_enc_part;
};

static krb5_error_code check_pw_with_krb5_send_and_recv_func(krb5_context context,
					void *data, /* struct check_pw_with_krb5_ctx */
					krb5_krbhst_info *_hi,
					time_t timeout,
					const krb5_data *send_buf,
					krb5_data *recv_buf)
{
	struct check_pw_with_krb5_ctx *ctx =
		talloc_get_type_abort(data, struct check_pw_with_krb5_ctx);
	krb5_error_code k5ret;
	krb5_krbhst_info hi = *_hi;
	size_t used;
	int ret;

	hi.proto = KRB5_KRBHST_TCP;

	krb5_free_error_contents(ctx->smb_krb5_context->krb5_context,
				 &ctx->error);
	ctx->counts.io++;

	k5ret = smb_krb5_send_and_recv_func_forced(context, ctx->server,
						   &hi, timeout, send_buf, recv_buf);
	if (k5ret != 0) {
		ctx->counts.fail++;
		return k5ret;
	}

	ret = decode_KRB_ERROR(recv_buf->data, recv_buf->length,
			       &ctx->error, &used);
	if (ret == 0) {
		ctx->counts.errors++;
		ctx->counts.error_io = ctx->counts.io;
	} else {
		ctx->counts.ok++;
	}

	return k5ret;
}

static int check_pw_with_krb5_ctx_destructor(struct check_pw_with_krb5_ctx *ctx)
{
	if (ctx->server != NULL) {
		freeaddrinfo(ctx->server);
		ctx->server = NULL;
	}

	if (ctx->krb_options != NULL) {
		krb5_get_init_creds_opt_free(ctx->smb_krb5_context->krb5_context,
					     ctx->krb_options);
		ctx->krb_options = NULL;
	}

	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->my_creds);

	if (ctx->opt_canon != NULL) {
		krb5_get_creds_opt_free(ctx->smb_krb5_context->krb5_context,
					ctx->opt_canon);
		ctx->opt_canon = NULL;
	}

	if (ctx->opt_nocanon != NULL) {
		krb5_get_creds_opt_free(ctx->smb_krb5_context->krb5_context,
					ctx->opt_nocanon);
		ctx->opt_nocanon = NULL;
	}

	if (ctx->krbtgt_ccache != NULL) {
		krb5_cc_close(ctx->smb_krb5_context->krb5_context,
			      ctx->krbtgt_ccache);
		ctx->krbtgt_ccache = NULL;
	}

	if (ctx->upn_realm != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_realm);
		ctx->upn_realm = NULL;
	}

	if (ctx->upn_dns != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_dns);
		ctx->upn_dns = NULL;
	}

	if (ctx->upn_netbios != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_netbios);
		ctx->upn_netbios = NULL;
	}

	if (ctx->krbtgt_trust_realm != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_trust_realm);
		ctx->krbtgt_trust_realm = NULL;
	}

	if (ctx->krbtgt_trust_realm_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->krbtgt_trust_realm_creds);
		ctx->krbtgt_trust_realm_creds = NULL;
	}

	if (ctx->krbtgt_trust_dns != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_trust_dns);
		ctx->krbtgt_trust_dns = NULL;
	}

	if (ctx->krbtgt_trust_dns_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->krbtgt_trust_dns_creds);
		ctx->krbtgt_trust_dns_creds = NULL;
	}

	if (ctx->krbtgt_trust_netbios != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_trust_netbios);
		ctx->krbtgt_trust_netbios = NULL;
	}

	if (ctx->krbtgt_trust_netbios_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->krbtgt_trust_netbios_creds);
		ctx->krbtgt_trust_netbios_creds = NULL;
	}

	if (ctx->cifs_trust_dns != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->cifs_trust_dns);
		ctx->cifs_trust_dns = NULL;
	}

	if (ctx->cifs_trust_dns_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->cifs_trust_dns_creds);
		ctx->cifs_trust_dns_creds = NULL;
	}

	if (ctx->cifs_trust_netbios != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->cifs_trust_netbios);
		ctx->cifs_trust_netbios = NULL;
	}

	if (ctx->cifs_trust_netbios_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->cifs_trust_netbios_creds);
		ctx->cifs_trust_netbios_creds = NULL;
	}

	if (ctx->drs_trust_dns != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->drs_trust_dns);
		ctx->drs_trust_dns = NULL;
	}

	if (ctx->drs_trust_dns_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->drs_trust_dns_creds);
		ctx->drs_trust_dns_creds = NULL;
	}

	if (ctx->drs_trust_netbios != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->drs_trust_netbios);
		ctx->drs_trust_netbios = NULL;
	}

	if (ctx->drs_trust_netbios_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->drs_trust_netbios_creds);
		ctx->drs_trust_netbios_creds = NULL;
	}

	if (ctx->four_trust_dns != NULL) {
		krb5_free_principal(ctx->smb_krb5_context->krb5_context,
				    ctx->four_trust_dns);
		ctx->four_trust_dns = NULL;
	}

	if (ctx->four_trust_dns_creds != NULL) {
		krb5_free_creds(ctx->smb_krb5_context->krb5_context,
				ctx->four_trust_dns_creds);
		ctx->four_trust_dns_creds = NULL;
	}

	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);

	free_Ticket(&ctx->krbtgt_referral_ticket);

	krb5_free_keyblock_contents(ctx->smb_krb5_context->krb5_context,
				    &ctx->krbtgt_referral_keyblock);

	free_EncTicketPart(&ctx->krbtgt_referral_enc_part);

	krb5_free_error_contents(ctx->smb_krb5_context->krb5_context,
				 &ctx->error);

	talloc_unlink(ctx, ctx->smb_krb5_context);
	ctx->smb_krb5_context = NULL;
	return 0;
}

static bool check_pw_with_krb5(struct torture_context *tctx,
			       struct cli_credentials *credentials,
			       const struct lsa_TrustDomainInfoInfoEx *trusted)
{
	const char *trusted_dns_name = trusted->domain_name.string;
	const char *trusted_netbios_name = trusted->netbios_name.string;
	char *trusted_realm_name = NULL;
	krb5_principal principal = NULL;
	enum credentials_obtained obtained;
	const char *error_string = NULL;
	const char *workstation = cli_credentials_get_workstation(credentials);
	const char *password = cli_credentials_get_password(credentials);
	const struct samr_Password *nthash = NULL;
	const struct samr_Password *old_nthash = NULL;
	const char *old_password = cli_credentials_get_old_password(credentials);
	int kvno = cli_credentials_get_kvno(credentials);
	int expected_kvno = 0;
	krb5uint32 t_kvno = 0;
	const char *host = torture_setting_string(tctx, "host", NULL);
	krb5_error_code k5ret;
	krb5_boolean k5ok;
	int type;
	bool ok;
	struct check_pw_with_krb5_ctx *ctx = NULL;
	char *assertion_message = NULL;
	const char *realm = NULL;
	char *upn_realm_string = NULL;
	char *upn_dns_string = NULL;
	char *upn_netbios_string = NULL;
	char *krbtgt_cc_name = NULL;
	char *krbtgt_trust_realm_string = NULL;
	char *krbtgt_trust_dns_string = NULL;
	char *krbtgt_trust_netbios_string = NULL;
	char *cifs_trust_dns_string = NULL;
	char *cifs_trust_netbios_string = NULL;
	char *drs_trust_dns_string = NULL;
	char *drs_trust_netbios_string = NULL;
	char *four_trust_dns_string = NULL;

	ctx = talloc_zero(tctx, struct check_pw_with_krb5_ctx);
	torture_assert(tctx, ctx != NULL, "Failed to allocate");

	realm = cli_credentials_get_realm(credentials);
	trusted_realm_name = strupper_talloc(tctx, trusted_dns_name);

	nthash = cli_credentials_get_nt_hash(credentials, ctx);
	old_nthash = cli_credentials_get_old_nt_hash(credentials, ctx);

	k5ret = smb_krb5_init_context(ctx, tctx->lp_ctx, &ctx->smb_krb5_context);
	torture_assert_int_equal(tctx, k5ret, 0, "smb_krb5_init_context failed");

	ok = interpret_string_addr_internal(&ctx->server, host, 0);
	torture_assert(tctx, ok, "Failed to parse target server");
	talloc_set_destructor(ctx, check_pw_with_krb5_ctx_destructor);

	set_sockaddr_port(ctx->server->ai_addr, 88);

	k5ret = krb5_set_send_to_kdc_func(ctx->smb_krb5_context->krb5_context,
					  check_pw_with_krb5_send_and_recv_func,
					  ctx);
	torture_assert_int_equal(tctx, k5ret, 0, "krb5_set_send_to_kdc_func failed");

	torture_assert_int_equal(tctx,
			krb5_get_init_creds_opt_alloc(ctx->smb_krb5_context->krb5_context,
						      &ctx->krb_options),
			0, "krb5_get_init_creds_opt_alloc failed");
	torture_assert_int_equal(tctx,
			krb5_get_init_creds_opt_set_pac_request(
				ctx->smb_krb5_context->krb5_context,
				ctx->krb_options, true),
			0, "krb5_get_init_creds_opt_set_pac_request failed");

	upn_realm_string = talloc_asprintf(ctx, "user@%s",
					   trusted_realm_name);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->upn_realm,
						realm, upn_realm_string, NULL),
			0, "smb_krb5_make_principal failed");
	smb_krb5_principal_set_type(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_realm, KRB5_NT_ENTERPRISE_PRINCIPAL);

	upn_dns_string = talloc_asprintf(ctx, "user@%s",
					 trusted_dns_name);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->upn_dns,
						realm, upn_dns_string, NULL),
			0, "smb_krb5_make_principal failed");
	smb_krb5_principal_set_type(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_dns, KRB5_NT_ENTERPRISE_PRINCIPAL);

	upn_netbios_string = talloc_asprintf(ctx, "user@%s",
					 trusted_netbios_name);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->upn_netbios,
						realm, upn_netbios_string, NULL),
			0, "smb_krb5_make_principal failed");
	smb_krb5_principal_set_type(ctx->smb_krb5_context->krb5_context,
				    ctx->upn_netbios, KRB5_NT_ENTERPRISE_PRINCIPAL);

	k5ret = principal_from_credentials(ctx, credentials, ctx->smb_krb5_context,
					   &principal, &obtained,  &error_string);
	torture_assert_int_equal(tctx, k5ret, 0, error_string);

	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_init_creds_password(ctx->smb_krb5_context->krb5_context,
					     &ctx->my_creds, ctx->upn_realm,
					     "_none_", NULL, NULL, 0,
					     NULL, ctx->krb_options);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_init_creds_password(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u/%u,ok=%u]",
				upn_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.error_io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.error_io, 1, assertion_message);
	torture_assert_int_equal(tctx, KRB5_ERROR_CODE(&ctx->error), 68, assertion_message);
	torture_assert(tctx, ctx->error.crealm != NULL, assertion_message);
	torture_assert_str_equal(tctx, *ctx->error.crealm, trusted_realm_name, assertion_message);
	torture_assert(tctx, ctx->error.cname == NULL, assertion_message);
	torture_assert_str_equal(tctx, ctx->error.realm, realm, assertion_message);

	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_init_creds_password(ctx->smb_krb5_context->krb5_context,
					     &ctx->my_creds, ctx->upn_dns,
					     "_none_", NULL, NULL, 0,
					     NULL, ctx->krb_options);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_init_creds_password(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u/%u,ok=%u]",
				upn_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.error_io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.error_io, 1, assertion_message);
	torture_assert_int_equal(tctx, KRB5_ERROR_CODE(&ctx->error), 68, assertion_message);
	torture_assert(tctx, ctx->error.crealm != NULL, assertion_message);
	torture_assert_str_equal(tctx, *ctx->error.crealm, trusted_realm_name, assertion_message);
	torture_assert(tctx, ctx->error.cname == NULL, assertion_message);
	torture_assert_str_equal(tctx, ctx->error.realm, realm, assertion_message);

	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_init_creds_password(ctx->smb_krb5_context->krb5_context,
					     &ctx->my_creds, ctx->upn_netbios,
					     "_none_", NULL, NULL, 0,
					     NULL, ctx->krb_options);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_init_creds_password(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u/%u,ok=%u]",
				upn_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.error_io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.error_io, 1, assertion_message);
	torture_assert_int_equal(tctx, KRB5_ERROR_CODE(&ctx->error), 68, assertion_message);
	torture_assert(tctx, ctx->error.crealm != NULL, assertion_message);
	torture_assert_str_equal(tctx, *ctx->error.crealm, trusted_realm_name, assertion_message);
	torture_assert(tctx, ctx->error.cname == NULL, assertion_message);
	torture_assert_str_equal(tctx, ctx->error.realm, realm, assertion_message);

	torture_comment(tctx, "(%s:%s) password[%s] old_password[%s]\n",
			__location__, __FUNCTION__,
			password, old_password);
	if (old_password != NULL) {
		k5ret = krb5_get_init_creds_password(ctx->smb_krb5_context->krb5_context,
						     &ctx->my_creds, principal,
						     old_password, NULL, NULL, 0,
						     NULL, ctx->krb_options);
		torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_PREAUTH_FAILED,
					 "preauth should fail with old password");
	}

	k5ret = krb5_get_init_creds_password(ctx->smb_krb5_context->krb5_context,
					     &ctx->my_creds, principal,
					     password, NULL, NULL, 0,
					     NULL, ctx->krb_options);
	if (k5ret == KRB5KDC_ERR_PREAUTH_FAILED) {
		TALLOC_FREE(ctx);
		return false;
	}

	assertion_message = talloc_asprintf(ctx,
				"krb5_get_init_creds_password for failed: %s",
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	torture_assert_int_equal(tctx,
			krb5_get_creds_opt_alloc(ctx->smb_krb5_context->krb5_context,
						 &ctx->opt_canon),
			0, "krb5_get_creds_opt_alloc");

	krb5_get_creds_opt_add_options(ctx->smb_krb5_context->krb5_context,
				       ctx->opt_canon,
				       KRB5_GC_CANONICALIZE);

	krb5_get_creds_opt_add_options(ctx->smb_krb5_context->krb5_context,
				       ctx->opt_canon,
				       KRB5_GC_NO_STORE);

	torture_assert_int_equal(tctx,
			krb5_get_creds_opt_alloc(ctx->smb_krb5_context->krb5_context,
						 &ctx->opt_nocanon),
			0, "krb5_get_creds_opt_alloc");

	krb5_get_creds_opt_add_options(ctx->smb_krb5_context->krb5_context,
				       ctx->opt_nocanon,
				       KRB5_GC_NO_STORE);

	krbtgt_cc_name = talloc_asprintf(ctx, "MEMORY:%p.krbtgt", ctx->smb_krb5_context);
	torture_assert_int_equal(tctx,
			krb5_cc_resolve(ctx->smb_krb5_context->krb5_context,
					krbtgt_cc_name,
					&ctx->krbtgt_ccache),
			0, "krb5_cc_resolve failed");

	torture_assert_int_equal(tctx,
			krb5_cc_initialize(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_ccache,
					   ctx->my_creds.client),
			0, "krb5_cc_initialize failed");

	torture_assert_int_equal(tctx,
			krb5_cc_store_cred(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_ccache,
					   &ctx->my_creds),
			0, "krb5_cc_store_cred failed");

	krbtgt_trust_realm_string = talloc_asprintf(ctx, "krbtgt/%s@%s",
						    trusted_realm_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->krbtgt_trust_realm,
						realm, "krbtgt",
						trusted_realm_name, NULL),
			0, "smb_krb5_make_principal failed");

	krbtgt_trust_dns_string = talloc_asprintf(ctx, "krbtgt/%s@%s",
						  trusted_dns_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->krbtgt_trust_dns,
						realm, "krbtgt",
						trusted_dns_name, NULL),
			0, "smb_krb5_make_principal failed");

	krbtgt_trust_netbios_string = talloc_asprintf(ctx, "krbtgt/%s@%s",
						      trusted_netbios_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->krbtgt_trust_netbios,
						realm, "krbtgt",
						trusted_netbios_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we can do a TGS for krbtgt/trusted_realm */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_nocanon,
			       ctx->krbtgt_ccache,
			       ctx->krbtgt_trust_realm,
			       &ctx->krbtgt_trust_realm_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_trust_realm_creds->server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_trust_realm_creds->server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Confirm if we have no referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, KRB5_CC_END, assertion_message);

	/* Confirm if we can do a TGS for krbtgt/trusted_dns with CANON */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->krbtgt_trust_dns,
			       &ctx->krbtgt_trust_dns_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				krbtgt_trust_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);
	k5ret = decode_Ticket(ctx->krbtgt_referral_creds.ticket.data,
			      ctx->krbtgt_referral_creds.ticket.length,
			      &ctx->krbtgt_referral_ticket, NULL);
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	if (kvno > 0) {
		expected_kvno = kvno - 1;
	}
	if (ctx->krbtgt_referral_ticket.enc_part.kvno != NULL) {
		t_kvno = *ctx->krbtgt_referral_ticket.enc_part.kvno;
		assertion_message = talloc_asprintf(ctx,
				"krbtgt_referral_ticket(%s) kvno(%u) expected(%u) current(%u)",
				krbtgt_trust_realm_string,
				(unsigned)t_kvno, (unsigned)expected_kvno,(unsigned)kvno);
		torture_comment(tctx, "%s\n", assertion_message);
		torture_assert_int_not_equal(tctx, t_kvno, 0, assertion_message);
	} else {
		assertion_message = talloc_asprintf(ctx,
				"krbtgt_referral_ticket(%s) kvno(NULL) exptected(%u) current(%u)",
				krbtgt_trust_realm_string,
				(unsigned)expected_kvno,(unsigned)kvno);
		torture_comment(tctx, "%s\n", assertion_message);
	}
	torture_assert_int_equal(tctx, t_kvno, expected_kvno, assertion_message);

	if (old_nthash != NULL && expected_kvno != kvno) {
		torture_comment(tctx, "old_nthash: %s\n", assertion_message);
		k5ret = smb_krb5_keyblock_init_contents(ctx->smb_krb5_context->krb5_context,
							ENCTYPE_ARCFOUR_HMAC,
							old_nthash->hash,
							sizeof(old_nthash->hash),
							&ctx->krbtgt_referral_keyblock);
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	} else {
		torture_comment(tctx, "nthash: %s\n", assertion_message);
		k5ret = smb_krb5_keyblock_init_contents(ctx->smb_krb5_context->krb5_context,
							ENCTYPE_ARCFOUR_HMAC,
							nthash->hash,
							sizeof(nthash->hash),
							&ctx->krbtgt_referral_keyblock);
		torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	}
	k5ret = krb5_decrypt_ticket(ctx->smb_krb5_context->krb5_context,
				    &ctx->krbtgt_referral_ticket,
				    &ctx->krbtgt_referral_keyblock,
				    &ctx->krbtgt_referral_enc_part,
				    0);
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	/* Confirm if we can do a TGS for krbtgt/trusted_dns no CANON */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_nocanon,
			       ctx->krbtgt_ccache,
			       ctx->krbtgt_trust_dns,
			       &ctx->krbtgt_trust_dns_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s, nocanon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				krbtgt_trust_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 2, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 2, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_trust_dns_creds->server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_trust_dns_creds->server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	/* Confirm if we can do a TGS for krbtgt/NETBIOS with CANON */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->krbtgt_trust_netbios,
			       &ctx->krbtgt_trust_netbios_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s, canon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				krbtgt_trust_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	/* Confirm if we can do a TGS for krbtgt/NETBIOS no CANON */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_nocanon,
			       ctx->krbtgt_ccache,
			       ctx->krbtgt_trust_netbios,
			       &ctx->krbtgt_trust_netbios_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s, nocanon) for failed: "
				"(%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				krbtgt_trust_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 2, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 2, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_trust_netbios_creds->server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_trust_netbios_creds->server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	cifs_trust_dns_string = talloc_asprintf(ctx, "cifs/%s@%s",
						trusted_dns_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->cifs_trust_dns,
						realm, "cifs",
						trusted_dns_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we get krbtgt/trusted_realm back when asking for cifs/trusted_realm */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->cifs_trust_dns,
			       &ctx->cifs_trust_dns_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s) for failed: (%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				cifs_trust_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	cifs_trust_netbios_string = talloc_asprintf(ctx, "cifs/%s@%s",
						trusted_netbios_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->cifs_trust_netbios,
						realm, "cifs",
						trusted_netbios_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we get krbtgt/trusted_realm back when asking for cifs/trusted_realm */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->cifs_trust_netbios,
			       &ctx->cifs_trust_netbios_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s) for failed: (%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				cifs_trust_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	drs_trust_dns_string = talloc_asprintf(ctx,
			"E3514235-4B06-11D1-AB04-00C04FC2DCD2/%s/%s@%s",
			workstation, trusted_dns_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->drs_trust_dns,
						realm, "E3514235-4B06-11D1-AB04-00C04FC2DCD2",
						workstation, trusted_dns_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we get krbtgt/trusted_realm back when asking for a 3 part principal */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->drs_trust_dns,
			       &ctx->drs_trust_dns_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s) for failed: (%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				drs_trust_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	drs_trust_netbios_string = talloc_asprintf(ctx,
			"E3514235-4B06-11D1-AB04-00C04FC2DCD2/%s/%s@%s",
			workstation, trusted_netbios_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->drs_trust_netbios,
						realm, "E3514235-4B06-11D1-AB04-00C04FC2DCD2",
						workstation, trusted_netbios_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we get krbtgt/trusted_realm back when asking for a 3 part principal */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->drs_trust_netbios,
			       &ctx->drs_trust_netbios_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s) for failed: (%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				drs_trust_netbios_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5_KDC_UNREACH, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.ok, 1, assertion_message);

	/* Confirm if we have the referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	k5ok = krb5_principal_compare(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_referral_creds.server,
				      ctx->krbtgt_trust_realm);
	torture_assert(tctx, k5ok, assertion_message);
	type = smb_krb5_principal_get_type(ctx->smb_krb5_context->krb5_context,
					   ctx->krbtgt_referral_creds.server);
	torture_assert_int_equal(tctx, type, KRB5_NT_SRV_INST, assertion_message);

	/* Delete the referral ticket from the cache */
	k5ret = krb5_cc_remove_cred(ctx->smb_krb5_context->krb5_context,
				    ctx->krbtgt_ccache,
				    0,
				    &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_remove_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, 0, assertion_message);

	four_trust_dns_string = talloc_asprintf(ctx, "four/tree/two/%s@%s",
						trusted_dns_name, realm);
	torture_assert_int_equal(tctx,
			smb_krb5_make_principal(ctx->smb_krb5_context->krb5_context,
						&ctx->four_trust_dns,
						realm, "four", "tree", "two",
						trusted_dns_name, NULL),
			0, "smb_krb5_make_principal failed");

	/* Confirm if we get an error back for a 4 part principal */
	ZERO_STRUCT(ctx->counts);
	k5ret = krb5_get_creds(ctx->smb_krb5_context->krb5_context,
			       ctx->opt_canon,
			       ctx->krbtgt_ccache,
			       ctx->four_trust_dns,
			       &ctx->four_trust_dns_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_get_creds(%s) for failed: (%d) %s; t[d=0x%x,t=0x%x,a=0x%x] [io=%u,error=%u,ok=%u]",
				four_trust_dns_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx),
				trusted->trust_direction,
				trusted->trust_type,
				trusted->trust_attributes,
				ctx->counts.io, ctx->counts.errors, ctx->counts.ok);
	torture_assert_int_equal(tctx, k5ret, KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.io, 1, assertion_message);
	torture_assert_int_equal(tctx, ctx->counts.error_io, 1, assertion_message);
	torture_assert_int_equal(tctx, KRB5_ERROR_CODE(&ctx->error), 7, assertion_message);

	/* Confirm if we have no referral ticket in the cache */
	krb5_free_cred_contents(ctx->smb_krb5_context->krb5_context,
				&ctx->krbtgt_referral_creds);
	k5ret = krb5_cc_retrieve_cred(ctx->smb_krb5_context->krb5_context,
				      ctx->krbtgt_ccache,
				      0,
				      ctx->krbtgt_trust_realm_creds,
				      &ctx->krbtgt_referral_creds);
	assertion_message = talloc_asprintf(ctx,
				"krb5_cc_retrieve_cred(%s) for failed: (%d) %s",
				krbtgt_trust_realm_string,
				k5ret,
				smb_get_krb5_error_message(ctx->smb_krb5_context->krb5_context,
							   k5ret, ctx));
	torture_assert_int_equal(tctx, k5ret, KRB5_CC_END, assertion_message);

	TALLOC_FREE(ctx);
	return true;
}
#endif

static bool check_dom_trust_pw(struct dcerpc_pipe *p,
			       struct torture_context *tctx,
			       const char *our_netbios_name,
			       const char *our_dns_name,
			       enum netr_SchannelType secure_channel_type,
			       const struct lsa_TrustDomainInfoInfoEx *trusted,
			       const char *previous_password,
			       const char *current_password,
			       uint32_t current_version,
			       const char *next_password,
			       uint32_t next_version,
			       bool expected_result)
{
	struct cli_credentials *incoming_creds;
	char *server_name = NULL;
	char *account = NULL;
	char *principal = NULL;
	char *workstation = NULL;
	const char *binding = torture_setting_string(tctx, "binding", NULL);
	const char *host = torture_setting_string(tctx, "host", NULL);
	const char *ip;
	struct nbt_name nbt_name;
	struct dcerpc_binding *b2;
	struct netlogon_creds_CredentialState *creds;
	struct samr_CryptPassword samr_crypt_password;
	struct netr_CryptPassword netr_crypt_password;
	struct netr_Authenticator req_auth;
	struct netr_Authenticator rep_auth;
	struct netr_ServerPasswordSet2 s;
	struct dcerpc_pipe *p1 = NULL;
	struct dcerpc_pipe *p2 = NULL;
	NTSTATUS status;
	bool ok;
	int rc;
	const char *trusted_netbios_name = trusted->netbios_name.string;
	const char *trusted_dns_name = trusted->domain_name.string;
	struct tsocket_address *dest_addr;
	struct cldap_socket *cldap;
	struct cldap_netlogon cldap1;

	incoming_creds = cli_credentials_init(tctx);
	torture_assert(tctx, incoming_creds, "cli_credentials_init");

	cli_credentials_set_domain(incoming_creds, our_netbios_name, CRED_SPECIFIED);
	cli_credentials_set_realm(incoming_creds, our_dns_name, CRED_SPECIFIED);

	if (secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
		account = talloc_asprintf(tctx, "%s.", trusted_dns_name);
		torture_assert(tctx, account, __location__);

		principal = talloc_asprintf(tctx, "%s$@%s",
					    trusted_netbios_name,
					    cli_credentials_get_realm(incoming_creds));
		torture_assert(tctx, principal, __location__);

		workstation = talloc_asprintf(tctx, "%sUP",
					      trusted_netbios_name);
		torture_assert(tctx, workstation, __location__);
	} else {
		account = talloc_asprintf(tctx, "%s$", trusted_netbios_name);
		torture_assert(tctx, account, __location__);

		workstation = talloc_asprintf(tctx, "%sDOWN",
					      trusted_netbios_name);
		torture_assert(tctx, workstation, __location__);
	}

	cli_credentials_set_username(incoming_creds, account, CRED_SPECIFIED);
	if (principal != NULL) {
		cli_credentials_set_principal(incoming_creds, principal,
					      CRED_SPECIFIED);
	}
	cli_credentials_set_kvno(incoming_creds, current_version);
	cli_credentials_set_password(incoming_creds, current_password, CRED_SPECIFIED);
	cli_credentials_set_old_password(incoming_creds, previous_password, CRED_SPECIFIED);
	cli_credentials_set_workstation(incoming_creds, workstation, CRED_SPECIFIED);
	cli_credentials_set_secure_channel_type(incoming_creds, secure_channel_type);

	make_nbt_name_server(&nbt_name, host);

	status = resolve_name_ex(lpcfg_resolve_context(tctx->lp_ctx),
				 0, 0, &nbt_name, tctx, &ip, tctx->ev);
	torture_assert_ntstatus_ok(tctx, status,
			talloc_asprintf(tctx,"Failed to resolve %s: %s",
					nbt_name.name, nt_errstr(status)));

	rc = tsocket_address_inet_from_strings(tctx, "ip",
					       ip,
					       lpcfg_cldap_port(tctx->lp_ctx),
					       &dest_addr);
	torture_assert_int_equal(tctx, rc, 0,
				 talloc_asprintf(tctx,
						 "tsocket_address_inet_from_strings failed parsing %s:%d",
						 host, lpcfg_cldap_port(tctx->lp_ctx)));

	/* cldap_socket_init should now know about the dest. address */
	status = cldap_socket_init(tctx, NULL, dest_addr, &cldap);
	torture_assert_ntstatus_ok(tctx, status, "cldap_socket_init");

	ZERO_STRUCT(cldap1);
	cldap1.in.dest_address = NULL;
	cldap1.in.dest_port = 0;
	cldap1.in.version = NETLOGON_NT_VERSION_5 | NETLOGON_NT_VERSION_5EX;
	cldap1.in.user = account;
	if (secure_channel_type == SEC_CHAN_DNS_DOMAIN) {
		cldap1.in.acct_control = ACB_AUTOLOCK;
	} else {
		cldap1.in.acct_control = ACB_DOMTRUST;
	}
	status = cldap_netlogon(cldap, tctx, &cldap1);
	torture_assert_ntstatus_ok(tctx, status, "cldap_netlogon");
	torture_assert_int_equal(tctx, cldap1.out.netlogon.ntver,
				 NETLOGON_NT_VERSION_5EX,
				 "ntver");
	torture_assert_int_equal(tctx, cldap1.out.netlogon.data.nt5_ex.nt_version,
				 NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX,
				 "nt_version");
	torture_assert_int_equal(tctx, cldap1.out.netlogon.data.nt5_ex.command,
				 LOGON_SAM_LOGON_RESPONSE_EX,
				 "command");
	torture_assert_str_equal(tctx, cldap1.out.netlogon.data.nt5_ex.user_name,
				 cldap1.in.user,
				 "user_name");
	server_name = talloc_asprintf(tctx, "\\\\%s",
			cldap1.out.netlogon.data.nt5_ex.pdc_dns_name);
	torture_assert(tctx, server_name, __location__);

	status = dcerpc_parse_binding(tctx, binding, &b2);
	torture_assert_ntstatus_ok(tctx, status, "Bad binding string");

	status = dcerpc_pipe_connect_b(tctx, &p1, b2,
				       &ndr_table_netlogon,
				       cli_credentials_init_anon(tctx),
				       tctx->ev, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_pipe_connect_b");

	ok = check_pw_with_ServerAuthenticate3(p1, tctx,
					       NETLOGON_NEG_AUTH2_ADS_FLAGS,
					       server_name,
					       incoming_creds, &creds);
	torture_assert_int_equal(tctx, ok, expected_result,
				 "check_pw_with_ServerAuthenticate3");
	if (expected_result == true) {
		ok = test_SetupCredentialsPipe(p1, tctx, incoming_creds, creds,
					       DCERPC_SIGN | DCERPC_SEAL, &p2);
		torture_assert_int_equal(tctx, ok, true,
					 "test_SetupCredentialsPipe");
	}
	TALLOC_FREE(p1);

	if (trusted->trust_type != LSA_TRUST_TYPE_DOWNLEVEL) {
#ifdef SAMBA4_USES_HEIMDAL
		ok = check_pw_with_krb5(tctx, incoming_creds, trusted);
		torture_assert_int_equal(tctx, ok, expected_result,
					 "check_pw_with_krb5");
#else
		torture_comment(tctx, "skipping check_pw_with_krb5 for MIT Kerberos build");
#endif
	}

	if (expected_result != true || next_password == NULL) {
		TALLOC_FREE(p2);
		return true;
	}

	/*
	 * netr_ServerPasswordSet2
	 */
	ok = encode_pw_buffer(samr_crypt_password.data,
			      next_password, STR_UNICODE);
	torture_assert(tctx, ok, "encode_pw_buffer");

	if (next_version != 0) {
		struct NL_PASSWORD_VERSION version;
		uint32_t len = IVAL(samr_crypt_password.data, 512);
		uint32_t ofs = 512 - len;
		uint8_t *ptr;

		ofs -= 12;

		version.ReservedField = 0;
		version.PasswordVersionNumber = next_version;
		version.PasswordVersionPresent =
			NETLOGON_PASSWORD_VERSION_NUMBER_PRESENT;

		ptr = samr_crypt_password.data + ofs;
		SIVAL(ptr, 0, version.ReservedField);
		SIVAL(ptr, 4, version.PasswordVersionNumber);
		SIVAL(ptr, 8, version.PasswordVersionPresent);
	}

	netlogon_creds_client_authenticator(creds, &req_auth);
	ZERO_STRUCT(rep_auth);

	if (creds->negotiate_flags & NETLOGON_NEG_SUPPORTS_AES) {
		netlogon_creds_aes_encrypt(creds,
					   samr_crypt_password.data,
					   516);
	} else {
		netlogon_creds_arcfour_crypt(creds,
					     samr_crypt_password.data,
					     516);
	}

	memcpy(netr_crypt_password.data,
	       samr_crypt_password.data, 512);
	netr_crypt_password.length = IVAL(samr_crypt_password.data, 512);


	s.in.server_name = server_name;
	s.in.account_name = cli_credentials_get_username(incoming_creds);
	s.in.secure_channel_type = cli_credentials_get_secure_channel_type(incoming_creds);
	s.in.computer_name = cli_credentials_get_workstation(incoming_creds);
	s.in.credential = &req_auth;
	s.in.new_password = &netr_crypt_password;
	s.out.return_authenticator = &rep_auth;
	status = dcerpc_netr_ServerPasswordSet2_r(p2->binding_handle, tctx, &s);
	torture_assert_ntstatus_ok(tctx, status, "failed to set password");

	ok = netlogon_creds_client_check(creds, &rep_auth.cred);
	torture_assert(tctx, ok, "netlogon_creds_client_check");

	cli_credentials_set_kvno(incoming_creds, next_version);
	cli_credentials_set_password(incoming_creds, next_password, CRED_SPECIFIED);
	cli_credentials_set_old_password(incoming_creds, current_password, CRED_SPECIFIED);

	TALLOC_FREE(p2);
	status = dcerpc_pipe_connect_b(tctx, &p2, b2,
				       &ndr_table_netlogon,
				       cli_credentials_init_anon(tctx),
				       tctx->ev, tctx->lp_ctx);
	torture_assert_ntstatus_ok(tctx, status, "dcerpc_pipe_connect_b");

	ok = check_pw_with_ServerAuthenticate3(p2, tctx,
					       NETLOGON_NEG_AUTH2_ADS_FLAGS,
					       server_name,
					       incoming_creds, &creds);
	torture_assert(tctx, ok, "check_pw_with_ServerAuthenticate3 with changed password");

	if (trusted->trust_type != LSA_TRUST_TYPE_DOWNLEVEL) {
#if SAMBA4_USES_HEIMDAL
		ok = check_pw_with_krb5(tctx, incoming_creds, trusted);
		torture_assert(tctx, ok, "check_pw_with_krb5 with changed password");
#else
		torture_comment(tctx, "skipping check_pw_with_krb5 for MIT Kerberos build");
#endif
	}

	TALLOC_FREE(p2);
	return true;
}

static bool test_CreateTrustedDomainEx_common(struct dcerpc_pipe *p,
					      struct torture_context *tctx,
					      struct policy_handle *handle,
					      uint32_t num_trusts,
					      bool ex2_call)
{
	NTSTATUS status;
	bool ret = true;
	struct lsa_QueryInfoPolicy2 p2;
	union lsa_PolicyInformation *our_info = NULL;
	struct lsa_CreateTrustedDomainEx r;
	struct lsa_CreateTrustedDomainEx2 r2;
	struct lsa_TrustDomainInfoInfoEx trustinfo;
	struct lsa_TrustDomainInfoAuthInfoInternal *authinfo_internal = NULL;
	struct lsa_TrustDomainInfoAuthInfo *authinfo = NULL;
	struct dom_sid **domsid;
	struct policy_handle *trustdom_handle;
	struct lsa_QueryTrustedDomainInfo q;
	union lsa_TrustedDomainInfo *info = NULL;
	DATA_BLOB session_key;
	int i;
	struct dcerpc_binding_handle *b = p->binding_handle;
	const char *id;
	const char *incoming_v00 = TRUSTPW "InV00";
	const char *incoming_v0 = TRUSTPW "InV0";
	const char *incoming_v1 = TRUSTPW "InV1";
	const char *incoming_v2 = TRUSTPW "InV2";
	const char *incoming_v40 = TRUSTPW "InV40";
	const char *outgoing_v00 = TRUSTPW "OutV00";
	const char *outgoing_v0 = TRUSTPW "OutV0";

	if (ex2_call) {
		torture_comment(tctx, "\nTesting CreateTrustedDomainEx2 for %d domains\n", num_trusts);
		id = "3";
	} else {
		torture_comment(tctx, "\nTesting CreateTrustedDomainEx for %d domains\n", num_trusts);
		id = "2";
	}

	domsid = talloc_array(tctx, struct dom_sid *, num_trusts);
	trustdom_handle = talloc_array(tctx, struct policy_handle, num_trusts);

	status = dcerpc_fetch_session_key(p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		torture_comment(tctx, "dcerpc_fetch_session_key failed - %s\n", nt_errstr(status));
		return false;
	}

	ZERO_STRUCT(p2);
	p2.in.handle = handle;
	p2.in.level = LSA_POLICY_INFO_DNS;
	p2.out.info = &our_info;

	torture_assert_ntstatus_ok(tctx,
				dcerpc_lsa_QueryInfoPolicy2_r(b, tctx, &p2),
				"lsa_QueryInfoPolicy2 failed");
	torture_assert_ntstatus_ok(tctx, p2.out.result,
				"lsa_QueryInfoPolicy2 failed");
	torture_assert(tctx, our_info != NULL, "lsa_QueryInfoPolicy2 our_info");

	for (i=0; i< num_trusts; i++) {
		char *trust_name = talloc_asprintf(tctx, "TORTURE%s%02d", id, i);
		char *trust_name_dns = talloc_asprintf(tctx, "torturedom%s%02d.samba._none_.example.com", id, i);
		char *trust_sid = talloc_asprintf(tctx, "S-1-5-21-97398-379795-%s%02d", id, i);
		bool ok;

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

		ok = gen_authinfo_internal(tctx, incoming_v00, incoming_v0,
				  outgoing_v00, outgoing_v0,
				  session_key, &authinfo_internal);
		if (!ok) {
			torture_comment(tctx, "gen_authinfo_internal failed");
			ret = false;
		}

		ok = gen_authinfo(tctx, incoming_v00, incoming_v0,
				  outgoing_v00, outgoing_v0,
				  &authinfo);
		if (!ok) {
			torture_comment(tctx, "gen_authinfonfo failed");
			ret = false;
		}

		if (ex2_call) {

			r2.in.policy_handle = handle;
			r2.in.info = &trustinfo;
			r2.in.auth_info_internal = authinfo_internal;
			r2.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			r2.out.trustdom_handle = &trustdom_handle[i];

			torture_assert_ntstatus_ok(tctx,
				dcerpc_lsa_CreateTrustedDomainEx2_r(b, tctx, &r2),
				"CreateTrustedDomainEx2 failed");

			status = r2.out.result;
		} else {

			r.in.policy_handle = handle;
			r.in.info = &trustinfo;
			r.in.auth_info = authinfo;
			r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			r.out.trustdom_handle = &trustdom_handle[i];

			torture_assert_ntstatus_ok(tctx,
				dcerpc_lsa_CreateTrustedDomainEx_r(b, tctx, &r),
				"CreateTrustedDomainEx failed");

			status = r.out.result;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			test_DeleteTrustedDomain(b, tctx, handle, trustinfo.netbios_name);
			if (ex2_call) {
				torture_assert_ntstatus_ok(tctx,
					dcerpc_lsa_CreateTrustedDomainEx2_r(b, tctx, &r2),
					"CreateTrustedDomainEx2 failed");
				status = r2.out.result;
			} else {
				torture_assert_ntstatus_ok(tctx,
					dcerpc_lsa_CreateTrustedDomainEx_r(b, tctx, &r),
					"CreateTrustedDomainEx2 failed");
				status = r.out.result;
			}
		}
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(tctx, "CreateTrustedDomainEx failed2 - %s\n", nt_errstr(status));
			ret = false;
		} else {
			/* For outbound and MIT trusts there is no trust account */
			if (trustinfo.trust_direction != 2 &&
			    trustinfo.trust_type != 3) {

				if (torture_setting_bool(tctx, "samba3", false)) {
					torture_comment(tctx, "skipping trusted domain auth tests against samba3\n");
				} else if (ex2_call == false &&
					   torture_setting_bool(tctx, "samba4", false)) {
					torture_comment(tctx, "skipping CreateTrustedDomainEx trusted domain auth tests against samba4\n");

				} else {
					ok = check_dom_trust_pw(p, tctx,
								our_info->dns.name.string,
								our_info->dns.dns_domain.string,
								SEC_CHAN_DOMAIN,
								&trustinfo,
								NULL,
								"x" TRUSTPW "x", 0,
								NULL, 0,
								false);
					if (!ok) {
						torture_comment(tctx, "Password check passed unexpectedly\n");
						ret = false;
					}
					ok = check_dom_trust_pw(p, tctx,
								our_info->dns.name.string,
								our_info->dns.dns_domain.string,
								SEC_CHAN_DOMAIN,
								&trustinfo,
								incoming_v00,
								incoming_v0, 0,
								incoming_v1, 1,
								true);
					if (!ok) {
						torture_comment(tctx, "Password check failed (SEC_CHAN_DOMAIN)\n");
						ret = false;
					}
					ok = check_dom_trust_pw(p, tctx,
								our_info->dns.name.string,
								our_info->dns.dns_domain.string,
								SEC_CHAN_DNS_DOMAIN,
								&trustinfo,
								incoming_v0,
								incoming_v1, 1,
								incoming_v2, 2,
								true);
					if (!ok) {
						torture_comment(tctx, "Password check failed v2 (SEC_CHAN_DNS_DOMAIN)\n");
						ret = false;
					}
					ok = check_dom_trust_pw(p, tctx,
								our_info->dns.name.string,
								our_info->dns.dns_domain.string,
								SEC_CHAN_DNS_DOMAIN,
								&trustinfo,
								incoming_v1,
								incoming_v2, 2,
								incoming_v40, 40,
								true);
					if (!ok) {
						torture_comment(tctx, "Password check failed v4 (SEC_CHAN_DNS_DOMAIN)\n");
						ret = false;
					}
				}
			}

			q.in.trustdom_handle = &trustdom_handle[i];
			q.in.level = LSA_TRUSTED_DOMAIN_INFO_INFO_EX;
			q.out.info = &info;
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryTrustedDomainInfo_r(b, tctx, &q),
				"QueryTrustedDomainInfo failed");
			if (!NT_STATUS_IS_OK(q.out.result)) {
				torture_comment(tctx, "QueryTrustedDomainInfo level 1 failed - %s\n", nt_errstr(q.out.result));
				ret = false;
			} else if (!q.out.info) {
				torture_comment(tctx, "QueryTrustedDomainInfo level 1 failed to return an info pointer\n");
				ret = false;
			} else {
				if (strcmp(info->info_ex.domain_name.string, trustinfo.domain_name.string) != 0) {
					torture_comment(tctx, "QueryTrustedDomainInfo returned inconsistent long name: %s != %s\n",
					       info->info_ex.domain_name.string, trustinfo.domain_name.string);
					ret = false;
				}
				if (strcmp(info->info_ex.netbios_name.string, trustinfo.netbios_name.string) != 0) {
					torture_comment(tctx, "QueryTrustedDomainInfo returned inconsistent short name: %s != %s\n",
					       info->info_ex.netbios_name.string, trustinfo.netbios_name.string);
					ret = false;
				}
				if (info->info_ex.trust_type != trustinfo.trust_type) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust type %d != %d\n",
					       trust_name, info->info_ex.trust_type, trustinfo.trust_type);
					ret = false;
				}
				if (info->info_ex.trust_attributes != LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust attributes %d != %d\n",
					       trust_name, info->info_ex.trust_attributes, LSA_TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION);
					ret = false;
				}
				if (info->info_ex.trust_direction != trustinfo.trust_direction) {
					torture_comment(tctx, "QueryTrustedDomainInfo of %s returned incorrect trust direction %d != %d\n",
					       trust_name, info->info_ex.trust_direction, trustinfo.trust_direction);
					ret = false;
				}
			}
		}
	}

	/* now that we have some domains to look over, we can test the enum calls */
	if (!test_EnumTrustDom(b, tctx, handle)) {
		torture_comment(tctx, "test_EnumTrustDom failed\n");
		ret = false;
	}

	if (!test_EnumTrustDomEx(b, tctx, handle)) {
		torture_comment(tctx, "test_EnumTrustDomEx failed\n");
		ret = false;
	}

	for (i=0; i<num_trusts; i++) {
		if (!test_DeleteTrustedDomainBySid(b, tctx, handle, domsid[i])) {
			torture_comment(tctx, "test_DeleteTrustedDomainBySid failed\n");
			ret = false;
		}
	}

	return ret;
}

static bool test_CreateTrustedDomainEx2(struct dcerpc_pipe *p,
					struct torture_context *tctx,
					struct policy_handle *handle,
					uint32_t num_trusts)
{
	return test_CreateTrustedDomainEx_common(p, tctx, handle, num_trusts, true);
}

static bool test_CreateTrustedDomainEx(struct dcerpc_pipe *p,
				       struct torture_context *tctx,
				       struct policy_handle *handle,
				       uint32_t num_trusts)
{
	return test_CreateTrustedDomainEx_common(p, tctx, handle, num_trusts, false);
}

static bool test_QueryDomainInfoPolicy(struct dcerpc_binding_handle *b,
				 struct torture_context *tctx,
				 struct policy_handle *handle)
{
	struct lsa_QueryDomainInformationPolicy r;
	union lsa_DomainInformationPolicy *info = NULL;
	int i;
	bool ret = true;

	if (torture_setting_bool(tctx, "samba3", false)) {
		torture_skip(tctx, "skipping QueryDomainInformationPolicy test\n");
	}

	torture_comment(tctx, "\nTesting QueryDomainInformationPolicy\n");

	for (i=2;i<4;i++) {
		r.in.handle = handle;
		r.in.level = i;
		r.out.info = &info;

		torture_comment(tctx, "\nTrying QueryDomainInformationPolicy level %d\n", i);

		torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryDomainInformationPolicy_r(b, tctx, &r),
			"QueryDomainInformationPolicy failed");

		/* If the server does not support EFS, then this is the correct return */
		if (i == LSA_DOMAIN_INFO_POLICY_EFS && NT_STATUS_EQUAL(r.out.result, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			continue;
		} else if (!NT_STATUS_IS_OK(r.out.result)) {
			torture_comment(tctx, "QueryDomainInformationPolicy failed - %s\n", nt_errstr(r.out.result));
			ret = false;
			continue;
		}
	}

	return ret;
}


static bool test_QueryInfoPolicyCalls(	bool version2,
					struct dcerpc_binding_handle *b,
					struct torture_context *tctx,
					struct policy_handle *handle)
{
	struct lsa_QueryInfoPolicy r;
	union lsa_PolicyInformation *info = NULL;
	int i;
	bool ret = true;
	const char *call = talloc_asprintf(tctx, "QueryInfoPolicy%s", version2 ? "2":"");

	torture_comment(tctx, "\nTesting %s\n", call);

	if (version2 && torture_setting_bool(tctx, "samba3", false)) {
		torture_skip(tctx, "skipping QueryInfoPolicy2 tests\n");
	}

	for (i=1;i<=14;i++) {
		r.in.handle = handle;
		r.in.level = i;
		r.out.info = &info;

		torture_comment(tctx, "\nTrying %s level %d\n", call, i);

		if (version2)
			/* We can perform the cast, because both types are
			   structurally equal */
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryInfoPolicy2_r(b, tctx,
				 (struct lsa_QueryInfoPolicy2*) &r),
				 "QueryInfoPolicy2 failed");
		else
			torture_assert_ntstatus_ok(tctx, dcerpc_lsa_QueryInfoPolicy_r(b, tctx, &r),
				"QueryInfoPolicy2 failed");

		switch (i) {
		case LSA_POLICY_INFO_MOD:
		case LSA_POLICY_INFO_AUDIT_FULL_SET:
		case LSA_POLICY_INFO_AUDIT_FULL_QUERY:
			if (!NT_STATUS_EQUAL(r.out.result, NT_STATUS_INVALID_PARAMETER)) {
				torture_comment(tctx, "Server should have failed level %u: %s\n", i, nt_errstr(r.out.result));
				ret = false;
			}
			break;
		case LSA_POLICY_INFO_DOMAIN:
		case LSA_POLICY_INFO_ACCOUNT_DOMAIN:
		case LSA_POLICY_INFO_REPLICA:
		case LSA_POLICY_INFO_QUOTA:
		case LSA_POLICY_INFO_ROLE:
		case LSA_POLICY_INFO_AUDIT_LOG:
		case LSA_POLICY_INFO_AUDIT_EVENTS:
		case LSA_POLICY_INFO_PD:
			if (!NT_STATUS_IS_OK(r.out.result)) {
				torture_comment(tctx, "%s failed - %s\n", call, nt_errstr(r.out.result));
				ret = false;
			}
			break;
		case LSA_POLICY_INFO_L_ACCOUNT_DOMAIN:
		case LSA_POLICY_INFO_DNS_INT:
		case LSA_POLICY_INFO_DNS:
			if (torture_setting_bool(tctx, "samba3", false)) {
				/* Other levels not implemented yet */
				if (!NT_STATUS_EQUAL(r.out.result, NT_STATUS_INVALID_INFO_CLASS)) {
					torture_comment(tctx, "%s failed - %s\n", call, nt_errstr(r.out.result));
					ret = false;
				}
			} else if (!NT_STATUS_IS_OK(r.out.result)) {
				torture_comment(tctx, "%s failed - %s\n", call, nt_errstr(r.out.result));
				ret = false;
			}
			break;
		default:
			if (torture_setting_bool(tctx, "samba4", false)) {
				/* Other levels not implemented yet */
				if (!NT_STATUS_EQUAL(r.out.result, NT_STATUS_INVALID_INFO_CLASS)) {
					torture_comment(tctx, "%s failed - %s\n", call, nt_errstr(r.out.result));
					ret = false;
				}
			} else if (!NT_STATUS_IS_OK(r.out.result)) {
				torture_comment(tctx, "%s failed - %s\n", call, nt_errstr(r.out.result));
				ret = false;
			}
			break;
		}

		if (NT_STATUS_IS_OK(r.out.result) && (i == LSA_POLICY_INFO_DNS
			|| i == LSA_POLICY_INFO_DNS_INT)) {
			/* Let's look up some of these names */

			struct lsa_TransNameArray tnames, dnames;
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
			ret &= test_LookupNames(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &tnames);

			/* Try to use in-forest search for the test machine */
			dnames.count = 1;
			dnames.names = talloc_zero_array(tctx, struct lsa_TranslatedName, dnames.count);
			dnames.names[0].name.string = talloc_asprintf(tctx, "%s\\"TEST_MACHINENAME "$", info->dns.name.string);
			dnames.names[0].sid_type = SID_NAME_USER;
			ret &= test_LookupNames(b, tctx, handle, LSA_LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY2, &dnames);
		}
	}

	return ret;
}

static bool test_QueryInfoPolicy(struct dcerpc_binding_handle *b,
				 struct torture_context *tctx,
				 struct policy_handle *handle)
{
	return test_QueryInfoPolicyCalls(false, b, tctx, handle);
}

static bool test_QueryInfoPolicy2(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx,
				  struct policy_handle *handle)
{
	return test_QueryInfoPolicyCalls(true, b, tctx, handle);
}

static bool test_GetUserName(struct dcerpc_binding_handle *b,
			     struct torture_context *tctx)
{
	struct lsa_GetUserName r;
	struct lsa_String *authority_name_p = NULL;
	struct lsa_String *account_name_p = NULL;

	torture_comment(tctx, "\nTesting GetUserName\n");

	r.in.system_name	= "\\";
	r.in.account_name	= &account_name_p;
	r.in.authority_name	= NULL;
	r.out.account_name	= &account_name_p;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_GetUserName_r(b, tctx, &r),
		"GetUserName failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"GetUserName result failed");
	torture_assert_not_null(tctx, r.out.account_name, "r.out.account_name");
	torture_assert_not_null(tctx, *r.out.account_name, "*r.out.account_name");
	torture_assert(tctx, r.out.authority_name == NULL, "r.out.authority_name");

	account_name_p = NULL;
	r.in.account_name	= &account_name_p;
	r.in.authority_name	= &authority_name_p;
	r.out.account_name	= &account_name_p;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_GetUserName_r(b, tctx, &r),
		"GetUserName failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"GetUserName result failed");
	torture_assert_not_null(tctx, r.out.account_name, "r.out.account_name");
	torture_assert_not_null(tctx, *r.out.account_name, "*r.out.account_name");
	torture_assert_not_null(tctx, r.out.authority_name, "r.out.authority_name");
	torture_assert_not_null(tctx, *r.out.authority_name, "*r.out.authority_name");

	torture_comment(tctx,
			"Account Name: %s, Authority Name: %s\n",
			(*r.out.account_name)->string,
			(*r.out.authority_name)->string);

	return true;
}

static bool test_GetUserName_fail(struct dcerpc_binding_handle *b,
				  struct torture_context *tctx)
{
	struct lsa_GetUserName r;
	struct lsa_String *account_name_p = NULL;
	NTSTATUS status;

	torture_comment(tctx, "\nTesting GetUserName_fail\n");

	r.in.system_name	= "\\";
	r.in.account_name	= &account_name_p;
	r.in.authority_name	= NULL;
	r.out.account_name	= &account_name_p;

	status = dcerpc_lsa_GetUserName_r(b, tctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			torture_comment(tctx,
					"GetUserName correctly returned with "
					"status: %s\n",
					nt_errstr(status));
			return true;
		}

		torture_assert_ntstatus_equal(tctx,
					      status,
					      NT_STATUS_ACCESS_DENIED,
					      "GetUserName return value should "
					      "be ACCESS_DENIED");
		return true;
	}

	if (!NT_STATUS_IS_OK(r.out.result)) {
		if (NT_STATUS_EQUAL(r.out.result, NT_STATUS_ACCESS_DENIED) ||
		    NT_STATUS_EQUAL(r.out.result, NT_STATUS_RPC_PROTSEQ_NOT_SUPPORTED)) {
			torture_comment(tctx,
					"GetUserName correctly returned with "
					"result: %s\n",
					nt_errstr(r.out.result));
			return true;
		}
	}

	torture_assert_ntstatus_equal(tctx,
				      r.out.result,
				      NT_STATUS_OK,
				      "GetUserName return value should be "
				      "ACCESS_DENIED");

	return false;
}

bool test_lsa_Close(struct dcerpc_binding_handle *b,
		    struct torture_context *tctx,
		    struct policy_handle *handle)
{
	struct lsa_Close r;
	struct policy_handle handle2;

	torture_comment(tctx, "\nTesting Close\n");

	r.in.handle = handle;
	r.out.handle = &handle2;

	torture_assert_ntstatus_ok(tctx, dcerpc_lsa_Close_r(b, tctx, &r),
		"Close failed");
	torture_assert_ntstatus_ok(tctx, r.out.result,
		"Close failed");

	torture_assert_ntstatus_equal(tctx, dcerpc_lsa_Close_r(b, tctx, &r),
		NT_STATUS_RPC_SS_CONTEXT_MISMATCH, "Close should failed");

	torture_comment(tctx, "\n");

	return true;
}

bool torture_rpc_lsa(struct torture_context *tctx)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	bool ret = true;
	struct policy_handle *handle = NULL;
	struct test_join *join = NULL;
	struct cli_credentials *machine_creds;
	struct dcerpc_binding_handle *b;
	enum dcerpc_transport_t transport;

	status = torture_rpc_connection(tctx, &p, &ndr_table_lsarpc);
	torture_assert_ntstatus_ok(tctx, status, "Error connecting to server");

	b = p->binding_handle;
	transport = dcerpc_binding_get_transport(p->binding);

	/* Test lsaLookupSids3 and lsaLookupNames4 over tcpip */
	if (transport == NCACN_IP_TCP) {
		if (!test_OpenPolicy_fail(b, tctx)) {
			ret = false;
		}

		if (!test_OpenPolicy2_fail(b, tctx)) {
			ret = false;
		}

		if (!test_many_LookupSids(p, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
			ret = false;
		}

		return ret;
	}

	if (!test_OpenPolicy(b, tctx)) {
		ret = false;
	}

	if (!test_lsa_OpenPolicy2(b, tctx, &handle)) {
		ret = false;
	}

	if (handle) {
		join = torture_join_domain(tctx, TEST_MACHINENAME, ACB_WSTRUST, &machine_creds);
		if (!join) {
			ret = false;
		}

		if (!test_LookupSids_async(b, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
			ret = false;
		}

		if (!test_QueryDomainInfoPolicy(b, tctx, handle)) {
			ret = false;
		}

		if (!test_CreateSecret(p, tctx, handle)) {
			ret = false;
		}

		if (!test_QueryInfoPolicy(b, tctx, handle)) {
			ret = false;
		}

		if (!test_QueryInfoPolicy2(b, tctx, handle)) {
			ret = false;
		}

		if (!test_Delete(b, tctx, handle)) {
			ret = false;
		}

		if (!test_many_LookupSids(p, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
			ret = false;
		}

		if (!test_lsa_Close(b, tctx, handle)) {
			ret = false;
		}

		torture_leave_domain(tctx, join);

	} else {
		if (!test_many_LookupSids(p, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
			ret = false;
		}
	}

	if (!test_GetUserName(b, tctx)) {
		ret = false;
	}

	return ret;
}

bool torture_rpc_lsa_get_user(struct torture_context *tctx)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	bool ret = true;
	struct dcerpc_binding_handle *b;
	enum dcerpc_transport_t transport;

	status = torture_rpc_connection(tctx, &p, &ndr_table_lsarpc);
	torture_assert_ntstatus_ok(tctx, status, "Error connecting to server");

	b = p->binding_handle;
	transport = dcerpc_binding_get_transport(p->binding);

	if (transport == NCACN_IP_TCP) {
		if (!test_GetUserName_fail(b, tctx)) {
			ret = false;
		}
		return ret;
	}

	if (!test_GetUserName(b, tctx)) {
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
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(p->binding);

	if (transport != NCACN_NP && transport != NCALRPC) {
		torture_comment(tctx, "testcase_LookupNames is only available "
				"over NCACN_NP or NCALRPC");
		return true;
	}

	if (!test_OpenPolicy(b, tctx)) {
		ret = false;
	}

	if (!test_lsa_OpenPolicy2(b, tctx, &handle)) {
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

	if (!test_LookupNames(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &tnames)) {
		ret = false;
	}

	tnames2.count = 1;
	tnames2.names = talloc_array(tctx, struct lsa_TranslatedName2, tnames2.count);
	ZERO_STRUCT(tnames2.names[0]);
	tnames2.names[0].name.string = "BUILTIN";
	tnames2.names[0].sid_type = SID_NAME_DOMAIN;

	if (!test_LookupNames2(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &tnames2, true)) {
		ret = false;
	}

	if (!test_LookupNames3(b, tctx, handle, LSA_LOOKUP_NAMES_ALL, &tnames2, true)) {
		ret = false;
	}

	if (!test_LookupNames_wellknown(b, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
		ret = false;
	}

	if (!test_LookupNames_NULL(b, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
		ret = false;
	}

	if (!test_LookupNames_bogus(b, tctx, handle, LSA_LOOKUP_NAMES_ALL)) {
		ret = false;
	}

	if (!test_lsa_Close(b, tctx, handle)) {
		ret = false;
	}

	return ret;
}

struct torture_suite *torture_rpc_lsa_lookup_names(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;

	suite = torture_suite_create(mem_ctx, "lsa.lookupnames");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "lsa",
						  &ndr_table_lsarpc);
	torture_rpc_tcase_add_test(tcase, "LookupNames",
				   testcase_LookupNames);

	return suite;
}

struct lsa_trustdom_state {
	uint32_t num_trusts;
};

static bool testcase_TrustedDomains(struct torture_context *tctx,
				    struct dcerpc_pipe *p,
				    void *data)
{
	bool ret = true;
	struct policy_handle *handle;
	struct lsa_trustdom_state *state =
		talloc_get_type_abort(data, struct lsa_trustdom_state);
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(p->binding);

	if (transport != NCACN_NP && transport != NCALRPC) {
		torture_comment(tctx, "testcase_TrustedDomains is only available "
				"over NCACN_NP or NCALRPC");
		return true;
	}

	torture_comment(tctx, "Testing %d domains\n", state->num_trusts);

	if (!test_OpenPolicy(b, tctx)) {
		ret = false;
	}

	if (!test_lsa_OpenPolicy2(b, tctx, &handle)) {
		ret = false;
	}

	if (!handle) {
		ret = false;
	}

	if (!test_CreateTrustedDomain(b, tctx, handle, state->num_trusts)) {
		ret = false;
	}

	if (!test_CreateTrustedDomainEx(p, tctx, handle, state->num_trusts)) {
		ret = false;
	}

	if (!test_CreateTrustedDomainEx2(p, tctx, handle, state->num_trusts)) {
		ret = false;
	}

	if (!test_lsa_Close(b, tctx, handle)) {
		ret = false;
	}

	return ret;
}

struct torture_suite *torture_rpc_lsa_trusted_domains(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;
	struct lsa_trustdom_state *state;

	state = talloc(mem_ctx, struct lsa_trustdom_state);

	state->num_trusts = 12;

	suite = torture_suite_create(mem_ctx, "lsa.trusted.domains");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "lsa",
						  &ndr_table_lsarpc);
	torture_rpc_tcase_add_test_ex(tcase, "TrustedDomains",
				      testcase_TrustedDomains,
				      state);

	return suite;
}

static bool testcase_Privileges(struct torture_context *tctx,
				struct dcerpc_pipe *p)
{
	struct policy_handle *handle;
	struct dcerpc_binding_handle *b = p->binding_handle;
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(p->binding);

	if (transport != NCACN_NP && transport != NCALRPC) {
		torture_skip(tctx, "testcase_Privileges is only available "
				"over NCACN_NP or NCALRPC");
	}

	if (!test_OpenPolicy(b, tctx)) {
		return false;
	}

	if (!test_lsa_OpenPolicy2(b, tctx, &handle)) {
		return false;
	}

	if (!handle) {
		return false;
	}

	if (!test_CreateAccount(b, tctx, handle)) {
		return false;
	}

	if (!test_EnumAccounts(b, tctx, handle)) {
		return false;
	}

	if (!test_EnumPrivs(b, tctx, handle)) {
		return false;
	}

	if (!test_lsa_Close(b, tctx, handle)) {
		return false;
	}

	return true;
}


struct torture_suite *torture_rpc_lsa_privileges(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite;
	struct torture_rpc_tcase *tcase;

	suite = torture_suite_create(mem_ctx, "lsa.privileges");

	tcase = torture_suite_add_rpc_iface_tcase(suite, "lsa",
						  &ndr_table_lsarpc);
	torture_rpc_tcase_add_test(tcase, "Privileges",
				   testcase_Privileges);

	return suite;
}
