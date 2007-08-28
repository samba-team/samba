/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc lookup operations

   Copyright (C) Volker Lendecke 2006
   
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
#include "lib/events/events.h"
#include "libnet/libnet_join.h"
#include "torture/rpc/rpc.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"
#include "libcli/security/security.h"

static BOOL open_policy(TALLOC_CTX *mem_ctx, struct dcerpc_pipe *p,
			struct policy_handle **handle)
{
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 r;
	NTSTATUS status;

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

	return NT_STATUS_IS_OK(status);
}

static BOOL get_domainsid(TALLOC_CTX *mem_ctx, struct dcerpc_pipe *p,
			  struct policy_handle *handle,
			  struct dom_sid **sid)
{
	struct lsa_QueryInfoPolicy r;
	NTSTATUS status;

	r.in.level = LSA_POLICY_INFO_DOMAIN;
	r.in.handle = handle;

	status = dcerpc_lsa_QueryInfoPolicy(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) return False;

	*sid = r.out.info->domain.sid;
	return True;
}

static NTSTATUS lookup_sids(TALLOC_CTX *mem_ctx, uint16_t level,
			    struct dcerpc_pipe *p,
			    struct policy_handle *handle,
			    struct dom_sid **sids, uint32_t num_sids,
			    struct lsa_TransNameArray *names)
{
	struct lsa_LookupSids r;
	struct lsa_SidArray sidarray;
	uint32_t count = 0;
	uint32_t i;

	names->count = 0;
	names->names = NULL;

	sidarray.num_sids = num_sids;
	sidarray.sids = talloc_array(mem_ctx, struct lsa_SidPtr, num_sids);

	for (i=0; i<num_sids; i++) {
		sidarray.sids[i].sid = sids[i];
	}

	r.in.handle = handle;
	r.in.sids = &sidarray;
	r.in.names = names;
	r.in.level = level;
	r.in.count = &count;
	r.out.names = names;
	r.out.count = &count;

	return dcerpc_lsa_LookupSids(p, mem_ctx, &r);
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
	}
	return "Invalid sid type\n";
}

static BOOL test_lookupsids(TALLOC_CTX *mem_ctx, struct dcerpc_pipe *p,
			    struct policy_handle *handle,
			    struct dom_sid **sids, uint32_t num_sids,
			    int level, NTSTATUS expected_result, 
			    enum lsa_SidType *types)
{
	struct lsa_TransNameArray names;
	NTSTATUS status;
	uint32_t i;
	BOOL ret = True;

	status = lookup_sids(mem_ctx, level, p, handle, sids, num_sids,
			     &names);
	if (!NT_STATUS_EQUAL(status, expected_result)) {
		printf("For level %d expected %s, got %s\n",
		       level, nt_errstr(expected_result),
		       nt_errstr(status));
		return False;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OK) &&
	    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		return True;
	}

	for (i=0; i<num_sids; i++) {
		if (names.names[i].sid_type != types[i]) {
			printf("In level %d, for sid %s expected %s, "
			       "got %s\n", level,
			       dom_sid_string(mem_ctx, sids[i]),
			       sid_type_lookup(types[i]),
			       sid_type_lookup(names.names[i].sid_type));
			ret = False;
		}
	}
	return ret;
}

static BOOL get_downleveltrust(TALLOC_CTX *mem_ctx, struct dcerpc_pipe *p,
			       struct policy_handle *handle,
			       struct dom_sid **sid)
{
	struct lsa_EnumTrustDom r;
	uint32_t resume_handle = 0;
	struct lsa_DomainList domains;
	NTSTATUS status;
	int i;

	r.in.handle = handle;
	r.in.resume_handle = &resume_handle;
	r.in.max_size = 1000;
	r.out.domains = &domains;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_lsa_EnumTrustDom(p, mem_ctx, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		printf("no trusts\n");
		return False;
	}

	if (domains.count == 0) {
		printf("no trusts\n");
		return False;
	}

	for (i=0; i<domains.count; i++) {
		struct lsa_QueryTrustedDomainInfoBySid q;

		if (domains.domains[i].sid == NULL)
			continue;

		q.in.handle = handle;
		q.in.dom_sid = domains.domains[i].sid;
		q.in.level = 6;
		status = dcerpc_lsa_QueryTrustedDomainInfoBySid(p, mem_ctx, &q);
		if (!NT_STATUS_IS_OK(status)) continue;

		if ((q.out.info->info_ex.trust_direction & 2) &&
		    (q.out.info->info_ex.trust_type == 1)) {
			*sid = domains.domains[i].sid;
			return True;
		}
	}

	printf("I need a AD DC with an outgoing trust to NT4\n");
	return False;
}

#define NUM_SIDS 8

BOOL torture_rpc_lsa_lookup(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx;
	BOOL ret = True;
	struct policy_handle *handle;
	struct dom_sid *dom_sid;
	struct dom_sid *trusted_sid;
	struct dom_sid *sids[NUM_SIDS];

	mem_ctx = talloc_init("torture_rpc_lsa");

	status = torture_rpc_connection(torture, &p, &ndr_table_lsarpc);
	if (!NT_STATUS_IS_OK(status)) {
		ret = False;
		goto done;
	}

	ret &= open_policy(mem_ctx, p, &handle);
	if (!ret) goto done;

	ret &= get_domainsid(mem_ctx, p, handle, &dom_sid);
	if (!ret) goto done;

	ret &= get_downleveltrust(mem_ctx, p, handle, &trusted_sid);
	if (!ret) goto done;

	printf("domain sid: %s\n", dom_sid_string(mem_ctx, dom_sid));

	sids[0] = dom_sid_parse_talloc(mem_ctx, "S-1-1-0");
	sids[1] = dom_sid_parse_talloc(mem_ctx, "S-1-5-4");
	sids[2] = dom_sid_parse_talloc(mem_ctx, "S-1-5-32");
	sids[3] = dom_sid_parse_talloc(mem_ctx, "S-1-5-32-545");
	sids[4] = dom_sid_dup(mem_ctx, dom_sid);
	sids[5] = dom_sid_add_rid(mem_ctx, dom_sid, 512);
	sids[6] = dom_sid_dup(mem_ctx, trusted_sid);
	sids[7] = dom_sid_add_rid(mem_ctx, trusted_sid, 512);

	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 0,
			       NT_STATUS_INVALID_PARAMETER, NULL);

	{
		enum lsa_SidType types[NUM_SIDS] =
			{ SID_NAME_WKN_GRP, SID_NAME_WKN_GRP, SID_NAME_DOMAIN,
			  SID_NAME_ALIAS, SID_NAME_DOMAIN, SID_NAME_DOM_GRP,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP };

		ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 1,
				       NT_STATUS_OK, types);
	}

	{
		enum lsa_SidType types[NUM_SIDS] =
			{ SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP };
		ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 2,
				       STATUS_SOME_UNMAPPED, types);
	}

	{
		enum lsa_SidType types[NUM_SIDS] =
			{ SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN };
		ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 3,
				       STATUS_SOME_UNMAPPED, types);
	}

	{
		enum lsa_SidType types[NUM_SIDS] =
			{ SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN };
		ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 4,
				       STATUS_SOME_UNMAPPED, types);
	}

	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 5,
			       NT_STATUS_NONE_MAPPED, NULL);

	{
		enum lsa_SidType types[NUM_SIDS] =
			{ SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN,
			  SID_NAME_DOMAIN, SID_NAME_DOM_GRP,
			  SID_NAME_UNKNOWN, SID_NAME_UNKNOWN };
		ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 6,
				       STATUS_SOME_UNMAPPED, types);
	}

	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 7,
			       NT_STATUS_INVALID_PARAMETER, NULL);
	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 8,
			       NT_STATUS_INVALID_PARAMETER, NULL);
	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 9,
			       NT_STATUS_INVALID_PARAMETER, NULL);
	ret &= test_lookupsids(mem_ctx, p, handle, sids, NUM_SIDS, 10,
			       NT_STATUS_INVALID_PARAMETER, NULL);

 done:
	talloc_free(mem_ctx);

	return ret;
}
