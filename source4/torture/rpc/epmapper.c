/* 
   Unix SMB/CIFS implementation.
   test suite for epmapper rpc operations

   Copyright (C) Andrew Tridgell 2003
   
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
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/ndr/ndr_table.h"
#include "librpc/rpc/dcerpc_proto.h"
#include "torture/rpc/torture_rpc.h"


/*
  display any protocol tower
 */
static void display_tower(struct torture_context *tctx, struct epm_tower *twr)
{
	int i;

	for (i = 0; i < twr->num_floors; i++) {
		torture_comment(tctx,
				" %s",
				epm_floor_string(tctx, &twr->floors[i]));
	}
	torture_comment(tctx, "\n");
}

static bool test_Map(struct dcerpc_binding_handle *b,
		     struct torture_context *tctx,
		     struct epm_twr_t *twr)
{
	NTSTATUS status;
	struct epm_Map r;
	struct GUID uuid;
	struct policy_handle handle;
	struct ndr_syntax_id syntax;
	uint32_t num_towers;
	uint32_t i;

	ZERO_STRUCT(uuid);
	ZERO_STRUCT(handle);

	r.in.object = &uuid;
	r.in.map_tower = twr;
	r.in.entry_handle = &handle;
	r.out.entry_handle = &handle;
	r.in.max_towers = 10;
	r.out.num_towers = &num_towers;

	dcerpc_floor_get_lhs_data(&twr->tower.floors[0], &syntax);

	torture_comment(tctx,
			"epm_Map results for '%s':\n",
			ndr_interface_name(&syntax.uuid, syntax.if_version));

	/* RPC protocol identifier */
	twr->tower.floors[2].lhs.protocol = EPM_PROTOCOL_NCACN;
	twr->tower.floors[2].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[2].rhs.ncacn.minor_version = 0;

	/* Port address */
	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_TCP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.tcp.port = 0;

	/* Transport */
	twr->tower.floors[4].lhs.protocol = EPM_PROTOCOL_IP;
	twr->tower.floors[4].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[4].rhs.ip.ipaddr = "0.0.0.0";

	status = dcerpc_epm_Map_r(b, tctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(tctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_HTTP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.http.port = 0;

	status = dcerpc_epm_Map_r(b, tctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(tctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_UDP;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.http.port = 0;

	status = dcerpc_epm_Map_r(b, tctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i=0;i<*r.out.num_towers;i++) {
			if (r.out.towers[i].twr) {
				display_tower(tctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	twr->tower.floors[3].lhs.protocol = EPM_PROTOCOL_SMB;
	twr->tower.floors[3].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[3].rhs.smb.unc = "";

	twr->tower.floors[4].lhs.protocol = EPM_PROTOCOL_NETBIOS;
	twr->tower.floors[4].lhs.lhs_data = data_blob(NULL, 0);
	twr->tower.floors[4].rhs.netbios.name = "";

	status = dcerpc_epm_Map_r(b, tctx, &r);
	if (NT_STATUS_IS_OK(status) && r.out.result == 0) {
		for (i = 0; i < *r.out.num_towers; i++) {
			if (r.out.towers[i].twr) {
				display_tower(tctx, &r.out.towers[i].twr->tower);
			}
		}
	}

	/* FIXME: Extend to do other protocols as well (ncacn_unix_stream, ncalrpc) */

	return true;
}

static bool test_Map_simple(struct torture_context *tctx,
			    struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct policy_handle entry_handle;
	uint32_t num_ents = 0;
	struct dcerpc_binding_handle *h = p->binding_handle;

	ZERO_STRUCT(entry_handle);

	torture_comment(tctx, "Testing epm_Map\n");

	/* get all elements */
	r.in.inquiry_type = RPC_C_EP_ALL_ELTS;
	r.in.object = NULL;
	r.in.interface_id = NULL;
	r.in.vers_option = RPC_C_VERS_ALL;

	r.in.entry_handle = &entry_handle;
	r.in.max_ents = 10;

	r.out.entry_handle = &entry_handle;
	r.out.num_ents = &num_ents;

	do {
		int i;

		status = dcerpc_epm_Lookup_r(h, tctx, &r);
		if (!NT_STATUS_IS_OK(status) ||
		    r.out.result != EPMAPPER_STATUS_OK) {
			break;
		}

		for (i = 0; i < *r.out.num_ents; i++) {
			if (r.out.entries[i].tower->tower.num_floors == 5) {
				test_Map(h, tctx, r.out.entries[i].tower);
			}
		}
	} while (NT_STATUS_IS_OK(status) &&
		 r.out.result == EPMAPPER_STATUS_OK &&
		 *r.out.num_ents == r.in.max_ents &&
		 !policy_handle_empty(&entry_handle));

	torture_assert_ntstatus_ok(tctx, status, "epm_Map_simple failed");

	torture_assert(tctx,
		       policy_handle_empty(&entry_handle),
		       "epm_Map_simple failed - The policy handle should be emtpy.");

	return true;
}

static bool test_LookupHandleFree(struct torture_context *tctx,
				  struct dcerpc_binding_handle *h,
				  struct policy_handle *entry_handle) {
	NTSTATUS status;
	struct epm_LookupHandleFree r;

	if (torture_setting_bool(tctx, "samba4", false)) {
		torture_skip(tctx, "Skip Insert test against Samba4");
	}

	if (policy_handle_empty(entry_handle)) {
		torture_comment(tctx,
				"epm_LookupHandleFree failed - empty policy_handle\n");
		return false;
	}

	r.in.entry_handle = entry_handle;
	r.out.entry_handle = entry_handle;

	status = dcerpc_epm_LookupHandleFree_r(h, tctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		torture_comment(tctx,
				"epm_LookupHandleFree failed - %s\n",
				nt_errstr(status));
		return false;
	}

	if (r.out.result != EPMAPPER_STATUS_OK) {
		torture_comment(tctx,
				"epm_LookupHandleFree failed - internal error: "
				"0x%.4x\n",
				r.out.result);
		return false;
	}

	return true;
}

static bool test_Lookup_simple(struct torture_context *tctx,
			       struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct policy_handle entry_handle;
	uint32_t num_ents = 0;
	struct dcerpc_binding_handle *h = p->binding_handle;

	ZERO_STRUCT(entry_handle);

	torture_comment(tctx, "Testing epm_Lookup\n");

	/* get all elements */
	r.in.inquiry_type = RPC_C_EP_ALL_ELTS;
	r.in.object = NULL;
	r.in.interface_id = NULL;
	r.in.vers_option = RPC_C_VERS_ALL;

	r.in.entry_handle = &entry_handle;
	r.in.max_ents = 10;

	r.out.entry_handle = &entry_handle;
	r.out.num_ents = &num_ents;

	do {
		int i;

		status = dcerpc_epm_Lookup_r(h, tctx, &r);
		if (!NT_STATUS_IS_OK(status) ||
		    r.out.result != EPMAPPER_STATUS_OK) {
			break;
		}

		torture_comment(tctx,
				"epm_Lookup returned %d events, entry_handle: %s\n",
				*r.out.num_ents,
				GUID_string(tctx, &entry_handle.uuid));

		for (i = 0; i < *r.out.num_ents; i++) {
			torture_comment(tctx,
					"\n  Found '%s'\n",
					r.out.entries[i].annotation);

			display_tower(tctx, &r.out.entries[i].tower->tower);
		}
	} while (NT_STATUS_IS_OK(status) &&
		 r.out.result == EPMAPPER_STATUS_OK &&
		 *r.out.num_ents == r.in.max_ents &&
		 !policy_handle_empty(&entry_handle));

	torture_assert_ntstatus_ok(tctx, status, "epm_Lookup failed");
	torture_assert(tctx, r.out.result == EPMAPPER_STATUS_NO_MORE_ENTRIES, "epm_Lookup failed");

	torture_assert(tctx,
		       policy_handle_empty(&entry_handle),
		       "epm_Lookup failed - The policy handle should be emtpy.");

	return true;
}

/*
 * This test starts a epm_Lookup request, but doesn't finish the
 * call terminates the search. So it will call epm_LookupHandleFree.
 */
static bool test_Lookup_terminate_search(struct torture_context *tctx,
					 struct dcerpc_pipe *p)
{
	bool ok;
	NTSTATUS status;
	struct epm_Lookup r;
	struct policy_handle entry_handle;
	uint32_t i, num_ents = 0;
	struct dcerpc_binding_handle *h = p->binding_handle;

	ZERO_STRUCT(entry_handle);

	torture_comment(tctx, "Testing epm_Lookup and epm_LookupHandleFree\n");

	/* get all elements */
	r.in.inquiry_type = RPC_C_EP_ALL_ELTS;
	r.in.object = NULL;
	r.in.interface_id = NULL;
	r.in.vers_option = RPC_C_VERS_ALL;

	r.in.entry_handle = &entry_handle;
	r.in.max_ents = 2;

	r.out.entry_handle = &entry_handle;
	r.out.num_ents = &num_ents;

	status = dcerpc_epm_Lookup_r(h, tctx, &r);

	torture_assert_ntstatus_ok(tctx, status, "epm_Lookup failed");
	torture_assert(tctx, r.out.result == EPMAPPER_STATUS_OK, "epm_Lookup failed");

	torture_comment(tctx,
			"epm_Lookup returned %d events, entry_handle: %s\n",
			*r.out.num_ents,
			GUID_string(tctx, &entry_handle.uuid));

	for (i = 0; i < *r.out.num_ents; i++) {
		torture_comment(tctx,
				"\n  Found '%s'\n",
				r.out.entries[i].annotation);
	}

	ok = test_LookupHandleFree(tctx,
				   h,
				   &entry_handle);
	if (!ok) {
		return false;
	}

	return true;
}

static bool test_Delete(struct torture_context *tctx,
			struct dcerpc_binding_handle *h,
			struct epm_entry_t *entries)
{
	NTSTATUS status;
	struct epm_Delete r;

	r.in.num_ents = 1;
	r.in.entries = entries;

	status = dcerpc_epm_Delete_r(h, tctx, &r);
	if (NT_STATUS_IS_ERR(status)) {
		torture_comment(tctx,
				"epm_Delete failed - %s\n",
				nt_errstr(status));
		return false;
	}

	if (r.out.result != EPMAPPER_STATUS_OK) {
		torture_comment(tctx,
				"epm_Delete failed - internal error: 0x%.4x\n",
				r.out.result);
		return false;
	}

	return true;
}

static bool test_Insert_noreplace(struct torture_context *tctx,
				  struct dcerpc_pipe *p)
{
	bool ok;
	NTSTATUS status;
	struct epm_Insert r;
	struct dcerpc_binding *b;
	struct dcerpc_binding_handle *h = p->binding_handle;

	torture_comment(tctx, "Testing epm_Insert(noreplace) and epm_Delete\n");

	if (torture_setting_bool(tctx, "samba4", false)) {
		torture_skip(tctx, "Skip Insert test against Samba4");
	}

	r.in.num_ents = 1;
	r.in.entries = talloc_array(tctx, struct epm_entry_t, 1);

	ZERO_STRUCT(r.in.entries[0].object);
	r.in.entries[0].annotation = "smbtorture endpoint";

	status = dcerpc_parse_binding(tctx, "ncalrpc:[SMBTORTURE]", &b);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "Unable to generate dcerpc_binding struct");

	r.in.entries[0].tower = talloc(tctx, struct epm_twr_t);

	status = dcerpc_binding_build_tower(tctx,
					    b,
					    &r.in.entries[0].tower->tower);
	torture_assert_ntstatus_ok(tctx,
				   status,
				   "Unable to build tower from binding struct");
	r.in.replace = 0;

	status = dcerpc_epm_Insert_r(h, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "epm_Insert failed");

	torture_assert(tctx, r.out.result == 0, "epm_Insert failed");

	ok = test_Delete(tctx, h, r.in.entries);
	if (!ok) {
		return false;
	}

	return true;
}

#if 0
/*
 * The MS-RPCE documentation states that this function isn't implemented and
 * SHOULD NOT be called by a client.
 */
static bool test_InqObject(struct torture_context *tctx, struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct epm_InqObject r;
	struct dcerpc_binding_handle *b = p->binding_handle;

	r.in.epm_object = talloc(tctx, struct GUID);
	*r.in.epm_object = ndr_table_epmapper.syntax_id.uuid;

	status = dcerpc_epm_InqObject_r(b, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "InqObject failed");

	return true;
}
#endif

struct torture_suite *torture_rpc_epmapper(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "epmapper");
	struct torture_rpc_tcase *tcase;

	tcase = torture_suite_add_rpc_iface_tcase(suite,
						  "epmapper",
						  &ndr_table_epmapper);

	torture_rpc_tcase_add_test(tcase,
				   "Insert_noreplace",
				   test_Insert_noreplace);
	torture_rpc_tcase_add_test(tcase,
				   "Lookup_terminate_search",
				   test_Lookup_terminate_search);
	torture_rpc_tcase_add_test(tcase,
				   "Lookup_simple",
				   test_Lookup_simple);
	torture_rpc_tcase_add_test(tcase,
				   "Map_simple",
				   test_Map_simple);


	return suite;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
