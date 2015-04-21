/*
   Unix SMB/CIFS implementation.
   test suite for mgmt rpc operations

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
#include "librpc/gen_ndr/ndr_mgmt_c.h"
#include "auth/gensec/gensec.h"
#include "librpc/ndr/ndr_table.h"
#include "torture/rpc/torture_rpc.h"
#include "param/param.h"


/*
  ask the server what interface IDs are available on this endpoint
*/
bool test_inq_if_ids(struct torture_context *tctx,
		     struct dcerpc_binding_handle *b,
		     TALLOC_CTX *mem_ctx,
		     bool (*per_id_test)(struct torture_context *,
					 const struct ndr_interface_table *iface,
					 TALLOC_CTX *mem_ctx,
					 struct ndr_syntax_id *id),
		     const void *priv)
{
	struct mgmt_inq_if_ids r;
	struct rpc_if_id_vector_t *vector;
	int i;

	vector = talloc(mem_ctx, struct rpc_if_id_vector_t);
	r.out.if_id_vector = &vector;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_mgmt_inq_if_ids_r(b, mem_ctx, &r),
		"inq_if_ids failed");

	torture_assert_werr_ok(tctx,
		r.out.result,
		"inq_if_ids gave unexpected error code");

	if (!vector) {
		torture_comment(tctx, "inq_if_ids gave NULL if_id_vector\n");
		return false;
	}

	for (i=0;i<vector->count;i++) {
		struct ndr_syntax_id *id = vector->if_id[i].id;
		if (!id) continue;

		torture_comment(tctx, "\tuuid %s  version 0x%08x  '%s'\n",
		       GUID_string(mem_ctx, &id->uuid),
		       id->if_version,
		       ndr_interface_name(&id->uuid, id->if_version));

		if (per_id_test) {
			per_id_test(tctx, priv, mem_ctx, id);
		}
	}

	return true;
}

static bool test_inq_stats(struct torture_context *tctx,
			   struct dcerpc_binding_handle *b,
			   TALLOC_CTX *mem_ctx)
{
	struct mgmt_inq_stats r;
	struct mgmt_statistics statistics;

	r.in.max_count = MGMT_STATS_ARRAY_MAX_SIZE;
	r.in.unknown = 0;
	r.out.statistics = &statistics;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_mgmt_inq_stats_r(b, mem_ctx, &r),
		"inq_stats failed");

	if (statistics.count != MGMT_STATS_ARRAY_MAX_SIZE) {
		torture_comment(tctx, "Unexpected array size %d\n", statistics.count);
		return false;
	}

	torture_comment(tctx, "\tcalls_in %6d  calls_out %6d\n\tpkts_in  %6d  pkts_out  %6d\n",
	       statistics.statistics[MGMT_STATS_CALLS_IN],
	       statistics.statistics[MGMT_STATS_CALLS_OUT],
	       statistics.statistics[MGMT_STATS_PKTS_IN],
	       statistics.statistics[MGMT_STATS_PKTS_OUT]);

	return true;
}

static bool test_inq_princ_name_size(struct torture_context *tctx,
				     struct dcerpc_binding_handle *b,
				     uint32_t authn_proto,
				     const char *expected_princ_name)
{
	struct mgmt_inq_princ_name r;
	uint32_t len, i;

	len = strlen(expected_princ_name);

	r.in.authn_proto = authn_proto;

	/*
	 * 0 gives NT_STATUS_RPC_BAD_STUB_DATA
	 */

	for (i=1; i <= len; i++) {
		r.in.princ_name_size = i;

		torture_assert_ntstatus_ok(tctx,
			dcerpc_mgmt_inq_princ_name_r(b, tctx, &r),
			"mgmt_inq_princ_name failed");
		torture_assert_werr_equal(tctx,
			r.out.result,
			WERR_INSUFFICIENT_BUFFER,
			"mgmt_inq_princ_name failed");
	}

	r.in.princ_name_size = len + 1;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_mgmt_inq_princ_name_r(b, tctx, &r),
		"mgmt_inq_princ_name failed");
	torture_assert_werr_ok(tctx,
		r.out.result,
		"mgmt_inq_princ_name failed");

	return true;
}

static bool test_inq_princ_name(struct torture_context *tctx,
				struct dcerpc_binding_handle *b,
				TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_inq_princ_name r;
	int i;
	bool ret = false;

	for (i=0;i<256;i++) {
		r.in.authn_proto = i;  /* DCERPC_AUTH_TYPE_* */
		r.in.princ_name_size = 100;

		status = dcerpc_mgmt_inq_princ_name_r(b, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			const char *name = gensec_get_name_by_authtype(NULL, i);
			ret = true;
			if (name) {
				torture_comment(tctx, "\tprinciple name for proto %u (%s) is '%s'\n",
				       i, name, r.out.princ_name);
			} else {
				torture_comment(tctx, "\tprinciple name for proto %u is '%s'\n",
				       i, r.out.princ_name);
			}

			switch (i) {
			case DCERPC_AUTH_TYPE_KRB5:
			case DCERPC_AUTH_TYPE_NTLMSSP:
			case DCERPC_AUTH_TYPE_SPNEGO:
				torture_assert(tctx,
					test_inq_princ_name_size(tctx, b, i, r.out.princ_name),
					"failed");
				break;
			case DCERPC_AUTH_TYPE_SCHANNEL:
				/*
				 * for some reason schannel behaves differently
				 *
				 */
			default:
				break;
			}
		}
	}

	if (!ret) {
		torture_comment(tctx, "\tno principle names?\n");
	}

	return true;
}

static bool test_is_server_listening(struct torture_context *tctx,
				     struct dcerpc_binding_handle *b,
				     TALLOC_CTX *mem_ctx)
{
	struct mgmt_is_server_listening r;
	r.out.status = talloc(mem_ctx, uint32_t);

	torture_assert_ntstatus_ok(tctx,
		dcerpc_mgmt_is_server_listening_r(b, mem_ctx, &r),
		"is_server_listening failed");

	if (*r.out.status != 0 || r.out.result == 0) {
		torture_comment(tctx, "\tserver is NOT listening\n");
	} else {
		torture_comment(tctx, "\tserver is listening\n");
	}

	return true;
}

static bool test_stop_server_listening(struct torture_context *tctx,
				       struct dcerpc_binding_handle *b,
				       TALLOC_CTX *mem_ctx)
{
	struct mgmt_stop_server_listening r;

	torture_assert_ntstatus_ok(tctx,
		dcerpc_mgmt_stop_server_listening_r(b, mem_ctx, &r),
		"stop_server_listening failed");

	if (!W_ERROR_IS_OK(r.out.result)) {
		torture_comment(tctx, "\tserver refused to stop listening - %s\n", win_errstr(r.out.result));
	} else {
		torture_comment(tctx, "\tserver allowed a stop_server_listening request\n");
		return false;
	}

	return true;
}


bool torture_rpc_mgmt(struct torture_context *tctx)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx, *loop_ctx;
	bool ret = true;
	const struct ndr_interface_list *l;
	struct dcerpc_binding *b;

	mem_ctx = talloc_init("torture_rpc_mgmt");

	status = torture_rpc_binding(tctx, &b);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return false;
	}

	for (l=ndr_table_list();l;l=l->next) {
		struct dcerpc_binding_handle *bh;

		loop_ctx = talloc_named(mem_ctx, 0, "torture_rpc_mgmt loop context");

		/* some interfaces are not mappable */
		if (l->table->num_calls == 0 ||
		    strcmp(l->table->name, "mgmt") == 0) {
			talloc_free(loop_ctx);
			continue;
		}

		torture_comment(tctx, "\nTesting pipe '%s'\n", l->table->name);

		status = dcerpc_epm_map_binding(loop_ctx, b, l->table,
						tctx->ev, tctx->lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			torture_comment(tctx, "Failed to map port for uuid %s\n",
				   GUID_string(loop_ctx, &l->table->syntax_id.uuid));
			talloc_free(loop_ctx);
			continue;
		}

		lpcfg_set_cmdline(tctx->lp_ctx, "torture:binding", dcerpc_binding_string(loop_ctx, b));

		status = torture_rpc_connection(tctx, &p, &ndr_table_mgmt);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			torture_comment(tctx, "Interface not available - skipping\n");
			talloc_free(loop_ctx);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(loop_ctx);
			torture_comment(tctx, "Interface not available (%s) - skipping\n", nt_errstr(status));
			ret = false;
			continue;
		}
		bh = p->binding_handle;

		if (!test_is_server_listening(tctx, bh, loop_ctx)) {
			ret = false;
		}

		if (!test_stop_server_listening(tctx, bh, loop_ctx)) {
			ret = false;
		}

		if (!test_inq_stats(tctx, bh, loop_ctx)) {
			ret = false;
		}

		if (!test_inq_princ_name(tctx, bh, loop_ctx)) {
			ret = false;
		}

		if (!test_inq_if_ids(tctx, bh, loop_ctx, NULL, NULL)) {
			ret = false;
		}

	}

	return ret;
}
