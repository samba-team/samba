/* 
   Unix SMB/CIFS implementation.
   test suite for mgmt rpc operations

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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_mgmt_c.h"
#include "auth/gensec/gensec.h"
#include "librpc/rpc/dcerpc_table.h"
#include "torture/rpc/rpc.h"


/*
  ask the server what interface IDs are available on this endpoint
*/
BOOL test_inq_if_ids(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx,
		     BOOL (*per_id_test)(const struct dcerpc_interface_table *iface,
					 TALLOC_CTX *mem_ctx,
					 struct dcerpc_syntax_id *id),
		     const void *priv)
{
	NTSTATUS status;
	struct mgmt_inq_if_ids r;
	struct rpc_if_id_vector_t *vector;
	int i;

	vector = talloc(mem_ctx, struct rpc_if_id_vector_t);
	r.out.if_id_vector = &vector;
	
	status = dcerpc_mgmt_inq_if_ids(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("inq_if_ids failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("inq_if_ids gave error code %s\n", win_errstr(r.out.result));
		return False;
	}

	if (!vector) {
		printf("inq_if_ids gave NULL if_id_vector\n");
		return False;
	}

	for (i=0;i<vector->count;i++) {
		struct dcerpc_syntax_id *id = vector->if_id[i].id;
		if (!id) continue;

		printf("\tuuid %s  version 0x%08x  '%s'\n",
		       GUID_string(mem_ctx, &id->uuid),
		       id->if_version, idl_pipe_name(&id->uuid, id->if_version));

		if (per_id_test) {
			per_id_test(priv, mem_ctx, id);
		}
	}

	return True;
}

static BOOL test_inq_stats(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_inq_stats r;
	struct mgmt_statistics statistics;

	r.in.max_count = MGMT_STATS_ARRAY_MAX_SIZE;
	r.in.unknown = 0;
	r.out.statistics = &statistics;

	status = dcerpc_mgmt_inq_stats(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("inq_stats failed - %s\n", nt_errstr(status));
		return False;
	}

	if (statistics.count != MGMT_STATS_ARRAY_MAX_SIZE) {
		printf("Unexpected array size %d\n", statistics.count);
		return False;
	}

	printf("\tcalls_in %6d  calls_out %6d\n\tpkts_in  %6d  pkts_out  %6d\n",
	       statistics.statistics[MGMT_STATS_CALLS_IN],
	       statistics.statistics[MGMT_STATS_CALLS_OUT],
	       statistics.statistics[MGMT_STATS_PKTS_IN],
	       statistics.statistics[MGMT_STATS_PKTS_OUT]);

	return True;
}

static BOOL test_inq_princ_name(struct dcerpc_pipe *p, 
				TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_inq_princ_name r;
	int i;
	BOOL ret = False;

	for (i=0;i<100;i++) {
		r.in.authn_proto = i;  /* DCERPC_AUTH_TYPE_* */
		r.in.princ_name_size = 100;

		status = dcerpc_mgmt_inq_princ_name(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status)) {
			continue;
		}
		if (W_ERROR_IS_OK(r.out.result)) {
			const char *name = gensec_get_name_by_authtype(i);
			ret = True;
			if (name) {
				printf("\tprinciple name for proto %u (%s) is '%s'\n", 
				       i, name, r.out.princ_name);
			} else {
				printf("\tprinciple name for proto %u is '%s'\n", 
				       i, r.out.princ_name);
			}
		}
	}

	if (!ret) {
		printf("\tno principle names?\n");
	}

	return True;
}

static BOOL test_is_server_listening(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_is_server_listening r;
	r.out.status = talloc(mem_ctx, uint32_t);

	status = dcerpc_mgmt_is_server_listening(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("is_server_listening failed - %s\n", nt_errstr(status));
		return False;
	}

	if (*r.out.status != 0 || r.out.result == 0) {
		printf("\tserver is NOT listening\n");
	} else {
		printf("\tserver is listening\n");
	}

	return True;
}

static BOOL test_stop_server_listening(struct dcerpc_pipe *p, 
				       TALLOC_CTX *mem_ctx)
{
	NTSTATUS status;
	struct mgmt_stop_server_listening r;

	status = dcerpc_mgmt_stop_server_listening(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("stop_server_listening failed - %s\n", nt_errstr(status));
		return False;
	}

	if (!W_ERROR_IS_OK(r.out.result)) {
		printf("\tserver refused to stop listening - %s\n", win_errstr(r.out.result));
	} else {
		printf("\tserver allowed a stop_server_listening request\n");
		return False;
	}

	return True;
}


BOOL torture_rpc_mgmt(struct torture_context *torture)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx, *loop_ctx;
	BOOL ret = True;
	const char *binding = torture_setting_string(torture, "binding", NULL);
	const struct dcerpc_interface_list *l;
	struct dcerpc_binding *b;

	mem_ctx = talloc_init("torture_rpc_mgmt");

	if (!binding) {
		printf("You must supply a ncacn binding string\n");
		return False;
	}
	
	status = dcerpc_parse_binding(mem_ctx, binding, &b);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		printf("Failed to parse binding '%s'\n", binding);
		return False;
	}

	for (l=librpc_dcerpc_pipes();l;l=l->next) {		
		loop_ctx = talloc_named(mem_ctx, 0, "torture_rpc_mgmt loop context");
		
		/* some interfaces are not mappable */
		if (l->table->num_calls == 0 ||
		    strcmp(l->table->name, "mgmt") == 0) {
			talloc_free(loop_ctx);
			continue;
		}

		printf("\nTesting pipe '%s'\n", l->table->name);

		status = dcerpc_epm_map_binding(loop_ctx, b, l->table, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Failed to map port for uuid %s\n", 
				   GUID_string(loop_ctx, &l->table->syntax_id.uuid));
			talloc_free(loop_ctx);
			continue;
		}

		lp_set_cmdline("torture:binding", dcerpc_binding_string(loop_ctx, b));

		status = torture_rpc_connection(loop_ctx, &p, &dcerpc_table_mgmt);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			printf("Interface not available - skipping\n");
			talloc_free(loop_ctx);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(loop_ctx);
			ret = False;
			continue;
		}

		if (!test_is_server_listening(p, loop_ctx)) {
			ret = False;
		}

		if (!test_stop_server_listening(p, loop_ctx)) {
			ret = False;
		}

		if (!test_inq_stats(p, loop_ctx)) {
			ret = False;
		}

		if (!test_inq_princ_name(p, loop_ctx)) {
			ret = False;
		}

		if (!test_inq_if_ids(p, loop_ctx, NULL, NULL)) {
			ret = False;
		}

	}

	return ret;
}
