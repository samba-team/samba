/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight client functions

   Copyright (C) Ralph Boehme 2019

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
#include "rpc_client.h"
#include "librpc/gen_ndr/mdssvc.h"
#include "cli_mdssvc.h"
#include "cli_mdssvc_private.h"
#include "cli_mdssvc_util.h"
#include "lib/util/tevent_ntstatus.h"
#include "rpc_server/mdssvc/dalloc.h"
#include "rpc_server/mdssvc/marshalling.h"

NTSTATUS mdscli_blob_search(TALLOC_CTX *mem_ctx,
			    struct mdscli_search_ctx *search,
			    struct mdssvc_blob *blob)
{
	struct mdscli_ctx *ctx = search->mdscli_ctx;
	DALLOC_CTX *d = NULL;
	uint64_t *uint64p = NULL;
	sl_array_t *array = NULL;
	sl_array_t *cmd_array = NULL;
	sl_dict_t *query_dict = NULL;
	sl_array_t *attr_array = NULL;
	sl_array_t *scope_array = NULL;
	double dval;
	uint64_t uint64val;
	ssize_t len;
	int ret;

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array = dalloc_zero(d, sl_array_t);
	if (array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(d, array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cmd_array = dalloc_zero(d, sl_array_t);
	if (cmd_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, cmd_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(cmd_array, "openQueryWithParams:forContext:");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	uint64p = talloc_zero_array(cmd_array, uint64_t, 2);
	if (uint64p == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_name(uint64p, "uint64_t *");

	uint64p[0] = search->ctx_id.id;
	uint64p[1] = search->ctx_id.connection;

	ret = dalloc_add(cmd_array, uint64p, uint64_t *);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	query_dict = dalloc_zero(array, sl_dict_t);
	if (query_dict == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, query_dict, sl_dict_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDQueryBatchFirstDelay");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	dval = 1;
	ret = dalloc_add_copy(query_dict, &dval, double);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDQueryUniqueId");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_add_copy(query_dict, &search->unique_id, uint64_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDAttributeArray");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	attr_array = dalloc_zero(query_dict, sl_array_t);
	if (attr_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_add(query_dict, attr_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_stradd(attr_array, "kMDItemFSName");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDQueryBatchFirstCount");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	uint64val = 10;
	ret = dalloc_add_copy(query_dict, &uint64val, uint64_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDQueryBatchUpdateCount");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	uint64val = 100;
	ret = dalloc_add_copy(query_dict, &uint64val, uint64_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDQueryString");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_stradd(query_dict, search->mds_query);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(query_dict, "kMDScopeArray");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	scope_array = dalloc_zero(query_dict, sl_array_t);
	if (scope_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_add(query_dict, scope_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	ret = dalloc_stradd(scope_array, search->path_scope);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	blob->spotlight_blob = talloc_array(d,
					    uint8_t,
					    ctx->max_fragment_size);
	if (blob->spotlight_blob == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	blob->size = ctx->max_fragment_size;

	len = sl_pack(d, (char *)blob->spotlight_blob, blob->size);
	TALLOC_FREE(d);
	if (len == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->length = len;
	blob->size = len;
	return NT_STATUS_OK;
}

NTSTATUS mdscli_blob_get_results(TALLOC_CTX *mem_ctx,
				 struct mdscli_search_ctx *search,
				 struct mdssvc_blob *blob)
{
	struct mdscli_ctx *ctx = search->mdscli_ctx;
	DALLOC_CTX *d = NULL;
	uint64_t *uint64p = NULL;
	sl_array_t *array = NULL;
	sl_array_t *cmd_array = NULL;
	ssize_t len;
	int ret;

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array = dalloc_zero(d, sl_array_t);
	if (array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(d, array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cmd_array = dalloc_zero(d, sl_array_t);
	if (cmd_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, cmd_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(cmd_array, "fetchQueryResultsForContext:");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	uint64p = talloc_zero_array(cmd_array, uint64_t, 2);
	if (uint64p == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_name(uint64p, "uint64_t *");

	uint64p[0] = search->ctx_id.id;
	uint64p[1] = search->ctx_id.connection;

	ret = dalloc_add(cmd_array, uint64p, uint64_t *);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	blob->spotlight_blob = talloc_array(d,
					    uint8_t,
					    ctx->max_fragment_size);
	if (blob->spotlight_blob == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	blob->size = ctx->max_fragment_size;

	len = sl_pack(d, (char *)blob->spotlight_blob, blob->size);
	TALLOC_FREE(d);
	if (len == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->length = len;
	blob->size = len;
	return NT_STATUS_OK;
}

NTSTATUS mdscli_blob_get_path(TALLOC_CTX *mem_ctx,
			      struct mdscli_ctx *ctx,
			      uint64_t cnid,
			      struct mdssvc_blob *blob)
{
	struct mdsctx_id ctx_id = mdscli_new_ctx_id(ctx);
	DALLOC_CTX *d = NULL;
	uint64_t *uint64var = NULL;
	sl_array_t *array = NULL;
	sl_array_t *cmd_array = NULL;
	sl_array_t *attr_array = NULL;
	sl_cnids_t *cnids = NULL;
	ssize_t len;
	int ret;

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array = dalloc_zero(d, sl_array_t);
	if (array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(d, array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cmd_array = dalloc_zero(d, sl_array_t);
	if (cmd_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, cmd_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(cmd_array, "fetchAttributes:forOIDArray:context:");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	uint64var = talloc_zero_array(cmd_array, uint64_t, 2);
	if (uint64var == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_name(uint64var, "uint64_t *");

	uint64var[0] = ctx_id.id;
	uint64var[1] = 0;

	ret = dalloc_add(cmd_array, &uint64var[0], uint64_t *);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	attr_array = dalloc_zero(d, sl_array_t);
	if (attr_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, attr_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(attr_array, "kMDItemPath");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	/* CNIDs */
	cnids = talloc_zero(array, sl_cnids_t);
	if (cnids == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cnids->ca_cnids = dalloc_new(cnids);
	if (cnids->ca_cnids == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cnids->ca_unkn1 = 0xadd;
	cnids->ca_context = 0x6b000020;

	ret = dalloc_add_copy(cnids->ca_cnids, &cnid, uint64_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, cnids, sl_cnids_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	blob->spotlight_blob = talloc_array(d,
					    uint8_t,
					    ctx->max_fragment_size);
	if (blob->spotlight_blob == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	blob->size = ctx->max_fragment_size;

	len = sl_pack(d, (char *)blob->spotlight_blob, blob->size);
	TALLOC_FREE(d);
	if (len == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->length = len;
	blob->size = len;
	return NT_STATUS_OK;
}

NTSTATUS mdscli_blob_close_search(TALLOC_CTX *mem_ctx,
				  struct mdscli_search_ctx *search,
				  struct mdssvc_blob *blob)
{
	struct mdscli_ctx *ctx = search->mdscli_ctx;
	DALLOC_CTX *d = NULL;
	uint64_t *uint64p = NULL;
	sl_array_t *array = NULL;
	sl_array_t *cmd_array = NULL;
	ssize_t len;
	int ret;

	d = dalloc_new(mem_ctx);
	if (d == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	array = dalloc_zero(d, sl_array_t);
	if (array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(d, array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	cmd_array = dalloc_zero(d, sl_array_t);
	if (cmd_array == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_add(array, cmd_array, sl_array_t);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	ret = dalloc_stradd(cmd_array, "closeQueryForContext:");
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	uint64p = talloc_zero_array(cmd_array, uint64_t, 2);
	if (uint64p == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_name(uint64p, "uint64_t *");

	uint64p[0] = search->ctx_id.id;
	uint64p[1] = search->ctx_id.connection;

	ret = dalloc_add(cmd_array, uint64p, uint64_t *);
	if (ret != 0) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}

	blob->spotlight_blob = talloc_array(d,
					    uint8_t,
					    ctx->max_fragment_size);
	if (blob->spotlight_blob == NULL) {
		TALLOC_FREE(d);
		return NT_STATUS_NO_MEMORY;
	}
	blob->size = ctx->max_fragment_size;

	len = sl_pack(d, (char *)blob->spotlight_blob, blob->size);
	TALLOC_FREE(d);
	if (len == -1) {
		return NT_STATUS_NO_MEMORY;
	}

	blob->length = len;
	blob->size = len;
	return NT_STATUS_OK;
}
