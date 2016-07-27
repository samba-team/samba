/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c)  Noel Power
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include <unistd.h>
#include "client.h"
#include "libcli/wsp/wsp_aqs.h"
#include "rpc_client/wsp_cli.h"
#include "rpc_server/wsp/wsp_backend.h"
#include "lib/cmdline/cmdline.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include "librpc/wsp/wsp_util.h"
#include "util/util_file.h"

static const uint32_t BUFFER_SIZE = 20000;

static bool get_blob_from_file(TALLOC_CTX *ctx,
			       const char *message_bytes_file,
			       DATA_BLOB *blob)
{
	char *content = NULL;

	content = file_load(message_bytes_file,
			    &blob->length,
			    BUFFER_SIZE,
			    ctx);
	if (content == NULL) {
		return false;
	}
	blob->data = (uint8_t*)content;
	return true;
}

static enum ndr_err_code parse_createquery(TALLOC_CTX *ctx,
					   DATA_BLOB *blob,
					   struct wsp_request *request)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;

	ndr = ndr_pull_init_blob(blob, ctx);
	if (ndr == NULL) {
		DBG_ERR("out of memory\n");
		return NDR_ERR_ALLOC;
	}

	err = ndr_pull_wsp_request(ndr, ndr_flags, request);
	if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
		DBG_ERR("corrupted message, couldn't extract header\n");
		return err;
	}

	if (request->header.msg != CPMCREATEQUERY) {
		DBG_ERR("wrong msg request type was expecting CPMCREATEQUERY, "
			"got %d\n",
			request->header.msg);
		return NDR_ERR_VALIDATE;
	}
	return err;
}

static bool synthesize_bindings(TALLOC_CTX *ctx,
				struct wsp_ccolumnset *columnset,
				struct wsp_cpidmapper *pidmapper,
				struct wsp_ctablecolumn **columns,
				uint32_t *ncols)
{
	struct wsp_ctablecolumn *tab_cols = NULL;
	int i;

	tab_cols = talloc_zero_array(ctx,
				     struct wsp_ctablecolumn,
				     columnset->count);
	if (tab_cols == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}
	*ncols = columnset->count;

	for (i = 0; i < columnset->count; i++) {
		int pid_index = columnset->indexes[i];
		struct wsp_cfullpropspec *prop_spec =
				&pidmapper->apropspec[pid_index];

		tab_cols[i].propspec = *prop_spec;
	}
	*columns = tab_cols;
	return true;
}

static struct {
	int id;
	const char *name;
} backend_map[] = {
	{WSP_BACKEND_NONE, "none"},
};

static int get_backend_id(const char *backend_name)
{
	int i;
	int id = WSP_BACKEND_NONE;

	for (i = 0; i < ARRAY_SIZE(backend_map); i++) {
		if (strequal(backend_map[i].name, backend_name)) {
			return backend_map[i].id;
		}
	}
	return id;
}

int main(int argc, const char *argv[])
{
	DATA_BLOB blob;
	int result;
	TALLOC_CTX *ctx = talloc_stackframe();
	struct wsp_request *request = NULL;
	enum ndr_err_code err;
	const char *query_str = NULL;
	const char *share = NULL;
	const char *restrictionset_expr = NULL;
	const char *backend = NULL;
	struct wsp_cpmcreatequeryin *query = NULL;
	struct wsp_ccolumnset *projected_col_offsets = NULL;
	struct wsp_crestrictionarray *restrictionset = NULL;
	struct wsp_cpidmapper *pidmapper = NULL;
	struct backend_selected_cols backend_cols = {};
	int i = 0;
	int c = 0;
	bool raw = false;
	bool restriction = false;
	const char *infile = NULL;
	char* full_query = NULL;
	t_select_stmt *select_stmt = NULL;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "query",
			.shortName  = 'q',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &full_query,
			.val        = 'q',
			.descrip    = "specify a more complex query",
			.argDescrip = "query"
		},
		{
			.longName   = "input",
			.shortName  = 'i',
			.argInfo    = POPT_ARG_STRING,
			.arg        = &infile,
			.val        = 'i',
			.descrip    = "specify binary file with query message content",
			.argDescrip = "input"
		},
		{
			.longName   = "restriction",
			.shortName  = 'r',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'r',
			.descrip    = "prints out the restriction only part of the expression",
			.argDescrip = "restriction"
		},
		{
			.longName   = "verbose",
			.shortName  = 'v',
			.argInfo    = POPT_ARG_NONE,
			.arg        = NULL,
			.val        = 'v',
			.descrip    = "doesn't do any conversion to backend "
				"properties, doesn't drop any part of the"
				"expression, just prints out what it can",
			.argDescrip = "verbose"
		},
		POPT_COMMON_SAMBA
		POPT_TABLEEND
	};
	HRESULT hres;
	struct wsp_csortset *sortset = NULL;
	struct query_conv_ops *conv_ops = NULL;
	int id;
	const char **const_argv = discard_const_p(const char *, argv);
	bool ok;

	ok = samba_cmdline_init(ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to set up cmdline parser\n");
		result = -1;
		goto out;
	}

	pc = samba_popt_get_context("wsp-to",
				    argc,
				    const_argv,
				    long_options,
				    0);

	poptSetOtherOptionHelp(pc, "backend");

	while ((c = poptGetNextOpt(pc)) != -1) {
		switch (c) {
		case 'v':
			raw = true;
			break;
		case 'r':
			restriction = true;
			break;
		}
	}

	if (backend == NULL && poptPeekArg(pc)) {
		backend = talloc_strdup(ctx, poptGetArg(pc));
		if (backend == NULL) {
			return -1;
		}
	} else {
		backend = "none";
	}

	id = get_backend_id(backend);
	conv_ops = get_query_conv_ops(id);
	if (conv_ops == NULL) {
		DBG_ERR("No backend retrieved for %s\n", backend);
		return -1;
	}

	if (infile == NULL) {
		infile = talloc_strdup(ctx, poptGetArg(pc));
	}

	if ((full_query == NULL && infile == NULL)
	    || (full_query != NULL && infile != NULL))
	{
		fprintf(stderr, "Either --query or --input must be specified\n");
		poptPrintUsage(pc, stderr, 0);
		return -1;
	}

	if (full_query != NULL) {
		select_stmt = get_wsp_sql_tree(full_query);
	}

	if (!lp_load_with_shares(get_dyn_CONFIGFILE())) {
		DBG_ERR("failed to load %s\n",get_dyn_CONFIGFILE());
		return -1;
	}

	poptFreeContext(pc);

	request = talloc_zero(ctx, struct wsp_request);
	if (request == NULL) {
		DBG_ERR("out of memory\n");
		result = 1;
		goto out;
	}

	if (select_stmt == NULL) {
		if (!get_blob_from_file(ctx, infile, &blob)) {
			DBG_ERR("failed to process %s\n", infile);
			result = 1;
			goto out;
		}

		err = parse_createquery(ctx, &blob, request);
		if (err) {
			DBG_ERR("failed to parse blob error %d\n", err);
			result = 1;
			goto out;
		}
	} else {
		create_querysearch_request(ctx, request, select_stmt);
	}

	query = &request->message.cpmcreatequery;
	pidmapper = &query->pidmapper;

	if (query->ccolumnsetpresent) {
		projected_col_offsets = &query->columnset.columnset;
	}
	if (query->crestrictionpresent) {
		restrictionset = &query->restrictionarray.restrictionarray;
	}

	if (query->csortsetpresent) {
		struct wsp_cingroupsortaggregset *aggregset = NULL;

		aggregset = &query->sortset.groupsortaggregsets.sortsets[0];
		sortset = &aggregset->sortaggregset;
	}

	hres = conv_ops->bld_query(ctx,
			NULL,
			projected_col_offsets,
			restrictionset,
			pidmapper,
			sortset,
			&backend_cols,
			!raw,
			&share,
			&query_str,
			&restrictionset_expr);
	if (!HRES_IS_OK(hres)) {
		DBG_ERR("Failed to build query %s\n",
			hresult_errstr(hres));
		result = 1;
		goto out;
	}

	if (query_str == NULL || strlen(query_str) == 0) {
		DBG_ERR("failed to generate query expression\n");
		result = 1;
		goto out;
	}

	if (restriction == false) {
		struct binding_result_mapper *result_converter = NULL;
		struct map_data *map_data = NULL;
		struct wsp_ctablecolumn *columns = NULL;
		uint32_t  ncolumns;

		if (query->csortsetpresent) {
			struct wsp_cingroupsortaggregset *aggregset = NULL;
			aggregset =
				&query->sortset.groupsortaggregsets.sortsets[0];
			sortset = &aggregset->sortaggregset;
		}

		result_converter = talloc_zero(ctx,
					       struct binding_result_mapper);
		if (result_converter == NULL) {
			DBG_ERR("out of memory\n");
			result = -1;
			goto out;
		}

		/*
		 * currently the tool doesn't have access to the bindings so
		 * we synthesise them here from the columnset & pidmapper info
		 * from the query message.
		 * #TODO allow bindings be specified on the commandline also
		 * to be used here.
		 */
		if (!synthesize_bindings(ctx, projected_col_offsets, pidmapper,
					 &columns, &ncolumns)) {
			DBG_ERR("Failed to synthesize bindings\n");
			result = -1;
			goto out;
		}

		printf("query is:\n\"%s\"\n", query_str);
		printf("selected columns:\n");

		if (!conv_ops->bld_mapper(ctx,
					  columns,
					  ncolumns,
					  &backend_cols,
					  result_converter)) {
			DBG_ERR("failed to build mapper!\n");
			result = -1;
			goto out;
		}

		map_data = result_converter->map_data;

		for (i = 0; i < result_converter->ncols; i++) {
			int pid_index = projected_col_offsets->indexes[i];
			struct wsp_cfullpropspec *prop_spec =
					&pidmapper->apropspec[pid_index];
			char *prop = NULL;
			const char *backend_id = NULL;
			int backend_col = map_data[i].col_with_value;

			prop = prop_from_fullprop(ctx, prop_spec);
			if (prop == NULL) {
				DBG_ERR("out of memory\n");
				result = -1;
				goto out;
			}
			backend_id = backend_cols.backend_ids[backend_col];

			if (map_data[i].convert_fn) {
				printf("Col[%d] %s is mapped/converted from "
				       "backend col[%d] %s\n",
				       i,
				       prop,
				       map_data[i].col_with_value,
				       backend_id);
			} else {
				printf("Col[%d] %s Will not return a value\n",
				       i,
				       prop);
			}
		}
	} else {
		printf("restriction expression\n\"%s\"\n",
			restrictionset_expr);
	}
	result = 0;
out:
	TALLOC_FREE(ctx);
	return result;
}
