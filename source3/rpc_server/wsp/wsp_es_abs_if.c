/*
 *  Unix SMB/CIFS implementation.
 *
 *  Window Search Service
 *
 *  Copyright (c) Noel Power
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

#include <includes.h>
#include "wsp_es_abs_if.h"
#include "libcli/util/ntstatus_gen.h"
#include "tevent.h"
#include "wsp_gss.h"
#include "librpc/wsp/wsp_util.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "wsp_backend.h"
#include "wsp_es_conv.h"
#include "smbd/proto.h"
#include "util/tevent_ntstatus.h"
#include "util/tevent_hresult.h"
#include "libcli/security/security.h"
#include "rpc_server/rpc_pipes.h"
#include "rpc_server/rpc_server.h"
#include <jansson.h>
#include "libcli/http/http.h"
#include "credentials.h"
#include "lib/tls/tls.h"
#include "lib/param/param.h"
#include "wspd_db.h"
#include "librpc/gen_ndr/ndr_wsp_data.h"
#include "source3/lib/global_contexts.h"

 /*
  * max results to return with query
  * note: this is not the max rows/results returned
  *       by say a getrowsin request but rather the max
  *       number of results for a single query of maybe
  *       many that might be needed to satisfy the number
  *       of rows requested by a getrowsin request.
  */
#define MAX_ES_RESULTS 100

/*
 * Maybe this should be a config item
 * this is the size in bytes of a field returned by
 * an elasticsearch query that if exceeded will results
 * in the value been 'deferred'. This will require to client
 * to issue a getpropertyvalue request to retrieve the property.
 * The idea here is two fold
 *  1. ensure we have maximum space in the rows set returned by limiting
 *     the size of column values
 *  2. limit the size of the results we cache when acl_filtering is enabled
 *     and force the client to fetch larger value on demand
 */

#define DEFER_SIZE 500

struct es_client_info {
	struct http_conn *http_conn;
	uint16_t server_port;
	char *server_addr;
	struct tstream_tls_params *tls_params;
	struct cli_credentials *creds;
};

struct backend_col_data {
	uint8_t backend_val_type;
	union backend_value value;
};

struct backend_row {
	uint32_t ncols;
	struct backend_col_data *columns;
	bool folder_result;
};

struct backend_getrowsout {
	uint32_t nrows;
	uint32_t nrows_remaining;
	struct backend_row *rows;
};

static void *get_value(int i, int j, struct backend_col_data *col_val)
{
	void *value = NULL;

	switch (col_val->backend_val_type) {
		case BACKEND_STRING:
			value = discard_const_p(void, col_val->value.string);
			DBG_DEBUG("String value[%d][%d] is %s\n",
				  i, j, col_val->value.string);
			break;
		case BACKEND_INTEGER:
			value = (void*)&col_val->value.integer;
			DBG_DEBUG("Integer value[%d][%d] is %"PRIu64"\n",
				  i, j, col_val->value.integer);
			break;
		case BACKEND_BOOLEAN:
			value = (void*)&col_val->value.boolean;
			DBG_DEBUG("Boolean value[%d][%d] is %d(bool)\n",
				  i, j, col_val->value.boolean);
			break;
		case BACKEND_DOUBLE:
			value = (void*)&col_val->value.double_val;
			DBG_DEBUG("Double value[%d][%d] is %f(float)\n",
				  i, j, (float)col_val->value.double_val);
			break;
	}
	return value;
}

static HRESULT convert_backend_rows(TALLOC_CTX *ctx,
			struct conn_wrap *conn_wrap,
			struct backend_getrowsout *backend_rows,
			struct map_data *map_data,
			struct wsp_ctablecolumn *columns,
			uint32_t rows,
			uint32_t ncols,
			struct wsp_cbasestoragevariant **rowsarray,
			uint32_t *rows_converted,
			struct es_row_data *row_data)
{
	HRESULT hres;
	uint32_t row, col;
	struct wsp_cbasestoragevariant **rowsout = NULL;

	rowsout = rowsarray;
	if (rowsout == NULL) {
		return HRES_E_OUTOFMEMORY;
	}
	for (row = 0; row < rows; row++) {
		/*
		 * try and convert the columns of stuff returned from search
		 * to the columns required for the bindings
		 */
		struct backend_row *row_item = &backend_rows->rows[row];
		struct row_conv_data *row_private_data = NULL;
		struct wsp_cbasestoragevariant *rowval = NULL;
		struct conv_call_ctx *call_ctx = NULL;

		rowval = talloc_zero_array(rowsout,
					struct wsp_cbasestoragevariant,
					ncols);
		if (rowval == NULL) {
			return HRES_E_OUTOFMEMORY;
		}

		rowsout[row] = rowval;

		row_private_data =
			talloc_zero(rowval, struct row_conv_data);

		if (row_private_data == NULL) {
			return HRES_E_OUTOFMEMORY;
		}

		call_ctx = talloc_zero(rowval, struct conv_call_ctx);
		if (call_ctx == NULL) {
			return HRES_E_OUTOFMEMORY;
		}

		call_ctx->row_conv_data = row_private_data;
		/*
		 * Here we deviate from the spec, we *don't* acl filter
		 * results before passing back to the client as we have
		 * already acl checked the results returned (and cached) from
		 * the query. Note: MS-WSP documentation is very ambiguous
		 * about how this filtering should work, the description to
		 * me seems to contradict itself and is very unclear.
		 * Also in practise with win8 at least it seems that the
		 * filtering is already done when the query returns
		 * (reflected in the num results contained in
		 * CPMGETQUERYSTATUSEX _cResultsFound response field.
		 */
		row_private_data->conn_wrap = conn_wrap;
		row_private_data->row_data = row_data;
		row_private_data->is_folder_result = row_item->folder_result;

		for (col = 0; col < ncols; col++) {
			struct wsp_ctablecolumn *bind_desc =
				&columns[col];
			struct wsp_cbasestoragevariant *col_val =
				&rowval[col];
			bool deferred = false;
			uint32_t val_col = map_data[col].col_with_value;
			const char *wsp_id = prop_from_fullprop(rowsout,
							&bind_desc->propspec);

			DBG_DEBUG("about to process row[%d]col[%d] by using "
				   "col %d with result_converter %p\n",
				   row, col, map_data[col].col_with_value,
				   map_data[col].convert_fn);

			if (row_item->columns[val_col].backend_val_type ==
			    BACKEND_DEFERRED)
			{
				deferred = true;
			}
			if (!deferred && map_data[col].vtype != VT_NULL) {
				HRESULT conv_status = HRES_E_NOTIMPL;
				struct backend_col_data *trker_col = NULL;
				void *val = NULL;

				trker_col = &row_item->columns[val_col];
				val = get_value(row, col, trker_col);
				if (val == NULL) {
					DBG_DEBUG("failed to process row "
						 "%d col %d, no value available:\n",
						 row, col);
					col_val->vtype = VT_EMPTY;
				} else if (map_data[col].convert_fn != NULL) {
					call_ctx->private_data =
						map_data[col].calling_ctx;

					conv_status = map_data[col].convert_fn(
						rowsout,
						call_ctx,
						col_val,
						trker_col->backend_val_type,
						map_data[col].vtype,
						val);
				}
				if (!HRES_IS_OK(conv_status)) {
					/* mark column as unprocessable */
					DBG_DEBUG("failed to process row "
						 "%d col %d, error: %s\n",
						 row, col,
						 hresult_errstr(conv_status));
					col_val->vtype = VT_EMPTY;
				}
			} else {
				/* mark column as unprocessable or missing... */
				if (deferred) {
					DBG_WARNING("column %d for %s is "
						    "deferred\n",
						    col,
						    wsp_id);
					/*
					 * use vtype VT_NULL to mark the value
					 * as deferred we use vtype
					 * VT_EMPTY to mark the value as missing
					 * or empty
					 */
					col_val->vtype = VT_NULL;
				} else {
					DBG_WARNING("column %d for %s is "
						    "missing or we cannot "
						    "process it\n",
						    col,
						    wsp_id);
					col_val->vtype = VT_EMPTY;
				}
			}
		}
		(*rows_converted)++;
	}
	hres = HRES_OK;
	return hres;
}

struct next_cursor_data {
	struct next_cursor_data *prev, *next;
	uint32_t cursor;
	uint32_t chapter;
	uint32_t index;
};

struct next_cursor_list {
	struct next_cursor_data *items;
};

enum es_query_state {
	ES_IDLE,
	ES_QUERY_ERROR,
	ES_QUERY_IN_PROGRESS,
	ES_QUERY_COMPLETE,
};


struct binding_data {
	struct binding_data *prev, *next;
	struct wsp_ctablecolumn *columns;
	struct binding_result_mapper *result_converter;
	uint32_t ncols;
	uint32_t cursor_hndl;
};

struct binding_list {
	int nbindings;
	struct binding_data *items;
};

struct client_query_data {
	struct client_query_data *prev, *next;
	uint32_t query_id;
	struct wsp_crestrictionarray restrictionset;
	struct wsp_crowsetproperties rowsetproperties;
	struct backend_selected_cols cols_to_convert;
	struct next_cursor_list next_cursors;
	struct conn_wrap *vfs_conn_wrap;
	struct binding_list bindings;
	const char* where_filter;
	const char* jquery_str;
	const char* share;
	const char* share_path;
	const char* index_name;
	const char* sources;
	bool no_index;
	bool wsp_enabled;
	bool use_fscrawler_folder_idx;
	/*
	 * current index set from index passed from last call to
	 * SetNextGetRowsPosition. (maybe we should just store the
	 * last chapter...)
	 */
	uint32_t current_index;
	uint32_t ncursors;
	uint32_t nrows; /* only set when query is finished */
	enum es_query_state query_state;
	uint32_t query_result_limit;
	struct backend_getrowsout *rows;
	struct {
		const char *server_addr;
		int server_port;
		bool use_tls;
		bool acl_filter;
	} elastic_cfg;
};

struct wsp_abstract_state {
	json_t *mappings;
	struct tevent_context *ev;
	struct cli_credentials *creds;
	struct query_conv_ops *conv_ops;
	struct client_info *client_info_map;
	struct query_list {
		int nqueries;
		struct client_query_data *items;
	} queries;
};

static struct wsp_abstract_state *wsp_abstract_state = NULL;

static int destroy_wsp_abstract_state(struct wsp_abstract_state *glob_data)
{
	json_decref(glob_data->mappings);
	return 0;
}

static bool wsp_es_lookup_where_id(TALLOC_CTX *ctx,
			       struct wspd_client_state *client_state,
			       uint32_t where_id,
			       const char **filter_out,
			       const char **share_out);

static struct wsp_abstract_state *wsp_es_initialise(struct tevent_context *event_ctx)
{
	json_error_t json_error;
	char *default_path = NULL;
	const char *path = NULL;

	if (wsp_abstract_state != NULL) {
		/* global state */
		return wsp_abstract_state;
	}

	wsp_abstract_state = talloc_zero(NULL, struct wsp_abstract_state);
	if (wsp_abstract_state == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	DBG_INFO("Initialising elasticsearch backend\n");

	wsp_abstract_state->ev = event_ctx;
	wsp_abstract_state->conv_ops = es_wsp_conv_ops();
	/* replace default lookup_whereid implementation */
	wsp_abstract_state->conv_ops->bld_lookup_whereid =
		wsp_es_lookup_where_id;

	default_path = talloc_asprintf(
		wsp_abstract_state,
		"%s/wsp/elasticsearch_mappings.json",
		get_dyn_SAMBA_DATADIR());
	if (default_path == NULL) {
		TALLOC_FREE(wsp_abstract_state);
		return NULL;
	}

	path = lp_parm_const_string(GLOBAL_SECTION_SNUM,
				    "elasticsearch",
				    "wsp_mappings",
				    default_path);
	if (path == NULL) {
		TALLOC_FREE(wsp_abstract_state);
		return NULL;
	}

	wsp_abstract_state->mappings =  json_load_file(path, 0, &json_error);
	if (wsp_abstract_state->mappings == NULL) {
		DBG_ERR("Opening mapping file [%s] failed: %s\n",
			path, json_error.text);
		TALLOC_FREE(wsp_abstract_state);
		return NULL;
	}

	wsp_abstract_state->creds =
		cli_credentials_init_anon(wsp_abstract_state);
	if (wsp_abstract_state->creds == NULL) {
		TALLOC_FREE(wsp_abstract_state);
		return NULL;
	}
	talloc_set_destructor(wsp_abstract_state, destroy_wsp_abstract_state);
	return wsp_abstract_state;
}

static void wsp_es_get_server_versions(struct wspd_client_state *client_state,
				uint32_t *dwwinvermajor,
				uint32_t *dwwinverminor,
				uint32_t *dwnlsvermajor,
				uint32_t *dwnlsverminor,
				uint32_t *serverversion,
				bool *supportsversioninginfo)
{
	/* 64 bit win7 */
	const uint32_t SERVERVERSION = 0x00010700;

	*supportsversioninginfo = false;
	/*
	 * with supportsVersioningInfo = false
	 * version info (major, minor etc.) is
	 * optional and doesn't need to be set
	 */
	*serverversion = SERVERVERSION;
}

static bool wsp_es_is_catalog_available(struct wspd_client_state *client_data,
                                const char *catalogname)
{
       return strequal(catalogname, "Windows\\SYSTEMINDEX");
}

struct client_info {
	struct client_info *prev, *next;
	struct wsp_cpmconnectin *connectin;
	uint32_t query_id;
	uint32_t handle;
	struct es_client_info *es_info;
};

static int destroy_query_data(struct client_query_data *query_info)
{
	struct client_info* cli_item = NULL;

	SMB_ASSERT(wsp_abstract_state);
	cli_item = wsp_abstract_state->client_info_map;
	TALLOC_FREE(query_info->cols_to_convert.backend_ids);
	DLIST_REMOVE(wsp_abstract_state->queries.items, query_info);
	wsp_abstract_state->queries.nqueries--;

	while (cli_item) {
		struct client_info *next_cli = cli_item->next;
		if (cli_item->handle == query_info->query_id) {
			DLIST_REMOVE(wsp_abstract_state->client_info_map,
				     cli_item);
			TALLOC_FREE(cli_item);
		}
		cli_item = next_cli;
	}
	return 0;
}

static struct client_query_data * create_query_info(uint32_t query_id)
{
	struct client_query_data *item = NULL;

	SMB_ASSERT(wsp_abstract_state);
	item = talloc_zero(NULL, struct client_query_data);
	if (item == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}
	talloc_set_destructor(item, destroy_query_data);
	DLIST_ADD_END(wsp_abstract_state->queries.items, item);
out:
	return item;
}

static struct client_info *find_client_info(uint32_t handle)
{
	struct client_info *client_info = NULL;

	SMB_ASSERT(wsp_abstract_state);
	client_info = wsp_abstract_state->client_info_map;
	while(client_info) {
		if (client_info->handle == handle) {
			break;
		}
		client_info = client_info->next;
	}
	return client_info;
}

static struct wsp_cpmconnectin *wsp_es_get_client_information(
					struct wspd_client_state *client_state,
					uint32_t queryidentifier)
{
	struct client_info* client_info = find_client_info(queryidentifier);

	if (client_info != NULL) {
		return client_info->connectin;
	}
	return NULL;
}

static int destroy_client_info(struct client_info *info)
{
	struct client_info *cli_item = NULL;

	SMB_ASSERT(wsp_abstract_state);
	cli_item = wsp_abstract_state->client_info_map;

	while (cli_item != NULL) {
		struct client_info *next_cli = cli_item->next;
		if (cli_item->handle == info->query_id) {
			DLIST_REMOVE(wsp_abstract_state->client_info_map,
				     cli_item);
			TALLOC_FREE(cli_item);
		}
		cli_item = next_cli;
	}
	return 0;
}

static struct client_info *create_client_info(uint32_t handle)
{
	struct client_info *client_info = NULL;

	SMB_ASSERT(wsp_abstract_state);
	client_info = talloc_zero(NULL, struct client_info);
	if (client_info == NULL) {
		DBG_ERR("no memory\n");
		return client_info;
	}

	DLIST_ADD_END(wsp_abstract_state->client_info_map, client_info);
	talloc_set_destructor(client_info, destroy_client_info);
	return client_info;
}

static void wsp_es_store_client_information(
					struct wspd_client_state *client_state,
					uint32_t queryid,
					struct wsp_cpmconnectin *connectin,
					uint32_t handle)
{
	struct client_info *client_info = NULL;

	client_info = create_client_info(handle);
	SMB_ASSERT(client_info);
	client_info->handle = handle;
	client_info->query_id = queryid;
	client_info->connectin = connectin;
	/* take ownership of the connect message */
	talloc_steal(client_info, connectin);
}

static bool generate_sources_field(TALLOC_CTX *ctx,
				struct backend_selected_cols *selected,
				const char **sources)
{
	int i;
	const char *out = NULL;

	for (i = 0; i < selected->cols; i++) {
		if (i == 0) {
			out = talloc_asprintf(ctx,
				"%s",
				selected->backend_ids[i]);
		} else {
			out = talloc_asprintf(ctx,
				"%s %s",
				out,
				selected->backend_ids[i]);
		}
	}
	if (out == NULL) {
		return false;
	}
	*sources = out;
	return true;
}

static bool has_elastic_connection(struct client_info *client)
{
	if (client->es_info != NULL) {
		return client->es_info->http_conn != NULL;
	}
	return false;
}

struct wsp_es_connect_elastic_state {
	struct tevent_context *ev;
	struct es_client_info *es_info;
	struct wsp_abstract_state *abs_state;
	int num_retries;
};

static void wsp_es_connect_elastic_done(struct tevent_req *subreq);

static struct tevent_req *wsp_es_connect_elastic_send(TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct wsp_abstract_state *abs_state,
			struct client_query_data *query_data,
			struct client_info *client,
			struct cli_credentials *creds)
{
	NTSTATUS status;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	bool use_tls;
	struct wsp_es_connect_elastic_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct wsp_es_connect_elastic_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->abs_state = abs_state;

	/* already connected ? */
	if (has_elastic_connection(client)) {
		/*
		 * need to see if connection params used to create
		 * the connection are the same (they are dependent on
		 * the share configuration
		 */
		if (strequal(client->es_info->server_addr,
				query_data->elastic_cfg.server_addr)
		&& (client->es_info->server_port
				== query_data->elastic_cfg.server_port)
		&& ((client->es_info->tls_params
				&& query_data->elastic_cfg.use_tls)
		    || (client->es_info->tls_params == NULL
				&& !query_data->elastic_cfg.use_tls)))
		{
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}

		DBG_INFO("Connection has changed, resetting connection\n");
		client->es_info->tls_params = NULL;
		client->es_info->server_port = 0;
		TALLOC_FREE(client->es_info->server_addr);
	}

	if (client->es_info == NULL) {
		client->es_info = talloc_zero(client, struct es_client_info);
		if (tevent_req_nomem(client->es_info, req)) {
			return tevent_req_post(req, ev);
		}
	}

	/*
	 * #TODO decide if we need wsp_elastic:address etc.
	 * or continue to use a common elasticsearch config
	 */
	client->es_info->server_addr =
		talloc_strdup(client, query_data->elastic_cfg.server_addr);
	client->es_info->server_port = query_data->elastic_cfg.server_port;

	client->es_info->creds = creds;
	use_tls = query_data->elastic_cfg.use_tls;

	DBG_DEBUG("Connecting to HTTP [%s] port [%"PRIu16"] use tls = %s\n",
		  client->es_info->server_addr, client->es_info->server_port,
		  use_tls ? "true" : "false" );

	state->es_info = client->es_info;

	if (use_tls) {
		struct loadparm_context *lp_ctx = NULL;

		lp_ctx = loadparm_init_s3(state, loadparm_s3_helpers());
		if (tevent_req_nomem(lp_ctx, req)) {
			return tevent_req_post(req, ev);
		}

		status = tstream_tls_params_client_lpcfg(state,
						lp_ctx,
						client->es_info->server_addr,
						&client->es_info->tls_params);
		TALLOC_FREE(lp_ctx);

		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed tstream_tls_params_client "
				"- %s\n", nt_errstr(status));
			tevent_req_herror(req, HRESULT_FROM_NT(status));
			return tevent_req_post(req, ev);
		}
	}

	subreq = http_connect_send(state,
				ev,
				client->es_info->server_addr,
				client->es_info->server_port,
				client->es_info->creds,
				client->es_info->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_es_connect_elastic_done, req);
	return req;
}

static void wsp_es_connect_elastic_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_connect_elastic_state *state = tevent_req_data(
		req, struct wsp_es_connect_elastic_state);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_IO_TIMEOUT));
		return;
	}

	subreq = http_connect_send(state,
				state->ev,
				state->es_info->server_addr,
				state->es_info->server_port,
				state->es_info->creds,
				state->es_info->tls_params);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wsp_es_connect_elastic_done, req);
}

static void wsp_es_connect_elastic_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_connect_elastic_state *state = tevent_req_data(
		req, struct wsp_es_connect_elastic_state);
	int error;

	error = http_connect_recv(subreq,
				state->es_info,
				&state->es_info->http_conn);
	TALLOC_FREE(subreq);
	if (error != 0) {
		if (state->num_retries > 5) {
			tevent_req_herror(req, HRES_RPC_E_TIMEOUT);
			return;
		}
		state->num_retries++;
		DBG_ERR("HTTP connection failed, retrying [%d]\n",
			state->num_retries);
		subreq = tevent_wakeup_send(state,
					    state->ev,
					    tevent_timeval_current_ofs(10, 0));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					wsp_es_connect_elastic_waited,
					req);

		return;
	}
	tevent_req_done(req);
}

static HRESULT wsp_es_connect_elastic_recv(struct tevent_req *req)
{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_search_state {
	struct tevent_context *ev;
	struct client_query_data *query_data;
	struct client_info *client;
	struct wsp_abstract_state *glob_state;
	struct http_request http_request;
	struct http_request *http_response;
	struct conn_wrap *conn_wrap;
	struct auth_session_info *session_info;
	struct backend_getrowsout* rowsout;
	json_t *jsources; /* array */
	json_t *jquery; /* object */
	uint32_t size;
	uint32_t from;
	uint32_t nrows;
	bool do_acl_filtering;
};

static int destroy_esearch_state(struct wsp_es_search_state *state)
{
	if (state->jquery != NULL) {
		json_decref(state->jquery);
		state->jquery = NULL;
	}
	if (state->jsources != NULL) {
		json_decref(state->jsources);
		state->jsources = NULL;
	}
	return 0;
}
static void wsp_es_search_http_send_done(struct tevent_req *subreq);
static void wsp_es_search_connect_done(struct tevent_req *subreq);

static struct tevent_req *wsp_es_search_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct client_query_data *query_data,
				const char *sources,
				const char *query,
				bool reverse_fetch,
				uint32_t start,
				uint32_t rows_to_get,
				struct conn_wrap *conn_wrap,
				struct auth_session_info *session_info,
				struct wsp_abstract_state *glob_state)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_es_search_state *state = NULL;
	struct client_info *client = NULL;
	json_t *jsources = NULL;
	json_t *jquery = NULL;
	json_error_t jerr = {};

	req = tevent_req_create(mem_ctx, &state, struct wsp_es_search_state);
	if (req == NULL) {
		return NULL;
	}

	/* query_id/handle are the same in this implementation */
	client = find_client_info(query_data->query_id);
	if (client == NULL) {
		DBG_ERR("No client for handle %u\n", query_data->query_id);
		tevent_req_herror(req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (sources != NULL) {
		char **list = str_list_make(
				state,
				sources,
				" ");
		const char *item;
		jsources = json_array();
		for (;list != NULL && *list != NULL; list++) {
			item = *list;
			json_array_append_new(jsources, json_string(item));
		}
	}

	jquery = json_loads(query, 0, &jerr);
	if (jquery == NULL) {
		DBG_ERR("can't create json object from query %s\n"
			"error: %s\n", query, jerr.text);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	*state = (struct wsp_es_search_state) {
		.ev = ev,
		.query_data = query_data,
		.client = client,
		.glob_state = glob_state,
		.conn_wrap = conn_wrap,
		.session_info = session_info,
		.rowsout = talloc_zero(state, struct backend_getrowsout),
		.jsources = jsources,
		.jquery = jquery,
		.from = start,
		.size = rows_to_get,
		.nrows = 0,
		.do_acl_filtering = query_data->elastic_cfg.acl_filter,
	};

	talloc_set_destructor(state, destroy_esearch_state);
	if (tevent_req_nomem(state->rowsout, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = wsp_es_connect_elastic_send(state,
				      ev,
				      glob_state,
				      query_data,
				      client,
				      glob_state->creds);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_es_search_connect_done, req);
	return req;
}

static bool populate_http_request(struct wsp_es_search_state *state,
				  uint32_t size)
{
	json_t *jquery = NULL;
	json_t *jval = NULL;
	char *jdump = NULL;
	char *uri = NULL;
	char *elastic_query = NULL;
	size_t elastic_query_len;
	char *elastic_query_len_str = NULL;
	char *hostname = NULL;
	bool pretty = false;
	const char *index_name = state->query_data->index_name;

	if (DEBUGLVL(10)) {
		pretty = true;
	}

	if (!strequal(state->query_data->index_name, "_all")) {
		if (state->query_data->use_fscrawler_folder_idx) {
			index_name = talloc_asprintf(state,
						    "%s,%s_folder",
						    index_name,
						    index_name);
		}
	}
	uri = talloc_asprintf(state,
			      "/%s/_search%s",
			      index_name,
			      pretty ? "?pretty" : "");
	if (uri == NULL) {
		return false;
	}

	jquery = json_pack("{sisisO}",
			"from", state->from,
			"size",
			(size_t)MIN(size,
				MAX_ES_RESULTS),
			"_source", state->jsources);

	jval = json_object_get(state->jquery, "query");
	if (jval != NULL) {
		json_object_set(jquery, "query", jval);
	}

	jval = json_object_get(state->jquery, "sort");

	if (jval != NULL) {
		json_object_set(jquery, "sort", jval);
	}

	jdump = json_dumps(jquery, JSON_INDENT(2));

	if (jdump != NULL) {
		elastic_query = talloc_strdup(state,
				jdump);
		free(jdump);
	}

	json_decref(jquery);
	if (elastic_query == NULL) {
		return false;
	}

	DBG_DEBUG("Elastic query: '%s'\n", elastic_query);

	elastic_query_len = strlen(elastic_query);

	state->http_request = (struct http_request) {
		.type = HTTP_REQ_POST,
		.uri = uri,
		.major = '1',
		.minor = '1',
	};

	if (state->http_request.body.data != NULL) {
		TALLOC_FREE(state->http_request.body.data);
	}

	state->http_request.body = data_blob_const(elastic_query,
						   elastic_query_len),

	elastic_query_len_str = talloc_asprintf(state, "%zu",
						elastic_query_len);
	if (elastic_query_len_str == NULL) {
		return false;
	}

	hostname = get_myname(state);
	if (hostname == NULL) {
		return false;
	}

	http_replace_header(state, &state->http_request.headers,
			"Content-Type",	"application/json");
	http_replace_header(state, &state->http_request.headers,
			"Accept", "application/json");
	http_replace_header(state, &state->http_request.headers,
			"User-Agent", "Samba/wspd");
	http_replace_header(state, &state->http_request.headers,
			"Host", hostname);
	http_replace_header(state, &state->http_request.headers,
			"Content-Length", elastic_query_len_str);
	return true;
}

static void wsp_es_search_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_search_state *state = tevent_req_data(
		req, struct wsp_es_search_state);

	struct es_client_info *es_info = NULL;
	HRESULT hres;

	hres = wsp_es_connect_elastic_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		DBG_ERR("connection has error %s\n", hresult_errstr(hres));
		return;
	}

	es_info = state->client->es_info;
	if (tevent_req_nomem(es_info, req)) {
		DBG_ERR("No es_info object available!!!\n");
		return;
	}

	if (!populate_http_request(state, state->size)) {
		DBG_ERR("Failed to create http_request!!!\n");
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return;
	}

	subreq = http_send_request_send(state,
					state->ev,
					es_info->http_conn,
					&state->http_request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	tevent_req_set_callback(subreq, wsp_es_search_http_send_done, req);
	return;
}

static void wsp_es_search_http_read_done(struct tevent_req *subreq);
static void wsp_es_search_http_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_search_state *state = tevent_req_data(
		req, struct wsp_es_search_state);

	NTSTATUS status;

	DBG_DEBUG("Sent out search [%u]\n", state->query_data->query_id);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return;
	}

	subreq = http_read_response_send(state,
					 state->ev,
					 state->client->es_info->http_conn,
					 MAX_ES_RESULTS * 8192);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wsp_es_search_http_read_done, req);
}

static bool parse_json_val(const char* attribute,
		TALLOC_CTX *ctx,
		json_t *matches,
		int *level,
		char **state,
		struct backend_col_data *col_data,
		bool allow_defer)
{
	char* next_seg = NULL;
	json_t *value = NULL;
	int ret;

	if (*level <= 0) {
		DBG_ERR("recursion limit reached\n");
		return false;
	}
	(*level)--;
	ret = json_unpack(matches, "{s:o}", attribute, &value);
	if (ret != 0) {
		DBG_ERR("Error unpacking %s\n", attribute);
		return false;
	}
	next_seg = strtok_r(NULL, ".", state);
	if (next_seg == NULL) {
		int type;
		if (value == NULL) {
			DBG_ERR("NULL value for segment %s\n", attribute);
			return false;
		}
		type = json_typeof(value);
		switch(type) {
			case JSON_STRING:
			{
				char *val = NULL;
				ret = json_unpack(value,
					"s",
					&val);
				if (ret == 0) {
					if (allow_defer &&
					    strlen(val) > DEFER_SIZE) {
						col_data->backend_val_type
							= BACKEND_DEFERRED;
					} else {
						col_data->value.string =
							talloc_strdup(ctx, val);
						col_data->backend_val_type =
							BACKEND_STRING;
					}
				}
				break;
			}
			case JSON_INTEGER:
				ret = json_unpack(value,
					"i",
					&col_data->value.integer);
				if (ret == 0) {
					col_data->backend_val_type =
						BACKEND_INTEGER;
				}
				break;
			case JSON_REAL:
				ret = json_unpack(value,
					"f",
					&col_data->value.double_val);
				if (ret == 0) {
					col_data->backend_val_type =
						BACKEND_DOUBLE;
				}
				break;
			case JSON_TRUE:
				col_data->value.boolean = 1;
				ret = 0;
				col_data->backend_val_type = BACKEND_BOOLEAN;
				break;
			case JSON_FALSE:
				col_data->value.boolean = 0;
				ret = 0;
				col_data->backend_val_type = BACKEND_BOOLEAN;
				break;
			/*
			 * we will need to somehow handle array as
			 * some attributes are definitetly arrays
			 */
			case JSON_ARRAY:
			case JSON_OBJECT:
			case JSON_NULL:
			default:
				/* unsupported */
				col_data->backend_val_type = BACKEND_NULL;
				DBG_ERR("Unsupported json type %d\n",
					type);
				ret = 1;
				break;
		};
		if (ret !=0) {
			DBG_ERR("failed to unpack value for final seg %s\n", attribute);
		}
		return true;
	}
	return parse_json_val(next_seg,
			      ctx,
			      value,
			      level,
			      state,
			      col_data,
			      allow_defer);
}

static bool check_http_response(struct http_request *response)
{
	char *err_str = NULL;

	switch (response->response_code) {
	case 200:
		break;
	default:
		err_str = talloc_strndup(response,
					 (char *)response->body.data,
					 response->body.length);
		if (err_str == NULL) {
			return false;
		}
		DBG_ERR("HTTP server response: error code: %u\n",
			response->response_code);
		DBG_ERR("HTTP server response: %s\n", err_str);
		TALLOC_FREE(err_str);
		return false;
	}
	return true;
}

static bool extract_hits_from_query_response(json_t *root, int *hits)
{
	int total_hits;
	int ret;

	/*
	 * Get the total number of results the first time, format
	 * used by Elasticsearch 7.0 or newer
	 */
	ret = json_unpack(root, "{s: {s: {s: i}}}",
			  "hits", "total", "value", &total_hits);
	if (ret != 0) {
		/* Format used before 7.0 */
		ret = json_unpack(root, "{s: {s: i}}",
				  "hits", "total", &total_hits);
		if (ret != 0) {
			DBG_ERR("json_unpack failed\n");
			return false;
		}
	}
	*hits = total_hits;
	return true;
}

static json_t *extract_matches_from_query_response(json_t *root)
{
	int ret;
	json_t *matches = NULL;

	ret =  json_unpack(root, "{s: {s:o}}",
			  "hits", "hits", &matches);
	if (ret != 0 || matches == NULL) {
		DBG_ERR("json_unpack hits failed\n");
		return NULL;
	}
	return matches;
}

static struct backend_col_data *get_and_convert_columns(
				TALLOC_CTX *ctx,
				json_t *sources,
				const char* id,
				struct backend_selected_cols *cols_to_convert,
				bool allow_defer)
{
	static struct backend_col_data *dest_columns = NULL;
	uint32_t col;
	int recursion_limit = 10;
	char* tmp_attrib = NULL;

	dest_columns = talloc_zero_array(ctx,
					 struct backend_col_data,
					 cols_to_convert->cols);
	if (dest_columns == NULL) {
		goto out;
	}

	for (col = 0; col < cols_to_convert->cols; col++) {
		const char* attrib = NULL;
		bool parse_col;
		char* tok_state = NULL;
		recursion_limit = 10;
		attrib = cols_to_convert->backend_ids[col];
		if (attrib == NULL) {
			continue;
		}

		/*
		 * special processing for _id, it's not part
		 * or the _source attributes returned (even
		 * if for convenience we present it as such)
		 * and we have already retrieved it.
		 */
		if (strequal("_id", attrib)) {
			dest_columns[col].backend_val_type = BACKEND_STRING;
			dest_columns[col].value.string = talloc_strdup(
						dest_columns,
						id);
			continue;
		}
		tmp_attrib = talloc_strdup(NULL, attrib);
		if (tmp_attrib == NULL) {
			DBG_ERR("out of memory\n");
			goto out;
		}
		tmp_attrib = strtok_r(tmp_attrib, ".", &tok_state);
		if (tmp_attrib == NULL) {
			DBG_ERR("failed to parse %s\n", attrib);
			goto out;
		}
		parse_col = parse_json_val(tmp_attrib,
			dest_columns,
			sources,
			&recursion_limit,
			&tok_state,
			&dest_columns[col],
			allow_defer);
		if (!parse_col) {
			DBG_DEBUG("failed to parse/extract "
				  "value for %s\n", attrib);
		}
		TALLOC_FREE(tmp_attrib);
	}
out:
	return dest_columns;
}

static bool skip_path_from_source(struct wsp_es_search_state *state,
				  json_t *row_data)
{
	struct backend_col_data data;
	int recursion_limit = 10;
	char* tok_state = NULL;
	char* tmp_attrib = NULL;
	const char *path = NULL;
	bool result;
	bool ok;

	if (state->do_acl_filtering == false) {
		result = false;
		goto out;
	}

	tmp_attrib = talloc_strdup(state, "path.real");
	if (tmp_attrib == NULL) {
		DBG_ERR("out of memory\n");
		result = true;
		goto out;
	}
	tmp_attrib = strtok_r(tmp_attrib, ".", &tok_state);
	if (tmp_attrib == NULL) {
		DBG_ERR("failed to parse path.real\n");
		result = true;
		goto out;
	}

	if (!parse_json_val(tmp_attrib,
			    state->rowsout->rows,
			    row_data,
			    &recursion_limit,
			    &tok_state,
			    &data,
			    true)) {
		DBG_ERR("Failed get extract path.real attribute from results\n");
		result = true;
		goto out;
	}

	if (data.backend_val_type == BACKEND_STRING) {
		path = data.value.string;
	}
	if (path == NULL) {
		DBG_ERR("ACL filtering was requested but "
			"no path was available to check, "
			"skipping row!!!!\n");
		result = true;
		goto out;
	}

	ok = can_access_url(state->conn_wrap, path);
	if (!ok) {
		DBG_DEBUG("Can't access %s skipping row!!!!\n",
			path);
		result = true;
		goto out;
	}
	DBG_DEBUG("ACL filtering says we can access %s\n", path);
	result = false;
out:
	TALLOC_FREE(tmp_attrib);
	return result;
}

static bool extract_rows_from_query_response(struct wsp_es_search_state *state,
					     json_t *root,
					     json_t *matches)
{
	size_t row;
	int hits;
	int ret;
	json_t *match = NULL;
	struct client_query_data *query_data = state->query_data;

	hits = json_array_size(matches);
	DBG_DEBUG("Hits: %d\n", hits);

	for (row = 0;
	     row < hits && state->rowsout->nrows < state->size;
	     row++) {
		char* id = NULL;
		json_t *row_data = NULL;
		struct backend_col_data *dest_columns = NULL;
		bool is_folder_result = false;
		match = json_array_get(matches, row);

		if (match == NULL) {
			DBG_ERR("Huh?! No value for index %zu\n", row);
			goto fail;
		}

		ret = json_unpack(match,
				"{s: o}",
				"_source", &row_data);
		if (ret != 0) {
			DBG_ERR("json_unpack _source failed\n");
			goto fail;
		}

		ret = json_unpack(match, "{s: s}", "_id", &id);
		if (ret != 0) {
			DBG_ERR("json_unpack _id object failed\n");
			goto fail;
		}

		if (query_data->use_fscrawler_folder_idx) {
			const char *folder_id = "_folder";
			int folder_id_len = strlen(folder_id);
			int len;
			char* index = NULL;
			ret = json_unpack(match, "{s: s}",
					  "_index", &index);
			if (ret != 0) {
				DBG_ERR("json_unpack _index "
					"object failed\n");
				goto fail;
			}
			/*
			 * if index ends with "_folder" result is a
			 * folder
			 */
			len = strlen(index);
			if (len > folder_id_len &&
				strequal(index + (len - folder_id_len),
					 folder_id)) {
				is_folder_result = true;
			}
		}

		if (skip_path_from_source(state, row_data)) {
			continue;
		}

		state->rowsout->rows[state->rowsout->nrows].folder_result =
							is_folder_result;

		DBG_DEBUG("i=%d from=%d nrows=%d row_index=%d\n",
			(int)row, state->from, state->nrows,
			state->rowsout->nrows);

		dest_columns = get_and_convert_columns(
					state->rowsout->rows,
					row_data,
					id,
					&query_data->cols_to_convert,
					true);

		state->rowsout->rows[state->rowsout->nrows].ncols =
				query_data->cols_to_convert.cols;
		state->rowsout->rows[state->rowsout->nrows].columns =
				dest_columns;

		state->rowsout->nrows = state->rowsout->nrows + 1;
		if (state->do_acl_filtering == true) {
			if (state->rowsout->nrows
				>= query_data->query_result_limit) {
				DBG_DEBUG("client or server result limit "
					  "detected !!\n");
				/* ensure all other row processing finishes */
				state->rowsout->nrows_remaining = 0;
				return true;
			}
		}
	}

	state->from = state->from + row;
	state->rowsout->nrows_remaining = state->size - state->rowsout->nrows;
	return true;
fail:
	return false;
}

static void wsp_es_search_http_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_search_state *state = tevent_req_data(
		req, struct wsp_es_search_state);

	json_t *root = NULL;
	json_t *matches = NULL;
	json_error_t error;
	int hits;
	int total_hits;
	NTSTATUS status;
	struct client_query_data *query_data = state->query_data;

	DBG_DEBUG("Got response for search query id[%u]\n",
			query_data->query_id);

	status = http_read_response_recv(subreq, state, &state->http_response);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		query_data->query_state = ES_QUERY_ERROR;
		DBG_DEBUG("HTTP response failed: %s\n", nt_errstr(status));
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return;
	}

	if (check_http_response(state->http_response) == false) {
		goto fail;
	}

	DBG_DEBUG("JSON response:\n%s\n",
		  talloc_strndup(state,
				 (char *)state->http_response->body.data,
				 state->http_response->body.length));

	root = json_loadb((char *)state->http_response->body.data,
			  state->http_response->body.length,
			  0,
			  &error);
	if (root == NULL) {
		DBG_ERR("json_loadb failed\n");
		goto fail;
	}

	if (extract_hits_from_query_response(root, &total_hits) == false) {
		goto fail;
	}

	DBG_DEBUG("Total: %d\n", total_hits);
	if (total_hits == 0) {
		/* nothing to retrieve */
		goto out;
	}

	matches = extract_matches_from_query_response(root);
	if (matches == NULL) {
		goto fail;
	}

	hits = json_array_size(matches);
	DBG_DEBUG("Hits: %d\n", hits);

	if (hits != 0) {
		if (hits > state->size) {
			DBG_ERR("something has gone wrong, we've gotten "
				"more results than we asked for\n");
			goto fail;
		}
		if (state->rowsout->rows == NULL) {
			state->rowsout->rows = talloc_zero_array(state->rowsout,
					struct backend_row,
					state->size);
			if (state->rowsout->rows == NULL) {
				DBG_ERR("out of memory, allocating %d rows\n",
					state->size);
				goto fail;
			}
			state->rowsout->nrows_remaining = 0;
		}
	} else {
		uint32_t boolean_options =
				query_data->rowsetproperties.ubooleanoptions;

		DBG_DEBUG("Query has no results to return\n");
		/* finished and no results (or we searched but didn't want ask to
		 * get back any rows)
		 * If we didn't ask for any rows then use total hits for num. results
		 */
		if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
			/*
			 * only update if we didn't ask for rows
			 * otherwise we could overwrite the calculated
			 * number of results when trying to
			 * read from a row index after the end of results
			 * (which can happen the way ieexplore searches)
			 */
			if (state->size == 0) {
				state->nrows = total_hits;
			}
		}
		goto out;
	}
	if (extract_rows_from_query_response(state, root, matches) == false) {
		goto fail;
	}

	json_decref(root);
	root = NULL;

	/*
	 * We always will try to give back the amount of rows requested.
	 * if we still have rows to get AND there are more rows available
	 * then keep trying to fill state->rowsout by requesting more
	 * rows (by repeating the same query with adjusted from and size
	 * values)
	 */
	if (state->rowsout->nrows_remaining && state->from < total_hits) {
		size_t remaining =
				(size_t)state->rowsout->nrows_remaining;
		/*
		 * we haven't filled backend_getrowsout with
		 * the required amount of rows, get the rest
		 */
		if (!populate_http_request(state, remaining)) {
			DBG_ERR("Failed to popluate http request\n");
			goto fail;
		}
		subreq = http_send_request_send(state,
					state->ev,
					state->client->es_info->http_conn,
					&state->http_request);

		if (subreq == NULL) {
			goto fail;
		}

		tevent_req_set_callback(subreq,
				wsp_es_search_http_send_done,
				req);
		return;
	}

	state->rowsout->nrows_remaining = 0;
	state->nrows = state->rowsout->nrows;
out:
	query_data->query_state = ES_QUERY_COMPLETE;
	if (root != NULL) {
		json_decref(root);
	}

	tevent_req_done(req);
	return;

fail:
	if (root != NULL) {
		json_decref(root);
	}
	query_data->query_state = ES_QUERY_ERROR;
	tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
	return;
}

static HRESULT wsp_es_search_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct backend_getrowsout **rows,
	uint32_t *rows_left,
	uint32_t *total_rows)
{
	struct wsp_es_search_state *state = tevent_req_data(
		req, struct wsp_es_search_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	if (state->rowsout && rows) {
		*rows_left = state->rowsout->nrows_remaining;
		*rows = talloc_move(mem_ctx, &state->rowsout);
	}
	*total_rows = state->nrows;
	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_run_new_query_state {
	struct tevent_context *ev;
	bool canquerynow;
	uint32_t *cursorhandleslist;
	bool ftruesequential;
	bool fworkidunique;
	struct client_query_data *query_info;
};

static uint32_t *create_cursor_handleslist(
		struct client_query_data *query_info)
{
	uint32_t *cursorhandleslist = NULL;
	uint32_t i;

	cursorhandleslist = talloc_zero_array(query_info, uint32_t,
					       query_info->ncursors);
	if (cursorhandleslist == NULL) {
		return NULL;
	}
	/* allocate cursor id(s) */
	for (i = 0; i < query_info->ncursors; i++) {
		struct next_cursor_data *item = talloc_zero(query_info,
					struct next_cursor_data);
		cursorhandleslist[i] = i + 1;

		/* initial index (with unchaptered chapter) */
		item->chapter = 0;
		item->cursor = cursorhandleslist[i];
		item->index = 0;

		DLIST_ADD_END(query_info->next_cursors.items, item);
	}
	return cursorhandleslist;
}

static HRESULT setup_share_for_query(
		struct wsp_abstract_state *glob_data,
		struct client_query_data *query_info,
		struct auth_session_info *session_info,
		const char *share)
{
	struct connection_struct *conn = NULL;
	char *service = NULL;
	int snum = find_service(query_info, share, &service);
	int server_results_limit;
	const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();
	NTSTATUS status;
	HRESULT hres;
	uint32_t share_access;
	bool read_only;

	DBG_INFO("SHARE %s has indexing = %s\n", share,
		lp_wsp(snum) ? "enabled" : "disabled");

	query_info->share = talloc_strdup(query_info,share);
	if (query_info->share == NULL) {
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}
	query_info->wsp_enabled = lp_wsp(snum);
	query_info->no_index = !query_info->wsp_enabled;
	query_info->share_path = talloc_strdup(query_info,
					lp_path(query_info, lp_sub, snum));
	if (query_info->wsp_enabled == false) {
		hres = HRES_OK;
		goto out;
	}
	if ((snum == -1) || (service == NULL)) {
		DBG_ERR("share %s not found\n", share);
		hres = HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER);
		goto out;
	}

	status = create_conn_struct(query_info,
				    global_messaging_context(),
				    snum,
				    query_info->share_path,
				    session_info,
				    &query_info->vfs_conn_wrap);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("create_conn_struct failed: %s\n", nt_errstr(status));
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	conn = conn_wrap_connection(query_info->vfs_conn_wrap);

	status = set_conn_force_user_group(conn, snum);
	if (!NT_STATUS_IS_OK(status)) {
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	status = check_user_share_access(conn,
			conn->session_info,
			&share_access,
			&read_only);
	if (!NT_STATUS_IS_OK(status)) {
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	/* Needed for %u with string substitution below */
	if (!become_authenticated_pipe_user(conn->session_info)) {
		DBG_ERR("can't become authenticated user:\n");
		hres = HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL);
		goto out;
	}

	query_info->use_fscrawler_folder_idx = lp_parm_bool(snum,
					   "elasticsearch",
					   "wsp use fscrawler folders",
					   false);

	query_info->index_name = lp_parm_substituted_string(query_info,
					loadparm_s3_global_substitution(),
					snum,
					"elasticsearch",
					"index",
					"_all");

	unbecome_authenticated_pipe_user();

	server_results_limit = lp_parm_int(snum,
					   "elasticsearch",
					   "max results",
					   MAX_ES_RESULTS);
	/*
	 * determine limit of results based on cmaxresults and max results
	 * configured for the server (if defined)
	 */
	if (server_results_limit
	    && query_info->rowsetproperties.cmaxresults)
	{
		query_info->query_result_limit =
			MIN(server_results_limit,
			    query_info->rowsetproperties.cmaxresults);
	} else {
		query_info->query_result_limit =
			MAX(server_results_limit,
			    query_info->rowsetproperties.cmaxresults);
	}
	query_info->elastic_cfg.server_addr =
				lp_parm_const_string(snum,
						     "elasticsearch",
						     "address",
						     "localhost");

	query_info->elastic_cfg.server_port =
				lp_parm_int(snum,
					    "elasticsearch",
					    "port",
					    9200);

	query_info->elastic_cfg.use_tls =
				lp_parm_bool(snum,
					     "elasticsearch",
					     "use tls",
					     false);
	query_info->elastic_cfg.acl_filter =
				lp_parm_bool(snum,
					     "elasticsearch",
					     "wsp_acl_filtering",
					     true);
	hres = HRES_OK;
out:
	return hres;
}

static void wsp_es_run_new_query_done(struct tevent_req *subreq);
static struct tevent_req *wsp_es_run_new_query_send(TALLOC_CTX *ctx,
			  struct tevent_context *ev,
			  struct wspd_client_state *client_state,
			  uint32_t queryidentifier,
			  struct wsp_ccolumnset *projectioncolumnsoffsets,
			  struct wsp_crestrictionarray *restrictionset,
			  struct wsp_csortset *sortorders,
			  struct wsp_ccategorizationset *groupings,
			  struct wsp_crowsetproperties *rowsetproperties,
			  struct wsp_cpidmapper *pidmapper,
			  struct wsp_ccolumngrouparray *grouparray,
			  uint32_t Lcid)
{
	struct client_query_data *query_info = NULL;
	struct client_info *client = NULL;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct auth_session_info *session_info = get_session_info(client_state);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_es_run_new_query_state *state = NULL;
	const char *share = NULL;
	uint32_t boolean_options;
	uint32_t rows_to_get = 0;
	bool no_index = false;
	HRESULT hres;

	req = tevent_req_create(ctx, &state, struct wsp_es_run_new_query_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	state->canquerynow = true;
	if (restrictionset == NULL) {
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	/* query_id/handle are the same in this implementation */
	client = find_client_info(queryidentifier);
	if (client == NULL) {
		DBG_ERR("No client for handle %u\n", queryidentifier);
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return tevent_req_post(req, ev);
	}

	query_info = create_query_info(queryidentifier);
	if (query_info == NULL) {
		DBG_ERR("out of memory\n");
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return tevent_req_post(req, ev);
	}
	state->query_info = query_info;

	query_info->query_state = ES_QUERY_IN_PROGRESS;
	query_info->query_id = queryidentifier;
	query_info->ncursors = groupings != NULL ? groupings->size + 1 : 1;

	hres = glob_data->conv_ops->bld_query(query_info,
				client_state,
				projectioncolumnsoffsets,
				restrictionset,
				pidmapper,
				sortorders,
				&query_info->cols_to_convert,
				true,
				&share,
				&query_info->jquery_str,
				&query_info->where_filter
				);
	if (!HRES_IS_OK(hres)) {
		DBG_ERR("error %s when creating filter string\n",
			hresult_errstr(hres));
		/*
		 * let this special error through, just don't
		 * actually run the query
		 */
		if (!HRES_IS_EQUAL(hres, HRES_ERROR(WIN_UPDATE_ERR))) {
			state->canquerynow = false;
			tevent_req_herror(req, hres);
			return tevent_req_post(req, ev);
		}
		no_index = true;
		query_info->no_index = true;
	}

	if (!generate_sources_field(query_info,
				    &query_info->cols_to_convert,
				    &query_info->sources)) {
		DBG_ERR("error creating sources from selected columns\n");
		state->canquerynow = false;
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	state->cursorhandleslist = create_cursor_handleslist(query_info);
	if (state->cursorhandleslist == NULL) {
		DBG_ERR("out of memory\n");
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_NO_MEMORY));
		return tevent_req_post(req, ev);
	}

	query_info->rowsetproperties = *rowsetproperties;

	if (share == NULL) {
		DBG_ERR("No share passed in the RestrictionSet\n");
		state->canquerynow = false;
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	hres = setup_share_for_query(glob_data,
				       query_info,
				       session_info,
				       share);
	if (!HRES_IS_OK(hres)) {
		state->canquerynow = false;
		tevent_req_herror(req, hres);
		return tevent_req_post(req, ev);
	}
	no_index = query_info->no_index;

	talloc_steal(query_info, restrictionset->restrictions);
	query_info->restrictionset = *restrictionset;

	state->fworkidunique = false;

	if (no_index || !state->canquerynow) {
		/*
		 * not able to perform a query due to either an error,
		 * share not enabled for wsp or some other reason.
		 * regardless don't actually send a query
		 */
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	boolean_options = query_info->rowsetproperties.ubooleanoptions;

	if (query_info->elastic_cfg.acl_filter) {
		uint32_t limit = query_info->query_result_limit;

		if (limit == 0) {
			/*
			 * unbounded results (no limit) isn't allowed
			 * with acl_filtering enabled.  You MUST
			 * specific a server (or client limit)
			 * for results, we could warn and silently
			 * change the limit but probably better to
			 * just fail hard.
			 */
			DBG_ERR("Failed to create query, acl_filtering "
				"enabled but no limit for number of "
				"results to cache defined ! Please set "
				"[S] 'elasticsearch max results = N' "
				"in share section for share = [%s]\n",
				share);
			state->canquerynow = false;
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL));
			return tevent_req_post(req, ev);
		}
		/*
		 * Because we don't know how many actual results
		 * we need to filter to get to at least 'limit'
		 * results it is better to pick a bigger result
		 * 'size' to return from the query other wise
		 * even a limit of 100 would take at least
		 * 10 search(es) (if no result were rejected while
		 * testing acl filtering the results)
		 */
		if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
			rows_to_get = MAX(limit, MAX_ES_RESULTS);
		}
	}

	subreq = wsp_es_search_send(state,
				ev,
				query_info,
				query_info->sources,
				query_info->jquery_str,
				false,
				0,
				rows_to_get,
				query_info->vfs_conn_wrap,
				session_info,
				glob_data);
	if (subreq == NULL) {
		DBG_ERR("failed to create search\n");
		state->canquerynow = false;
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL));
		return tevent_req_post(req, ev);
	}

	/* kick off query */
	DBG_INFO("es_query is \"%s\"\n", query_info->where_filter);
	tevent_req_set_callback(subreq, wsp_es_run_new_query_done, req);
	return req;
}

static void wsp_es_run_new_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	HRESULT hres;
	struct wsp_es_run_new_query_state *state =
		tevent_req_data(req, struct wsp_es_run_new_query_state);
	uint32_t rows_left;

	hres =  wsp_es_search_recv(subreq,
				 state->query_info,
				 &state->query_info->rows,
				 &rows_left,
				 &state->query_info->nrows);

	DBG_DEBUG("Query finished %s results %d\n",
			hresult_errstr(hres),
			(int)state->query_info->nrows);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	} else {
		state->canquerynow = true;
        }

	tevent_req_done(req);
}

static HRESULT wsp_es_run_new_query_recv(struct tevent_req* req,
			TALLOC_CTX *ctx,
			uint32_t **cursorhandleslist,
			bool *ftruesequential,
			bool *fworkidunique,
			bool *canquerynow)
{
	HRESULT hres;
	struct wsp_es_run_new_query_state *state = tevent_req_data(
		req, struct wsp_es_run_new_query_state);

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*ftruesequential = state->ftruesequential;
	*fworkidunique = state->fworkidunique;
	*canquerynow = state->canquerynow;
	*cursorhandleslist = talloc_steal(ctx, state->cursorhandleslist);
	tevent_req_received(req);
	return HRES_OK;
}

static struct client_query_data *find_query_info(uint32_t query_id)
{
	struct client_query_data *item = NULL;

	SMB_ASSERT(wsp_abstract_state);
	item = wsp_abstract_state->queries.items;
	for (; item; item = item->next) {
		if (item->query_id == query_id) {
			return item;
		}
	}
	return item;
}

static bool wsp_es_clientquery_has_cursorhandle(
			struct wspd_client_state *client_state,
			uint32_t queryidentifier,
			uint32_t cursorhandle)
{
	bool result;
	struct client_query_data *query_data = find_query_info(queryidentifier);
	struct next_cursor_data *item;

	if (query_data == NULL) {
		DBG_ERR("no query_data for query id, something "
			 "pretty major wrong :/\n");
		result = false;
		goto out;
	}

	item = query_data->next_cursors.items;
	for (; item; item = item->next) {
		if (item->cursor == cursorhandle) {
			result = true;
			goto out;
		}
	}
	result = false;
out:
	return result;
}

struct wsp_es_query_status_state {
	uint32_t *rows;
	uint32_t *status;
};

/*
 * Fake async method here
 */

static struct tevent_req *wsp_es_query_status_send(TALLOC_CTX *ctx,
			     struct tevent_context *ev,
			     struct wsp_abstract_state *glob_data,
			     uint32_t queryidentifier,
			     uint32_t *status,
			     uint32_t *nrows)
{
	struct tevent_req *req = NULL;
	struct wsp_es_query_status_state *state = NULL;
	struct client_query_data *query_info = NULL;

	req = tevent_req_create(ctx, &state,
				struct wsp_es_query_status_state);
	if (req == NULL) {
		return NULL;
	}

	state->rows = nrows;
	state->status = status;

	query_info = find_query_info(queryidentifier);
	if (query_info == NULL) {
		DBG_ERR("No query data for query id=%u\n", queryidentifier);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (query_info->no_index) {
		*state->status = ES_QUERY_COMPLETE;
		*state->rows = 0;
	} else {
		*state->rows = query_info->nrows;
		*state->status = query_info->query_state;
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS wsp_es_query_status_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

struct wsp_es_get_query_status_state {
	uint32_t querystatus;
	uint32_t error;
	uint32_t nrows;
	struct client_query_data *query_data;
};

static void wsp_es_get_query_status_done(struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_query_status_send(
					TALLOC_CTX *ctx,
					struct tevent_context *ev,
					struct wspd_client_state *client_state,
					uint32_t queryidentifier)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_es_get_query_status_state *state = NULL;
	struct wsp_abstract_state *glob_state = client_state->wsp_abstract_state;
	struct client_query_data *query_data = find_query_info(queryidentifier);

	req = tevent_req_create(ctx, &state,
				struct wsp_es_get_query_status_state);
	if (req == NULL) {
		return NULL;
	}
	state->query_data = query_data;
	if (query_data->wsp_enabled == false) {
		state->querystatus = 2;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = wsp_es_query_status_send(state, ev, glob_state, queryidentifier,
				&query_data->query_state, &state->nrows);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wsp_es_get_query_status_done, req);
	return req;
}

static void wsp_es_get_query_status_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_query_status_state *state = tevent_req_data(
		req, struct wsp_es_get_query_status_state);
	NTSTATUS status = NT_STATUS_OK;

	status = wsp_es_query_status_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(
			req,
			HRESULT_FROM_NT(status));
		return;
	}

	switch(state->query_data->query_state) {
		case ES_QUERY_IN_PROGRESS:
			state->querystatus = STAT_BUSY;
			break;
		case ES_QUERY_COMPLETE:
			state->querystatus = STAT_DONE;
			state->query_data->nrows = state->nrows;
			break;
		case ES_QUERY_ERROR:
		case ES_IDLE:
		default:
			state->querystatus = STAT_ERROR;
			break;
	}
	tevent_req_done(req);
}

static HRESULT wsp_es_get_query_status_recv(struct tevent_req *req,
				      uint32_t *querystatus)
{
	struct wsp_es_get_query_status_state *state =
		tevent_req_data(req,
			struct wsp_es_get_query_status_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		*querystatus = STAT_ERROR;
		tevent_req_received(req);
		return hres;
	}

	*querystatus = state->querystatus;
	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_get_state_state {
	struct tevent_context *ev;
	struct wsp_cpmcistateinout out;
	struct client_info *client;
	const char *index;
	struct http_request http_request;
	struct http_request *http_response;
	struct http_conn *http_conn;
	struct wsp_abstract_state *glob_state;
};

static void wsp_es_get_state_connect_done(struct tevent_req *subreq);
static struct tevent_req *wsp_es_get_state_send(TALLOC_CTX *ctx,
					 struct tevent_context *ev,
					 struct wspd_client_state *client_state)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_es_get_state_state *state = NULL;
	struct wsp_abstract_state *glob_state = client_state->wsp_abstract_state;
	uint32_t handle;
	struct client_info *client = NULL;
	struct client_query_data *query_data = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_es_get_state_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->glob_state = glob_state;

	handle = get_handle(client_state);

	client = find_client_info(handle);
	if (client == NULL) {
		DBG_ERR("Client with handle %u doesn't exist\n", handle);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_HANDLE));
		return tevent_req_post(req, ev);
	}

	query_data = find_query_info(client->query_id);
	if (query_data == NULL) {
		DBG_ERR("No query data for query id=%u\n", client->query_id);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_HANDLE));
		return tevent_req_post(req, ev);
	}
	/*
	 * #FIXME #TODO need to handle this better (and need to examine
	 * more closely what message status (and data) is returned in windows
	 * when a share has indexing disabled).
	 */

	if (client->es_info == NULL) {
		/* no valid connection */
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_CONNECTION_INVALID));
		return tevent_req_post(req, ev);
	}

	state->index =  query_data->index_name;
	state->http_conn = client->es_info->http_conn;
	state->client = client;

	subreq = wsp_es_connect_elastic_send(state,
				      ev,
				      glob_state,
				      query_data,
				      client,
				      glob_state->creds);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_es_get_state_connect_done, req);
	return req;
}

static bool populate_http_getstate_request(struct wsp_es_get_state_state *state)
{
	bool pretty = false;
	char *uri = NULL;
	char *hostname = NULL;

	if (DEBUGLVL(10)) {
		pretty = true;
	}

	uri = talloc_asprintf(state,
			      "/%s/_stats%s",
			      state->index,
			      pretty ? "?pretty" : "");

	if (uri == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	state->http_request = (struct http_request) {
		.type = HTTP_REQ_GET,
		.uri = uri,
		.body = {NULL},
		.major = '1',
		.minor = '1',
	};

	hostname = get_myname(state);
	if (hostname == false) {
		return false;
	}

	http_replace_header(state, &state->http_request.headers,
			"Accept", "*/*\r\n");
	http_replace_header(state, &state->http_request.headers,
			"User-Agent", "Samba/wspd");
	http_replace_header(state, &state->http_request.headers,
			"Host", hostname);
	return true;
}

static void wsp_es_get_state_http_send_done(struct tevent_req *subreq);

static void wsp_es_get_state_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_state_state *state = tevent_req_data(
		req, struct wsp_es_get_state_state);
	HRESULT hres;

	hres = wsp_es_connect_elastic_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	if (populate_http_getstate_request(state) == false) {
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return;
	}

	subreq = http_send_request_send(state,
					state->ev,
					state->http_conn,
					&state->http_request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wsp_es_get_state_http_send_done, req);
	return;
}

static void wsp_es_get_state_http_read_done(struct tevent_req *subreq);
static void wsp_es_get_state_http_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_state_state *state =  tevent_req_data(
		req, struct wsp_es_get_state_state);
	NTSTATUS status;

	DBG_DEBUG("Sent out stats request [%p]\n", state);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		DBG_DEBUG("error with http_send_request_recv [%s]\n",
			nt_errstr(status));
		return;
	}

	subreq = http_read_response_send(state,
					 state->ev,
					 state->http_conn,
					 MAX_ES_RESULTS * 8192);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wsp_es_get_state_http_read_done, req);

}

static void wsp_es_get_state_http_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_state_state *state =  tevent_req_data(
		req, struct wsp_es_get_state_state);
	json_t *root = NULL;
	size_t total = 0;
	int ret;
	json_error_t error;
	NTSTATUS status;

	DBG_DEBUG("Got response for get state request [%p]\n", state);

	status = http_read_response_recv(subreq, state, &state->http_response);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		DBG_DEBUG("HTTP response failed: %s\n", nt_errstr(status));
		return;
	}

	if (!check_http_response(state->http_response)) {
		goto fail;
	}

	root = json_loadb((char *)state->http_response->body.data,
			  state->http_response->body.length,
			  0,
			  &error);
	if (root == NULL) {
		DBG_ERR("json_loadb failed\n");
		goto fail;
	}
	ret = json_unpack(root, "{s: {s: {s: {s: i}}}}",
				  "_all", "total", "docs", "count", &total);
	if (ret != 0) {
		DBG_ERR("Failed to read total documents indexed\n");
		goto fail;
	}
	DBG_DEBUG("Total: %zu\n", total);
	state->out.cwordlist = total;
	/* not sure if this is a good default */
	state->out.dwmergeprogress = 100;
	/*
	 * following values are a bit dubious
	 */
	state->out.estate = 0;
	state->out.cfiltereddocuments =
					state->out.cwordlist;
	state->out.ctotaldocuments =
					state->out.cwordlist;
	/*
	 * and the next ones not even filled out (for now)
	 * #TODO investigate these more (but their absence doesn't
	 * seem to adversely affect windows searches)
	 *
	 * state->out->cpendingscans = ?;
	 * state->out->cqueries = state->glob_state->queries.nqueries;
	 * out->cfreshtest = ?;
	 * state->out->dwindexsize = ?;
	 * state->out->cuniquekeys = ?;
	 * state->out->csecqdocuments = ?;
	 * state->out->dwpropcachesize = ?;
	 */
	json_decref(root);
	tevent_req_done(req);
	return;
fail:
	if (root != NULL) {
		json_decref(root);
	}
	tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
	return;
}

static HRESULT wsp_es_get_state_recv(struct tevent_req *req,
				      struct wsp_cpmcistateinout *out)
{
	struct wsp_es_get_state_state *state = tevent_req_data(
		req, struct wsp_es_get_state_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	*out = state->out;
	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_get_propertyvalue_for_workid_state {
	struct tevent_context *ev;
	DATA_BLOB value;
	struct binding_result_mapper mapper;
	struct memcache *id_cache;
	struct http_request http_request;
	struct http_request *http_response;
	struct http_conn *http_conn;
	struct conn_wrap *conn_wrap;
	struct wsp_abstract_state *glob_state;
	struct backend_selected_cols cols_to_convert;
	uint16_t size;
};

static bool populate_http_getpropertyvalue_request(
		struct wsp_es_get_propertyvalue_for_workid_state *state,
		const char *index,
		const char *query)
{
	bool pretty = false;
	char *uri = NULL;
	char *hostname = NULL;
	size_t query_len;
	char *query_len_str = NULL;

	if (DEBUGLVL(10)) {
		pretty = true;
	}

	uri = talloc_asprintf(state,
			      "/%s/_search%s",
			      index,
			      pretty ? "?pretty" : "");

	if (uri == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	query_len = strlen(query);

	state->http_request = (struct http_request) {
		.type = HTTP_REQ_GET,
		.uri = uri,
		.body = {NULL},
		.major = '1',
		.minor = '1',
	};

	if (state->http_request.body.data != NULL) {
		TALLOC_FREE(state->http_request.body.data);
	}

	state->http_request.body = data_blob_const(query,
						   query_len),

	query_len_str = talloc_asprintf(state, "%zu",
						query_len);
	if (query_len_str == NULL) {
		return false;
	}

	hostname = get_myname(state);
	if (hostname == false) {
		return false;
	}

	http_replace_header(state, &state->http_request.headers,
			"Content-Type",	"application/json");
	http_replace_header(state, &state->http_request.headers,
			"Accept", "*/*\r\n");
	http_replace_header(state, &state->http_request.headers,
			"User-Agent", "Samba/wspd");
	http_replace_header(state, &state->http_request.headers,
			"Host", hostname);
	http_replace_header(state, &state->http_request.headers,
			"Content-Length", query_len_str);
	return true;
}

static void wsp_es_get_propertyvalue_for_workid_http_send_done(
				struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_propertyvalue_for_workid_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *wspd_client_state,
                                uint32_t queryidentifier,
                                uint32_t workid,
                                struct wsp_cfullpropspec *propspec)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	const char *query = NULL;
	struct wsp_es_get_propertyvalue_for_workid_state *state = NULL;
	struct wsp_abstract_state *glob_state =
		wspd_client_state->wsp_abstract_state;
	uint32_t handle;
	struct client_info *client = NULL;
	struct client_query_data *query_data = NULL;
	const char *index_name = NULL;
	char *wsp_id = prop_from_fullprop(ctx, propspec);
	const struct full_propset_info *prop_info =
			get_prop_info(wsp_id);

	req = tevent_req_create(ctx, &state,
			struct wsp_es_get_propertyvalue_for_workid_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	handle = get_handle(wspd_client_state);
	client = find_client_info(handle);

	if (prop_info == NULL) {
		DBG_ERR("WSP property %s is unknown to us\n", wsp_id);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INTERNAL_ERROR));
		return tevent_req_post(req, ev);
	}

	if (client == NULL) {
		DBG_ERR("Client with handle %u doesn't exist\n", handle);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INTERNAL_ERROR));
		return tevent_req_post(req, ev);
	}

	query_data = find_query_info(queryidentifier);
	if (query_data == NULL) {
		DBG_ERR("No query data for query id=%u\n", client->query_id);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INTERNAL_ERROR));
		return tevent_req_post(req, ev);
	}

	index_name = query_data->index_name;

	if (client->es_info == NULL) {
		/* no valid connection */
                tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
                return tevent_req_post(req, ev);
	}

	query = get_propvalueforworkid_query(query_data,
					     wspd_client_state->id_cache,
					     index_name,
					     workid,
					     propspec,
					     &state->mapper,
					     &state->cols_to_convert);
        if (query == NULL) {
                tevent_req_herror(req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
                return tevent_req_post(req, ev);
        }

	state->id_cache = wspd_client_state->id_cache;
	state->glob_state = glob_state;
	state->http_conn = client->es_info->http_conn;
	state->conn_wrap = query_data->vfs_conn_wrap;
	state->size = prop_info->max_size;

	if (!populate_http_getpropertyvalue_request(state,
						    index_name,
						    query)) {
                tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
                return tevent_req_post(req, ev);
	}

	subreq = http_send_request_send(state,
					state->ev,
					state->http_conn,
					&state->http_request);
	if (tevent_req_nomem(subreq, req)) {
                return tevent_req_post(req, ev);
        }
	tevent_req_set_callback(
		subreq,
		wsp_es_get_propertyvalue_for_workid_http_send_done,
		req);
	return req;
}

static void wsp_es_get_propertyvalue_for_workid_http_read_done(
				struct tevent_req *subreq);

static void wsp_es_get_propertyvalue_for_workid_http_send_done(
						struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_propertyvalue_for_workid_state *state = tevent_req_data(
		req, struct wsp_es_get_propertyvalue_for_workid_state);
	NTSTATUS status;

	DBG_DEBUG("Sent out get_propertyvalue request [%p]\n", state);

	status = http_send_request_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		DBG_DEBUG("error with http_send_request_recv [%s]\n",
			  nt_errstr(status));
		return;
	}

	subreq = http_read_response_send(state,
					 state->ev,
					 state->http_conn,
					 MAX_ES_RESULTS * 8192);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(
		subreq,
		wsp_es_get_propertyvalue_for_workid_http_read_done,
		req);
}

static bool get_fetch_value(
		TALLOC_CTX *ctx,
		struct wsp_es_get_propertyvalue_for_workid_state *state,
		struct backend_col_data *col_value,
		DATA_BLOB *value)
{
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
        struct ndr_push* push_ndr;
        enum ndr_err_code err;
	struct wsp_cbasestoragevariant *result = NULL;
	void *val = NULL;
	struct row_conv_data *row_private_data = NULL;
	struct conv_call_ctx *call_ctx = NULL;
	struct map_data *map_data = NULL;
	struct es_row_data *row_data = NULL;

	map_data = state->mapper.map_data;

	row_data = talloc_zero(ctx, struct es_row_data);
	if (row_data == NULL) {
		DBG_ERR("out of memory!!\n");
		return false;
	}

	row_data->id_cache = state->id_cache;

	row_private_data = talloc_zero(ctx, struct row_conv_data);
	if (row_private_data == NULL) {
		DBG_ERR("out of memory!!\n");
		return false;
	}

	call_ctx = talloc_zero(ctx, struct conv_call_ctx);
	if (call_ctx == NULL) {
		DBG_ERR("out of memory!!\n");
		return false;
	}

	row_private_data->conn_wrap = state->conn_wrap;
	row_private_data->row_data = row_data;

	call_ctx->row_conv_data = row_private_data;
	result = talloc_zero(ctx, struct wsp_cbasestoragevariant);
        if (result == NULL) {
		DBG_ERR("out of memory!!\n");
		return false;
	}

	switch (col_value->backend_val_type) {
		case BACKEND_STRING:
			val = discard_const_p(void, col_value->value.string);
			/*
			 * if converted type and input type are strings then
			 * truncate if necessary
			 */
			if (state->mapper.map_data->vtype == VT_LPWSTR &&
			    strlen(col_value->value.string) > (state->size/2)) {
				/* truncate the string */
				char *tmp = talloc_strdup(state,
							  col_value->value.string);
				if (tmp == NULL) {
					DBG_ERR("out of memory!\n");
					return false;
				}
				tmp[state->size/2 + 1] = '\0';
				val = (void*)tmp;
			}
                        break;
		case BACKEND_INTEGER:
			val = (void*)&col_value->value.integer;
			break;
		case BACKEND_BOOLEAN:
			val = (void*)&col_value->value.boolean;
			break;
		case BACKEND_DOUBLE:
			val = (void*)&col_value->value.double_val;
			break;
	}
	if (map_data[0].vtype != VT_NULL) {
		HRESULT hres;
		hres = HRES_E_NOTIMPL;
		if (val == NULL) {
			DBG_DEBUG("No value available for fetch value\n");
			return false;
		}

		if (map_data[0].convert_fn != NULL) {
			call_ctx->private_data = map_data[0].calling_ctx;
			hres = map_data[0].convert_fn(ctx,
						call_ctx,
						result,
						col_value->backend_val_type,
						map_data[0].vtype,
						val);
			if (!HRES_IS_OK(hres)) {
				DBG_ERR("conv function %p for fetch value "
					"failed with %s\n",
					map_data[0].convert_fn,
					hresult_errstr(hres));
				return false;
			}
			push_ndr = ndr_push_init_ctx(ctx);
			if (push_ndr == NULL) {
				DBG_ERR("out of memory\n");
				return false;
			}
			/*
			 * while cbasestoragevariant seems like it is mostly
			 * interchangeable with SERIALIZEDPROPERTYVAL we
			 * probably either need a function to convert
			 * (or write out) a cbasestoragevariant as a
			 * SERIALIZEDPROPERTYVAL.
			 * Note: just for the moment we are using a
			 *       cbasestoragevariant
			 */
			err = ndr_push_wsp_cbasestoragevariant(push_ndr,
							ndr_flags,
							result);
			if (err != NDR_ERR_SUCCESS) {
				DBG_ERR("failed to push fetched value "
					"to blob\n");
				return false;
			}
			*value = ndr_push_blob(push_ndr);
		}
	} else {
		DBG_ERR("Not possible to convert fetch value\n");
		return false;
	}
	return true;
}

static void wsp_es_get_propertyvalue_for_workid_http_read_done(
				struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_propertyvalue_for_workid_state *state =  tevent_req_data(
		req, struct wsp_es_get_propertyvalue_for_workid_state);
	json_t *root = NULL;
	json_error_t error;
	json_t *matches = NULL;
	NTSTATUS status;
	int total_hits;
	int hits;

	DBG_DEBUG("Got response for get state request [%p]\n", state);

	status = http_read_response_recv(subreq, state, &state->http_response);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req,  HRESULT_FROM_NT(status));
		DBG_DEBUG("HTTP response failed: %s\n", nt_errstr(status));
		return;
	}

	if (!check_http_response(state->http_response)) {
		goto fail;
	}

	DBG_DEBUG("JSON response:\n%s\n",
		  talloc_strndup(state,
				 (char *)state->http_response->body.data,
				 state->http_response->body.length));

	root = json_loadb((char *)state->http_response->body.data,
			  state->http_response->body.length,
			  0,
			  &error);
	if (root == NULL) {
		DBG_ERR("json_loadb failed\n");
		goto fail;
	}

	if (extract_hits_from_query_response(root, &total_hits) == false) {
		goto fail;
	}


	DBG_DEBUG("Total: %d\n", total_hits);
	if (total_hits == 0) {
		/* nothing to retrieve */
		goto out;
	}

	matches = extract_matches_from_query_response(root);
	if (matches == NULL) {
		goto fail;
	}

	hits = json_array_size(matches);
	DBG_DEBUG("Hits: %d\n", hits);

	if (hits != 0) {
		json_t *row_data = NULL;
		json_t *match = NULL;
		char* id = NULL;
		struct backend_col_data *dest_column = NULL;
		int ret;

		if (hits > 1) {
			DBG_ERR("Unexpected results, expected 1 got %d\n",
				hits);
			goto fail;
		}
		match = json_array_get(matches, 0);
		if (match == NULL) {
			DBG_ERR("Unable to extract value for index 0\n");
			goto fail;
		}

		ret = json_unpack(match, "{s: s}", "_id", &id);
		if (ret != 0) {
			DBG_ERR("json_unpack _id object failed\n");
			goto fail;
		}

		ret = json_unpack(match,
				"{s: o}",
				"_source", &row_data);

		if (ret != 0) {
			DBG_ERR("json_unpack _source failed\n");
			goto fail;
		}

#if 0
		/*
		 * should we double check acl access here, if so we need
		 * to have also retrieved real.path
		 */
		if (skip_path_from_source(state, row_data)) {
			continue;
		}
#endif
		dest_column = get_and_convert_columns(
					state,
					row_data,
					id,
					&state->cols_to_convert, false);

		get_fetch_value(state, state, dest_column, &state->value);
	}
out:
	if (root != NULL) {
		json_decref(root);
	}

	tevent_req_done(req);
	return;
fail:
	if (root != NULL) {
		json_decref(root);
	}
	tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
	return;
}

static HRESULT wsp_es_get_propertyvalue_for_workid_recv(struct tevent_req *req,
                                TALLOC_CTX *ctx,
                                DATA_BLOB *property,
                                uint32_t *valueexists)
{
	struct wsp_es_get_propertyvalue_for_workid_state * state = tevent_req_data(
		req, struct wsp_es_get_propertyvalue_for_workid_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*valueexists = state->value.length > 0;
	property->length = state->value.length;
	property->data = talloc_steal(ctx,  state->value.data);
	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_get_ratiofinished_params_state {
	struct client_query_data *query_data;
	uint32_t rdwratiofinisheddenominator;
	uint32_t rdwratiofinishednumerator;
	uint32_t crows;
	uint32_t fnewrows;
	uint32_t rows;
};

static void wsp_es_get_ratiofinished_params_query_status_done(
					struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_ratiofinished_params_send(TALLOC_CTX *ctx,
				     struct tevent_context *ev,
				     struct wspd_client_state *client_state,
				     uint32_t queryidentifier,
				     uint32_t cursorhandle)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct client_query_data *query_data = find_query_info(queryidentifier);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_es_get_ratiofinished_params_state *state = NULL;
	int rows = 0;

	req = tevent_req_create(ctx,
				&state,
				struct wsp_es_get_ratiofinished_params_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	if (query_data == NULL) {
		DBG_ERR("No query data for query id=%u\n", queryidentifier);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}
	state->query_data = query_data;

	if (query_data->wsp_enabled &&
	    query_data->query_state != ES_QUERY_COMPLETE)
	{
		subreq = wsp_es_query_status_send(state, ev,
					  glob_data,
					  queryidentifier,
					  &query_data->query_state,
					  &state->rows);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq,
			wsp_es_get_ratiofinished_params_query_status_done,
			req);
		return req;
	}

	if (query_data->wsp_enabled) {
		rows = query_data->nrows;
	}

	state->rdwratiofinisheddenominator = rows;
	state->crows = rows; /* MS-WSP says client doesn't use it */
	state->fnewrows = (rows > 0) ? 1 : 0;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void wsp_es_get_ratiofinished_params_query_status_done(
						struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_ratiofinished_params_state *state = tevent_req_data(
		req, struct wsp_es_get_ratiofinished_params_state);
	NTSTATUS status;

	status = wsp_es_query_status_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return;
	}

	if (state->query_data->query_state == ES_QUERY_COMPLETE) {
		state->query_data->nrows = state->rows;
	}
	if (state->query_data->wsp_enabled == false) {
		tevent_req_done(req);
		return;
	}
	state->rdwratiofinisheddenominator = 0;
	state->rdwratiofinisheddenominator = state->rows;
	state->crows = state->rows; /* MS-WSP says client doesn't use it */
	state->fnewrows = (state->rows > 0) ? 1 : 0;;
	tevent_req_done(req);
}

static HRESULT wsp_es_get_ratiofinished_params_recv(
		struct tevent_req *req,
		uint32_t *rdwratiofinisheddenominator,
		uint32_t *rdwratiofinishednumerator,
		uint32_t *crows,
		uint32_t *fnewrows)
{
	struct wsp_es_get_ratiofinished_params_state *state =
		tevent_req_data(req, struct wsp_es_get_ratiofinished_params_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	*rdwratiofinisheddenominator = state->rdwratiofinisheddenominator;
	*rdwratiofinishednumerator = state->rdwratiofinishednumerator;
	*crows = state->crows;
	*fnewrows = state->fnewrows;
	return HRES_OK;
}

static struct next_cursor_data *find_next_cursor_index(
					struct client_query_data *data,
					uint32_t cursorhdl,
					uint32_t chapter)
{
	struct next_cursor_data *item = NULL;

	for (item = data->next_cursors.items; item; item = item->next) {
		if (item->chapter == chapter && item->cursor == cursorhdl) {
			return item;
		}
	}
	return NULL;
}

static void wsp_es_set_nextgetrowsposition(struct wspd_client_state *client_state,
				    uint32_t queryidentifier,
				    uint32_t cursorhandle,
				    uint32_t chapter,
				    uint32_t index)
{
	struct client_query_data *query_data = find_query_info(queryidentifier);
	struct next_cursor_data *next_cursor = NULL;

	/*
	 * we store 0 based indices ala array indices
	 */
	if (query_data == NULL) {
		return;
	}
	next_cursor = find_next_cursor_index(query_data,
					     cursorhandle,
					     chapter);
	if (next_cursor != NULL) {
		next_cursor->index = index;
	}
	query_data->current_index = index;
}

static uint32_t wsp_es_get_nextgetrowsposition(struct wspd_client_state *client_state,
					uint32_t queryidentifier,
					uint32_t cursorhandle,
					uint32_t chapter)
{
	struct client_query_data *query_data = find_query_info(queryidentifier);
	struct next_cursor_data *next_cursor = NULL;
	uint32_t index = 0;

	if (query_data == NULL) {
		DBG_ERR("couldn't get index for queryid %u cursor "
			"handle %u chapter %u\n",
			queryidentifier, cursorhandle, chapter);
		/* shouldn't get here */
		return 0;
	}
	next_cursor = find_next_cursor_index(query_data,
					     cursorhandle,
					     chapter);
	if (next_cursor != NULL) {
		index = next_cursor->index;
	}
	return index;
}

static struct binding_data *find_binding_data(struct client_query_data *data,
					      uint32_t cursorhdl)
{
	struct binding_data *item = NULL;
	struct client_query_data *query_data = NULL;

	query_data = find_query_info(data->query_id);
	if (query_data == NULL) {
		return NULL;
	}
	for (item = query_data->bindings.items; item; item = item->next) {
		if (item->cursor_hndl == cursorhdl) {
			break;
		}
	}
	return item;
}

static struct binding_data *find_bindings(uint32_t queryidentifier,
				uint32_t cursorhandle)
{
	struct binding_data *item = NULL;
	struct client_query_data *query_data = NULL;

	query_data = find_query_info(queryidentifier);
	if (query_data == NULL) {
		return NULL;
	}
	item = find_binding_data(query_data, cursorhandle);
	return item;
}

static struct wsp_ctablecolumn *wsp_es_get_binding(
					struct wspd_client_state *client_state,
					uint32_t queryidentifier,
					uint32_t cursorhandle,
					uint32_t *ncols)
{
	struct binding_data *binding_info = NULL;

	binding_info = find_bindings(queryidentifier, cursorhandle);
	if (binding_info == NULL) {
		return NULL;
	}
	*ncols  = binding_info->ncols;
	return binding_info->columns;
}

static bool wsp_es_has_bindings(struct wspd_client_state *client_state,
			 uint32_t queryidentifier,
			 uint32_t cursorhandle)
{
	struct binding_data *item = NULL;

	item = find_bindings(queryidentifier, cursorhandle);
	return (item != NULL);
}

static struct binding_data *create_binding_data(struct client_query_data *data,
						uint32_t cursorhdl)
{
	struct binding_data *item = NULL;

	item = talloc_zero(data, struct binding_data);

	if (item == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}
	DLIST_ADD_END(data->bindings.items, item);
	data->bindings.nbindings++;
out:
	return item;
}

static void wsp_es_set_bindings(struct wspd_client_state *client_state,
			 uint32_t queryidentifier,
			 uint32_t cursorhandle,
			 struct wsp_ctablecolumn *columns,
			 uint32_t ncolumns)
{
	struct client_query_data * query_data;
	struct binding_data *binding;
	struct query_conv_ops *conv_ops = NULL;

	query_data = find_query_info(queryidentifier);
	DBG_INFO("got bindings for %d columns %p\n", ncolumns, columns);
	/* #FIXME need to pass CursorHandle here ? */
	binding = create_binding_data(query_data, cursorhandle);
	binding->columns = columns;
	binding->ncols = ncolumns;
	binding->cursor_hndl = cursorhandle;
	/*
	 * need to create a mapping between the elastic cols returned
	 * and the binding columns requested
	 */
	binding->result_converter = talloc_zero(binding,
						struct binding_result_mapper);
	conv_ops = client_state->wsp_abstract_state->conv_ops;

	conv_ops->bld_mapper(binding,
			     columns,
			     ncolumns,
			     &query_data->cols_to_convert,
			     binding->result_converter);
}

static uint32_t wsp_es_get_bookmarkpos(struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle,
				uint32_t bmkhandle)
{
	uint32_t result = 0;

	/*
	 *
	 * e.g. with CRowSeekAt
	 *
	 * a)   _bmkOffset DBBMK_FIRST, _cskip 0
	 *         -> rows[0]
	 * b)   _bmkOffset DBBMK_FIRST, _cskip 1
	 *         -> rows[1]
	 * c)   _bmkOffset 0xFFFFFFFB, _cskip 0
	 *         -> rows[0]
	 * d)   _bmkOffset 0xFFFFFFFB, _cskip 1
	 *         -> rows[1]
	 * e)   _bmkOffset 0, _cskip 0
	 *         -> [empty results] empty rows data returned
	 * f)   _bmkOffset 0, _cskip 1
	 *         -> rows[1]
	 * g)   _bmkOffset 1, _cskip 0
	 *         -> rows[1]
	 * h)   _bmkOffset 1, _cskip 0
	 *         -> rows[1]
	 * i)   _bmkOffset DBBMK_LAST, _cskip 0
	 *         -> rows[size - 1]
	 * j)   _bmkOffset DBBMK_LAST, _cskip 1
	 *         -> [empty results] empty rows data returned
	 *
	 */
	switch (bmkhandle) {
		case 0xFFFFFFFB:
		case DBBMK_FIRST:
			result = 0;
			break;
		case DBBMK_LAST: {
			struct client_query_data *query_data =
					find_query_info(queryidentifier);
			SMB_ASSERT(query_data != NULL);
			result = result - 1;
			break;
		}
		default:
			if (bmkhandle >= 0) {
				result = bmkhandle - 1;
			}
		DBG_INFO("bmkhandle 0x%x\n", bmkhandle);
		break;
	}
	return result;
}

struct wsp_es_get_expensive_properties_state {
	struct client_query_data *query_data;
	uint32_t rcrowstotal;
	uint32_t rdwresultcount;
	uint32_t maxrank;
	uint32_t num_rows;
};

static void wsp_es_get_expensive_properties_query_status_done(
						struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_expensive_properties_send(TALLOC_CTX *ctx,
					struct tevent_context *ev,
					struct wspd_client_state *client_state,
					uint32_t queryidentifier,
					uint32_t cursorhandle)
{
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	struct client_query_data *query_data = find_query_info(queryidentifier);
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_es_get_expensive_properties_state *state = NULL;
	uint32_t boolean_options;
	uint32_t num_rows = 0;

	req = tevent_req_create(ctx, &state,
				struct wsp_es_get_expensive_properties_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	if (query_data == NULL) {
		DBG_ERR("failed to find query for %u\n", queryidentifier);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}
	state->query_data = query_data;

	if (query_data->wsp_enabled &&
	    query_data->query_state != ES_QUERY_COMPLETE)
	{
		subreq = wsp_es_query_status_send(state, ev,
						  glob_data,
						  queryidentifier,
						  &query_data->query_state,
						  &state->num_rows);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq,
			wsp_es_get_expensive_properties_query_status_done,
			req);
		return req;
	}

	if (query_data->wsp_enabled) {
		num_rows = query_data->nrows;
	}

	boolean_options = query_data->rowsetproperties.ubooleanoptions;
	if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
		state->rdwresultcount = num_rows;
		state->rcrowstotal = num_rows;
		/* how does one fake the makrank ? */
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void wsp_es_get_expensive_properties_query_status_done(
						struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_expensive_properties_state *state = tevent_req_data(
		req, struct wsp_es_get_expensive_properties_state);
	uint32_t boolean_options;
	NTSTATUS status;

	status = wsp_es_query_status_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return;
	}

	if (state->query_data->query_state == ES_QUERY_COMPLETE) {
		state->query_data->nrows = state->num_rows;
	}
	boolean_options = state->query_data->rowsetproperties.ubooleanoptions;
	if (!(boolean_options & EDONOTCOMPUTEEXPENSIVEPROPS)) {
		state->rdwresultcount = state->num_rows;
		state->rcrowstotal = state->num_rows;
		/* how does one fake the makrank ? */
	}
	tevent_req_done(req);
}

static HRESULT wsp_es_get_expensive_properties_recv(struct tevent_req *req,
			uint32_t *rcrowstotal,
			uint32_t *rdwresultcount,
			uint32_t *maxrank)
{
	HRESULT hres;

	struct wsp_es_get_expensive_properties_state *state =
		tevent_req_data(req, struct wsp_es_get_expensive_properties_state);

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	*rcrowstotal = state->rcrowstotal;
	*rdwresultcount = state->rdwresultcount;
	*maxrank = state->maxrank;

	tevent_req_received(req);
	return HRES_OK;

}

struct wsp_es_get_rows_data_state {
	TALLOC_CTX *ctx;
	struct backend_getrowsout **rowsout;
	struct client_query_data *query_info;
	struct wspd_client_state *client_state;
	uint32_t rows_requested;
	bool *nomorerowstoreturn;
	uint32_t index;
	uint32_t rows_to_get;
	uint32_t fbwdfetch;
};


static HRESULT fetch_rows_from_cache(
		TALLOC_CTX *ctx,
		struct wspd_client_state *client_state,
		struct client_query_data *query_data,
		struct backend_getrowsout **rowsout,
		uint32_t index,
		uint32_t rows_to_get,
		uint32_t fbwdfetch,
		bool *nomorerowstoreturn)
{
	struct backend_getrowsout *p_rowsout = NULL;
	int i;
	int j;
	uint32_t limit = query_data->query_result_limit;

	if (index > query_data->nrows) {
		DBG_ERR("start index (%d) exceeds num rows "
			"(%d) in cached results\n",
			index,
			query_data->nrows);
		return HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL);
	}

	p_rowsout = talloc_zero(ctx,
				struct backend_getrowsout);
	if (p_rowsout == NULL) {
		return HRES_E_OUTOFMEMORY;
	}

	p_rowsout->rows = talloc_zero_array(p_rowsout,
					    struct backend_row,
					    rows_to_get);
	if (p_rowsout->rows == NULL) {
		return HRES_E_OUTOFMEMORY;
	}

	for (i = index, j = 0;
	     i < query_data->nrows
	     && i < index + rows_to_get
	     && i < limit;
	     i++, j++)
	{
		p_rowsout->rows[j] = query_data->rows->rows[i];
	}
	p_rowsout->nrows = j;
	*rowsout = p_rowsout;
	*nomorerowstoreturn = (p_rowsout->nrows < rows_to_get);
	return HRES_OK;
}

static void wsp_es_get_rows_data_cached_done(struct tevent_req *subreq);
static void wsp_es_get_rows_data_done(struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_rows_data_send(TALLOC_CTX *ctx,
			  struct tevent_context *ev,
			  struct wspd_client_state *client_state,
			  struct client_query_data *query_data,
			  struct backend_getrowsout **rowsout, uint32_t index,
			  uint32_t rows_to_get, uint32_t fbwdfetch,
			  bool *nomorerowstoreturn)
{
	struct auth_session_info *session_info = get_session_info(client_state);
	struct tevent_req *req, *subreq = NULL;
	struct wsp_es_get_rows_data_state *state = NULL;
	struct wsp_abstract_state *glob_data = client_state->wsp_abstract_state;
	bool reverse_fetch = (fbwdfetch == 1);
	uint32_t limit = query_data->query_result_limit;

	req = tevent_req_create(ctx, &state, struct wsp_es_get_rows_data_state);
	if (req == NULL) {
		return NULL;
	}

	state->rowsout = rowsout;
	state->ctx = ctx;
	state->nomorerowstoreturn = nomorerowstoreturn;

	if ((int32_t)index < 0) {
		/*
		 * #FIXME #TODO #CHECK why am I doing this ???
		 * surely we should just set *nomorerowstoreturn = true
		 * and compelete the req and just return ?
		 */
		(*state->rowsout) = talloc_zero(ctx,
					struct backend_getrowsout);
		if (tevent_req_nomem((*state->rowsout), req)) {
			return tevent_req_post(req, ev);
		}
		(*state->rowsout)->rows = talloc_zero_array((*state->rowsout),
						struct backend_row,
						rows_to_get);

		if (tevent_req_nomem((*state->rowsout)->rows, req)) {
			return tevent_req_post(req, ev);
		}
		*nomorerowstoreturn = true;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (query_data->elastic_cfg.acl_filter) {
		HRESULT hres;
		if (query_data->rows == NULL || query_data->rows->rows == NULL) {
			DBG_ERR("acl filtering enabled but no results available\n");
			state->query_info = query_data;
			state->fbwdfetch = fbwdfetch;
			state->index = index;
			state->rows_to_get = rows_to_get;
			state->client_state = client_state;
			/*
			 * acl_filtered results need to be cached
			 * we don't yet have any cached results because
			 * either
			 *   a) EDONOTCOMPUTEEXPENSIVEPROPS was set so
			 *      we didn't cache the results of the query
			 *   b) there were no results at all and we are
			 *      retrying
			 *
			 * we need to call wsp_es_search_send again here
			 * in order to trigger caching of the results.
			 */
			subreq = wsp_es_search_send(ctx,
						ev,
						query_data,
						query_data->sources,
						query_data->jquery_str,
						false,
						0,
						limit,
						query_data->vfs_conn_wrap,
						session_info,
						glob_data);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}
			tevent_req_set_callback(subreq,
						wsp_es_get_rows_data_cached_done, req);
			return req;
		}
		hres = fetch_rows_from_cache(ctx,
					       client_state,
					       query_data,
					       rowsout,
					       index,
					       rows_to_get,
					       fbwdfetch,
					       nomorerowstoreturn);
		if (!HRES_IS_OK(hres)) {
			tevent_req_herror(req, hres);
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->rows_requested = rows_to_get;

	if (limit && index >= limit) {
		*nomorerowstoreturn = true;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (limit && (index + rows_to_get) >= limit) {
		rows_to_get = limit - index;
	}
	subreq = wsp_es_search_send(state,
			ev,
			query_data,
			query_data->sources,
			query_data->jquery_str,
			reverse_fetch,
			index,
			rows_to_get,
			query_data->vfs_conn_wrap,
			session_info,
			glob_data);
	if (subreq == NULL) {
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_UNSUCCESSFUL));
		req = tevent_req_post(req, ev);
		return req;
	}

	tevent_req_set_callback(subreq, wsp_es_get_rows_data_done, req);
	return req;
}

static void wsp_es_get_rows_data_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_rows_data_state *state = tevent_req_data(
		req, struct wsp_es_get_rows_data_state);
	HRESULT hres;
	uint32_t total_rows;
	uint32_t rows_left;

	hres = wsp_es_search_recv(subreq,
				state->ctx,
				state->rowsout,
				&rows_left,
				&total_rows
				);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	*state->nomorerowstoreturn =
		((*state->rowsout)->nrows < state->rows_requested);
	tevent_req_done(req);
}

static HRESULT wsp_es_get_rows_data_recv(struct tevent_req *req)
{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	tevent_req_received(req);
	return HRES_OK;
}

static void wsp_es_get_rows_data_cached_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_rows_data_state *state = tevent_req_data(
		req, struct wsp_es_get_rows_data_state);
	uint32_t rows_left;
	HRESULT hres;

	hres =  wsp_es_search_recv(subreq,
				 state->query_info,
				 &state->query_info->rows,
				 &rows_left,
				 &state->query_info->nrows);
	DBG_DEBUG("Query finished %s cached %d results\n",
			hresult_errstr(hres),
			(int)state->query_info->nrows);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	hres = fetch_rows_from_cache(state->ctx,
				       state->client_state,
				       state->query_info,
				       state->rowsout,
				       state->index,
				       state->rows_to_get,
				       state->fbwdfetch,
				       state->nomorerowstoreturn);

	if (!HRES_IS_OK(hres)) {
		tevent_req_herror(req, hres);
		return;
	}
	tevent_req_done(req);
}

struct wsp_es_get_rows_state {
	struct tevent_context *ev;
	struct wsp_cbasestoragevariant **rowsarray;
	struct backend_getrowsout *rows;
	struct conn_wrap *conn_wrap;
	struct wspd_client_state *client_state;
	uint32_t queryid;
	bool nomorerowstoreturn;
	uint32_t numrowsreturned;
	uint32_t remaining_rows;
	struct binding_data *binding;
	uint32_t nbinding_cols;
	struct map_data *map_data;
	uint32_t index;
};

static void wsp_es_get_rows_done(struct tevent_req *subreq);

static struct tevent_req *wsp_es_get_rows_send(TALLOC_CTX *ctx,
		     struct tevent_context *ev,
		     struct wspd_client_state *client_state,
		     uint32_t queryidentifier,
		     uint32_t cursorhandle,
		     uint32_t numrowsrequested,
		     uint32_t fetchforward)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct client_query_data *query_data = NULL;
	struct wsp_es_get_rows_state *state = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_es_get_rows_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->client_state = client_state;
	state->queryid = queryidentifier;

	/* find the bindings associated with this query */
	state->binding = find_bindings(queryidentifier, cursorhandle);
	if (state->binding == NULL) {
		/* early exit with E_UNEXPECTED set */
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return tevent_req_post(req, ev);
	}

	state->map_data = state->binding->result_converter->map_data;
	state->nbinding_cols = state->binding->ncols;

	query_data = find_query_info(queryidentifier);
	if (query_data == NULL) {
		DBG_ERR("No query data for query id=%u\n", queryidentifier);
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return tevent_req_post(req, ev);
	}

	if (query_data->query_state == ES_QUERY_ERROR) {
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return tevent_req_post(req, ev);
	}

	if (query_data->wsp_enabled == false) {
		state->nomorerowstoreturn = true;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	state->conn_wrap = query_data->vfs_conn_wrap;

	state->rowsarray = talloc_zero_array(state,
			struct wsp_cbasestoragevariant*,
			numrowsrequested);
	if (state->rowsarray == NULL) {
		DBG_ERR("out of memory\n");
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return tevent_req_post(req, ev);
	}

	/* current index was set from last call to SetNextGetRowsPosition */
	state->index = query_data->current_index;

	state->rows = talloc_zero(state, struct backend_getrowsout);
	if (state->rows == NULL) {
		DBG_ERR("out of memory\n");
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return tevent_req_post(req, ev);
	}

	subreq = wsp_es_get_rows_data_send(state, ev, client_state,
			       query_data,
			       &state->rows,
			       state->index, numrowsrequested,
			       fetchforward,
			       &state->nomorerowstoreturn);
	if (subreq == NULL) {
		DBG_ERR("unexpected failure trying to return row data\n");
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wsp_es_get_rows_done, req);
	return req;
}

static void wsp_es_get_rows_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_es_get_rows_state *state = tevent_req_data(
		req, struct wsp_es_get_rows_state);
	uint32_t rows_to_try = state->rows->nrows; /* this is how many rows we got */
	struct es_row_data *row_data = NULL;
	struct client_query_data *query_data = NULL;
	HRESULT hres;

	DBG_DEBUG("rows return is %d\n", rows_to_try);
	DBG_DEBUG("rows allocated is %d\n",
		(int)talloc_array_length(state->rowsarray));

	hres = wsp_es_get_rows_data_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		DBG_ERR("failed to fetch row data: %s\n",
			hresult_errstr(hres));
		return;
	}

	row_data = talloc_zero(state->rowsarray, struct es_row_data);
	if (row_data == NULL) {
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return;
	}

	query_data = find_query_info(state->queryid);
	if (query_data == NULL) {
		DBG_ERR("Failed to find query data for query %d\n",
			state->queryid);
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return;
	}

	row_data->rowid_generator = talloc_zero(row_data, uint32_t);
	if (row_data->rowid_generator == NULL) {
		tevent_req_herror(req, HRES_E_OUTOFMEMORY);
		return;
	}

	*row_data->rowid_generator = state->index;
	row_data->id_cache = state->client_state->id_cache;
	row_data->share_path = query_data->share_path;
	row_data->share = query_data->share;

	hres = convert_backend_rows(state->rowsarray,
				state->conn_wrap,
				state->rows,
				state->map_data,
				state->binding->columns,
				rows_to_try,
				state->nbinding_cols,
				state->rowsarray,
				&state->numrowsreturned,
				row_data);
	if (!HRES_IS_OK(hres)) {
		tevent_req_herror(req, hres);
		return;
	}

	tevent_req_done(req);
}

static HRESULT wsp_es_get_rows_recv(struct tevent_req *req,
			TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant ***rowsarray,
			bool *nomorerowstoreturn,
			uint32_t *numrowsreturned)
{
	struct wsp_es_get_rows_state *state = tevent_req_data(
		req, struct wsp_es_get_rows_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*nomorerowstoreturn = state->nomorerowstoreturn;
	*numrowsreturned = state->numrowsreturned;
	*rowsarray = talloc_steal(ctx, state->rowsarray);

	tevent_req_received(req);
	return HRES_OK;
}

struct wsp_es_get_approximate_position_state {
	uint32_t position;
};

static struct tevent_req *wsp_es_get_approximate_position_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle,
				uint32_t bmk)
{
	/*
	 * not sure how to handle this yet, somehow it seems bookmarks
	 * must be exposed to the client from the row results, but...
	 * I am not sure how yet.
	 * For the moment just pass this onto wsp_es_get_bookmarkpos
	 * Strange the documentation for handling
	 * the CPMGETAPPOXIMATEPOSITION message doesn't mention
	 * the Chapter specified...
	 */
	struct tevent_req *req = NULL;
	struct wsp_es_get_approximate_position_state *state = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_es_get_approximate_position_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}
	state->position = wsp_es_get_bookmarkpos(client_state,
					  queryidentifier,
					  cursorhandle,
					  bmk);
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_get_approximate_position_recv(struct tevent_req *req,
			uint32_t *position)
{
	HRESULT hres;

	struct wsp_es_get_approximate_position_state *state = tevent_req_data(
		req, struct wsp_es_get_approximate_position_state);

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	*position = state->position;
	tevent_req_received(req);
	return HRES_OK;
}

static void remove_cursors_data(uint32_t cursor_handle,
			struct client_query_data *query_info)
{
	struct next_cursor_data *item = query_info->next_cursors.items;

	while (item) {
		struct next_cursor_data *tmp = item->next;

		if (item->cursor == cursor_handle) {
			DLIST_REMOVE(query_info->next_cursors.items, item);
			TALLOC_FREE(item);
			query_info->ncursors--;
			item = tmp;
		} else {
			item = item->next;
		}
	}
}

struct wsp_es_release_cursor_state {
	uint32_t remaining_cursors;
};

static struct tevent_req *wsp_es_release_cursor_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				uint32_t cursorhandle)
{
	struct wsp_es_release_cursor_state *state = NULL;
	struct tevent_req *req = NULL;
	struct client_query_data *query_info = NULL;
	struct binding_data *binding = NULL;
	uint32_t ncursors = 0;

	req = tevent_req_create(ctx,
				&state,
				struct wsp_es_release_cursor_state);
	if (req == NULL) {
		return NULL;
	}

	query_info = find_query_info(queryidentifier);
	binding = find_binding_data(query_info, cursorhandle);

	if (binding != NULL && query_info != NULL) {
		DLIST_REMOVE(query_info->bindings.items, binding);
		/* #FIXME freeing the binding should result in it's removal from the list */
		TALLOC_FREE(binding);
		query_info->bindings.nbindings--;
		remove_cursors_data(cursorhandle, query_info);
	}
	state->remaining_cursors = ncursors;
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_release_cursor_recv(struct tevent_req *req,
				uint32_t *remaining_cursors)
{
	struct wsp_es_release_cursor_state *state = tevent_req_data(
		req, struct wsp_es_release_cursor_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*remaining_cursors = state->remaining_cursors;
	tevent_req_received(req);
	return HRES_OK;
}


struct wsp_es_release_query_state {
	uint32_t dummy;
};

static struct tevent_req *wsp_es_release_query_send(TALLOC_CTX *ctx,
					struct tevent_context *ev,
					struct wspd_client_state *client_state,
					uint32_t queryidentifier)
{
	struct client_query_data *query_info = NULL;
	struct wsp_es_release_query_state *state = NULL;
	struct tevent_req *req = tevent_req_create(ctx, &state,
				struct wsp_es_release_query_state);

	if (req == NULL) {
		return NULL;
	}

	query_info = find_query_info(queryidentifier);
	if (query_info == NULL) {
		DBG_ERR("failed to retrieve query associated with handle %u\n",
			queryidentifier);
		tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}
	TALLOC_FREE(query_info);
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_release_query_recv(struct tevent_req *req)
{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	tevent_req_received(req);
	return HRES_OK;
}

static void wsp_es_get_last_unretrieved_evt(struct wspd_client_state *client_state,
				     uint32_t queryidentifier,
				     /* out */
				     uint32_t *wid,
				     uint8_t *eventtype,
				     bool *moreevents,
				     uint8_t *rowsetitemstate,
				     uint8_t *changeditemstate,
				     uint8_t *rowsetevent,
				     uint64_t *rowseteventdata1,
				     uint64_t *rowseteventdata2)
{
	/* can't handle this */
	*wid = 0;
	*eventtype = 0;
	*moreevents = false;
	*rowsetitemstate = 0;
	*changeditemstate = 0;
	*rowsetevent = 0;
	*rowseteventdata1 = 0;
	*rowseteventdata2 = 0;
}

struct wsp_es_get_last_unretrieved_evt_state {
	uint32_t wid;
	uint8_t eventtype;
	bool moreevents;
	uint8_t rowsetitemstate;
	uint8_t changeditemstate;
	uint8_t rowsetevent;
	uint64_t rowseteventdata1;
	uint64_t rowseteventdata2;
};

static struct tevent_req *wsp_es_get_last_unretrieved_evt_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier)
{
	struct wsp_es_get_last_unretrieved_evt_state *state = NULL;
	struct tevent_req *req = NULL;

	req = tevent_req_create(ctx,
				&state,
				struct wsp_es_get_last_unretrieved_evt_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	wsp_es_get_last_unretrieved_evt(client_state,
				queryidentifier,
				&state->wid,
				&state->eventtype,
				&state->moreevents,
				&state->rowsetitemstate,
				&state->changeditemstate,
				&state->rowsetevent,
				&state->rowseteventdata1,
				&state->rowseteventdata2);
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_get_last_unretrieved_evt_recv(struct tevent_req *req,
				     uint32_t *wid,
				     uint8_t *eventtype,
				     bool *moreevents,
				     uint8_t *rowsetitemstate,
				     uint8_t *changeditemstate,
				     uint8_t *rowsetevent,
				     uint64_t *rowseteventdata1,
				     uint64_t *rowseteventdata2)
{
	struct wsp_es_get_last_unretrieved_evt_state *state =
		tevent_req_data(req, struct wsp_es_get_last_unretrieved_evt_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*wid = state->wid;
	*eventtype = state->eventtype;
	*moreevents = state->moreevents;
	*rowsetitemstate = state->rowsetitemstate;
	*changeditemstate = state->changeditemstate;
	*rowsetevent = state->rowsetevent;
	*rowseteventdata1 = state->rowseteventdata1;
	*rowseteventdata2 = state->rowseteventdata2;
	tevent_req_received(req);
	return HRES_OK;
}

static NTSTATUS wsp_es_get_query_stats(struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				uint32_t *numindexeditems,
				uint32_t *numoutstandingadds,
				uint32_t *numoutstandingmodifies)
{
	struct client_query_data * query_info = NULL;

	/* don't believe we can handle this, just init all to 0 */
	*numindexeditems = 0;
	*numoutstandingadds = 0;
	*numoutstandingmodifies = 0;

	query_info = find_query_info(queryidentifier);
	if (query_info == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (query_info->wsp_enabled == false) {
		DBG_ERR("indexing not available for share %s\n",
			 query_info->share);
		/*
		 * On windows we see that an indexed share that has
		 * indexing turned off seems to return zero results
		 * until such time as the client requests scope statistics
		 * if we sent the error below then the client will fall back
		 * to searching via smb.
		 */
		return NT_STATUS(0x80070003);
	}
	if (query_info->no_index){
		return NT_STATUS(WIN_UPDATE_ERR);
	}
	return NT_STATUS_OK;
}

struct wsp_es_get_query_stats_state {
	uint32_t numindexeditems;
	uint32_t numoutstandingadds;
	uint32_t numoutstandingmodifies;
};

static struct tevent_req *wsp_es_get_query_stats_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier)
{
	struct wsp_es_get_query_stats_state *state = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	req = tevent_req_create(ctx,
				&state,
				struct wsp_es_get_query_stats_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	status = wsp_es_get_query_stats(client_state,
				queryidentifier,
				&state->numindexeditems,
				&state->numoutstandingadds,
				&state->numoutstandingmodifies);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return tevent_req_post(req, ev);
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_get_query_stats_recv(struct tevent_req *req,
			uint32_t *numindexeditems,
			uint32_t *numoutstandingadds,
			uint32_t *numoutstandingmodifies)
{
	struct wsp_es_get_query_stats_state *state =
		tevent_req_data(req, struct wsp_es_get_query_stats_state);
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}

	*numindexeditems = state->numindexeditems;
	*numoutstandingadds = state->numoutstandingadds;
	*numoutstandingmodifies =  state->numoutstandingmodifies;
	tevent_req_received(req);
	return HRES_OK;
}

static NTSTATUS wsp_es_set_scope_prio(struct wspd_client_state *client_state,
			       uint32_t queryidentifier,
			       uint32_t priority)
{
	struct client_query_data *query_info = NULL;

	query_info = find_query_info(queryidentifier);
	if (query_info == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	if (query_info->no_index){
		return NT_STATUS(WIN_UPDATE_ERR);
	}
	return NT_STATUS_OK;
}

struct wsp_es_set_scope_prio_state {
	uint32_t dummy;
};

static struct tevent_req *wsp_es_set_scope_prio_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state,
				uint32_t queryidentifier,
				uint32_t priority)
{
	struct wsp_es_set_scope_prio_state *state = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	req = tevent_req_create(ctx,
				&state,
				struct wsp_es_set_scope_prio_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	status = wsp_es_set_scope_prio(client_state,
				queryidentifier,
				priority);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_herror(req, HRESULT_FROM_NT(status));
		return tevent_req_post(req, ev);
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static HRESULT wsp_es_set_scope_prio_recv(struct tevent_req *req)
{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	tevent_req_received(req);
	return HRES_OK;
}

static uint32_t wsp_es_get_whereid(struct wspd_client_state *client_state,
			    uint32_t queryidentifier)
{
	return queryidentifier;
}

void init_elastic_wsp_abs_interace(void)
{
	static struct wsp_abstract_interface concrete_impl = {};

	concrete_impl.initialise = wsp_es_initialise;
	concrete_impl.getserverversions = wsp_es_get_server_versions;
	concrete_impl.iscatalogavailable = wsp_es_is_catalog_available;
	concrete_impl.getclientinformation = wsp_es_get_client_information;
	concrete_impl.storeclientinformation = wsp_es_store_client_information;
	concrete_impl.runnewquery_send = wsp_es_run_new_query_send;
	concrete_impl.runnewquery_recv = wsp_es_run_new_query_recv;
	concrete_impl.clientqueryhascursorhandle = wsp_es_clientquery_has_cursorhandle;
	concrete_impl.getquerystatus_send = wsp_es_get_query_status_send;
	concrete_impl.getquerystatus_recv = wsp_es_get_query_status_recv;
	concrete_impl.getstate_send = wsp_es_get_state_send;
	concrete_impl.getstate_recv = wsp_es_get_state_recv;
	concrete_impl.getratiofinishedparams_send =
			wsp_es_get_ratiofinished_params_send;
	concrete_impl.getratiofinishedparams_recv =
			wsp_es_get_ratiofinished_params_recv;
	concrete_impl.setnextgetrowsposition = wsp_es_set_nextgetrowsposition;
	concrete_impl.getnextgetrowsposition = wsp_es_get_nextgetrowsposition;
	concrete_impl.getbindings = wsp_es_get_binding;
	concrete_impl.hasbindings = wsp_es_has_bindings;
	concrete_impl.getbookmarkposition = wsp_es_get_bookmarkpos;
	concrete_impl.getexpensiveproperties_send =
			wsp_es_get_expensive_properties_send;
	concrete_impl.getexpensiveproperties_recv =
			wsp_es_get_expensive_properties_recv;
		concrete_impl.getnextgetrowsposition = wsp_es_get_nextgetrowsposition;
	concrete_impl.getrows_send = wsp_es_get_rows_send;
	concrete_impl.getrows_recv = wsp_es_get_rows_recv;
	concrete_impl.setbindings = wsp_es_set_bindings;
		concrete_impl.getapproximatepos_send =
		wsp_es_get_approximate_position_send;
	concrete_impl.getapproximatepos_recv =
		wsp_es_get_approximate_position_recv;
	concrete_impl.releasecursor_send = wsp_es_release_cursor_send;
	concrete_impl.releasecursor_recv = wsp_es_release_cursor_recv;
	concrete_impl.releasequery_send = wsp_es_release_query_send;
	concrete_impl.releasequery_recv = wsp_es_release_query_recv;
	concrete_impl.getlastunretrievedevt_send =
		wsp_es_get_last_unretrieved_evt_send;
	concrete_impl.getlastunretrievedevt_recv =
		wsp_es_get_last_unretrieved_evt_recv;
	concrete_impl.getquerystats_send = wsp_es_get_query_stats_send;
	concrete_impl.getquerystats_recv = wsp_es_get_query_stats_recv;
	concrete_impl.setscopepriority_send = wsp_es_set_scope_prio_send;
	concrete_impl.setscopepriority_recv = wsp_es_set_scope_prio_recv;
	concrete_impl.getwhereid = wsp_es_get_whereid;
	concrete_impl.getpropertyvalueforworkid_send =
			wsp_es_get_propertyvalue_for_workid_send;
	concrete_impl.getpropertyvalueforworkid_recv =
			wsp_es_get_propertyvalue_for_workid_recv;
	register_backend_impl(WSP_BACKEND_ELASTIC,
			es_wsp_conv_ops(),
			&concrete_impl);
}

static bool wsp_es_lookup_where_id(TALLOC_CTX *mem_ctx,
			       struct wspd_client_state *client_state,
			       uint32_t where_id,
			       const char **filter_out,
			       const char **share_out)
{
	struct client_query_data *item = NULL;
	char *lcl_filter = NULL;
	char *lcl_share = NULL;

	/*
	 * search all open queries (handled by this worker process)
	 * for where id
	 */

	item = find_query_info(where_id);
	if (item == NULL) {
		DBG_WARNING("Unknown where_id [0x%" PRIx32 "]\n", where_id);
		return false;
	}

	if (item->query_id != where_id ||
	    item->where_filter == NULL ||
	    item->share == NULL)
	{
		DBG_WARNING("Unknown where_id [0x%" PRIx32 "] "
			    " where_filter [%s] share [%s]\n",
			    where_id,
			    item->where_filter,
			    item->share);
		return false;
	}

	lcl_filter = talloc_strdup(mem_ctx, item->where_filter);
	if (lcl_filter == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	lcl_share = talloc_strdup(mem_ctx, item->share);
	if (lcl_share == NULL) {
		DBG_ERR("out of memory\n");
		TALLOC_FREE(lcl_filter);
		return false;
	}

	*filter_out = lcl_filter;
	*share_out = lcl_share;

	return true;
}
