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
#include "includes.h"
#include "lib/util/debug.h"
#include "lib/cmdline/cmdline.h"
#include "lib/cmdline_contexts.h"
#include "param.h"
#include "client.h"
#include "libsmb/proto.h"
#include "librpc/rpc/rpc_common.h"
#include "librpc/wsp/wsp_util.h"
#include "rpc_client/cli_pipe.h"
#include "rpc_client/wsp_cli.h"
#include "libcli/wsp/wsp_aqs.h"
#include "librpc/gen_ndr/ndr_wsp.h"
#include "librpc/gen_ndr/ndr_wsp_data.h"
#include "dcerpc.h"

#define WIN_VERSION_64 0x10000

/* send connectin message */
static NTSTATUS wsp_connect(TALLOC_CTX *ctx,
			struct wsp_client_ctx *wsp_ctx,
			const char* clientmachine,
			const char* clientuser,
			const char* server,
			bool *is_64bit)
{
	struct wsp_request *request = NULL;
	struct wsp_response *response = NULL;
	uint32_t client_ver;
	uint32_t server_ver;
	DATA_BLOB unread = data_blob_null;
	NTSTATUS status;
	TALLOC_CTX *local_ctx = talloc_new(ctx);


	if (local_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	response = talloc_zero(local_ctx, struct wsp_response);
	if (!response) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	request = talloc_zero(local_ctx, struct wsp_request);
	if (!request) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (!init_connectin_request(local_ctx, request,
			       clientmachine, clientuser, server)) {
		DBG_ERR("Failed in initialise connection message\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status =  wsp_request_response(local_ctx, wsp_ctx,
			request, response, &unread);
	if (NT_STATUS_IS_OK(status)) {
		client_ver = request->message.cpmconnect.iclientversion;
		server_ver = response->message.cpmconnect.server_version;
		*is_64bit =
			(server_ver & WIN_VERSION_64)
			&& (client_ver & WIN_VERSION_64);
	}

out:
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_query(TALLOC_CTX *ctx,
			     struct wsp_client_ctx *wsp_ctx,
			     uint32_t limit,
			     t_select_stmt *select,
			     uint32_t *single_cursor)
{
	struct wsp_request *request = NULL;
	struct wsp_response *response = NULL;
	NTSTATUS status;
	DATA_BLOB unread = data_blob_null;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	if (local_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	request = talloc_zero(local_ctx, struct wsp_request);
	if (!request) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	response = talloc_zero(local_ctx, struct wsp_response);
	if (!response) {
		status = NT_STATUS_NO_MEMORY;
		goto out;;
	}

	if (!create_querysearch_request(ctx, request, select)) {
		DBG_ERR("error setting up query request message\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	request->message.cpmcreatequery.rowsetproperties.cmaxresults = limit;

	status = wsp_request_response(local_ctx,
			wsp_ctx,
			request,
			response,
			&unread);
	if (NT_STATUS_IS_OK(status)) {
		if (unread.length == 4) {
			*single_cursor = IVAL(unread.data, 0);
		}
	}

out:
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS create_bindings(TALLOC_CTX *ctx,
				struct wsp_client_ctx *wsp_ctx,
				t_select_stmt *select,
				uint32_t cursor,
				struct wsp_cpmsetbindingsin *bindings_out,
				bool is_64bit)
{
	struct wsp_request *request = NULL;
	struct wsp_response *response = NULL;
	NTSTATUS status;
	DATA_BLOB unread = data_blob_null;

	request = talloc_zero(ctx, struct wsp_request);
	if (!request) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	response = talloc_zero(ctx, struct wsp_response);
	if (!response) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	if (!create_setbindings_request(ctx,
				request,
				select,
				cursor,
				is_64bit)) {
		DBG_ERR("Failed to create setbindings message\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto out;
	}

	status = wsp_request_response(ctx,
			wsp_ctx,
			request,
			response,
			&unread);
	if (NT_STATUS_IS_OK(status)) {
		*bindings_out = request->message.cpmsetbindings;
	}

out:
	data_blob_free(&unread);
	return status;
}

static NTSTATUS create_querystatusex(TALLOC_CTX *ctx,
				struct wsp_client_ctx *wsp_ctx,
				uint32_t cursor,
				uint32_t *nrows)
{
	struct wsp_request *request = NULL;
	struct wsp_response *response = NULL;
	struct wsp_cpmgetquerystatusexin *statusexin = NULL;
	NTSTATUS status;
	DATA_BLOB unread = data_blob_null;
	TALLOC_CTX *local_ctx = talloc_new(ctx);

	if (local_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	request = talloc_zero(local_ctx, struct wsp_request);
	if (!request) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	response = talloc_zero(local_ctx, struct wsp_response);
	if (!response) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	statusexin = &request->message.cpmgetquerystatusex;

	request->header.msg = CPMGETQUERYSTATUSEX;
	statusexin->hcursor = cursor;
	statusexin->bmk = 0xfffffffc;
	status = wsp_request_response(local_ctx,
			wsp_ctx,
			request,
			response,
			&unread);
	if (NT_STATUS_IS_OK(status)) {
		*nrows = response->message.cpmgetquerystatusex.resultsfound;
	}

out:
	data_blob_free(&unread);
	TALLOC_FREE(local_ctx);
	return status;
}

static NTSTATUS print_rowsreturned(
				TALLOC_CTX *ctx,
				DATA_BLOB *buffer,
				bool is_64bit,
				bool disp_all_cols,
				struct wsp_cpmsetbindingsin *bindings,
				uint32_t cbreserved,
				uint64_t address,
				uint32_t rowsreturned,
				uint32_t *rows_processed)
{
	NTSTATUS status;
	uint32_t row = 0;
	TALLOC_CTX *local_ctx = NULL;
	struct wsp_cbasestoragevariant **rowsarray = NULL;
	enum ndr_err_code err;

	local_ctx = talloc_init("results");
	if (local_ctx == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	rowsarray = talloc_zero_array(local_ctx,
			struct wsp_cbasestoragevariant*,
			rowsreturned);
	if (rowsarray == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	err = extract_rowsarray(rowsarray,
			buffer,
			is_64bit,
			bindings,
			cbreserved,
			address,
			rowsreturned,
			rowsarray);
	if (err) {
		DBG_ERR("failed to extract rows from getrows response\n");
		status = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	for(row = 0; row < rowsreturned; row++) {
		TALLOC_CTX *row_ctx = NULL;
		const char *col_str = NULL;

		row_ctx = talloc_init("row");
		if (row_ctx == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		if (disp_all_cols) {
			int i;
			for (i = 0; i < bindings->ccolumns; i++){
				col_str =
					variant_as_string(
						row_ctx,
						&rowsarray[row][i],
						true);
				if (col_str) {
					printf("%s%s",
						i ? ", " : "", col_str);
				} else {
					printf("%sN/A",
						i ? ", " : "");
				}
			}
		} else {
			col_str = variant_as_string(
					row_ctx,
					&rowsarray[row][0],
					true);
			printf("%s", col_str);
		}
		printf("\n");
		TALLOC_FREE(row_ctx);
	}
	status = NT_STATUS_OK;
out:
	TALLOC_FREE(local_ctx);
	*rows_processed = row;
	return status;
}

static NTSTATUS create_getrows(TALLOC_CTX *ctx,
			       struct wsp_client_ctx *wsp_ctx,
			       struct wsp_cpmsetbindingsin *bindings,
			       uint32_t cursor,
			       uint32_t nrows,
			       bool disp_all_cols,
			       bool is_64bit)
{
	struct wsp_request *request = NULL;
	struct wsp_response *response = NULL;
	NTSTATUS status;
	DATA_BLOB unread = data_blob_null;
	uint32_t bmk = 0xfffffffc;
	uint32_t skip = 0;
	uint32_t total_rows = 0;
	uint32_t INITIAL_ROWS = 32;
	uint32_t requested_rows = INITIAL_ROWS;
	uint32_t rows_printed;
	uint64_t baseaddress;
	uint32_t offset_lowbits = 0xdeabd860;
	uint32_t offset_hibits  = 0xfeeddeaf;

	TALLOC_CTX *row_ctx;
	bool loop_again;

	do {
		row_ctx = talloc_new(NULL);
		if (!row_ctx) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
		request = talloc_zero(row_ctx, struct wsp_request);
		if (!request) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
		response = talloc_zero(row_ctx, struct wsp_response);
		if (!response) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		create_seekat_getrows_request(request,
					request,
					cursor,
					bmk,
					skip,
					requested_rows,
					40,
					offset_lowbits,
					bindings->brow,
					0);

		if (is_64bit) {
			/*
			 * MS-WSP 2.2.2
			 * ulreservered holds the high 32-bits part of
			 * a 64-bit offset if 64-bit offsets are being used.
			 */
			request->header.ulreserved2 = offset_hibits;
			baseaddress = request->header.ulreserved2;
			baseaddress <<= 32;
			baseaddress += offset_lowbits;
		} else {
			baseaddress = offset_lowbits;
		}

		status = wsp_request_response(request,
				wsp_ctx,
				request,
				response,
				&unread);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}

		total_rows += response->message.cpmgetrows.rowsreturned;
		if (response->message.cpmgetrows.rowsreturned
		   != requested_rows) {
			uint32_t rowsreturned =
				response->message.cpmgetrows.rowsreturned;
			if (response->message.cpmgetrows.etype == EROWSEEKAT) {
				struct wsp_cpmgetrowsout *resp;
				struct wsp_crowseekat *seekat;
				resp = &response->message.cpmgetrows;
				seekat =
					&resp->seekdescription.crowseekat;
				bmk = seekat->bmkoffset;
				skip = seekat->cskip;
			} else {
				bmk = 0xfffffffc;
				skip = total_rows;
			}
			requested_rows = requested_rows - rowsreturned;
		} else {
			requested_rows = INITIAL_ROWS;
			bmk = 0xfffffffc;
			skip = total_rows;
		}

		if (response->message.cpmgetrows.rowsreturned) {
			status = print_rowsreturned(row_ctx, &unread,
				is_64bit,
				disp_all_cols,
				bindings, 40,
				baseaddress,
				response->message.cpmgetrows.rowsreturned,
				&rows_printed);
			if (!NT_STATUS_IS_OK(status)) {
				goto out;
			}
			data_blob_free(&unread);
		}

		/*
		 * response is a talloc child of row_ctx so we need to
		 * assign loop_again before we delete row_ctx
		 */
		loop_again = response->message.cpmgetrows.rowsreturned;

		TALLOC_FREE(row_ctx);
		if (nrows && total_rows > nrows) {
			DBG_ERR("Something is wrong, results returned %d "
				"exceed expected number of results %d\n",
				total_rows, nrows);
			status = NT_STATUS_UNSUCCESSFUL;
			goto out;
		}
	} while (loop_again);
out:
	data_blob_free(&unread);
	TALLOC_FREE(row_ctx);
	return status;
}

const char *default_column = "System.ItemUrl";

static bool is_valid_kind(const char *kind)
{
	const char* kinds[] = {"calendar",
		"communication",
		"contact",
		"document",
		"email",
		"feed",
		"folder",
		"game",
		"instantMessage",
		"journal",
		"link",
		"movie",
		"music",
		"note",
		"picture",
		"program",
		"recordedtv",
		"searchfolder",
		"task",
		"video",
		"webhistory"};
	char* search_kind = NULL;
	int i;
	bool found = false;

	search_kind = strlower_talloc(NULL, kind);
	if (search_kind == NULL) {
		DBG_ERR("couldn't convert %s to lower case\n",
				kind);
		return NULL;
	}

	for (i=0; i<ARRAY_SIZE(kinds); i++) {
		if (strequal(search_kind, kinds[i])) {
			found = true;
			break;
		}
	}

	if (found == false) {
		DBG_ERR("Invalid kind %s\n", kind);
	}
	TALLOC_FREE(search_kind);
	return found;
}

static char * build_default_sql(TALLOC_CTX *ctx,
				const char *kind,
				const char *phrase,
				const char *location)
{
	char *sql = NULL;
	/* match what windows clients do */
	sql = talloc_asprintf(ctx,
		"Scope:\"%s\"  AND NOT System.Shell.SFGAOFlagsStrings:hidden"
		"  AND NOT System.Shell.OmitFromView:true", location);

	if (kind) {
		if (!is_valid_kind(kind)) {
			return NULL;
		}
		sql = talloc_asprintf(ctx, "System.Kind:%s AND %s",
					kind, sql);
	}

	if (phrase) {
		sql = talloc_asprintf(ctx,
				"All:$=\"%s\" OR All:$<\"%s\""
				" AND %s", phrase, phrase, sql);
	}
	sql =  talloc_asprintf(ctx, "SELECT %s"
				" WHERE %s", default_column, sql);
	return sql;
}

int main(int argc, char **argv)
{
	int opt;
	int result = 0;
	NTSTATUS status = NT_STATUS_OK;
	poptContext pc;
	char* server = NULL;
	char* share = NULL;
	char* path = NULL;
	char* location = NULL;
	char* query = NULL;
	bool custom_query = false;
	const char* phrase = NULL;
	const char* kind = NULL;
	uint32_t limit = 500;
	uint32_t nrows = 0;
	struct wsp_cpmsetbindingsin bindings_used = {0};
	bool is_64bit = false;
	struct poptOption long_options[] = {
                POPT_AUTOHELP
		{ "limit",
			0,
			POPT_ARG_INT,
			&limit,
			0,
			"limit results",
			"default is 500, specifying 0 means unlimited" },
		{ "search",
			0,
			POPT_ARG_STRING,
			&phrase,
			0,
			"Search phrase",
			"phrase" },
		{ "kind", 0, POPT_ARG_STRING, &kind, 0,
			"Kind of thing to search for [Calendar|Communication|"
			"Contact|Document|Email|Feed|Folder|Game|"
			"InstantMessage|Journal|Link|Movie|Music|Note|Picture|"
			"Program|RecordedTV|SearchFolder|Task|Video"
			"|WebHistory]",
			"kind" },
		{ "query",
			0,
			POPT_ARG_STRING,
			&query,
			0,
			"specify a more complex query",
			"query" },
                POPT_COMMON_SAMBA
                POPT_COMMON_CONNECTION
                POPT_COMMON_CREDENTIALS
                POPT_TABLEEND
	};
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev_ctx
		=  samba_tevent_context_init(talloc_tos());
	uint32_t cursor = 0;
	struct wsp_client_ctx *wsp_ctx = NULL;
	t_select_stmt *select_stmt = NULL;
	const char **const_argv = discard_const_p(const char *, argv);
	struct dcerpc_binding_handle *h = NULL;
	struct cli_state *c = NULL;
	uint32_t flags = CLI_FULL_CONNECTION_IPC;
	bool ok;
	struct smb_transports ts = { .num_transports = 0, };

	ok = samba_cmdline_init(frame,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Failed to set up cmdline parser\n");
		result = -1;
		goto out;
	}

	pc = samba_popt_get_context("wspsearch",
			argc,
			const_argv,
			long_options,
			0);
	poptSetOtherOptionHelp(pc, "[OPTIONS] //server1/share1");

	while ((opt = poptGetNextOpt(pc)) != -1) ;

	if(!poptPeekArg(pc)) {
		poptPrintUsage(pc, stderr, 0);
		result = -1;
		goto out;
	}

	path = talloc_strdup(talloc_tos(), poptGetArg(pc));
	if (!path) {
		DBG_ERR("Invalid argument\n");
		result = -1;
		goto out;
	}

	string_replace(path,'/','\\');
	server = talloc_strdup(talloc_tos(), path+2);
	if (!server) {
		DBG_ERR("Invalid argument\n");
		return -1;
	}

	if (server) {
		/*
		 * if we specify --query then we don't need actually need the
		 * share part, if it is specified then we don't care as we
		 * expect the scope to be part of the query (and if it isn't
		 * then it will probably fail anyway)
		 */
		share = strchr_m(server,'\\');
		if (!query && !share) {
			DBG_ERR("Invalid argument\n");
			return -1;
		}
		if (share) {
			*share = 0;
			share++;
		}
	}

	DBG_INFO("server name is %s\n", server ? server : "N/A");
	DBG_INFO("share name is %s\n", share ? share : "N/A");
	DBG_INFO("search phrase is %s\n", phrase ? phrase : "N/A");
	DBG_INFO("search kind is %s\n", kind ? kind : "N/A");

	if (!query && (kind == NULL && phrase == NULL)) {
		poptPrintUsage(pc, stderr, 0);
		result = -1;
		goto out;
	}

	if (!query) {
		location = talloc_asprintf(talloc_tos(),
				"FILE://%s/%s", server, share);
		query = build_default_sql(talloc_tos(), kind, phrase, location);
		if (!query) {
			result = -1;
			goto out;
		}
	} else {
		custom_query = true;
	}

	printf("custom_query %d\n", custom_query);
	select_stmt = get_wsp_sql_tree(query);

	poptFreeContext(pc);

	if (select_stmt == NULL) {
		DBG_ERR("query failed\n");
		result = -1;
		goto out;
	}

	if (select_stmt->cols == NULL) {
		select_stmt->cols = talloc_zero(select_stmt, t_col_list);
		if (select_stmt->cols == NULL) {
			DBG_ERR("out of memory\n");
			result = -1;
			goto out;
		}
		select_stmt->cols->num_cols = 1;
		select_stmt->cols->cols =
			talloc_zero_array(select_stmt->cols, char*, 1);
		if (select_stmt->cols->cols == NULL) {
			DBG_ERR("out of memory\n");
			result = -1;
			goto out;
		}
		select_stmt->cols->cols[0] =
			talloc_strdup(select_stmt->cols, default_column);
	}

	ts = smb_transports_parse("client smb transports",
				  lp_client_smb_transports());

	status = cli_full_connection_creds(talloc_tos(),
					   &c,
					   lp_netbios_name(),
					   server,
					   NULL,
					   &ts,
					   "IPC$",
					   "IPC",
					   samba_cmdline_get_creds(),
					   flags);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to IPC$: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	status = wsp_server_connect(talloc_tos(),
			server,
			ev_ctx,
			samba_cmdline_get_lp_ctx(),
			samba_cmdline_get_creds(),
			c,
			&wsp_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to wsp: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	h = get_wsp_pipe(wsp_ctx);
	if (h == NULL) {
		DBG_ERR("Failed to communicate with server, no pipe\n");
		result = -1;
		goto out;
	}

	dcerpc_binding_handle_set_timeout(h,
					  DCERPC_REQUEST_TIMEOUT * 1000);

	/* connect */
	DBG_INFO("sending connect\n");
	status = wsp_connect(talloc_tos(),
			 wsp_ctx,
			 lpcfg_netbios_name(samba_cmdline_get_lp_ctx()),
			 cli_credentials_get_username(
				 samba_cmdline_get_creds()),
			 server,
			 &is_64bit);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to connect to wsp: %s\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending query\n");

	status = create_query(talloc_tos(),
			wsp_ctx,
			limit,
			select_stmt,
			&cursor);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to send query: %s)\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	DBG_INFO("sending createbindings\n");
	/* set bindings */
	status = create_bindings(talloc_tos(),
			wsp_ctx,
			select_stmt,
			cursor,
			&bindings_used,
			is_64bit);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("failed to setbindings: %s)\n",
		      nt_errstr(status));
		result = -1;
		goto out;
	}

	status = create_querystatusex(talloc_tos(),
				      wsp_ctx,
				      bindings_used.hcursor,
				      &nrows);
	if (!nrows) {
		result = 0;
		DBG_ERR("no results found\n");
		goto out;
	}

	printf("found %d results, returning %d \n",
			nrows,
			limit ? MIN(nrows, limit) : nrows);
	status = create_getrows(talloc_tos(),
				wsp_ctx,
				&bindings_used,
				bindings_used.hcursor,
				limit ? MIN(nrows, limit) : nrows,
				custom_query,
				is_64bit);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to retrieve rows, error: %s\n",
			nt_errstr(status));
		result = -1;
		goto out;
	}
	result = 0;
out:
	TALLOC_FREE(frame);
	return result;
}
