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
#ifndef __LIBCLI_WSP_WSP_CLI
#define __LIBCLI_WSP_WSP_CLI

#include "libcli/wsp/wsp_aqs.h"

enum search_kind {
	CALENDAR,
	COMMUNICATION,
	CONTACT,
	DOCUMENT,
	EMAIL,
	FEED,
	FOLDER,
	GAME,
	INSTANTMESSAGE,
	JOURNAL,
	LINK,
	MOVIE,
	MUSIC,
	NOTE,
	PICTURE,
	PROGRAM,
	RECORDEDTV,
	SEARCHFOLDER,
	TASK,
	VIDEO,
	WEBHISTORY,
	NONE,
	UNKNOWN,
};

enum search_kind get_kind(const char* kind_str);

struct wsp_cpmcreatequeryin;
struct wsp_cpmsetbindingsin;
struct wsp_cpmgetrowsin;
struct dcerpc_binding_handle;

bool init_connectin_request(TALLOC_CTX *ctx,
			    struct wsp_request* request,
			    const char* clientmachine,
			    const char* clientuser,
			    const char* server);

bool create_querysearch_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql);

bool create_setbindings_request(TALLOC_CTX * ctx,
				struct wsp_request* request,
				t_select_stmt *sql,
				uint32_t cursor,
				bool is_64bit);

void create_seekat_getrows_request(TALLOC_CTX * ctx,
				   struct wsp_request* request,
				   uint32_t cursor,
				   uint32_t bookmark,
				   uint32_t skip,
				   uint32_t rows,
				   uint32_t cbreserved,
				   uint32_t ulclientbase,
				   uint32_t cbrowwidth,
				   uint32_t fbwdfetch);

enum ndr_err_code extract_rowsarray(TALLOC_CTX * ctx,
				    DATA_BLOB *rows_buf,
				    bool is_64bit,
				    struct wsp_cpmsetbindingsin *bindingsin,
				    uint32_t cbreserved,
				    uint64_t baseaddress,
				    uint32_t rows,
				    struct wsp_cbasestoragevariant **rowsarray);

struct wsp_client_ctx;
struct cli_credentials;

NTSTATUS wsp_server_connect(TALLOC_CTX *mem_ctx,
			    const char *servername,
			    struct tevent_context *ev_ctx,
			    struct loadparm_context *lp_ctx,
			    struct cli_credentials *credential,
			    struct cli_state *cli,
			    struct wsp_client_ctx **ctx);

/* simple sync api */
NTSTATUS wsp_request_response(TALLOC_CTX* ctx,
			      struct wsp_client_ctx *wsp_ctx,
			      struct wsp_request* request,
			      struct wsp_response *response,
			      DATA_BLOB *unread);

struct dcerpc_binding_handle* get_wsp_pipe(struct wsp_client_ctx *ctx);
#endif
