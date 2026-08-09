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
#include "wsp_gss.h"
#include "bin/default/librpc/gen_ndr/ndr_wsp.h"
#include "util/tevent_ntstatus.h"
#include "util/tevent_hresult.h"
#include "wsp_backend.h"
#include "librpc/wsp/wsp_util.h"
#include "lib/util/memcache.h"
#include "wspd_db.h"
#include "bin/default/librpc/gen_ndr/auth.h"

#define MSG_HEADER_SIZE 16
#define WINDOWS_32_BIT  0x00000109
#define MSG_GETROWOUT_MAXSEEK 12

/* MS-WSP 3.1.3 */
enum wsp_server_state {
	NOT_INITIALISED,
	RUNNING,
};

struct uint32_list {
	struct uint32_list *prev, *next;
	uint32_t number;
};

struct client_version_map {
	struct client_version_map *prev, *next;
	uint32_t fid_handle;
	uint32_t version;
};

struct query_rows_info {
	struct query_rows_info *prev, *next;
	uint32_t handle;
	uint32_t rowstart_index; /* index where 'rows' starts */
	uint32_t total_rows;     /* num rows stored */
	bool nomorerowstoreturn;
};

/*
 * A map of in memory caches, one per session holding local copies of
 * EntryID records. If we are using a multi worker model then a
 * worker could service handles from different sessions, handles for
 * the same session may exist in different workers, this would need
 * significant co-ordination to ensure EntryID records associated with
 * the session in one worker don't get torn down while some EntryID
 * records associated with the same session exist in another worker.
 * We want to keep ALL EntryID records associated with a session until all
 * connections associated with that session are gone regardless of location.
 * It would be ideal if we could use a similar mechanism to 'real' dcerpc
 * client/server e.g. have an association group associated with the session
 * like what happens as part of the bind.
 * Regardless even in a single process/worker model we need to cache EntryIDs
 * based on the session
 */
struct id_cache_map {
	struct id_cache_map *prev, *next;
	struct memcache *id_cache;
	struct GUID sessionid;
	uint32_t refcount;
};

struct wsp_gss_state {
	struct uint32_list *connectedclientsidentifiers;
	struct client_version_map *connectedclientversions;
	struct query_rows_info *query_info_map;
	enum wsp_server_state wsp_server_state;
	struct tevent_context *ev;
	struct wsp_abstract_state *wsp_abstract_state;
	struct id_cache_map *id_cache_map;
};

struct wsp_client_data {
	struct wsp_gss_state *wsp_gss_state;
	struct auth_session_info *session_info;
	struct uint32_list *prev_msgs;
	uint32_t fid;
};

static struct id_cache_map *get_or_create_id_cache(
					struct wspd_client_state *client_state)
{
	struct wsp_gss_state *wsp_gss_state = client_state->client_data->wsp_gss_state;
	struct GUID sessionid = client_state->sessionid;
	struct id_cache_map *item;
	bool found = false;

	for (item = wsp_gss_state->id_cache_map; item; item = item->next) {
		if (GUID_equal(&sessionid, &item->sessionid)) {
			found = true;
			break;
		}
	}
	if (found) {
		return item;
	}

	item = talloc_zero(wsp_gss_state, struct id_cache_map);
	if (item == NULL) {
		return NULL;
	}
	item->id_cache = memcache_init(wsp_gss_state, 0);
	if (item->id_cache == NULL) {
		TALLOC_FREE(item);
		return NULL;
	}
	item->sessionid = sessionid;
	DLIST_ADD_END(wsp_gss_state->id_cache_map, item);
	return item;
}

/* return the abstract interface implementation for the specified backend */
static struct uint32_list *find_prev_msg_entry(struct wsp_client_data *data,
					       uint32_t msgid)
{
	struct uint32_list *item = NULL;

	for (item = data->prev_msgs; item; item = item->next) {
		if (item->number == msgid) {
			return item;
		}
	}
	return item;
}

static struct query_rows_info *find_query_rows_info(uint32_t handle,
					    struct wsp_gss_state *wsp_gss_state)
{
	struct query_rows_info *item = NULL;

	for (item = wsp_gss_state->query_info_map; item; item = item->next){
		if (item->handle == handle) {
			return item;
		}
	}
	return NULL;
}

static int32_t find_client_version(uint32_t handle,
				    struct wsp_gss_state *wsp_gss_state)
{
	struct client_version_map *version_item = NULL;

	for (version_item = wsp_gss_state->connectedclientversions;
	     version_item; version_item = version_item->next) {
		if (version_item->fid_handle == handle) {
			return version_item->version;
		}
	}
	return -1;
}

/* return the abstract interface implementation for the specified backend */
static struct wsp_abstract_interface *get_impl(void)
{
	int backend_id;
	struct wsp_abstract_interface *backend_if = NULL;

	backend_id = lp_wsp_backend();
	backend_if = get_backend_impl(backend_id);
	return backend_if;
}

/* initialise the backend */
bool wsp_gss_init(struct wsp_gss_state *state)
{
	struct wsp_abstract_interface *abs_if = get_impl();

	if (abs_if == NULL) {
		DBG_ERR("No valid backend discovered\n");
		return false;
	}
	if (state->wsp_server_state != NOT_INITIALISED) {
		DBG_DEBUG("GSS_STATE is already initialised\n");
		return true;
	}
	state->wsp_abstract_state = abs_if->initialise(state->ev);
	if (!state->wsp_abstract_state) {
		DBG_ERR("failure initialise abstract interface\n");
		return false;
	}
	state->wsp_server_state = RUNNING;
	return true;
}

static bool extract_connectin_propsets(TALLOC_CTX *ctx,
				       struct wsp_cpmconnectin *cpmconnect,
				       struct connectin_propsets *propset)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	bool result = false;
	DATA_BLOB blob;

	blob.length = cpmconnect->cbblob1;
	blob.data = cpmconnect->propsets;
	ndr = ndr_pull_init_blob(&blob, ctx);
	if (ndr == NULL) {
		DBG_ERR("out of memory\n");
		goto out;
	}
	err = ndr_pull_connectin_propsets(ndr, ndr_flags, propset);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull propset: %d\n", err);
		goto out;
	}
	result = true;

out:
	return result;
}

static bool get_property(uint32_t propid,
			 struct wsp_cdbpropset *props,
			 struct wsp_cdbprop **prop_result)
{
	bool result = false;
	int i;

	for (i = 0; i < props->cproperties; i++) {
		if (props->aprops[i].dbpropid == propid) {
			*prop_result = &props->aprops[i];
			result = true;
			break;
		}
	}
	return result;
}

/* stub for getting lcid */
static uint32_t get_lcid(void)
{
	/* en-us */
	return WSP_DEFAULT_LCID;
}

/* MS-WSP 2.2.2 MS-WSP 3.2.4 */
static uint32_t calculate_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	uint32_t i;
	/* point at payload */
	uint8_t *buffer = blob->data + MSG_HEADER_SIZE;
	uint32_t buf_size = blob->length - MSG_HEADER_SIZE;
	uint32_t nwords = buf_size/4;
	uint32_t offset = 0;
	uint32_t checksum = 0;

	for (i = 0; i < nwords; i++) {
		checksum += PULL_LE_U32(buffer, offset);
		offset += 4;
	}

	checksum ^= XOR_CONST;
	checksum -= hdr->msg;
	return checksum;
}

static struct uint32_list *get_connected_client_entry(
			uint32_t handle,
			struct wsp_gss_state *wsp_gss_state)
{
	struct uint32_list *item = wsp_gss_state->connectedclientsidentifiers;

	for (; item != NULL; item = item->next) {
		DBG_INFO("compare 0x%x with 0x%x\n",
			 (uint32_t)handle, (uint32_t)item->number);
		if (handle == item->number) {
			return item;
		}
	}
	return NULL;
}

static bool has_connected_client(uint32_t handle, struct wsp_gss_state *state)
{
        return get_connected_client_entry(handle, state) != NULL;
}

static bool verify_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	return calculate_checksum(blob, hdr) == hdr->checksum;
}

static uint32_t serverversion = 0;

#define MSS_E_CATALOGNOTFOUND 0x80042103

struct wsp_gss_connect_state {
	bool dummy;
};

/* MS-WSP 2.2.3.2, MS-WSP 3.1.5.2.1 */
static struct tevent_req *wsp_gss_connect_send(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client,
				struct wsp_header *header,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct connectin_propsets propsets = {};
	struct wsp_cpmconnectin *client_info = NULL;
	struct wsp_cdbprop *catalog_name = NULL;
	struct uint32_list *item = NULL;
	struct client_version_map *version_info = NULL;
	uint32_t dwwinvermajor = 0;
	uint32_t dwwinverminor = 0;
	uint32_t dwnlsvermajor = 0;
	uint32_t dwnlsverminor = 0;
	bool supportsversioninginfo = false;
	struct wsp_cpmconnectin *cpmconnect = NULL;
	struct wsp_cpmconnectout *msg_out = &response->message.cpmconnect;
	struct wsp_gss_connect_state *state = NULL;
	struct tevent_req *req = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(ctx, &state, struct wsp_gss_connect_state);
	if (req == NULL) {
		return NULL;
	}

	cpmconnect = talloc_zero(ctx, struct wsp_cpmconnectin);
	if (tevent_req_nomem(cpmconnect, req)) {
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmconnectin(ndr, ndr_flags, cpmconnect);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull cpmconnectin message\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("error client %u is already connected\n", handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!extract_connectin_propsets(state, cpmconnect, &propsets)) {
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!get_property(DBPROP_CI_CATALOG_NAME, &propsets.propertyset1,
			  &catalog_name)) {
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (catalog_name->vvalue.vtype != VT_LPWSTR) {
		DBG_ERR("incorrect type %d for DBPROP_CI_CATALOG_NAME \n",
		      catalog_name->vvalue.vtype);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!abs_interface->iscatalogavailable(client,
				catalog_name->vvalue.vvalue.vt_lpwstr.value)){
		tevent_req_herror(req, HRES_ERROR(MSS_E_CATALOGNOTFOUND));
		return tevent_req_post(req, ev);
	}

	if ((cpmconnect->iclientversion | 0x0000FFFF) >= WINDOWS_32_BIT) {
		if (!verify_checksum(in_data, header)) {
			DBG_ERR("invalid checksum 0x%x\n",
			      header->checksum);
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		}
	}

	/*
	 * As far as I understand it according to MS-WSP spec the handle and
	 * query identifier are interchangeable (e.g. only one 'active'
	 * query is possible per connection over the WSP pipe) That
	 * is, a client can have many connections over the WSP pipe (where
	 * each connection has a unique handle to the pipe)
	 * BUT... my understanding is there can only be 1 active query per
	 * conversation over any handle, in otherwords in order to start a
	 * new query using a certain handle the previous query must have
	 * been closed/destroyed.
	 * We are generating a handle that that is globally unique.
	 */
	abs_interface->storeclientinformation(client,
					      (uint32_t)handle,
					      cpmconnect,
					      handle);

	client_info = abs_interface->getclientinformation(client, handle);
	if (client_info == NULL) {
		DBG_ERR("error, no client info for handle %u available\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	version_info = talloc_zero(wsp_gss_state, struct client_version_map);
	if (tevent_req_nomem(version_info, req)) {
		return tevent_req_post(req, ev);
	}
	version_info->fid_handle = handle;
	version_info->version = cpmconnect->iclientversion;
	DLIST_ADD_END(wsp_gss_state->connectedclientversions, version_info);

	abs_interface->getserverversions(client,
					 &dwwinvermajor,
					 &dwwinverminor,
					 &dwnlsvermajor,
					 &dwnlsverminor,
					 &serverversion,
					 &supportsversioninginfo);

	msg_out->server_version = serverversion;
	if (supportsversioninginfo) {
		msg_out->version_dependant.version_info.dwwinvermajor =
			dwwinvermajor;
		msg_out->version_dependant.version_info.dwwinverminor =
			dwwinverminor;
		msg_out->version_dependant.version_info.dwnlsvermajor =
			dwnlsvermajor;
		msg_out->version_dependant.version_info.dwnlsverminor =
			dwnlsverminor;
	}

	item = talloc_zero(wsp_gss_state, struct uint32_list);
	if (tevent_req_nomem(item, req)) {
		return tevent_req_post(req, ev);
	}
	item->number = handle;
	DLIST_ADD_END(wsp_gss_state->connectedclientsidentifiers, item);

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

struct wsp_gss_createquery_state {
	uint32_t num_cursor_handles;
	uint32_t *cursor_handles;
	bool ftrueseq;
	bool fworkid_unique;
	bool can_query_now;
	struct wsp_response *response;
	DATA_BLOB *extra_blob;
	struct wsp_abstract_interface *abs_interface;
};

static void wsp_gss_createquery_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.4, MS-WSP 3.1.5.2.2 */
static struct tevent_req *wsp_gss_createquery_send(TALLOC_CTX *ctx,
			       struct tevent_context *ev,
			       struct wspd_client_state *client,
			       struct wsp_header *header,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct wsp_cpmcreatequeryin *query = NULL;
	struct wsp_ccolumnset *projected_col_offsets = NULL;
	struct wsp_crestrictionarray *restrictionset = NULL;
	struct wsp_csortset *sort_orders = NULL;
	struct wsp_ccategorizationset *groupings = NULL;
	struct wsp_crowsetproperties *rowsetproperties = NULL;
	struct wsp_cpidmapper *pidmapper = NULL;
	struct wsp_ccolumngrouparray *grouparray = NULL;
	struct tevent_req *req = NULL, *subreq = NULL;
	struct query_rows_info *info = NULL;
	struct wsp_gss_createquery_state *state = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;
	int32_t clientversion;

	req = tevent_req_create(ctx, &state,
				struct wsp_gss_createquery_state);
	if (req == NULL) {
		return NULL;
	}

	/*
	 * a client can have more than one handle open
	 * therefore more than one active query.
	 */
	info = find_query_rows_info(handle, wsp_gss_state);
	if (info == NULL) {
		info = talloc_zero(wsp_gss_state, struct query_rows_info);
		if (tevent_req_nomem(info, req)) {
			return tevent_req_post(req, ev);
		}
		info->handle = handle;
		DLIST_ADD_END(wsp_gss_state->query_info_map, info);
	}

	clientversion = find_client_version(handle,
					    client->client_data->wsp_gss_state);
	if (clientversion < 0) {
		DBG_ERR("no cached version for client with handle %u\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if ((clientversion | 0x0000FFFF) >= WINDOWS_32_BIT) {
		if (!verify_checksum(in_data, header)) {
			DBG_ERR("invalid checksum 0x%x\n",
				header->checksum);
			tevent_req_herror(req,
					  HRESULT_FROM_NT(
						  NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		}
	}

	query = talloc_zero(ctx, struct wsp_cpmcreatequeryin);
	if (tevent_req_nomem(query, req)) {
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmcreatequeryin(ndr, ndr_flags, query);
	if (err != NDR_ERR_SUCCESS) {
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	rowsetproperties = &query->rowsetproperties;
	pidmapper = &query->pidmapper;
	grouparray = &query->grouparray;

	state->extra_blob = extra_out_blob;
	state->response = response;
	state->abs_interface = abs_interface;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (query->ccolumnsetpresent) {
		projected_col_offsets = &query->columnset.columnset;
	}
	if (query->crestrictionpresent) {
		restrictionset = &query->restrictionarray.restrictionarray;
	}
	if (query->csortsetpresent) {
		if (query->sortset.groupsortaggregsets.ccount) {
			struct wsp_cingroupsortaggregset* aggregset;
			aggregset =
				&query->sortset.groupsortaggregsets.sortsets[0];
			sort_orders = &aggregset->sortaggregset;
		}
	}
	if (query->ccategorizationsetpresent) {
		groupings = &query->ccategorizationset.ccategorizationset;
		if (groupings->size > 1) {
			DBG_WARNING("can't yet handle multiple categories\n");
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		}
	}

	state->num_cursor_handles = groupings ? groupings->size + 1 : 1;

	subreq = abs_interface->runnewquery_send(ctx, ev,
						 client,
						 handle,
						 projected_col_offsets,
						 restrictionset,
						 sort_orders,
						 groupings,
						 rowsetproperties,
						 pidmapper,
						 grouparray,
						 get_lcid());
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wsp_gss_createquery_done, req);
	return req;
}

static void wsp_gss_createquery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_createquery_state *state = tevent_req_data(
		req, struct wsp_gss_createquery_state);
	uint32_t *pcursors = NULL;
	HRESULT hres;
	int i;
	struct ndr_push *ndr_push = NULL;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	enum ndr_err_code ndrerr;

	hres = state->abs_interface->runnewquery_recv(subreq,
						state,
						&state->cursor_handles,
						&state->ftrueseq,
						&state->fworkid_unique,
						&state->can_query_now);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	ndr_push = ndr_push_init_ctx(req);
	if (tevent_req_nomem(ndr_push, req)) {
		return;
	}

	pcursors = state->cursor_handles;

	if (!state->can_query_now) {
		DBG_DEBUG("can_query_now=false, returning"
			  "NT_STATUS_INVALID_PARAMETER\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}

	for (i = 0; i < state->num_cursor_handles; i++) {
		ndrerr = ndr_push_uint32(ndr_push,
				      ndr_flags,
				      pcursors[i]);
		if (ndrerr != NDR_ERR_SUCCESS) {
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return;
		}
	}

	/*
	 * extra_blob is for tacking on typically dynamic content at the
	 * end of the message buffer that isn't easily (or at all)
	 * expressible in idl
	 */
	*state->extra_blob = ndr_push_blob(ndr_push);
	if (tevent_req_nomem(state->extra_blob->data, req)) {
		return;
	}
	tevent_req_done(req);
}

struct wsp_gss_querystatus_state {
	uint32_t status;
	struct wsp_response *response;
	struct wsp_abstract_interface *abs_if;
};

static void wsp_gss_querystatus_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.6, MS-WSP 3.1.5.2.3 */
static struct tevent_req *wsp_gss_querystatus_send(TALLOC_CTX *ctx,
			       struct tevent_context *ev,
			       struct wspd_client_state *client,
			       struct wsp_header *header,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_cpmgetquerystatusin *statusin = NULL;
	uint32_t hcursor;
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_gss_querystatus_state *state = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;
	bool ok;

	req = tevent_req_create(wsp_gss_state,
				&state,
				struct wsp_gss_querystatus_state);
	if (req == NULL) {
		return NULL;
	}

	statusin = talloc_zero(ctx, struct wsp_cpmgetquerystatusin);
	if (tevent_req_nomem(statusin, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmgetquerystatusin(ndr, ndr_flags, statusin);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmgetquerystatusin\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	hcursor = statusin->hcursor;

	state->status = NT_STATUS_V(NT_STATUS_OK);
	state->response = response;
	state->abs_if = abs_interface;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	ok = abs_interface->clientqueryhascursorhandle(client, handle, hcursor);
	if (!ok) {
		DBG_ERR("no cursor %d for handle %u\n", hcursor, handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->getquerystatus_send(state, ev, client, handle);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_querystatus_done, req);
	return req;
}

static void wsp_gss_querystatus_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatus_state *state = tevent_req_data(
		req, struct wsp_gss_querystatus_state);
	uint32_t querystatus;
	HRESULT hres;

	hres = state->abs_if->getquerystatus_recv(subreq, &querystatus);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	state->response->message.cpmgetquerystatus.qstatus = querystatus;
	tevent_req_done(req);
}

struct wsp_gss_querystatusex_state {
	struct tevent_context *ev;
	struct wspd_client_state *client;
	struct wsp_response *response;
	struct wsp_cpmcistateinout cistate;
	struct wsp_abstract_interface *abs_interface;
	uint32_t rows;
	uint32_t handle;
	uint32_t has_newrows;
	uint32_t hcursor;
	uint32_t bmk;
};

static void wsp_gss_querystatusex_getstate_done(struct tevent_req *subreq);
static void wsp_gss_querystatusex_getquerystatus_done(struct tevent_req *subreq);
static void wsp_gss_querystatusex_getratiofinished_done(struct tevent_req *subreq);
static void wsp_gss_querystatusex_getapproxpos_done(struct tevent_req *subreq);
static void wsp_gss_querystatusex_getexpensiveprops_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.7, MS-WSP 3.1.5.2.4 */
static struct tevent_req *wsp_gss_querystatusex_send(TALLOC_CTX *ctx,
				 struct tevent_context *ev,
				 struct wspd_client_state *client,
				 struct wsp_header *header,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_cpmgetquerystatusexin *statuxexin = NULL;
	uint32_t hcursor;
	uint32_t bmk;
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_gss_querystatusex_state *state = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;
	bool ok;

	req = tevent_req_create(wsp_gss_state,
				&state,
				struct wsp_gss_querystatusex_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	statuxexin = talloc_zero(ctx, struct wsp_cpmgetquerystatusexin);
	if (tevent_req_nomem(statuxexin, req)) {
		DBG_ERR("out of memory\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_NO_MEMORY));
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmgetquerystatusexin(ndr, ndr_flags, statuxexin);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmgetquerystatusin\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	hcursor = statuxexin->hcursor;
	bmk = statuxexin->bmk;

	state->ev = ev;
	state->client = client;
	state->response = response;
	state->abs_interface = abs_interface;
	state->handle = handle;
	state->hcursor = hcursor;
	state->bmk = bmk;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	ok = abs_interface->clientqueryhascursorhandle(client, handle, hcursor);
	if (!ok) {
		DBG_ERR("no cursor %d for handle %u\n", hcursor, handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->getstate_send(state, ev, client);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				wsp_gss_querystatusex_getstate_done,
				req);
	return req;
}

static void wsp_gss_querystatusex_getstate_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatusex_state *state = tevent_req_data(
		req, struct wsp_gss_querystatusex_state);
	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	HRESULT hres;

	hres = state->abs_interface->getstate_recv(subreq, &state->cistate);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	out->cfiltereddocuments = state->cistate.cfiltereddocuments;
	out->cdocumentstofilter = state->cistate.ctotaldocuments;

	subreq = state->abs_interface->getquerystatus_send(state,
							   state->ev,
							   state->client,
							   state->handle);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_querystatusex_getquerystatus_done,
				req);
}

static void wsp_gss_querystatusex_getquerystatus_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatusex_state *state = tevent_req_data(
		req, struct wsp_gss_querystatusex_state);
	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;

	/*
	 * For querystatusex we ignore any errors here
	 */
	(void)state->abs_interface->getquerystatus_recv(subreq, &out->qstatus);
	TALLOC_FREE(subreq);

	subreq = state->abs_interface->getratiofinishedparams_send(state,
					      state->ev,
					      state->client,
					      state->handle,
					      state->hcursor);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_querystatusex_getratiofinished_done,
				req);
}

static void wsp_gss_querystatusex_getratiofinished_done(
					struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatusex_state *state = tevent_req_data(
		req, struct wsp_gss_querystatusex_state);
	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	HRESULT hres;

	hres = state->abs_interface->getratiofinishedparams_recv(subreq,
					&out->dwratiofinisheddenominator,
					&out->dwratiofinishednumerator,
					&state->rows,
					&state->has_newrows);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	subreq = state->abs_interface->getapproximatepos_send(state,
							     state->ev,
							     state->client,
							     state->handle,
							     state->hcursor,
							     state->bmk);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_querystatusex_getapproxpos_done,
				req);
}

static void wsp_gss_querystatusex_getapproxpos_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatusex_state *state = tevent_req_data(
		req, struct wsp_gss_querystatusex_state);
	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	HRESULT hres;

	hres = state->abs_interface->getapproximatepos_recv(subreq,
							      &out->irowbmk);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	out->whereid = state->abs_interface->getwhereid(state->client,
							state->handle);

	subreq = state->abs_interface->getexpensiveproperties_send(
							state,
							state->ev,
							state->client,
							state->handle,
							state->hcursor);

	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_querystatusex_getexpensiveprops_done,
				req);
}

static void wsp_gss_querystatusex_getexpensiveprops_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_querystatusex_state *state = tevent_req_data(
		req, struct wsp_gss_querystatusex_state);
	struct wsp_cpmgetquerystatusexout *out =
			&state->response->message.cpmgetquerystatusex;
	HRESULT hres;

	hres = state->abs_interface->getexpensiveproperties_recv(subreq,
							&out->crowstotal,
							&out->resultsfound,
							&out->maxrank);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

/* MS-WSP 2.2.3.13, MS-WSP 3.1.5.2.5 */
struct wsp_gss_getratiofinished_state {
	struct wsp_cpmratiofinishedout *ratio_out;
	struct wsp_abstract_interface *abs_interface;
};

static void wsp_gss_getratiofinished_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_getratiofinished_send(
				TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client,
				struct wsp_header *header,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_gss_getratiofinished_state *state = NULL;
	struct wsp_cpmratiofinishedin *ratio_in = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(wsp_gss_state,
				&state,
				struct wsp_gss_getratiofinished_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	state->ratio_out = &response->message.wsp_cpmratiofinished;
	state->abs_interface = abs_interface;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	ratio_in = talloc_zero(ctx, struct wsp_cpmratiofinishedin);
	if (tevent_req_nomem(ratio_in, req)) {
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmratiofinishedin(ndr, ndr_flags, ratio_in);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmratiofinishedin\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->getratiofinishedparams_send(ctx,
					      ev,
					      client,
					      handle,
					      ratio_in->hcursor);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wsp_gss_getratiofinished_done, req);
	return req;
}

static void wsp_gss_getratiofinished_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getratiofinished_state *state = tevent_req_data(
		req, struct wsp_gss_getratiofinished_state);
	HRESULT hres;

	hres = state->abs_interface->getratiofinishedparams_recv(subreq,
				&state->ratio_out->uldenominator,
				&state->ratio_out->ulnumerator,
				&state->ratio_out->crows,
				&state->ratio_out->fnewrows);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

struct seekratio_data {
	uint32_t crowstotal;
	uint32_t resultsfound;
	uint32_t maxrank;
};

struct wsp_gss_getrows_state {
	struct tevent_context *ev;
	struct query_rows_info *info;
	struct wspd_client_state *client;
	DATA_BLOB *extra_out_blob;
	struct wsp_cpmgetrowsin *rowsin;
	struct wsp_cpmgetrowsout *rowsout;
	struct wsp_abstract_interface *abs_interface;
	struct wsp_gss_state *wsp_gss_state;

	uint32_t pad_adjust;
	uint8_t* row_buff;
	uint32_t buf_size;
	uint32_t ncols;
	uint32_t rowsreturned;
	uint32_t rows_requested;
	uint32_t cur_rowbuf_end_pos;
	uint32_t index;
	uint32_t handle;
	uint64_t baseaddress;
	struct wsp_ctablecolumn *binding;
	bool nomorerowstoreturn;
	bool is_64bit; /* #TODO need to also check 64k mode */
	struct seekratio_data *seekratio;
};

static void wsp_gss_get_expensive_props_done(struct tevent_req *subreq);
static void wsp_gss_getrows_process_rows_for_index(struct tevent_req *req);
static void wsp_gss_getrows_done(struct tevent_req *subreq);

/* MS-WSP 2.2.3.2, MS-WSP 3.1.5.2.6 */
static struct tevent_req *wsp_gss_getrows_send(TALLOC_CTX *ctx,
			   struct tevent_context *ev,
			   struct wspd_client_state *client,
			   struct wsp_header *header,
			   struct wsp_response *response,
			   DATA_BLOB *in_data,
			   DATA_BLOB *extra_out_blob,
			   struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct wsp_cpmgetrowsin *rowsin = NULL;
	struct wsp_cpmgetrowsout *rowsout = &response->message.cpmgetrows;
	uint32_t hcursor;
	uint32_t chapter;
	uint32_t oldindex;
	struct query_rows_info *info = NULL;
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_gss_getrows_state *state = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	int32_t clientversion;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(wsp_gss_state,
				&state,
				struct wsp_gss_getrows_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;

	info = find_query_rows_info(handle, wsp_gss_state);
	if (tevent_req_nomem(info, req)) {
		DBG_ERR("no cached data for query with handle %u\n", handle);
		return tevent_req_post(req, ev);
	}

	clientversion = find_client_version(handle,
					    client->client_data->wsp_gss_state);
	if (clientversion < 0) {
		DBG_ERR("no cached version for client with handle %u\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	rowsin = talloc_zero(ctx, struct wsp_cpmgetrowsin);
	if (tevent_req_nomem(rowsin, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmgetrowsin(ndr, ndr_flags, rowsin);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmgetrowsin\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	state->client = client;
	state->wsp_gss_state = client->client_data->wsp_gss_state;
	state->extra_out_blob = extra_out_blob;
	state->nomorerowstoreturn = true;
	state->is_64bit = false;
	state->abs_interface = abs_interface;
	state->handle = handle;
	state->info = info;
	state->rowsin = rowsin;
	state->rowsout = rowsout;

	if (clientversion > 0x00010000 && serverversion > 0x00010000) {
		state->is_64bit = true;
	}

	if (state->is_64bit) {
		/* capture high bytes */
		state->baseaddress = header->ulreserved2;
		state->baseaddress = (state->baseaddress << 32);
	}

	state->baseaddress += rowsin->ulclientbase + rowsin->cbreserved;

	hcursor = rowsin->hcursor;
	chapter = rowsin->chapt;
	state->rows_requested = rowsin->crowstotransfer;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if ((clientversion | 0x0000FFFF) >= WINDOWS_32_BIT) {
		if (!verify_checksum(in_data, header)) {
			DBG_ERR("invalid checksum 0x%x\n",
			      header->checksum);
			tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		}
	}

	if (!abs_interface->clientqueryhascursorhandle(client,
						       handle, hcursor)) {
		DBG_ERR("no cursor %u for handle %u\n", hcursor, handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!abs_interface->hasbindings(client, handle, hcursor)) {
		DBG_ERR("no bindings for handle %u and cursor %u\n",
			 handle, hcursor);
		tevent_req_herror(req, HRES_E_UNEXPECTED);
		return tevent_req_post(req, ev);
	}

	oldindex = abs_interface->getnextgetrowsposition(client,
							 handle, hcursor,
							 chapter);
	switch (rowsin->etype) {
		case EROWSEEKNONE:
			state->index = oldindex;
			break;
		case EROWSEEKNEXT:
			state->index =
				oldindex + rowsin->seekdescription.crowseeknext.cskip;
			break;
		case EROWSEEKAT: {
			uint32_t cskip =
				rowsin->seekdescription.crowseekat.cskip;
			uint32_t bmkoffset =
				rowsin->seekdescription.crowseekat.bmkoffset;

			state->index = abs_interface->getbookmarkposition(
								client,
								handle,
								hcursor,
								bmkoffset);
			state->index += cskip;
			break;
		}
		case EROWSEEKATRATIO: {
			uint32_t ulnumerator =
				rowsin->seekdescription.crowseekatratio.ulnumerator;
			uint32_t uldenominator =
				rowsin->seekdescription.crowseekatratio.uldenominator;

			state->seekratio = talloc_zero(state,
						       struct seekratio_data);
			if (tevent_req_nomem(state->seekratio, req)) {
				return tevent_req_post(req, ev);
			}
			if (!uldenominator || uldenominator > ulnumerator) {
				/* DB_E_BADRATIO */
				tevent_req_herror(req, HRES_ERROR(0x80040E12));
				return tevent_req_post(req, ev);
			}

			subreq = abs_interface->getexpensiveproperties_send(
					state,
					ev,
					client,
					handle,
					hcursor);
			if (tevent_req_nomem(subreq, req)) {
				return tevent_req_post(req, ev);
			}
			tevent_req_set_callback(subreq,
						wsp_gss_get_expensive_props_done,
						req);
			return req;
		}
		case EROWSEEKBYBOOKMARK:
			DBG_ERR("etype EROWSEEKBYBOOKMARK is unsupported for "
				 "GetRowsIn message");
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		default:
			DBG_ERR("illegal value for etype %d\n",
				 rowsin->etype);
			tevent_req_herror(
				req,
				HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
	}

	wsp_gss_getrows_process_rows_for_index(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void wsp_gss_get_expensive_props_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getrows_state *state = tevent_req_data(
		req, struct wsp_gss_getrows_state);
	HRESULT hres;

	hres = state->abs_interface->getexpensiveproperties_recv(req,
						&state->seekratio->crowstotal,
						&state->seekratio->resultsfound,
						&state->seekratio->maxrank);

	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	if (state->seekratio != NULL) {
		struct wsp_cpmgetrowsin *rowsin = state->rowsin;
		uint32_t ulnumerator =
			rowsin->seekdescription.crowseekatratio.ulnumerator;
		uint32_t uldenominator =
			rowsin->seekdescription.crowseekatratio.uldenominator;
		uint32_t crowstotal = state->seekratio->crowstotal;

		state->index = (ulnumerator/uldenominator) * crowstotal;
	}

	wsp_gss_getrows_process_rows_for_index(req);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}
}

static void wsp_gss_getrows_process_rows_for_index(struct tevent_req *req)
{
	struct wsp_gss_getrows_state *state = tevent_req_data(
		req, struct wsp_gss_getrows_state);
	uint32_t hcursor;
	uint32_t chapter;
	uint32_t handle;
	uint32_t fetchforward;
	struct wsp_abstract_interface *abs_interface = state->abs_interface;
	struct wsp_cpmgetrowsin *rowsin = state->rowsin;
	struct tevent_req* subreq = NULL;

	hcursor = state->rowsin->hcursor;
	chapter = state->rowsin->chapt;
	handle = state->handle;
	fetchforward = rowsin->fbwdfetch;

	abs_interface->setnextgetrowsposition(state->client,
					      handle, hcursor,
					      chapter, state->index);
	state->binding = abs_interface->getbindings(state->client,
						    handle, hcursor,
						    &state->ncols);
	/*
	 * allocate the full amount of possible padding (rowsin->cbreserved)
	 * note: cbreserved includes the header size (16) plus size of
	 * message (not including seekdescription)
	 * seekdescription is variable size 12 (or more) bytes.
	 * However since we don't currently support EROWSEEKBYBOOKMARK
	 * effectively this size is 12 bytes.
	 */

	state->pad_adjust = (rowsin->cbreserved
			    - (MSG_HEADER_SIZE + MSG_GETROWOUT_MAXSEEK));
	if (state->pad_adjust > rowsin->cbreserved) {
		DBG_ERR("cbreserved %d caused pad_adjust to wrap\n",
			rowsin->cbreserved);
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}

	/*
	 * spec says cbreadbuff should be the max between
	 * 1000 * rowstotransfer rounded up to the nearest 512 byte
	 * multiple with the result capped to 0x4000
	 * protocol example uses 1000 * rowwidth (which seems a bit
	 * more sensible) so test that.
	 */
	if (rowsin->cbrowWidth > MAX_ROW_BUFF_SIZE / 1000)
	{
		DBG_ERR("cbrowwidth 0x%x X 1000 exceeds max "
			"buff size of 0x%x\n",
			rowsin->cbrowWidth, MAX_ROW_BUFF_SIZE);
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}

	if (rowsin->cbreadbuffer > MAX_ROW_BUFF_SIZE) {
		DBG_ERR("cbreadbuff 0x%x exceeds max buff size of 0x%x\n",
			rowsin->cbreadbuffer, MAX_ROW_BUFF_SIZE);
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}

	state->buf_size =
		rowsin->cbreadbuffer - rowsin->cbreserved + state->pad_adjust;

	if (state->buf_size > rowsin->cbreadbuffer) {
		DBG_ERR("buf_size has overflowed\n");
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}
	state->row_buff = talloc_zero_array(req, uint8_t, state->buf_size);
	if (tevent_req_nomem(state->row_buff, req)) {
		DBG_ERR("out of memory\n");
		return;
	}

	/* position buffer to write into after max padding */
	state->row_buff = state->row_buff + state->pad_adjust;
	/* similarly adjust size */
	state->buf_size = state->buf_size - state->pad_adjust;
	state->cur_rowbuf_end_pos = state->buf_size;

	subreq = abs_interface->getrows_send(state, state->ev, state->client,
					     handle, hcursor,
					     rowsin->crowstotransfer,
					     fetchforward);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wsp_gss_getrows_done, req);
	return;
}

static enum ndr_err_code fill_variant_address_buffer(TALLOC_CTX *ctx,
			bool is_64bit,
			uint32_t cur_rowbuf_end_pos,
			uint64_t baseaddress,
			uint64_t *offsets,
			uint32_t count,
			DATA_BLOB *pbuffer)
{
	struct ndr_push *ndr_push = NULL;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	int i;
	enum ndr_err_code err;
	DATA_BLOB blob = data_blob_null;

	ndr_push = ndr_push_init_ctx(ctx);
	if (ndr_push == NULL) {
		DBG_ERR("failed to init push ctx\n");
		return NDR_ERR_ALLOC;
	}

	/* write addresses */
	for (i = 0; i < count; i++) {
		uint64_t offset = offsets[i] + cur_rowbuf_end_pos;
		uint64_t address = baseaddress + offset;

		if (is_64bit) {
			if (offset < offsets[i]) {
				DBG_ERR("Overflow!!\n");
				err = NDR_ERR_OFFSET;
				goto out;
			}
			if (address < baseaddress) {
				DBG_ERR("Overflow!!\n");
				err = NDR_ERR_OFFSET;
				goto out;
			}
			err = ndr_push_udlong(ndr_push,
					      ndr_flags,
					      address);
		} else {
			if (offset > UINT32_MAX) {
				DBG_ERR("Overflow!!\n");
				err = NDR_ERR_OFFSET;
				goto out;
			}
			if (address > UINT32_MAX) {
				DBG_ERR("Overflow!!\n");
				err = NDR_ERR_OFFSET;
				goto out;
			}
			err = ndr_push_uint32(ndr_push,
					      ndr_flags,
					      (uint32_t)address);
		}
		if (err != NDR_ERR_SUCCESS) {
			DBG_ERR("failed to write addresses to buffer\n");
			goto out;
		}
	}

	blob.data = talloc_steal(ctx, ndr_push->data);
	blob.length = ndr_push->offset;
	*pbuffer = blob;
	err = NDR_ERR_SUCCESS;
out:
	TALLOC_FREE(ndr_push);
	return err;
}

/*
 * store wsp_cbasestoragevariant[] values array returning both buffer
 * the array is stored in and offsets to where each item in the
 * values array is stored in the buffer.
 */
static enum ndr_err_code store_variant_array_to_buffer(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *values,
			uint32_t count,
			uint64_t **poffsets,
			DATA_BLOB *pbuffer)
{
	struct ndr_push *ndr_push = NULL;
	uint64_t *offsets = NULL;
	int i;
	DATA_BLOB buffer = data_blob_null;
	enum ndr_err_code err;

	offsets = talloc_zero_array(ctx, uint64_t, count);
	if (offsets == NULL) {
		DBG_ERR("failed to alloc array for offsets\n");
		return NDR_ERR_ALLOC;
	}

	ndr_push = ndr_push_init_ctx(ctx);
	if (ndr_push == NULL) {
		DBG_ERR("failed to init push ctx\n");
		return NDR_ERR_ALLOC;
	}

	/*
	 * save offsets (offset from 0) where
	 * values are stored
	 */
	for (i = 0; i < count; i++) {
		uint32_t saved_offset = ndr_push->offset;
		uint32_t save_flags = ndr_push->flags;

		if (values[i].vtype != VT_LPWSTR) {
			DBG_ERR("#FIXME Unhandled variant type %s\n",
				get_vtype_name(values[i].vtype));
			TALLOC_FREE(offsets);
			goto out;
		}

		ndr_set_flags(&ndr_push->flags, LIBNDR_FLAG_STR_NULLTERM);
		err = ndr_push_string(ndr_push,
				      NDR_SCALARS,
				      values[i].vvalue.vt_lpwstr.value);
		if (err != NDR_ERR_SUCCESS) {
			TALLOC_FREE(offsets);
			goto out;
		}
		ndr_push->flags = save_flags;
		offsets[i] = saved_offset;
	}

	err = NDR_ERR_SUCCESS;
	buffer.data = talloc_steal(ctx, ndr_push->data);
	buffer.length = ndr_push->offset;
	*poffsets = offsets;
	*pbuffer = buffer;
out:
	TALLOC_FREE(ndr_push);
	return err;
}

static bool convert_variant_vector_to_array(TALLOC_CTX *ctx,
			struct wsp_cbasestoragevariant *col_val,
			uint64_t *pcount,
			struct wsp_cbasestoragevariant **pvalues)
{
	uint64_t count = 0;
	struct wsp_cbasestoragevariant *values = NULL;
	uint32_t vtype = col_val->vtype & ~VT_VECTOR;
	int i;

	if (vtype != VT_LPWSTR) {
		DBG_ERR("converting vector of %s to array unsupported\n",
			get_vtype_name(vtype));
		return false;
	}
	count = col_val->vvalue.vt_lpwstr_v.vvector_elements;
	values = talloc_zero_array(ctx, struct wsp_cbasestoragevariant, count);
	if (values == NULL) {
		DBG_ERR("out of memory\n");
		return false;
	}

	for (i = 0; i < count; i++) {
		values[i].vvalue.vt_lpwstr =
			col_val->vvalue.vt_lpwstr_v.vvector_data[i];
		values[i].vtype = vtype;
	}

	*pvalues = values;
	*pcount = count;
	return true;
}

static enum ndr_err_code push_variable_type(
			TALLOC_CTX *ctx,
			bool is_64bit,
			struct ndr_push *ctablevariant_push,
			struct wsp_ctablecolumn *tab_col,
			struct wsp_cbasestoragevariant *col_val,
			uint8_t *buf_start,
			uint8_t *value_buf, uint8_t *row_buf,
			uint32_t *cur_rowbuf_end_pos,
			uint64_t baseaddress,
			uint32_t row_boundry)
{
	uint64_t *offsets = NULL;
	uint64_t count = 0;
	bool is_vector = col_val->vtype & VT_VECTOR;
	struct wsp_cbasestoragevariant *values = 0;
	enum ndr_err_code err;
	uint32_t addresslist_offset;
	uint32_t length_used = 0;
	uint32_t intsize;
	uint64_t address;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB values_buf = data_blob_null;
	DATA_BLOB addresses_buf = data_blob_null;

	if (is_vector) {
		if (!convert_variant_vector_to_array(ctx,
				col_val,
				&count,
				&values)) {
			err = NDR_ERR_VALIDATE;
			goto out;
		}
	} else {
		count = 1;
		values = talloc_zero_array(ctx,
				struct wsp_cbasestoragevariant,
				count);
		values[0] = *col_val;
	}

	/* write values to buffer storing the offsets */
	err = store_variant_array_to_buffer(ctx,
					    values,
					    count,
					    &offsets,
					    &values_buf);
	if (err != NDR_ERR_SUCCESS) {
		goto out;
	}

	/*
	 * length used is written to buffer at tab_col->lengthoffset.value
	 * in 32 bit mode windows seems to write out this length correctly
	 * in 64 bit mode it seems to cap this value (I couldn't find a
	 * consistent pattern) It does seem though that windows doesn't use
	 * this value when extracting the row variable (confirmed by
	 * inserting bad values and passing them to windows)
	 *
	 * the length value seems to be calculated as the space used to
	 * store the value at the offset specified in the ctablevariant
	 * offset member plus the max size of ctablevariant (e.g. as if
	 * representing a vector)
	 */

	length_used = values_buf.length;

	if (is_64bit) {
		/*
		 * max size ctablevariant (with (vtype & VT_VECTOR))
		 * vtype       (2)
		 * reserved1   (2)
		 * reservered2 (4)
		 * count       (8)
		 * address     (8)
		 * ===============
		 *            0x18
		 */
		length_used += 0x18;
		intsize = 8;
	} else {
		/*
		 * max size ctablevariant (with (vtype & VT_VECTOR))
		 * vtype       (2)
		 * reserved1   (2)
		 * reservered2 (4)
		 * count       (4)
		 * address     (4)
		 * ===============
		 *            0x10
		 */
		length_used += 0x10;
		intsize = 4;
	}

	if (is_vector) {
		/* update position of buffer offset */
		*cur_rowbuf_end_pos = *cur_rowbuf_end_pos
				     - (count * intsize) - values_buf.length;
		/* save pos in buffer to write address list to */
		addresslist_offset = *cur_rowbuf_end_pos + values_buf.length;

		err = fill_variant_address_buffer(ctx,
				is_64bit,
				*cur_rowbuf_end_pos,
				baseaddress,
				offsets,
				count,
				&addresses_buf);
		if (err != NDR_ERR_SUCCESS) {
			goto out;
		}

	} else {
		/* update position of buffer offset */
		if (values_buf.length >= *cur_rowbuf_end_pos) {
			DBG_NOTICE("Value len is %zd is larger or equal "
				   "to remaining buffer size %d\n",
				   values_buf.length,
				    *cur_rowbuf_end_pos);
			err = NDR_ERR_OFFSET;
			goto out;
		}

		*cur_rowbuf_end_pos = *cur_rowbuf_end_pos - values_buf.length;
		/* won't be using addresslist or addresses_buf */
		addresslist_offset = 0;
	}

	if (row_boundry >= *cur_rowbuf_end_pos) {
		/*
		 * col variant value about to corrupt
		 * fixed buffer
		*/
		DBG_NOTICE("col value overlapping fixed buffer "
			  "area\n");
		err = NDR_ERR_ARRAY_SIZE;
		goto out;
	}

	/* write out remainder of wsp_ctablevariant structure */
	if (is_vector) {
		address = addresslist_offset + baseaddress;
		/* store num items in vector */
		if (is_64bit) {
			if (address < addresslist_offset) {
				DBG_ERR("detected integer overflow when adding "
					"offset %d to %"PRIu64"\n",
					addresslist_offset, baseaddress);

				err = NDR_ERR_OFFSET;
			} else {
				err = ndr_push_udlong(ctablevariant_push,
						      ndr_flags,
						      count);
			}
		} else {
			if (address > UINT32_MAX) {
				DBG_ERR("detected integer overflow when adding "
					"offset %d to %"PRIu64"\n",
					addresslist_offset, baseaddress);

				err = NDR_ERR_OFFSET;
			} else {
				err = ndr_push_uint32(ctablevariant_push,
						      ndr_flags,
						      count);
			}
		}

		if (err != NDR_ERR_SUCCESS) {
			goto out;
		}

		/* store address of vector list addresses */
		if (is_64bit) {
			err = ndr_push_udlong(ctablevariant_push,
						      ndr_flags,
						      address);
		} else {
			err = ndr_push_uint32(ctablevariant_push,
					      ndr_flags,
					      address);
		}
	} else {
		uint32_t value_offset = *cur_rowbuf_end_pos + offsets[0];

		address = baseaddress + value_offset;
		/* store address value */
		if (is_64bit) {
			if (address < value_offset) {
				DBG_ERR("detected integer overflow when adding "
					"offset %d to %"PRIu64"\n",
					value_offset, baseaddress);

				err = NDR_ERR_OFFSET;
			} else {
				err = ndr_push_udlong(ctablevariant_push,
						      ndr_flags,
						      address);
			}
		} else {
			if (address > UINT32_MAX) {
				DBG_ERR("detected integer overflow when adding "
					"offset %d to %"PRIu64"\n",
					value_offset, baseaddress);
				err = NDR_ERR_OFFSET;
			} else {
				err = ndr_push_uint32(ctablevariant_push,
						      ndr_flags,
						      (uint32_t)address);
			}
		}
	}

	if (err != NDR_ERR_SUCCESS) {
		goto out;
	}

	/*
	 * copy out the list of values to the buffer
	 * leaving space for the address list to follow
	 */
	memcpy(buf_start + *cur_rowbuf_end_pos,
	       values_buf.data,
	       values_buf.length);
	/* followed by the address list */
	memcpy(buf_start + addresslist_offset,
	       addresses_buf.data,
	       addresses_buf.length);

	if (tab_col->lengthused) {
		PUSH_LE_U32(row_buf, tab_col->lengthoffset.value, length_used);
	}
	err = NDR_ERR_SUCCESS;
out:
	return err;
}

static enum ndr_err_code push_crowvariant(
			TALLOC_CTX *ctx,
			bool is_64bit,
			struct wsp_ctablecolumn *tab_col,
			struct wsp_cbasestoragevariant *col_val,
			uint8_t *buf_start,
			uint8_t *value_buf, uint8_t *row_buf,
			uint32_t *cur_rowbuf_end_pos,
			uint64_t baseaddress,
			uint32_t row_boundry)
{
	struct wsp_ctablevariant variant = {};
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push *ndr_push = NULL;

	ndr_push = ndr_push_init_ctx(ctx);
	if (ndr_push == NULL) {
		DBG_ERR("failed to init push ctx\n");
		return NDR_ERR_ALLOC;
	}

	if (col_val->vtype != VT_EMPTY) {
		variant.vtype = col_val->vtype; /* vtype */
	}

	err = ndr_push_wsp_ctablevariant(ndr_push, ndr_flags, &variant);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to fixed portion of ctablevariant %d\n", err);
		goto out;
	}

	/* default value.. adjusted below if necessary when processing values */
	if (tab_col->lengthused) {
		PUSH_LE_U32(row_buf, tab_col->lengthoffset.value, 0x10);
	}

	if (is_variable_size(col_val->vtype & ~(VT_VECTOR))) {
		/* variable size type */
		err = push_variable_type(ctx,
			is_64bit,
			ndr_push,
			tab_col,
			col_val,
			buf_start,
			value_buf, row_buf,
			cur_rowbuf_end_pos,
			baseaddress,
			row_boundry);
		if (err != NDR_ERR_SUCCESS) {
			DBG_ERR("Failed to write variable to buffer %d\n", err);
			goto out;
		}
	} else {
		/* fixed size type */
		if (col_val->vtype & VT_VECTOR) {
			DBG_ERR("not handling vectors of fixed size "
				"values\n");
			err = NDR_ERR_VALIDATE;
		}
		NDR_CHECK(ndr_push_set_switch_value(ndr_push,
						    &col_val->vvalue,
						    col_val->vtype));
		NDR_CHECK(ndr_push_variant_types(ndr_push,
						 NDR_SCALARS,
						 &col_val->vvalue));
	}
	err = NDR_ERR_SUCCESS;
	if ((value_buf - buf_start + ndr_push->offset) >= *cur_rowbuf_end_pos) {
		DBG_ERR("row value too bit to fit remaining row width\n");
		err = NDR_ERR_RANGE;
		goto out;
	}
	memcpy(value_buf, ndr_push->data, ndr_push->offset);
out:
	TALLOC_FREE(ndr_push);
	return err;
}

static enum ndr_err_code push_column(TALLOC_CTX *ctx,
			struct wsp_ctablecolumn *tab_col,
			struct wsp_cbasestoragevariant *col_val,
			DATA_BLOB *blob, uint32_t *cur_rowbuf_end_pos,
			int row, uint64_t baseaddress,
			uint32_t row_width, bool is_64bit)
{
	uint8_t *row_buff = blob->data + (row * row_width);
	uint32_t row_boundry = (row * row_width) + row_width;
	enum ndr_err_code err;

	if (row_boundry >= *cur_rowbuf_end_pos) {
		/*
		 * abandon row processing, variant and fixed portions about
		 * to collide
		 */
		DBG_NOTICE("row too big to fit...\n");
		return NDR_ERR_RANGE;
	}
	PUSH_LE_U16(row_buff, 0, 0xdead);
	if (tab_col->statusused) {
		if (row_buff - blob->data + tab_col->statusoffset.value
		    >= *cur_rowbuf_end_pos) {
			DBG_ERR("statusoffset value outside of row buffer\n");
			return NDR_ERR_RANGE;
		}
		if (col_val->vtype == VT_NULL) {
			*(row_buff + tab_col->statusoffset.value) =
				STORESTATUSDEFERRED;
			col_val->vtype = VT_EMPTY;
		} else if (col_val->vtype == VT_EMPTY) {
			*(row_buff + tab_col->statusoffset.value) =
				STORESTATUSNULL;
		} else {
			*(row_buff + tab_col->statusoffset.value) =
				STORESTATUSOK;
		}
	}

	if (tab_col->lengthused) {
		if (row_buff - blob->data + tab_col->lengthoffset.value
		     + sizeof(uint32_t) >= *cur_rowbuf_end_pos) {
			DBG_ERR("lengthoffset value outside of row buffer\n");
			return NDR_ERR_RANGE;
		}
	}

	if (tab_col->valueused) {
		uint8_t *value_buf = row_buff + tab_col->valueoffset.value;
		bool is_array = col_val->vtype & VT_ARRAY;
		if (value_buf - blob->data >= *cur_rowbuf_end_pos) {
			DBG_ERR("valueoffset value outside of row buffer\n");
			return NDR_ERR_RANGE;
		}

		if (is_array) {
			/*
			 * I think we might be required to coerce
			 * array to vector here (not sure) but
			 * it is fine to bail out for the moment
			 */
			DBG_ERR("Not handling arrays\n");
			return NDR_ERR_VALIDATE;
		}
		err = push_crowvariant(ctx,
				       is_64bit,
				       tab_col,
				       col_val,
				       blob->data,
				       value_buf,
				       row_buff,
				       cur_rowbuf_end_pos,
				       baseaddress,
				       row_boundry);
		if (err != NDR_ERR_SUCCESS) {
			DBG_ERR("Failed to push variable size value\n");
			goto out;;
		}
	}
	err = NDR_ERR_SUCCESS;
out:
	return err;
}

static HRESULT fill_rows_buffer(struct wsp_gss_getrows_state *state,
				struct wsp_cbasestoragevariant **rowsarray)
{
	int i, j;
	uint32_t nrows = 0;
	uint32_t hcursor;
	uint32_t chapter;
	struct wsp_cbasestoragevariant *row = NULL;
	DATA_BLOB rows_blob = data_blob_null;
	HRESULT res = HRES_OK;

	rows_blob.data = state->row_buff;
	rows_blob.length = state->buf_size;

	hcursor = state->rowsin->hcursor;
	chapter = state->rowsin->chapt;
	for (i = 0, nrows = 0; i < state->rowsreturned; i++) {
		row = rowsarray[i];
		for (j = 0; j < state->ncols; j++) {
			enum ndr_err_code err;
			struct wsp_cbasestoragevariant *col_val =
				&row[j];
			DBG_INFO("processing col[%d]\n", j);
			err = push_column(state, &state->binding[j],
					 col_val, &rows_blob,
					 &state->cur_rowbuf_end_pos, i,
					 state->baseaddress,
					 state->rowsin->cbrowWidth,
					 state->is_64bit);
			if (err) {
				/*
				 * we got some error trying to fit columns
				 * into row, return here with just the rows
				 * we managed to fill
				 */
				DBG_NOTICE("while pushing column error: %s\n"
					   "readjusting rows returned from %d "
					   "to %d\n",
					   ndr_map_error2string(err),
					   state->rowsreturned,
					   nrows);
				state->rowsreturned = nrows;
				/*
				 * reset nomorerowstoreturn if it's already set
				 * as we no longer are returning all rows
				 */
				if (state->nomorerowstoreturn) {
					state->nomorerowstoreturn = false;
				}
				break;
			}
		}
		nrows++;
	}

	state->abs_interface->setnextgetrowsposition(
					state->client,
					state->handle,
					hcursor, chapter,
					state->index + i);
	state->rowsout->rowsreturned = state->rowsreturned;
	state->rowsout->etype = 0;
	state->rowsout->chapt = state->rowsin->chapt;

	if (!state->nomorerowstoreturn
	    && (state->rows_requested != state->rowsreturned)) {
		if (state->rowsin->etype == EROWSEEKAT) {
			/* follow what windows seems to do, use a skip of 1 */
			uint32_t skip = 1;
			/*
			 * 3.1.5.2.6 Receiving a CPMGetRowsIn Request
			 * (bullet 5 - 10)
			 * MS-WSP is confusing here again, but.. at least by
			 * observation with SeekDescription etype EROWSEEKAT
			 * we set the response eType to be the eType from
			 * GetRowsIn *BUT* not copy it, instead we populate the
			 * bookmark offset with the index and skip values to
			 * allow the client restart the search.
			 * Note: we only seem to need to do this when we
			 *       haven't been able to fill the buffer with the
			 *       requested number of rows
			 * not sure how we handle the other types
			 */
			state->rowsout->etype = state->rowsin->etype;
			state->rowsout->seekdescription.crowseekat.cskip = skip;

			state->rowsout->seekdescription.crowseekat.bmkoffset =
					state->index + i - skip;
			/* we also need to set the special status */
			res = HRES_ERROR(DB_S_BLOCKLIMITEDROWS);
		}
	}
	/*
	 * assuming no seekdescription we rewind row_buf back the max padding
	 */
	if (!state->rowsout->etype) {
		state->row_buff -= state->pad_adjust;
		state->buf_size += state->pad_adjust;
	}

	rows_blob.data = state->row_buff;
	rows_blob.length = state->buf_size;

	/* set up out param */
	*state->extra_out_blob = rows_blob;

	if (state->nomorerowstoreturn) {
		res = HRES_ERROR(DB_S_ENDOFROWSET);
	}
	return res;
}

static bool status_is_hresult_success(uint32_t error);

static void wsp_gss_getrows_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getrows_state *state = tevent_req_data(
		req, struct wsp_gss_getrows_state);
	struct wsp_cbasestoragevariant **rows = NULL;
	HRESULT res;

	res = state->abs_interface->getrows_recv(
					subreq,
					state,
					&rows,
					&state->info->nomorerowstoreturn,
					&state->info->total_rows);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, res)) {
		return;
	}

	state->info->rowstart_index = state->index;

	/*
	 * state->info->nomorerowstoreturn (means after requesting
	 * state->rows_requested there are no more rows left to read
	 * at backend)
	 *
	 * state->info->total_rows is the number of rows returned from the
	 * backend
	 */

	state->nomorerowstoreturn = state->info->nomorerowstoreturn;
	state->rowsreturned = state->info->total_rows;

	res = fill_rows_buffer(state, rows);
	TALLOC_FREE(rows);
	if (tevent_req_herror(req, res)) {
		return;
	}
	tevent_req_done(req);
}

struct wsp_gss_fetchvalue_state {
	struct wsp_response *response;
	struct wsp_cpmfetchvalueout *valueout;
	struct wsp_abstract_interface *abs_interface;
	uint32_t fvalueexists;
	uint32_t fmoreexists;
	uint32_t cbsofar;
	uint32_t cbchunk;
	DATA_BLOB *extra_out_blob;
	DATA_BLOB value;
};

/* MS-WSP 3.1.5.2.7 Receiving a CPMFetchValueIn Request */
static void wsp_gss_fetchvalue_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_handle_fetchvalue(TALLOC_CTX *ctx,
				 struct tevent_context *ev,
				 struct wspd_client_state *client,
				 struct wsp_header *header,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_gss_fetchvalue_state *state = NULL;
	uint32_t handle = client->client_data->fid;
	struct wsp_cpmfetchvaluein *valuein = NULL;
	struct wsp_cpmfetchvalueout *valueout =	&response->message.cpmfetchvalue;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(ctx, &state, struct wsp_gss_fetchvalue_state);
	if (req == NULL) {
		return NULL;
	}

	valuein = talloc_zero(ctx, struct wsp_cpmfetchvaluein);
	if (tevent_req_nomem(valuein, req)) {
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmfetchvaluein(ndr, ndr_flags, valuein);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmfetchvaluein\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	state->abs_interface = abs_interface;
	state->response = response;
	state->valueout = valueout;
	state->extra_out_blob = extra_out_blob;
	state->cbsofar = valuein->cbsofar;
	state->cbchunk = valuein->cbchunk;

	subreq = abs_interface->getpropertyvalueforworkid_send(state,
			ev,
			client,
			handle,
			valuein->wid,
			&valuein->propspec);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_fetchvalue_done, req);
	return req;
}

static void wsp_gss_fetchvalue_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_fetchvalue_state *state = tevent_req_data(
		req, struct wsp_gss_fetchvalue_state);
	struct wsp_cpmfetchvalueout *valueout = state->valueout;
	HRESULT hres;
	size_t remainder;
	uint32_t cbvalue;

	hres = state->abs_interface->getpropertyvalueforworkid_recv(subreq,
							state,
							&state->value,
							&state->fvalueexists);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	if (!state->fvalueexists) {
		tevent_req_done(req);
		return;
	}

	if (state->cbsofar > state->value.length) {
		DBG_ERR("Data corruption, cbsofar %d exceeds value buffer len %zu\n",
			state->cbsofar, state->value.length);
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return;
	}

	remainder = state->value.length - state->cbsofar;
	if (remainder > state->cbchunk) {
		cbvalue = state->cbchunk;
	} else {
		cbvalue = remainder;
	}
	state->extra_out_blob->data = talloc_zero_array(req, uint8_t, cbvalue);
	if (tevent_req_nomem(state->extra_out_blob->data, req)) {
		return;
	}
	state->extra_out_blob->length = cbvalue;
	memcpy(state->extra_out_blob->data,
	       state->value.data + state->cbsofar,
	       state->extra_out_blob->length);
	valueout->cbvalue = cbvalue;
	valueout->fvalueexists = state->fvalueexists;
	valueout->fmoreexists =	(cbvalue != remainder);

	tevent_req_done(req);
}

struct wsp_gss_setbindings_state {
	bool dummy;
};

/* MS-WSP 2.2.3.10, MS-WSP 3.1.5.2.8 */
static struct tevent_req *wsp_gss_setbindings_send(TALLOC_CTX *ctx,
			       struct tevent_context *ev,
			       struct wspd_client_state *client,
			       struct wsp_header *header,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	struct wsp_cpmsetbindingsin *bindings = NULL;
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_setbindings_state *state = NULL;
	struct tevent_req *req = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;
	int32_t clientversion;

	req = tevent_req_create(ctx, &state, struct wsp_gss_setbindings_state);
	if (req == NULL) {
		return NULL;
	}

	bindings = talloc_zero(ctx, struct wsp_cpmsetbindingsin);
	if (tevent_req_nomem(bindings, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
			handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	clientversion = find_client_version(handle,
					    client->client_data->wsp_gss_state);
	if (clientversion < 0) {
		DBG_ERR("no cached version for client with handle %u\n",
			handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if ((clientversion | 0x0000FFFF) >= WINDOWS_32_BIT) {
		if (!verify_checksum(in_data, header)) {
			DBG_ERR("invalid checksum 0x%x\n", header->checksum);
			tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
			return tevent_req_post(req, ev);
		}
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmsetbindingsin(ndr, ndr_flags, bindings);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmsetbindingsin\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	/*
	 * #TODO we should ideally be checking the integrity of
	 * bindings->acolumns (but not entirely sure how).
	 */
	abs_interface->setbindings(client,
				   handle, bindings->hcursor,
				   bindings->acolumns,
				   bindings->ccolumns);
	/* keep the binding columns info */
	talloc_steal(get_connected_client_entry(handle, wsp_gss_state),
		     bindings->acolumns);
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

struct wsp_gss_getnotify_state {
	bool dummy;
};

/* MS-WSP 2.2.3.10, MS-WSP 3.1.5.2.9 */
static struct tevent_req *wsp_gss_getnotify_send(TALLOC_CTX *ctx,
			       struct tevent_context *ev,
			       struct wspd_client_state *client,
			       struct wsp_header *header,
			       struct wsp_response *response,
			       DATA_BLOB *in_data,
			       DATA_BLOB *extra_out_blob,
			       struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_getnotify_state *state = NULL;
	struct tevent_req *req = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;

	req = tevent_req_create(ctx, &state, struct wsp_gss_getnotify_state);
	if (req == NULL) {
		return NULL;
	}

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	/*
	 * with some basic testing it looked like windows10
	 * doesn't implement this and returns E_NOTIMPL
	 * in anycase for the moment won't implement here either
	 * */
	tevent_req_herror(req, HRES_E_NOTIMPL);
	return tevent_req_post(req, ev);
}

struct wsp_gss_getapproxpos_state {
	struct tevent_context *ev;
	uint32_t resultscount;
	uint32_t maxrank;
	uint32_t handle;
	uint32_t hcursor;
	struct wspd_client_state *client;
	struct wsp_cpmgetapproximatepositionout *approx_out;
	struct wsp_abstract_interface *abs_interface;
};

static void wsp_gss_getapproxpos_done(struct tevent_req *subreq);
static void wsp_gss_approx_getexpensiveprops_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_getapproxpos_send(TALLOC_CTX *ctx,
				 struct tevent_context *ev,
				 struct wspd_client_state *client,
				 struct wsp_header *header,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_cpmgetapproximatepositionin *approx_in = NULL;
	struct wsp_cpmgetapproximatepositionout *approx_out =
		&response->message.getapproximateposition;
	struct wsp_gss_getapproxpos_state *state = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(ctx, &state, struct wsp_gss_getapproxpos_state);
	if (req == NULL) {
		return NULL;
	}

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req,
				  HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	approx_in = talloc_zero(ctx, struct wsp_cpmgetapproximatepositionin);
	if (tevent_req_nomem(approx_in, req)) {
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmgetapproximatepositionin(ndr, ndr_flags, approx_in);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmgetapproximatepositionin\n");
		tevent_req_herror(req,
				  HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	state->ev = ev;
	state->approx_out = approx_out;
	state->client = client;
	state->handle = handle;
	state->hcursor = approx_in->hcursor;
	state->abs_interface = abs_interface;
	subreq = abs_interface->getapproximatepos_send(ctx,
						ev,
						client,
						handle,
						approx_in->hcursor,
						approx_in->bmk);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_getapproxpos_done, req);
	return req;
}

static void wsp_gss_getapproxpos_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getapproxpos_state *state = tevent_req_data(
		req, struct wsp_gss_getapproxpos_state);
	HRESULT hres;

	hres = state->abs_interface->getapproximatepos_recv(subreq,
					&state->approx_out->numerator);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	subreq = state->abs_interface->getexpensiveproperties_send(req,
					state->ev,
					state->client,
					state->handle,
					state->hcursor);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_approx_getexpensiveprops_done,
				req);
}

static void wsp_gss_approx_getexpensiveprops_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getapproxpos_state *state = tevent_req_data(
		req, struct wsp_gss_getapproxpos_state);
	HRESULT hres;

	hres = state->abs_interface->getexpensiveproperties_recv(subreq,
						&state->approx_out->denominator,
						&state->resultscount,
						&state->maxrank);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	tevent_req_done(req);
}

struct wsp_gss_comparebmk_state {
	bool dummy;
};

static struct tevent_req *wsp_gss_comparebmk_send(TALLOC_CTX *ctx,
				 struct tevent_context *ev,
				 struct wspd_client_state *client,
				 struct wsp_header *header,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	struct wsp_cpmcomparebmkin *bmkin = NULL;
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *req = NULL;
	struct wsp_gss_comparebmk_state *state = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;
	uint32_t first;
	uint32_t second;

	req = tevent_req_create(ctx, &state, struct wsp_gss_comparebmk_state);
	if (req == NULL) {
		return NULL;
	}

	bmkin = talloc_zero(state, struct wsp_cpmcomparebmkin);
	if (tevent_req_nomem(bmkin, req)) {
		return tevent_req_post(req, ev);
	}

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, state);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmcomparebmkin(ndr, ndr_flags, bmkin);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmcomparebmkin\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!abs_interface->clientqueryhascursorhandle(client,
					handle,
					bmkin->hcursor)) {
		tevent_req_herror(req, HRES_E_FAIL);
		return tevent_req_post(req, ev);
	}

	first = abs_interface->getbookmarkposition(client,
					handle,
					bmkin->hcursor,
					bmkin->bmkfirst);
	second = abs_interface->getbookmarkposition(client,
					handle,
					bmkin->hcursor,
					bmkin->bmksecond);

	/*
	 * results here must also be affected by the chapter
	 * e.g. if the bookmarks are in different chapters
	 * MS-WSP only says "if the chapter handle in CPMCompareBmkIn
	 * is invalid, or if one or both of the rows are not
	 * in the given chapter, the behavior is undefined."
	 * which kindof make me wonder why the chapter is in the
	 * bmkin message in the first place (or have I missed
	 * something)
	 */
	if (first < second) {
		response->message.cpmcomparebmk.dwcomparison =
			DBCOMPARE_LT;
	} else if (first > second) {
		response->message.cpmcomparebmk.dwcomparison =
			DBCOMPARE_GT;
	} else {
		response->message.cpmcomparebmk.dwcomparison =
			DBCOMPARE_EQ;
	}
	tevent_req_done(req);
	return tevent_req_post(req, wsp_gss_state->ev);
}

struct wsp_gss_restartposition_state {
	bool dummy;
};

/*
 * dummy handler to just return a blank response message with 'success'
 * status.
 */
static struct tevent_req *wsp_gss_restartposition_send(TALLOC_CTX *ctx,
			     struct tevent_context *ev,
			     struct wspd_client_state *client,
			     struct wsp_header *header,
			     struct wsp_response *response,
			     DATA_BLOB *in_data,
			     DATA_BLOB *extra_out_blob,
			     struct wsp_abstract_interface *abs_interface)
{
	struct wsp_gss_restartposition_state *state = NULL;
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *req = NULL;
	struct wsp_cpmrestartpositionin *restartpos = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(
		ctx, &state, struct wsp_gss_restartposition_state);
	if (req == NULL) {
		return NULL;
	}

	restartpos = talloc_zero(state, struct wsp_cpmrestartpositionin);
	if (tevent_req_nomem(restartpos, req)) {
		return tevent_req_post(req, ev);
	}

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmrestartpositionin(ndr, ndr_flags, restartpos);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmsetbindingsin\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (restartpos->chapter != DB_NULL_HCHAPTER) {
		DBG_ERR("hierarchical queries not supported\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}
	abs_interface->setnextgetrowsposition(client,
					      handle,
					      restartpos->hcursor,
					      restartpos->chapter,
					      0);
	tevent_req_done(req);
	return tevent_req_post(req, wsp_gss_state->ev);
}

struct wsp_gss_freecursor_state {
	struct tevent_context *ev;
	struct wsp_abstract_interface *abs_interface;
	struct wsp_response *response;
	struct wsp_cpmfreecursorout *out;
	struct wspd_client_state *client;
	uint32_t handle;
};

/* MS-WSP 3.1.5.2.13 Receiving a CPMFreeCursorIn Request */
static void wsp_gss_freecursor_release_cursor_done(struct tevent_req *subreq);
static void wsp_gss_freecursor_release_query_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_freecursor_send(TALLOC_CTX *ctx,
			      struct tevent_context *ev,
			      struct wspd_client_state *client,
			      struct wsp_header *header,
			      struct wsp_response *response,
			      DATA_BLOB *in_data,
			      DATA_BLOB *extra_out_blob,
			      struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct wsp_cpmfreecursorin *in = NULL;
	struct wsp_gss_freecursor_state *state = NULL;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(ctx, &state, struct wsp_gss_freecursor_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	in = talloc_zero(state, struct wsp_cpmfreecursorin);
	if (tevent_req_nomem(in, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmfreecursorin(ndr, ndr_flags, in);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmfreecursorin\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	state->response = response;
	state->out = &response->message.cpmfreecursor;
	state->ev = ev;
	state->client = client;
	state->handle = handle;
	state->abs_interface = abs_interface;

	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	if (!abs_interface->clientqueryhascursorhandle(client,
						       handle, in->hcursor)) {
		DBG_ERR("no cursor %u for handle %u\n", in->hcursor, handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->releasecursor_send(state,
						ev,
						client,
						handle,
						in->hcursor);
	if (tevent_req_nomem(subreq, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq,
				wsp_gss_freecursor_release_cursor_done,
				req);
	return req;
}

static void wsp_gss_freecursor_release_cursor_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq,	struct tevent_req);
	struct wsp_gss_freecursor_state *state = tevent_req_data(
		req, struct wsp_gss_freecursor_state);
	HRESULT hres;

	hres = state->abs_interface->releasecursor_recv(subreq,
					&state->out->ccursorsremaining);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	subreq = state->abs_interface->releasequery_send(
					state,
					state->ev,
					state->client,
					state->handle);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq,
				wsp_gss_freecursor_release_query_done,
				req);
}

static void wsp_gss_freecursor_release_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_freecursor_state *state = tevent_req_data(
		req, struct wsp_gss_freecursor_state);
	HRESULT hres;

	hres = state->abs_interface->releasequery_recv(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

static void release_client_resources(struct wspd_client_state *client)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct uint32_list *id_item = wsp_gss_state->connectedclientsidentifiers;
	struct client_version_map *version_item =
		wsp_gss_state->connectedclientversions;
	struct query_rows_info *info = wsp_gss_state->query_info_map;

	while (id_item != NULL) {
		struct uint32_list *next_id = id_item->next;

		if (id_item->number == handle) {
			DLIST_REMOVE(wsp_gss_state->connectedclientsidentifiers,
				     id_item);
			TALLOC_FREE(id_item);
		}
		id_item = next_id;
	}

	while (version_item != NULL) {
		struct client_version_map *next_version = version_item->next;

		if (version_item->fid_handle == handle) {
			DLIST_REMOVE(wsp_gss_state->connectedclientversions,
				     version_item);
			TALLOC_FREE(version_item);
		}
		version_item = next_version;
	}

	while (info != NULL) {
		struct query_rows_info *next_info = info->next;

		if (info->handle == handle) {
			DLIST_REMOVE(wsp_gss_state->query_info_map,
				     info);
			TALLOC_FREE(info);
		}
		info = next_info;
	}
}

struct wsp_gss_disconnect_state {
	struct wsp_abstract_interface *abs_interface;
	struct wspd_client_state *client;
	uint32_t handle;
};

static void wsp_gss_disconnect_releasequery_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_disconnect_send(TALLOC_CTX *ctx,
			      struct tevent_context *ev,
			      struct wspd_client_state *client,
			      struct wsp_header *header,
			      struct wsp_response *response,
			      DATA_BLOB *in_data,
			      DATA_BLOB *extra_out_blob,
			      struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct wsp_gss_disconnect_state *state = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_gss_disconnect_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}

	release_client_resources(client);

	state->abs_interface = abs_interface;
	state->client = client;
	state->handle = handle;

	subreq = abs_interface->releasequery_send(ctx, ev, client, handle);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_disconnect_releasequery_done, req);
	return req;
}

static void wsp_gss_disconnect_releasequery_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_disconnect_state *state = tevent_req_data(
		req, struct wsp_gss_disconnect_state);
	HRESULT hres;

	hres = state->abs_interface->releasequery_recv(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

struct wsp_gss_rowsetnotify_state {
	struct wsp_cpmgetrowsetnotifyout *out;
	struct wsp_abstract_interface *abs_interface;
};

/* MS-WSP 3.1.5.2.16 Receiving a CPMGetRowsetNotifyIn */
static void wsp_gss_rowsetnotify_lastunretrievedevt_done(struct tevent_req *req);

static struct tevent_req *wsp_gss_rowsetnotify_send(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client,
				struct wsp_header *header,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *subreq = NULL;
	struct tevent_req *req = NULL;
	struct wsp_gss_rowsetnotify_state *state = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_gss_rowsetnotify_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	state->out = &response->message.cpmgetrowsetnotifyout;
	state->abs_interface = abs_interface;
	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->getlastunretrievedevt_send(ctx, ev, client, handle);
	if (tevent_req_nomem(subreq, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				wsp_gss_rowsetnotify_lastunretrievedevt_done,
				req);
	return req;
}

static void wsp_gss_rowsetnotify_lastunretrievedevt_done(
						struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_rowsetnotify_state *state = tevent_req_data(
		req, struct wsp_gss_rowsetnotify_state);
	uint64_t data1;
	uint64_t data2;
	bool more_events;
	HRESULT hres;

	hres = state->abs_interface->getlastunretrievedevt_recv(subreq,
						&state->out->wid,
						&state->out->eventinfo,
						&more_events,
						&state->out->rowitemstate,
						&state->out->changeditemstate,
						&state->out->rowsetevent,
						&data1,
						&data2);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}

	state->out->eventinfo = (state->out->eventinfo << 1);
	if (more_events) {
		state->out->eventinfo = state->out->eventinfo | 0x1;
	} else {
		state->out->eventinfo = state->out->eventinfo & 0xFE;
	}
	memcpy(&state->out->rowseteventdata1, &data1, sizeof(data1));
	memcpy(&state->out->rowseteventdata2, &data2, sizeof(data2));
	tevent_req_done(req);
}

struct wsp_gss_getscopestate_state {
	struct wsp_cpmgetscopestatisticsout *statsout;
	struct wsp_abstract_interface *abs_interface;
};

/* MS-WSP 3.1.5.2.17 Receiving a CPMGetScopeStatisticsIn */
static void wsp_gss_getscopestats_done(struct tevent_req *req);

static struct tevent_req *wsp_gss_getscopestats_send(TALLOC_CTX *ctx,
				 struct tevent_context *ev,
				 struct wspd_client_state *client,
				 struct wsp_header *header,
				 struct wsp_response *response,
				 DATA_BLOB *in_data,
				 DATA_BLOB *extra_out_blob,
				 struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct wsp_cpmgetscopestatisticsout *statsout =
				&response->message.cpmgetscopestatistics;
	struct wsp_gss_getscopestate_state *state = NULL;
	struct tevent_req *subreq = NULL;
	struct tevent_req *req = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_gss_getscopestate_state);
	if (req == NULL) {
		DBG_ERR("no memory\n");
		return NULL;
	}

	state->statsout = statsout;
	if (!has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("no record of connected client for handle %u\n",
		      handle);
		tevent_req_herror(req, HRESULT_FROM_NT(NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}
	state->abs_interface = abs_interface;

	subreq = abs_interface->getquerystats_send(
					state,
					ev,
					client,
					handle);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_getscopestats_done, req);
	return req;
}

static void wsp_gss_getscopestats_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_getscopestate_state *state = tevent_req_data(
		req, struct wsp_gss_getscopestate_state);
	HRESULT hres;

	hres = state->abs_interface->getquerystats_recv(subreq,
					&state->statsout->dwindexeditems,
					&state->statsout->dwoutstandingadds,
					&state->statsout->dwoustandingmodifies);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

struct wsp_gss_setscopeprio_state {
	struct wsp_abstract_interface *abs_interface;
};

/* MS-WSP 3.1.5.2.18 Receiving a CPMSetScopePrioritizationIn */
static void wsp_gss_setscopeprio_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_setscopeprio_send(TALLOC_CTX *ctx,
			     struct tevent_context *ev,
			     struct wspd_client_state *client,
			     struct wsp_header *header,
			     struct wsp_response *response,
			     DATA_BLOB *in_data,
			     DATA_BLOB *extra_out_blob,
			     struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_setscopeprio_state *state = NULL;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct tevent_req *subreq = NULL;
	struct tevent_req *req = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_gss_setscopeprio_state);
	if (req == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	state->abs_interface = abs_interface;

	subreq = abs_interface->setscopepriority_send(state,
						      ev,
						      client,
						      handle,
						      PRIORITY_LEVEL_FOREGROUND);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, wsp_gss_state->ev);
	}
	tevent_req_set_callback(subreq, wsp_gss_setscopeprio_done, req);
	return req;
}

static void wsp_gss_setscopeprio_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
					struct tevent_req);
	struct wsp_gss_setscopeprio_state *state = tevent_req_data(req,
			struct wsp_gss_setscopeprio_state);
	HRESULT hres;

	hres = state->abs_interface->setscopepriority_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

struct wsp_gss_cistateout_state {
	struct wsp_cpmcistateinout *cistateinout;
	struct wsp_abstract_interface *abs_interface;
};

static void wsp_gss_cistateout_done(struct tevent_req *subreq);

/* MS-WSP 3.1.5.1.1 Receiving a CPMCiStateInOut Request */
static struct tevent_req *wsp_gss_cistateout_send(TALLOC_CTX *ctx,
			     struct tevent_context *ev,
			     struct wspd_client_state *client,
			     struct wsp_header *header,
			     struct wsp_response *response,
			     DATA_BLOB *in_data,
			     DATA_BLOB *extra_out_blob,
			     struct wsp_abstract_interface *abs_interface)
{
	uint32_t handle = client->client_data->fid;
	struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;
	struct wsp_cpmcistateinout *cistateinout = NULL;
	struct wsp_gss_cistateout_state *state = NULL;
	struct tevent_req *req, *subreq = NULL;
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	DATA_BLOB payload = data_blob_null;

	req = tevent_req_create(wsp_gss_state,
				&state,
				struct wsp_gss_cistateout_state);
	if (req == NULL) {
		return NULL;
	}

	if (has_connected_client(handle, wsp_gss_state)) {
		DBG_ERR("error client %u is already connected\n", handle);
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	cistateinout = talloc_zero(ctx, struct wsp_cpmcistateinout);
	if (tevent_req_nomem(cistateinout, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	state->cistateinout = &response->message.wsp_cpmcistate;
	state->abs_interface = abs_interface;
	/* we have already read the header */
	payload = *in_data;
	payload.length -= MSG_HEADER_SIZE;
	payload.data += MSG_HEADER_SIZE;

	ndr = ndr_pull_init_blob(&payload, ctx);
	if (tevent_req_nomem(ndr, req)) {
		DBG_ERR("out of memory\n");
		return tevent_req_post(req, ev);
	}

	err = ndr_pull_wsp_cpmcistateinout(ndr, ndr_flags, cistateinout);
	if (err != NDR_ERR_SUCCESS) {
		DBG_ERR("Failed to pull unmarshall wsp_cpmcistateinout\n");
		tevent_req_herror(req, HRESULT_FROM_NT(
					  NT_STATUS_INVALID_PARAMETER));
		return tevent_req_post(req, ev);
	}

	subreq = abs_interface->getstate_send(state, ev, client);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wsp_gss_cistateout_done, req);
	return req;
}

static void wsp_gss_cistateout_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_cistateout_state *state = tevent_req_data(
		req, struct wsp_gss_cistateout_state);
	struct wsp_cpmcistateinout *cistateinout = state->cistateinout;
	HRESULT hres;

	hres = state->abs_interface->getstate_recv(subreq, cistateinout);
	TALLOC_FREE(subreq);
	if (tevent_req_herror(req, hres)) {
		return;
	}
	tevent_req_done(req);
}

typedef struct tevent_req *(*wsp_msg_handler_send_fn)(TALLOC_CTX *ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client,
				struct wsp_header *header,
				struct wsp_response *response,
				DATA_BLOB *in_data,
				DATA_BLOB *extra_out_blob,
				struct wsp_abstract_interface *abs_interface);

/* map of message id -> message handler function */
static struct {
	uint32_t msgid;
	wsp_msg_handler_send_fn send_fn;
} wsp_msg_handler_send_fns [] = {
	{CPMCONNECT, wsp_gss_connect_send},
        {CPMCREATEQUERY, wsp_gss_createquery_send},
	{CPMGETQUERYSTATUS, wsp_gss_querystatus_send},
	{CPMGETQUERYSTATUSEX, wsp_gss_querystatusex_send},
	{CPMRATIOFINISHED, wsp_gss_getratiofinished_send},
	{CPMGETROWS, wsp_gss_getrows_send},
	{CPMFETCHVALUE, wsp_gss_handle_fetchvalue},
	{CPMSETBINDINGSIN, wsp_gss_setbindings_send},
	{CPMGETNOTIFY, wsp_gss_getnotify_send},
	{CPMGETAPPROXIMATEPOSITION, wsp_gss_getapproxpos_send},
	{CPMCOMPAREBMK, wsp_gss_comparebmk_send},
	{CPMRESTARTPOSITIONIN, wsp_gss_restartposition_send},
	{CPMFREECURSOR, wsp_gss_freecursor_send},
	{CPMDISCONNECT, wsp_gss_disconnect_send},
	{CPMFINDINDICES, NULL},
	{CPMGETROWSETNOTIFY, wsp_gss_rowsetnotify_send},
	{CPMGETSCOPESTATISTICS, wsp_gss_getscopestats_send},
	{CPMSETSCOPEPRIORITIZATION, wsp_gss_setscopeprio_send},
	{CPMCISTATEOUT, wsp_gss_cistateout_send},
};

/*
 * This is the common async recv function for all async send functions
 * in the wsp_msg_handlers[] table above.
 */
static HRESULT wsp_msg_handler_recv(struct tevent_req *req)

{
	HRESULT hres;

	if (tevent_req_is_herror(req, &hres)) {
		tevent_req_received(req);
		return hres;
	}
	tevent_req_received(req);
	return HRES_OK;
}

/* map of message id to message name */
static struct {
	uint32_t msgid;
	const char *msg_name;
} msg_id_name_map [] = {
	{CPMCONNECT, "CPMCONNECT"},
	{CPMCREATEQUERY, "CPMCREATEQUERY"},
	{CPMSETBINDINGSIN, "CPMSETBINDINGSIN"},
	{CPMGETQUERYSTATUS, "CPMGETQUERYSTATUS"},
	{CPMGETQUERYSTATUSEX, "CPMGETQUERYSTATUSEX"},
	{CPMDISCONNECT, "CPMDISCONNECT"},
	{CPMFREECURSOR, "CPMFREECURSOR"},
	{CPMGETROWS, "CPMGETROWS"},
	{CPMRATIOFINISHED, "CPMRATIOFINISHED"},
	{CPMCOMPAREBMK, "CPMCOMPAREBMK"},
	{CPMGETAPPROXIMATEPOSITION, "CPMGETAPPROXIMATEPOSITION"},
	{CPMGETNOTIFY, "CPMGETNOTIFY"},
	{CPMSENDNOTIFYOUT, "CPMSENDNOTIFYOUT"},
	{CPMCISTATEOUT, "CPMCISTATEOUT"},
	{CPMFETCHVALUE, "CPMFETCHVALUE"},
	{CPMRESTARTPOSITIONIN, "CPMRESTARTPOSITIONIN"},
	{CPMSETCATSTATEIN, "CPMSETCATSTATEIN"},
	{CPMGETROWSETNOTIFY, "CPMGETROWSETNOTIFY"},
	{CPMFINDINDICES, "CPMFINDINDICES"},
	{CPMSETSCOPEPRIORITIZATION, "CPMSETSCOPEPRIORITIZATION"},
	{CPMGETSCOPESTATISTICS, "CPMGETSCOPESTATISTICS"},
};

/* return message handler function given a message id */
static wsp_msg_handler_send_fn get_wsp_msg_handler(uint32_t msgid)
{
	int i;

	for(i = 0; i < ARRAY_SIZE(wsp_msg_handler_send_fns); i++) {
		if (wsp_msg_handler_send_fns[i].msgid != msgid) {
			continue;
		}
		if (wsp_msg_handler_send_fns[i].send_fn == NULL) {
			DBG_WARNING("unhandled msgid 0x%x\n", msgid);
			break;
		}
		return wsp_msg_handler_send_fns[i].send_fn;
	}
	DBG_ERR("no handler for unknown msgid 0x%x\n", msgid);
	return NULL;
}

/* return name of message given a message id */
static const char *msgid_to_string(uint32_t msgid)
{
	int i;
	const char *result = "UNKNOWN";
	for (i = 0; i < ARRAY_SIZE(msg_id_name_map); i++) {
		if (msgid == msg_id_name_map[i].msgid ){
			result = msg_id_name_map[i].msg_name;
			break;
		}
	}
	return result;
};

/* extract message header from wsp_blob into wsp_header */
static bool extract_wsp_header(TALLOC_CTX *ctx,
				DATA_BLOB *wsp_blob,
				void *wsp_header)
{
	struct ndr_pull *ndr = NULL;
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;

	DBG_DEBUG("got wsp message blob of size %d\n", (int)wsp_blob->length);
	ndr = ndr_pull_init_blob(wsp_blob, ctx);
	err = ndr_pull_wsp_header(ndr, ndr_flags, wsp_header);
	if (err) {
		return false;
	}
	return true;
}

static void set_msg_checksum(DATA_BLOB *blob, struct wsp_header *hdr)
{
	uint32_t checksum = calculate_checksum(blob, hdr);
	hdr->checksum = checksum;
}

static enum ndr_err_code insert_checksum_into_msg_and_hdr(DATA_BLOB* blob,
				struct wsp_header *header)
{
	enum ndr_err_code err;
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push *header_ndr = NULL;
	TALLOC_CTX *ctx = talloc_init("insert");

	if (ctx == NULL) {
		DBG_ERR("out of memory\n");
		err = NDR_ERR_INCOMPLETE_BUFFER;
		goto out;
	}

	header_ndr = ndr_push_init_ctx(ctx);
	if (header_ndr == NULL) {
		DBG_ERR("failed to init push ctx\n");
		err = NDR_ERR_ALLOC;
		goto out;
	}
	/* see_ulChecksum MS-WSP 2.2.2 */
	if ((blob->length > MSG_HEADER_SIZE) && (header->msg == CPMCONNECT
	|| header->msg == CPMCREATEQUERY
	|| header->msg == CPMSETBINDINGSIN
	|| header->msg == CPMGETROWS
	|| header->msg == CPMFETCHVALUE)) {

		set_msg_checksum(blob, header);
	} else {
		err = NDR_ERR_SUCCESS;
		goto out;
	}
	/*
	 * alternatively we could just shove in the checksum at the
	 * appropriate offset. Safer though I think to use the standard
	 * routines, also it's probably an advantage to be able to
	 * rewrite out the msg header (in case of late setting of some status)
	 */
	err = ndr_push_wsp_header(header_ndr, ndr_flags, header);
	if (err) {
		DBG_ERR("Failed to push header, error %d\n", err);
		goto out;
	}
	memcpy(blob->data, header_ndr->data, MSG_HEADER_SIZE);
out:
	TALLOC_FREE(ctx);
	return err;
}

static bool status_is_hresult_success(uint32_t error)
{
	/* make sure this isn't a ntstatus */
	if (NT_STATUS_IS_ERR(NT_STATUS(error))) {
		return false;
	}

	/* A HRESULT success value, such as DB_S_ENDOFROWSET,
	 * is one where the thirty-first bit is not set.
	 */
	if ((error & 0x80000000) == 0x80000000) {
		return false;
	}

	return true;

}

/*
 * marshal 'response' into out_blob
 * include contents of extra_out_blob at end of message (some messages
 * have optional content at end of of message not represented in idl)
 */
static bool insert_wsp_response(TALLOC_CTX *ctx, struct wsp_response *response,
				DATA_BLOB *out_blob, DATA_BLOB *extra_out_blob)
{
	int ndr_flags = NDR_SCALARS | NDR_BUFFERS;
	struct ndr_push* push_ndr = NULL;
	enum ndr_err_code err;
	bool header_only = false;
	uint32_t status;
	push_ndr = ndr_push_init_ctx(ctx);

	if (push_ndr == NULL) {
		DBG_ERR("failed to init push ctx\n");
		return false;
	}

	status = response->header.status;

	/*
	 * We don't send a response for CPMDISCONNECT
	 * Errors transported in header.status are either
	 * NTSTATUS or HRESULT values.
	 * A successful response is sent when our status is
	 * 0 or is a HRESULT success value (see MS-2.2.4).
	 */
	if (response->header.msg != CPMDISCONNECT
	   && (status == 0 || status_is_hresult_success(status))) {
		err = ndr_push_wsp_response(push_ndr, ndr_flags,
				    response);
	} else {
		/* if we have an error, reply with header only */
		err = ndr_push_wsp_header(push_ndr, ndr_flags,
					  &response->header);
		header_only = true;
	}

	if (err) {
		DBG_ERR("failed to marshall response\n");
		return false;
	}
	*out_blob = ndr_push_blob(push_ndr);
	if (!header_only && extra_out_blob->length) {
		out_blob->data = talloc_realloc(
				ctx,
				out_blob->data,
				uint8_t,
				out_blob->length + extra_out_blob->length);
		if (out_blob->data == NULL) {
			DBG_ERR("out of memory\n");
			return false;
		}
		memcpy(out_blob->data + out_blob->length,
		       extra_out_blob->data,
		       extra_out_blob->length);
		out_blob->length =  out_blob->length + extra_out_blob->length;
	}
	err = insert_checksum_into_msg_and_hdr(out_blob, &response->header);
	if (err) {
		DBG_ERR("failed to insert checksum\n");
		return false;
	}
	return true;
}

struct wsp_request_state {
	struct wsp_header *wsp_header;
	struct wsp_response *response;
	DATA_BLOB out_blob;
	DATA_BLOB extra_out_blob;
	struct wsp_client_data *client_data;
	TALLOC_CTX *request_ctx;
};

/* msg sequence rules MS-WSP 3.1.5 */

static bool check_msg_sequence(uint32_t msgid,
			       struct wsp_client_data *client_data)
{
	int i;
	struct {
		int msgid;
		int required[4]; /* max prev messages to check is 4 */
	} msg_sequence [] = {
		{CPMSETCATSTATEIN,
			{CPMCONNECT,0}},
		{CPMCONNECT,
			{0}},
		{CPMCREATEQUERY,
			{CPMCONNECT,0}},
		{CPMGETQUERYSTATUS,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMGETQUERYSTATUSEX,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMSETBINDINGSIN,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMGETROWS,
			{CPMCONNECT,CPMCREATEQUERY,CPMSETBINDINGSIN,0}},
		{CPMRATIOFINISHED,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMFETCHVALUE,
			{CPMCONNECT,CPMCREATEQUERY,CPMSETBINDINGSIN,CPMGETROWS}},
		{CPMGETNOTIFY,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMSENDNOTIFYOUT,
			{CPMCONNECT,CPMCREATEQUERY,CPMGETNOTIFY,0}},
		{CPMGETAPPROXIMATEPOSITION,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMCOMPAREBMK,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMRESTARTPOSITIONIN,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMFREECURSOR,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMDISCONNECT,
			{0}},
		{CPMFINDINDICES,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMGETROWSETNOTIFY,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMSETSCOPEPRIORITIZATION,
			{CPMCONNECT,CPMCREATEQUERY,0}},
		{CPMGETSCOPESTATISTICS,
			{CPMCONNECT,CPMCREATEQUERY,0}},
	};
	for (i=0; i<ARRAY_SIZE(msg_sequence); i++) {
		if (msgid == msg_sequence[i].msgid) {
			int y;
			bool ok = true;
			for (y=0; y<ARRAY_SIZE(msg_sequence[i].required); y++){
				uint32_t prev_msgid =
					msg_sequence[i].required[y];
				if (prev_msgid == 0) {
					/* no more to check */
					break;
				}
				if (find_prev_msg_entry(client_data,
							prev_msgid) == NULL) {
					DBG_ERR("required previous msg %s "
						"expected for %s not found\n",
						msgid_to_string(prev_msgid),
						msgid_to_string(msgid));
					ok = false;
					break;
				}
			}
			return ok;
		}
	}
	return true;
}

static void wsp_request_msg_handler_done(struct tevent_req *subreq);

/*
 * Main entry point for message processing handler,
 * in_blob contains the the request, when the message has
 * been processed (asynchronously) out_blob will be filled
 * with response
 */
struct tevent_req *wsp_request_send(TALLOC_CTX *ctx,
				    struct tevent_context *ev,
				    struct wspd_client_state *client,
				    DATA_BLOB *in_blob)
{
	struct wsp_header *wsp_header = NULL;
	struct wsp_response *response = NULL;
	struct tevent_req *req, *subreq = NULL;
	struct wsp_request_state *state = NULL;
	wsp_msg_handler_send_fn wsp_msg_handler_send = NULL;

	req = tevent_req_create(ctx, &state, struct wsp_request_state);
	if (req == NULL) {
		return NULL;
	}

	response = talloc_zero(state, struct wsp_response);
	if (tevent_req_nomem(response, req)) {
		return tevent_req_post(req, ev);
	}

	wsp_header = talloc_zero(state, struct wsp_header);
	if (tevent_req_nomem(wsp_header, req)) {
		return tevent_req_post(req, ev);
	}

	if (!extract_wsp_header(wsp_header, in_blob, wsp_header)) {
		DBG_ERR("error extracting WSP message for %s\n",
			msgid_to_string(wsp_header->msg));
		tevent_req_nterror(req, NT_STATUS_UNHANDLED_EXCEPTION);
		return tevent_req_post(req, ev);
	}

	response->header.msg = wsp_header->msg;

	if (!check_msg_sequence(wsp_header->msg,
				client->client_data)) {
		DBG_ERR("msg sequence rules failed for %s\n",
			msgid_to_string(wsp_header->msg));
		tevent_req_nterror(req, NT_STATUS_UNSUCCESSFUL);
		return tevent_req_post(req, ev);
	}
	state->wsp_header = wsp_header;
	state->response = response;
	state->request_ctx = ctx;
	state->client_data = client->client_data;

	DBG_NOTICE("received %s message from handle %d\n",
		  msgid_to_string(wsp_header->msg),
		  client->client_data->fid);

	wsp_msg_handler_send = get_wsp_msg_handler(wsp_header->msg);
	if (wsp_msg_handler_send == NULL) {
		tevent_req_nterror(req, NT_STATUS_FLT_NO_HANDLER_DEFINED);
		return tevent_req_post(req, ev);
	}

	subreq = wsp_msg_handler_send(req,
				      ev,
				      client,
				      wsp_header,
				      response,
				      in_blob,
				      &state->extra_out_blob,
				      get_impl());
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wsp_request_msg_handler_done, req);
	return req;
}

static void wsp_request_msg_handler_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_request_state *state = tevent_req_data(
		req, struct wsp_request_state);
	struct wsp_client_data *client_data = NULL;
	struct uint32_list *item = NULL;
	uint32_t msgid;
	HRESULT hres;
	bool ok;

	/*
	 * WSP errors can either be NTSTATUS or HRESULT
	 * Generally error conditions can be propagated in 2 ways,
	 * The async processing can succeed but the responses
	 * wsp_header.status field can be contain the error
	 * (this is normally the way that HRESULT errors are set)
	 * or alternatively the async processing can fail with the
	 * appropriate NTSTATUS error which we then propagate to the header.
	 */
	hres = wsp_msg_handler_recv(subreq);

	DBG_DEBUG("Message handler failed 0x%08x\n", HRES_ERROR_V(hres));

	/* Remove any FACILITY_NT_BIT bit */
	hres = HRESULT_TO_NT(hres);
	state->response->header.status = HRES_ERROR_V(hres);

	client_data = state->client_data;
	msgid = state->wsp_header->msg;

	/*
	 * log previous successfully processed msg responses
	 * (if we haven't added msgid already)
	 */
	if (HRES_IS_SUCCESS(hres)) {
		item = find_prev_msg_entry(client_data, msgid);
		if (item == NULL) {
			item = talloc_zero(client_data, struct uint32_list);
			if (item == NULL) {
				DBG_ERR("Out of memory\n");
				tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
				return;
			}
			item->number = msgid;
			DLIST_ADD_END(client_data->prev_msgs, item);
		}
	}

	if (state->wsp_header->msg == CPMDISCONNECT) {
		DBG_INFO("no message payload set for CPMDISCONNECT\n");
		/*
		 * Force error in lower rawpipe layer to trigger
		 * client disconnect.
		 */
		TALLOC_FREE(subreq);
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	ok = insert_wsp_response(state->request_ctx,
				 state->response,
				 &state->out_blob,
				 &state->extra_out_blob);
	TALLOC_FREE(subreq);
	if (!ok) {
		DBG_ERR("error inserting WSP response for msg %s\n",
			msgid_to_string(state->wsp_header->msg));
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS wsp_request_recv(struct tevent_req *req,
			  TALLOC_CTX *ctx,
			  DATA_BLOB *blob)
{
	struct wsp_request_state *state = tevent_req_data(
		req, struct wsp_request_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
        }

	blob->data = talloc_move(ctx, &state->out_blob.data);
	blob->length = state->out_blob.length;

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct auth_session_info *get_session_info(struct wspd_client_state *client_state)
{
	return client_state->client_data->session_info;
}

uint32_t get_handle(struct wspd_client_state *client_state)
{
	return client_state->client_data->fid;
}

static int destroy_wsp_gss_state(struct wsp_gss_state *wsp_gss_state)
{
	TALLOC_FREE(wsp_gss_state->wsp_abstract_state);
	return 0;
}

struct wsp_gss_state *wsp_gss_state_create(struct tevent_context *event_ctx)
{

	struct wsp_gss_state *state = NULL;

	state = talloc_zero(NULL, struct wsp_gss_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}
	DBG_NOTICE("wsp gss_start\n");
	state->connectedclientsidentifiers = talloc_zero(state,
							struct uint32_list);
	if (state->connectedclientsidentifiers == NULL) {
		DBG_ERR("Out of memory\n");
		TALLOC_FREE(state);
		return NULL;
	}
	state->connectedclientversions = talloc_zero(state,
						     struct client_version_map);
	if (state->connectedclientversions == NULL) {
		DBG_ERR("Out of memory\n");
		TALLOC_FREE(state);
		return NULL;
	}
	state->wsp_server_state = NOT_INITIALISED;
	state->ev = event_ctx;
	talloc_set_destructor(state, destroy_wsp_gss_state);
	return state;
}

static int destroy_client_state(struct wspd_client_state *client)
{
	release_client_resources(client);
	return 0;
}

struct wspd_client_state *wsp_gss_client_state_create(
			struct auth_session_info *session_info,
			struct wsp_gss_state *wsp_gss_state)
{
	struct wspd_client_state *state = NULL;
	struct id_cache_map *item = NULL;

	state = talloc_zero(NULL, struct wspd_client_state);
	if (state == NULL) {
		DBG_ERR("Out of memory\n");
		return NULL;
	}

	state->client_data = talloc_zero(state, struct wsp_client_data);
	if (state->client_data == NULL) {
		DBG_ERR("Out of memory\n");
		TALLOC_FREE(state);
		return NULL;
	}
	state->client_data->fid = generate_handle();
	state->client_data->session_info = session_info;
	state->client_data->wsp_gss_state = wsp_gss_state;
	state->wsp_abstract_state = wsp_gss_state->wsp_abstract_state;
	state->sessionid = session_info->unique_session_token;

	item = get_or_create_id_cache(state);
	if (item == NULL) {
		DBG_ERR("Failed to get or create id cache\n");
		TALLOC_FREE(state);
		return NULL;
	}
	item->refcount += 1;
	state->id_cache = item->id_cache;
	talloc_set_destructor(state, destroy_client_state);
	return state;
}

struct wsp_gss_client_disconnected_state {
	struct wspd_client_state *client_state;
};

static void wsp_gss_client_disconnected_done(struct tevent_req *subreq);

static struct tevent_req *wsp_gss_client_disconnected_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct wspd_client_state *client_state)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct wsp_gss_client_disconnected_state *state = NULL;

	DBG_NOTICE("got disconnect for handle %u\n",
		 client_state->client_data->fid);

	req = tevent_req_create(client_state->client_data->wsp_gss_state,
				&state,
				struct wsp_gss_client_disconnected_state);
	if (req == NULL) {
		DBG_ERR("out of memory\n");
		return NULL;
	}
	state->client_state = client_state;
	subreq = get_impl()->releasequery_send(state,
					       ev,
					       client_state,
					       client_state->client_data->fid);
	if (tevent_req_nomem(subreq, req)) {
		DBG_ERR("failed to create subrequest to release query "
			 "for handle %u\n", client_state->client_data->fid);
		TALLOC_FREE(state->client_state);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				wsp_gss_client_disconnected_done,
				req);
	return req;
}

static void wsp_gss_client_disconnected_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wsp_gss_client_disconnected_state *state = tevent_req_data(
		req, struct wsp_gss_client_disconnected_state);
	HRESULT hres;
	struct id_cache_map *idmap_item = NULL;

	hres = get_impl()->releasequery_recv(subreq);
	if (!HRES_IS_OK(hres)) {
		DBG_ERR("Failed to release query: %s\n", hresult_errstr(hres));
	}

	idmap_item = get_or_create_id_cache(state->client_state);
	if (idmap_item != NULL) {
		struct wspd_client_state *client = state->client_state;
		struct wsp_gss_state *wsp_gss_state = client->client_data->wsp_gss_state;

		idmap_item->refcount -= 1;
		if (idmap_item->refcount == 0) {
			DLIST_REMOVE(wsp_gss_state->id_cache_map,
				     idmap_item);
			TALLOC_FREE(idmap_item->id_cache);
			TALLOC_FREE(idmap_item);
		}
	}
	TALLOC_FREE(state->client_state);
	TALLOC_FREE(subreq);
	TALLOC_FREE(req);
}

static NTSTATUS wsp_gss_client_disconnected_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static void wsp_gss_client_state_destroy_done(struct tevent_req *subreq);

void wsp_gss_client_state_destroy(struct wspd_client_state *client_state,
				  struct tevent_context *ev)
{
	struct tevent_req *subreq = NULL;

	subreq = wsp_gss_client_disconnected_send(client_state,
						  ev,
						  client_state);
	if (subreq == NULL) {
		DBG_ERR("wsp_gss_client_disconnected_send() failed\n");
		TALLOC_FREE(client_state);
		return;
	}
	tevent_req_set_callback(
		subreq,
		wsp_gss_client_state_destroy_done,
		client_state);
}

static void wsp_gss_client_state_destroy_done(struct tevent_req *subreq)
{
	struct wspd_client_state *client_state = tevent_req_callback_data(
		subreq, struct wspd_client_state);
	NTSTATUS status;

	status = wsp_gss_client_disconnected_recv(subreq);
	TALLOC_FREE(subreq);
	TALLOC_FREE(client_state);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("wsp_gss_client_disconnected_recv() failed: %s\n",
			nt_errstr(status));
		return;
	}
	return;
}
