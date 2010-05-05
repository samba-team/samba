/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) 2009,2010 Kai Blin  <kai@samba.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */

#include "replace.h"
#include "libwbclient.h"
#include "../winbind_client.h"
#include "wbc_async.h"

struct wbc_lookup_name_state {
	struct winbindd_request req;
	struct wb_context *wb_ctx;
	struct wbcDomainSid *sid;
	enum wbcSidType name_type;
};

static void wbcLookupName_done(struct tevent_req *subreq);

/**
 * @brief Request a conversion of a domain and name to a domain sid
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		tevent context to use for async operation
 * @param wb_ctx	winbind context to use
 * @param *domain	Pointer to the domain to be resolved
 * @param *name		Pointer to the name to be resolved
 *
 * @return tevent_req on success, NULL on error
 **/

struct tevent_req *wbcLookupName_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct wb_context *wb_ctx,
				      const char *domain,
				      const char *name)
{
	struct tevent_req *req, *subreq;
	struct wbc_lookup_name_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_lookup_name_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_LOOKUPNAME;
	strncpy(state->req.data.name.dom_name, domain,
		sizeof(state->req.data.name.dom_name)-1);
	strncpy(state->req.data.name.name, name,
		sizeof(state->req.data.name.name)-1);
	state->wb_ctx = wb_ctx;


	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcLookupName_done, req);
	return req;
}

static void wbcLookupName_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_lookup_name_state *state = tevent_req_data(
			req, struct wbc_lookup_name_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	state->sid = talloc(state, struct wbcDomainSid);
	if (tevent_req_nomem(state->sid, req)) {
		return;
	}

	wbc_status = wbcStringToSid(resp->data.sid.sid, state->sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		wbcDebug(state->wb_ctx, WBC_DEBUG_ERROR,
			 "wbcStringToSid returned %s!\n",
			 wbcErrorString(wbc_status));
		tevent_req_error(req, wbc_status);
		return;
	}

	state->name_type = (enum wbcSidType)resp->data.sid.type;

	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive a conversion of a domain and name to a domain SID.
 *
 * @param req The tevent request calling this function.
 *
 * @param sid A pointer to store the sid looked up.
 *
 * @param name_type Pointer to store the resolved SID name type.
 *
 * @return #wbcErr
 */
wbcErr wbcLookupName_recv(struct tevent_req *req,
			  struct wbcDomainSid *sid,
			  enum wbcSidType *name_type)
{
	struct wbc_lookup_name_state *state = tevent_req_data(
			req, struct wbc_lookup_name_state);
	wbcErr wbc_status = WBC_ERR_SUCCESS;

	if (!sid || !name_type) {
		wbcDebug(state->wb_ctx, WBC_DEBUG_TRACE,
		"Sid is %p, name_type is %p\n", sid, name_type);
		wbc_status = WBC_ERR_INVALID_PARAM;
		goto failed;
	}

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		goto failed;
	}

	memcpy(sid, state->sid, sizeof(struct wbcDomainSid));
	*name_type = state->name_type;

failed:
	tevent_req_received(req);
	return wbc_status;
}


struct wbc_lookup_sid_state {
	struct winbindd_request req;
	char *domain;
	char *name;
	enum wbcSidType name_type;
};

static void wbcLookupSid_done(struct tevent_req *subreq);

/**
 * @brief Request a conversion of a SID to a domain and name
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		tevent context to use for async operation
 * @param wb_ctx	winbind context to use
 * @param *sid		Pointer to the domain SID to be resolved
 *
 * @return tevent_req on success, NULL on error
 **/

struct tevent_req *wbcLookupSid_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct wb_context *wb_ctx,
				     const struct wbcDomainSid *sid)
{
	struct tevent_req *req, *subreq;
	struct wbc_lookup_sid_state *state;
	char *sid_string;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	req = tevent_req_create(mem_ctx, &state, struct wbc_lookup_sid_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_LOOKUPSID;
	wbc_status = wbcSidToString(sid, &sid_string);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return tevent_req_post(req, ev);
	}
	strncpy(state->req.data.sid, sid_string, sizeof(state->req.data.sid)-1);
	wbcFreeMemory(sid_string);

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcLookupSid_done, req);
	return req;
}

static void wbcLookupSid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_lookup_sid_state *state = tevent_req_data(
			req, struct wbc_lookup_sid_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->domain = talloc_strdup(state, resp->data.name.dom_name);
	if (tevent_req_nomem(state->domain, req)) {
		return;
	}

	state->name   = talloc_strdup(state, resp->data.name.name);
	if (tevent_req_nomem(state->name, req)) {
		return;
	}

	state->name_type = (enum wbcSidType)resp->data.name.type;

	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive a conversion a SID to a domain and name
 *
 * @param req          The tevent request calling this function.
 *
 * @param mem_ctx      A talloc context to move results to.
 *
 * @param pdomain      A pointer to store the resolved domain name
 *                      (possibly "").
 *
 * @param pname        A pointer to store the resolved user or group name.
 *
 * @param pname_type   A pointer to store the resolved SID type.
 *
 * @return #wbcErr
 */
wbcErr wbcLookupSid_recv(struct tevent_req *req,
			 TALLOC_CTX *mem_ctx,
			 char **pdomain,
			 char **pname,
			 enum wbcSidType *pname_type)
{
	struct wbc_lookup_sid_state *state = tevent_req_data(
			req, struct wbc_lookup_sid_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	if (pdomain != NULL) {
		*pdomain = talloc_steal(mem_ctx, state->domain);
	}

	if (pname != NULL) {
		*pname   = talloc_steal(mem_ctx, state->name);
	}

	if (pname_type != NULL) {
		*pname_type = state->name_type;
	}

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}
