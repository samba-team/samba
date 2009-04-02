/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007
   Copyright (C) Kai Blin 2009


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

struct wbc_sid_to_uid_state {
	struct winbindd_request req;
	uid_t uid;
};

static void wbcSidToUid_done(struct tevent_req *subreq);

/**
 * @brief Convert a Windows SID to a Unix uid, allocating an uid if needed
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		tevent context to use for async operation
 * @param wb_ctx	winbind context to use
 * @param *sid		pointer to the domain SID to be resolved
 *
 * @return tevent_req on success, NULL on error
 */

struct tevent_req *wbcSidToUid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct wb_context *wb_ctx,
				    const struct wbcDomainSid *sid)
{
	struct tevent_req *req, *subreq;
	struct wbc_sid_to_uid_state *state;
	char *sid_string;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	req = tevent_req_create(mem_ctx, &state, struct wbc_sid_to_uid_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_SID_TO_UID;
	wbc_status = wbcSidToString(sid, &sid_string);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		return tevent_req_post(req, ev);
	}
	strncpy(state->req.data.sid, sid_string, sizeof(state->req.data.sid)-1);
	wbcFreeMemory(sid_string);

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcSidToUid_done, req);
	return req;
}

static void wbcSidToUid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_sid_to_uid_state *state = tevent_req_data(
			req, struct wbc_sid_to_uid_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->uid = resp->data.uid;
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive a Unix uid mapped to a Windows SID
 *
 * @param req		tevent_req containing the request
 * @param *puid		pointer to hold the resolved uid_t value
 *
 * @return #wbcErr
 */

wbcErr wbcSidToUid_recv(struct tevent_req *req, uid_t *puid)
{
	struct wbc_sid_to_uid_state *state = tevent_req_data(
			req, struct wbc_sid_to_uid_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*puid = state->uid;

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

/* Convert a Windows SID to a Unix uid, allocating an uid if needed */
wbcErr wbcSidToUid(const struct wbcDomainSid *sid, uid_t *puid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	char *sid_string = NULL;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!sid || !puid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.sid, sid_string, sizeof(request.data.sid)-1);
	wbcFreeMemory(sid_string);

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_SID_TO_UID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*puid = response.data.uid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/* Convert a Windows SID to a Unix uid if there already is a mapping */
wbcErr wbcQuerySidToUid(const struct wbcDomainSid *sid,
			uid_t *puid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

struct wbc_uid_to_sid_state {
	struct winbindd_request req;
	struct wbcDomainSid *sid;
};

static void wbcUidToSid_done(struct tevent_req *subreq);

/**
 * @brief Request a Windows SID for an Unix uid, allocating an SID if needed
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		tevent context to use for async operation
 * @param wb_ctx	winbind context to use
 * @param uid		uid to be resolved to a SID
 *
 * @return tevent_req on success, NULL on error
 */

struct tevent_req *wbcUidToSid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct wb_context *wb_ctx,
				    uid_t uid)
{
	struct tevent_req *req, *subreq;
	struct wbc_uid_to_sid_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wbc_uid_to_sid_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_UID_TO_SID;
	state->req.data.uid = uid;

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcUidToSid_done, req);
	return req;
}

static void wbcUidToSid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_uid_to_sid_state *state = tevent_req_data(
			req, struct wbc_uid_to_sid_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	state->sid = talloc(state, struct wbcDomainSid);
	if (state->sid == NULL) {
		TALLOC_FREE(resp);
		tevent_req_error(req, WBC_ERR_NO_MEMORY);
		return;
	}

	wbc_status = wbcStringToSid(resp->data.sid.sid, state->sid);
	TALLOC_FREE(resp);

	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}

	tevent_req_done(req);
}

/**
 * @brief Receive a Unix uid mapped to a Windows SID
 *
 * @param req		tevent_req containing the request
 * @param *psid		pointer to hold the resolved SID
 *
 * @return #wbcErr
 */

wbcErr wbcUidToSid_recv(struct tevent_req *req, struct wbcDomainSid *psid)
{
	struct wbc_uid_to_sid_state *state = tevent_req_data(
			req, struct wbc_uid_to_sid_state);
	wbcErr wbc_status;

	if (psid == NULL) {
		tevent_req_received(req);
		return WBC_ERR_INVALID_PARAM;
	}

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	memcpy(psid, state->sid, sizeof(struct wbcDomainSid));

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

/* Convert a Unix uid to a Windows SID, allocating a SID if needed */
wbcErr wbcUidToSid(uid_t uid, struct wbcDomainSid *sid)
{
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	struct winbindd_request request;
	struct winbindd_response response;

	if (!sid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.uid = uid;

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_UID_TO_SID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	wbc_status = wbcStringToSid(response.data.sid.sid, sid);
	BAIL_ON_WBC_ERROR(wbc_status);

done:
	return wbc_status;
}

/* Convert a Unix uid to a Windows SID if there already is a mapping */
wbcErr wbcQueryUidToSid(uid_t uid,
			struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

struct wbc_sid_to_gid_state {
	struct winbindd_request req;
	gid_t gid;
};

static void wbcSidToGid_done(struct tevent_req *subreq);

/**
 * @brief Request to convert a Windows SID to a Unix gid,
 * allocating a gid if needed
 *
 * @param mem_ctx	talloc context to allocate the request from
 * @param ev		tevent context to use for async operation
 * @param wb_ctx	winbind context to use
 * @param *sid		pointer to the domain SID to be resolved
 *
 * @return tevent_req on success, NULL on error
 */

struct tevent_req *wbcSidToGid_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct wb_context *wb_ctx,
				    const struct wbcDomainSid *sid)
{
	struct tevent_req *req, *subreq;
	struct wbc_sid_to_gid_state *state;
	char *sid_string;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	req = tevent_req_create(mem_ctx, &state, struct wbc_sid_to_gid_state);
	if (req == NULL) {
		return NULL;
	}

	ZERO_STRUCT(state->req);

	state->req.cmd = WINBINDD_SID_TO_GID;
	wbc_status = wbcSidToString(sid, &sid_string);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		return tevent_req_post(req, ev);
	}
	strncpy(state->req.data.sid, sid_string, sizeof(state->req.data.sid)-1);
	wbcFreeMemory(sid_string);

	subreq = wb_trans_send(state, ev, wb_ctx, false, &state->req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, wbcSidToGid_done, req);
	return req;
}

static void wbcSidToGid_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
			subreq, struct tevent_req);
	struct wbc_sid_to_gid_state *state = tevent_req_data(
			req, struct wbc_sid_to_gid_state);
	struct winbindd_response *resp;
	wbcErr wbc_status;

	wbc_status = wb_trans_recv(subreq, state, &resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		tevent_req_error(req, wbc_status);
		return;
	}
	state->gid = resp->data.gid;
	TALLOC_FREE(resp);

	tevent_req_done(req);
}

/**
 * @brief Receive a Unix gid mapped to a Windows SID
 *
 * @param req		tevent_req containing the request
 * @param *pgid		pointer to hold the resolved gid_t value
 *
 * @return #wbcErr
 */

wbcErr wbcSidToGid_recv(struct tevent_req *req, gid_t *pgid)
{
	struct wbc_sid_to_gid_state *state = tevent_req_data(
			req, struct wbc_sid_to_gid_state);
	wbcErr wbc_status;

	if (tevent_req_is_wbcerr(req, &wbc_status)) {
		tevent_req_received(req);
		return wbc_status;
	}

	*pgid = state->gid;

	tevent_req_received(req);
	return WBC_ERR_SUCCESS;
}

/** @brief Convert a Windows SID to a Unix gid, allocating a gid if needed
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/

wbcErr wbcSidToGid(const struct wbcDomainSid *sid, gid_t *pgid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid || !pgid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.sid, sid_string, sizeof(request.data.sid)-1);
	wbcFreeMemory(sid_string);

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_SID_TO_GID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	*pgid = response.data.gid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}


/* Convert a Windows SID to a Unix gid if there already is a mapping */

wbcErr wbcQuerySidToGid(const struct wbcDomainSid *sid,
			gid_t *pgid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Convert a Unix gid to a Windows SID, allocating a SID if needed */
wbcErr wbcGidToSid(gid_t gid, struct wbcDomainSid *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!sid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	/* Initialize request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.data.gid = gid;

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_GID_TO_SID,
					&request,
					&response);
	BAIL_ON_WBC_ERROR(wbc_status);

	wbc_status = wbcStringToSid(response.data.sid.sid, sid);
	BAIL_ON_WBC_ERROR(wbc_status);

done:
	return wbc_status;
}

/* Convert a Unix gid to a Windows SID if there already is a mapping */
wbcErr wbcQueryGidToSid(gid_t gid,
			struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Obtain a new uid from Winbind */
wbcErr wbcAllocateUid(uid_t *puid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!puid)
		return WBC_ERR_INVALID_PARAM;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_ALLOCATE_UID,
					   &request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Copy out result */
	*puid = response.data.uid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/* Obtain a new gid from Winbind */
wbcErr wbcAllocateGid(gid_t *pgid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	if (!pgid)
		return WBC_ERR_INVALID_PARAM;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	wbc_status = wbcRequestResponse(WINBINDD_ALLOCATE_GID,
					   &request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Copy out result */
	*pgid = response.data.gid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

/* we can't include smb.h here... */
#define _ID_TYPE_UID 1
#define _ID_TYPE_GID 2

/* Set an user id mapping */
wbcErr wbcSetUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid) {
		return WBC_ERR_INVALID_PARAM;
	}

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = uid;
	request.data.dual_idmapset.type = _ID_TYPE_UID;

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.dual_idmapset.sid, sid_string,
		sizeof(request.data.dual_idmapset.sid)-1);
	wbcFreeMemory(sid_string);

	wbc_status = wbcRequestResponse(WINBINDD_SET_MAPPING,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/* Set a group id mapping */
wbcErr wbcSetGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid) {
		return WBC_ERR_INVALID_PARAM;
	}

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = gid;
	request.data.dual_idmapset.type = _ID_TYPE_GID;

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.dual_idmapset.sid, sid_string,
		sizeof(request.data.dual_idmapset.sid)-1);
	wbcFreeMemory(sid_string);

	wbc_status = wbcRequestResponse(WINBINDD_SET_MAPPING,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/* Remove a user id mapping */
wbcErr wbcRemoveUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid) {
		return WBC_ERR_INVALID_PARAM;
	}

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = uid;
	request.data.dual_idmapset.type = _ID_TYPE_UID;

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.dual_idmapset.sid, sid_string,
		sizeof(request.data.dual_idmapset.sid)-1);
	wbcFreeMemory(sid_string);

	wbc_status = wbcRequestResponse(WINBINDD_REMOVE_MAPPING,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/* Remove a group id mapping */
wbcErr wbcRemoveGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	char *sid_string = NULL;

	if (!sid) {
		return WBC_ERR_INVALID_PARAM;
	}

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = gid;
	request.data.dual_idmapset.type = _ID_TYPE_GID;

	wbc_status = wbcSidToString(sid, &sid_string);
	BAIL_ON_WBC_ERROR(wbc_status);

	strncpy(request.data.dual_idmapset.sid, sid_string,
		sizeof(request.data.dual_idmapset.sid)-1);
	wbcFreeMemory(sid_string);

	wbc_status = wbcRequestResponse(WINBINDD_REMOVE_MAPPING,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/* Set the highwater mark for allocated uids. */
wbcErr wbcSetUidHwm(uid_t uid_hwm)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = uid_hwm;
	request.data.dual_idmapset.type = _ID_TYPE_UID;

	wbc_status = wbcRequestResponse(WINBINDD_SET_HWM,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}

/* Set the highwater mark for allocated gids. */
wbcErr wbcSetGidHwm(gid_t gid_hwm)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

	/* Initialise request */

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	/* Make request */

	request.data.dual_idmapset.id = gid_hwm;
	request.data.dual_idmapset.type = _ID_TYPE_GID;

	wbc_status = wbcRequestResponse(WINBINDD_SET_HWM,
					&request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

 done:
	return wbc_status;
}
