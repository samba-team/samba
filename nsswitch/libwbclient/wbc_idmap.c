/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

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
#include "lib/util/util.h"

/* Convert a Windows SID to a Unix uid, allocating an uid if needed */
wbcErr wbcCtxSidToUid(struct wbcContext *ctx, const struct wbcDomainSid *sid,
		      uid_t *puid)
{
	struct wbcUnixId xid;
	wbcErr wbc_status;

	if (!sid || !puid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = wbcCtxSidsToUnixIds(ctx, sid, 1, &xid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	if ((xid.type == WBC_ID_TYPE_UID) || (xid.type == WBC_ID_TYPE_BOTH)) {
		*puid = xid.id.uid;
		wbc_status = WBC_ERR_SUCCESS;
	} else {
		wbc_status = WBC_ERR_DOMAIN_NOT_FOUND;
	}

 done:
	return wbc_status;
}

wbcErr wbcSidToUid(const struct wbcDomainSid *sid, uid_t *puid)
{
	return wbcCtxSidToUid(NULL, sid, puid);
}

/* Convert a Windows SID to a Unix uid if there already is a mapping */
wbcErr wbcQuerySidToUid(const struct wbcDomainSid *sid,
			uid_t *puid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Convert a Unix uid to a Windows SID, allocating a SID if needed */
wbcErr wbcCtxUidToSid(struct wbcContext *ctx, uid_t uid,
		      struct wbcDomainSid *psid)
{
	struct wbcUnixId xid;
	struct wbcDomainSid sid;
	struct wbcDomainSid null_sid = { 0 };
	wbcErr wbc_status;

	if (!psid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	xid = (struct wbcUnixId) { .type = WBC_ID_TYPE_UID, .id.uid = uid };

	wbc_status = wbcCtxUnixIdsToSids(ctx, &xid, 1, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	if (memcmp(&sid, &null_sid, sizeof(sid)) != 0) {
		*psid = sid;
	} else {
		wbc_status = WBC_ERR_DOMAIN_NOT_FOUND;
	}

done:
	return wbc_status;
}

wbcErr wbcUidToSid(uid_t uid, struct wbcDomainSid *sid)
{
	return wbcCtxUidToSid(NULL, uid, sid);
}

/* Convert a Unix uid to a Windows SID if there already is a mapping */
wbcErr wbcQueryUidToSid(uid_t uid,
			struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/** @brief Convert a Windows SID to a Unix gid, allocating a gid if needed
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/

wbcErr wbcCtxSidToGid(struct wbcContext *ctx, const struct wbcDomainSid *sid,
		      gid_t *pgid)
{
	struct wbcUnixId xid;
	wbcErr wbc_status;

	if (!sid || !pgid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	wbc_status = wbcCtxSidsToUnixIds(ctx, sid, 1, &xid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	if ((xid.type == WBC_ID_TYPE_GID) || (xid.type == WBC_ID_TYPE_BOTH)) {
		*pgid = xid.id.gid;
		wbc_status = WBC_ERR_SUCCESS;
	} else {
		wbc_status = WBC_ERR_DOMAIN_NOT_FOUND;
	}

 done:
	return wbc_status;
}

wbcErr wbcSidToGid(const struct wbcDomainSid *sid, gid_t *pgid)
{
	return wbcCtxSidToGid(NULL, sid, pgid);
}

/* Convert a Windows SID to a Unix gid if there already is a mapping */

wbcErr wbcQuerySidToGid(const struct wbcDomainSid *sid,
			gid_t *pgid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}


/* Convert a Unix gid to a Windows SID, allocating a SID if needed */
wbcErr wbcCtxGidToSid(struct wbcContext *ctx, gid_t gid,
		      struct wbcDomainSid *psid)
{
	struct wbcUnixId xid;
	struct wbcDomainSid sid;
	struct wbcDomainSid null_sid = { 0 };
	wbcErr wbc_status;

	if (!psid) {
		wbc_status = WBC_ERR_INVALID_PARAM;
		BAIL_ON_WBC_ERROR(wbc_status);
	}

	xid = (struct wbcUnixId) { .type = WBC_ID_TYPE_GID, .id.gid = gid };

	wbc_status = wbcCtxUnixIdsToSids(ctx, &xid, 1, &sid);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		goto done;
	}

	if (memcmp(&sid, &null_sid, sizeof(sid)) != 0) {
		*psid = sid;
	} else {
		wbc_status = WBC_ERR_DOMAIN_NOT_FOUND;
	}

done:
	return wbc_status;
}

wbcErr wbcGidToSid(gid_t gid, struct wbcDomainSid *sid)
{
	return wbcCtxGidToSid(NULL, gid, sid);
}

/* Convert a Unix gid to a Windows SID if there already is a mapping */
wbcErr wbcQueryGidToSid(gid_t gid,
			struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Obtain a new uid from Winbind */
wbcErr wbcCtxAllocateUid(struct wbcContext *ctx, uid_t *puid)
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

	wbc_status = wbcRequestResponsePriv(ctx, WINBINDD_ALLOCATE_UID,
					    &request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Copy out result */
	*puid = response.data.uid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

wbcErr wbcAllocateUid(uid_t *puid)
{
	return wbcCtxAllocateUid(NULL, puid);
}

/* Obtain a new gid from Winbind */
wbcErr wbcCtxAllocateGid(struct wbcContext *ctx, gid_t *pgid)
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

	wbc_status = wbcRequestResponsePriv(ctx, WINBINDD_ALLOCATE_GID,
					    &request, &response);
	BAIL_ON_WBC_ERROR(wbc_status);

	/* Copy out result */
	*pgid = response.data.gid;

	wbc_status = WBC_ERR_SUCCESS;

 done:
	return wbc_status;
}

wbcErr wbcAllocateGid(gid_t *pgid)
{
	return wbcCtxAllocateGid(NULL, pgid);
}

/* we can't include smb.h here... */
#define _ID_TYPE_UID 1
#define _ID_TYPE_GID 2

/* Set an user id mapping - not implemented any more */
wbcErr wbcSetUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set a group id mapping - not implemented any more */
wbcErr wbcSetGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Remove a user id mapping - not implemented any more */
wbcErr wbcRemoveUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Remove a group id mapping - not implemented any more */
wbcErr wbcRemoveGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set the highwater mark for allocated uids - not implemented any more */
wbcErr wbcSetUidHwm(uid_t uid_hwm)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set the highwater mark for allocated gids - not implemented any more */
wbcErr wbcSetGidHwm(gid_t gid_hwm)
{
	return WBC_ERR_NOT_IMPLEMENTED;
}

/* Convert a list of SIDs */
wbcErr wbcCtxSidsToUnixIds(struct wbcContext *ctx,
			   const struct wbcDomainSid *sids,
			   uint32_t num_sids, struct wbcUnixId *ids)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;
	int buflen, extra_len;
	uint32_t i;
	char *sidlist, *p, *extra_data;

	buflen = num_sids * (WBC_SID_STRING_BUFLEN + 1) + 1;

	sidlist = (char *)malloc(buflen);
	if (sidlist == NULL) {
		return WBC_ERR_NO_MEMORY;
	}

	p = sidlist;

	for (i=0; i<num_sids; i++) {
		int remaining;
		int len;

		remaining = buflen - (p - sidlist);

		len = wbcSidToStringBuf(&sids[i], p, remaining);
		if (len > remaining) {
			free(sidlist);
			return WBC_ERR_UNKNOWN_FAILURE;
		}

		p += len;
		*p++ = '\n';
	}
	*p++ = '\0';

	ZERO_STRUCT(request);
	ZERO_STRUCT(response);

	request.extra_data.data = sidlist;
	request.extra_len = p - sidlist;

	wbc_status = wbcRequestResponse(ctx, WINBINDD_SIDS_TO_XIDS,
					&request, &response);
	free(sidlist);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		return wbc_status;
	}

	extra_len = response.length - sizeof(struct winbindd_response);
	extra_data = (char *)response.extra_data.data;

	if ((extra_len <= 0) || (extra_data[extra_len-1] != '\0')) {
		goto wbc_err_invalid;
	}

	p = extra_data;

	for (i=0; i<num_sids; i++) {
		struct wbcUnixId *id = &ids[i];
		char *q;
		int error = 0;

		switch (p[0]) {
		case 'U':
			id->type = WBC_ID_TYPE_UID;
			id->id.uid = smb_strtoul(p+1,
						 &q,
						 10,
						 &error,
						 SMB_STR_STANDARD);
			break;
		case 'G':
			id->type = WBC_ID_TYPE_GID;
			id->id.gid = smb_strtoul(p+1,
						 &q,
						 10,
						 &error,
						 SMB_STR_STANDARD);
			break;
		case 'B':
			id->type = WBC_ID_TYPE_BOTH;
			id->id.uid = smb_strtoul(p+1,
						 &q,
						 10,
						 &error,
						 SMB_STR_STANDARD);
			break;
		default:
			id->type = WBC_ID_TYPE_NOT_SPECIFIED;
			q = strchr(p, '\n');
			break;
		};
		if (q == NULL || q[0] != '\n' || error != 0) {
			goto wbc_err_invalid;
		}
		p = q+1;
	}
	wbc_status = WBC_ERR_SUCCESS;
	goto done;

wbc_err_invalid:
	wbc_status = WBC_ERR_INVALID_RESPONSE;
done:
	winbindd_free_response(&response);
	return wbc_status;
}

wbcErr wbcSidsToUnixIds(const struct wbcDomainSid *sids, uint32_t num_sids,
			struct wbcUnixId *ids)
{
	return wbcCtxSidsToUnixIds(NULL, sids, num_sids, ids);
}

wbcErr wbcCtxUnixIdsToSids(struct wbcContext *ctx,
			   const struct wbcUnixId *ids, uint32_t num_ids,
			   struct wbcDomainSid *sids)
{
	struct winbindd_request request;
	struct winbindd_response response;
	wbcErr wbc_status;
	char *buf;
	char *s;
	const size_t sidlen = (1 /* U/G */ + 10 /* 2^32 */ + 1 /* \n */);
	size_t ofs, buflen;
	uint32_t i;

	if (num_ids > SIZE_MAX / sidlen) {
		return WBC_ERR_NO_MEMORY; /* overflow */
	}
	buflen = num_ids * sidlen;

	buflen += 1;		/* trailing \0 */
	if (buflen < 1) {
		return WBC_ERR_NO_MEMORY; /* overflow */
	}

	buf = malloc(buflen);
	if (buf == NULL) {
		return WBC_ERR_NO_MEMORY;
	}

	ofs = 0;

	for (i=0; i<num_ids; i++) {
		const struct wbcUnixId *id = &ids[i];
		int len;

		switch (id->type) {
		case WBC_ID_TYPE_UID:
			len = snprintf(buf+ofs, buflen-ofs, "U%"PRIu32"\n",
				       (uint32_t)id->id.uid);
			break;
		case WBC_ID_TYPE_GID:
			len = snprintf(buf+ofs, buflen-ofs, "G%"PRIu32"\n",
				       (uint32_t)id->id.gid);
			break;
		default:
			free(buf);
			return WBC_ERR_INVALID_PARAM;
		}

		if (len + ofs >= buflen) { /* >= for the terminating '\0' */
			free(buf);
			return WBC_ERR_UNKNOWN_FAILURE;
		}
		ofs += len;
	}

	request = (struct winbindd_request) {
		.extra_data.data = buf, .extra_len = ofs+1
	};
	response = (struct winbindd_response) {0};

	wbc_status = wbcRequestResponse(ctx, WINBINDD_XIDS_TO_SIDS,
					&request, &response);
	free(buf);
	if (!WBC_ERROR_IS_OK(wbc_status)) {
		return wbc_status;
	}

	s = response.extra_data.data;
	for (i=0; i<num_ids; i++) {
		char *n = strchr(s, '\n');

		if (n == NULL) {
			goto fail;
		}
		*n = '\0';

		wbc_status = wbcStringToSid(s, &sids[i]);
		if (!WBC_ERROR_IS_OK(wbc_status)) {
			sids[i] = (struct wbcDomainSid) {0};
		}
		s = n+1;
	}

	wbc_status = WBC_ERR_SUCCESS;
fail:
	winbindd_free_response(&response);
	return wbc_status;
}

wbcErr wbcUnixIdsToSids(const struct wbcUnixId *ids, uint32_t num_ids,
			struct wbcDomainSid *sids)
{
	return wbcCtxUnixIdsToSids(NULL, ids, num_ids, sids);
}
