/*
   Unix SMB/CIFS implementation.

   Winbind client library.

   Copyright (C) 2008 Kai Blin  <kai@samba.org>

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
#include <tevent.h>
#include "nsswitch/winbind_client.h"
#include "libcli/wbclient/wbclient.h"
#include "libcli/security/dom_sid.h"
#include "nsswitch/libwbclient/wbclient.h"

NTSTATUS wbc_sids_to_xids(struct id_map *ids, uint32_t count)
{
	TALLOC_CTX *mem_ctx;
	uint32_t i;
	struct wbcDomainSid *sids;
	struct wbcUnixId *xids;
	wbcErr result;
	bool wb_off;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_array(mem_ctx, struct wbcDomainSid, count);
	if (sids == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	xids = talloc_array(mem_ctx, struct wbcUnixId, count);
	if (xids == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<count; i++) {
		memcpy(&sids[i], ids[i].sid, sizeof(struct dom_sid));
	}

	wb_off = winbind_env_set();
	if (wb_off) {
		(void)winbind_on();
	}

	result = wbcSidsToUnixIds(sids, count, xids);

	if (wb_off) {
		(void)winbind_off();
	}

	if (!WBC_ERROR_IS_OK(result)) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; i<count; i++) {
		struct wbcUnixId *xid = &xids[i];
		struct unixid *id = &ids[i].xid;

		switch (xid->type) {
		    case WBC_ID_TYPE_UID:
			id->type = ID_TYPE_UID;
			id->id = xid->id.uid;
			break;
		    case WBC_ID_TYPE_GID:
			id->type = ID_TYPE_GID;
			id->id = xid->id.gid;
			break;
		    case WBC_ID_TYPE_BOTH:
			id->type = ID_TYPE_BOTH;
			id->id = xid->id.uid;
			break;
		    case WBC_ID_TYPE_NOT_SPECIFIED:
			id->type = ID_TYPE_NOT_SPECIFIED;
			id->id = UINT32_MAX;
			break;
		}
		ids[i].status = ID_MAPPED;
	}

	TALLOC_FREE(mem_ctx);

	return NT_STATUS_OK;
}

NTSTATUS wbc_xids_to_sids(struct id_map *ids, uint32_t count)
{
	TALLOC_CTX *mem_ctx;
	uint32_t i;
	struct wbcDomainSid *sids;
	struct wbcUnixId *xids;
	wbcErr result;
	bool wb_off;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sids = talloc_array(mem_ctx, struct wbcDomainSid, count);
	if (sids == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	xids = talloc_array(mem_ctx, struct wbcUnixId, count);
	if (xids == NULL) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<count; i++) {
		struct id_map *id = &ids[i];
		struct wbcUnixId *xid = &xids[i];

		switch (id->xid.type) {
		    case ID_TYPE_UID:
			    *xid = (struct wbcUnixId) {
				    .type = WBC_ID_TYPE_UID,
				    .id.uid = id->xid.id
			    };
			    break;
		    case ID_TYPE_GID:
			    *xid = (struct wbcUnixId) {
				    .type = WBC_ID_TYPE_GID,
				    .id.uid = id->xid.id
			    };
			    break;
		    default:
			    TALLOC_FREE(mem_ctx);
			    return NT_STATUS_NOT_FOUND;
		}
	}

	wb_off = winbind_env_set();
	if (wb_off) {
		(void)winbind_on();
	}

	result = wbcUnixIdsToSids(xids, count, sids);

	if (wb_off) {
		(void)winbind_off();
	}

	if (!WBC_ERROR_IS_OK(result)) {
		TALLOC_FREE(mem_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	for (i=0; i<count; i++) {
		struct wbcDomainSid *sid = &sids[i];
		struct wbcDomainSid null_sid = { 0 };
		struct id_map *id = &ids[i];

		if (memcmp(sid, &null_sid, sizeof(*sid)) != 0) {
			struct dom_sid domsid;
			id->status = ID_MAPPED;

			memcpy(&domsid, sid, sizeof(struct dom_sid));
			id->sid = dom_sid_dup(ids, &domsid);
			if (id->sid == NULL) {
				TALLOC_FREE(mem_ctx);
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			id->status = ID_UNMAPPED;
			id->sid = NULL;
		}
	}

	TALLOC_FREE(mem_ctx);
	return NT_STATUS_OK;
}
