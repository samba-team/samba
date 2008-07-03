/*
   Unix SMB/CIFS implementation.
   ID Mapping Cache

   Copyright (C) Volker Lendecke	2008
   Copyright (C) Simo Sorce		2006
   Copyright (C) Rafal Szczesniak	2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.*/

#include "includes.h"
#include "winbindd.h"

static char *idmap_cache_sidkey(TALLOC_CTX *ctx, const DOM_SID *sid)
{
	fstring sidstr;

	return talloc_asprintf(ctx, "IDMAP/SID/%s",
			       sid_to_fstring(sidstr, sid));
}

static char *idmap_cache_idkey(TALLOC_CTX *ctx, const struct unixid *xid)
{
	return talloc_asprintf(ctx, "IDMAP/%s/%lu",
			       (xid->type==ID_TYPE_UID)?"UID":"GID",
			       (unsigned long)xid->id);
}

NTSTATUS idmap_cache_set(const struct id_map *id)
{
	NTSTATUS ret;
	time_t timeout = time(NULL) + lp_idmap_cache_time();
	char *sidkey;
	char *idkey;

	/* Don't cache lookups in the S-1-22-{1,2} domain */

	if (sid_check_is_in_unix_users(id->sid)
	    || sid_check_is_in_unix_groups(id->sid)) {
		return NT_STATUS_OK;
	}

	sidkey = idmap_cache_sidkey(talloc_tos(), id->sid);
	if (sidkey == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* use sidkey as the local memory ctx */
	idkey = idmap_cache_idkey(sidkey, &id->xid);
	if (idkey == NULL) {
		ret = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (!gencache_set(idkey, sidkey, timeout)
	    || !gencache_set(sidkey, idkey, timeout)) {
		DEBUG(3, ("Failed to store cache entry!\n"));
		ret = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

	ret = NT_STATUS_OK;

done:
	TALLOC_FREE(sidkey);
	return ret;
}

NTSTATUS idmap_cache_set_negative_sid(const struct id_map *id)
{
	NTSTATUS ret = NT_STATUS_OK;
	char *sidkey;

	sidkey = idmap_cache_sidkey(talloc_tos(), id->sid);
	if (sidkey == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!gencache_set(sidkey, "IDMAP/NEGATIVE",
			  time(NULL) + lp_idmap_negative_cache_time())) {
		DEBUG(3, ("Failed to store cache entry!\n"));
		ret = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

done:
	TALLOC_FREE(sidkey);
	return ret;
}

NTSTATUS idmap_cache_set_negative_id(const struct id_map *id)
{
	NTSTATUS ret = NT_STATUS_OK;
	char *idkey;

	idkey = idmap_cache_idkey(talloc_tos(), &id->xid);
	if (idkey == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!gencache_set(idkey, "IDMAP/NEGATIVE",
			  time(NULL) + lp_idmap_negative_cache_time())) {
		DEBUG(3, ("Failed to store cache entry!\n"));
		ret = NT_STATUS_ACCESS_DENIED;
		goto done;
	}

done:
	TALLOC_FREE(idkey);
	return ret;
}

/*
 * search the cache for the SID an return a mapping if found
 */

bool idmap_cache_map_sid(const struct dom_sid *sid, struct unixid *xid,
			 bool *mapped, bool *expired)
{
	bool ret = false;
	time_t timeout;
	char *sidkey;
	char *value;
	char *rem;

	sidkey = idmap_cache_sidkey(talloc_tos(), sid);
	if (sidkey == NULL) {
		DEBUG(0, ("idmap_cache_sidkey failed\n"));
		return false;
	}

	if (!gencache_get(sidkey, &value, &timeout)) {
		TALLOC_FREE(sidkey);
		return false;
	}

	if (strcmp(value, "IDMAP/NEGATIVE") == 0) {
		*mapped = false;
	}
	else if (strncmp(value, "IDMAP/UID/", 10) == 0) {
		*mapped = true;
		xid->type = ID_TYPE_UID;
		xid->id = strtol(&value[10], &rem, 10);
		if (*rem != '\0') {
			goto fail;
		}
	}
	else if (strncmp(value, "IDMAP/GID/", 10) == 0) {
		*mapped = true;
		xid->type = ID_TYPE_GID;
		xid->id = strtol(&value[10], &rem, 10);
		if (*rem != '\0') {
			goto fail;
		}
	}
	else {
		goto fail;
	}

	*expired = (timeout <= time(NULL));

	ret = true;

 fail:
	if (!ret) {
		DEBUG(1, ("Invalid entry %s in cache\n", value));
	}
	SAFE_FREE(value);
	TALLOC_FREE(sidkey);
	return ret;
}

/*
 * search the cache for the ID an return a mapping if found
 */

bool idmap_cache_map_id(const struct unixid *xid, struct dom_sid *psid,
			bool *mapped, bool *expired)
{
	bool ret = false;
	time_t timeout;
	char *idkey;
	char *value;

	idkey = idmap_cache_idkey(talloc_tos(), xid);
	if (idkey == NULL) {
		return false;
	}

	if (!gencache_get(idkey, &value, &timeout)) {
		TALLOC_FREE(idkey);
		return false;
	}

	if (strcmp(value, "IDMAP/NEGATIVE") == 0) {
		*mapped = false;
	}
	else if (strncmp(value, "IDMAP/SID/", 10) == 0) {
		*mapped = true;
		if (!string_to_sid(psid, value+10)) {
			goto fail;
		}
	}
	else {
		goto fail;
	}

	ret = true;

 fail:
	if (!ret) {
		DEBUG(1, ("Invalid entry %s in cache\n", value));
	}
	SAFE_FREE(value);
	TALLOC_FREE(idkey);
	return ret;
}

