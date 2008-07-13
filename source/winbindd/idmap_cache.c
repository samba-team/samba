/* 
   Unix SMB/CIFS implementation.
   ID Mapping Cache

   based on gencache

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

bool idmap_cache_find_sid2uid(const struct dom_sid *sid, uid_t *puid,
			      bool *expired)
{
	fstring sidstr;
	char *key;
	char *value;
	char *endptr;
	time_t timeout;
	uid_t uid;
	bool ret;

	key = talloc_asprintf(talloc_tos(), "IDMAP/SID2UID/%s",
			      sid_to_fstring(sidstr, sid));
	if (key == NULL) {
		return false;
	}
	ret = gencache_get(key, &value, &timeout);
	TALLOC_FREE(key);
	if (!ret) {
		return false;
	}
	uid = strtol(value, &endptr, 10);
	ret = (*endptr == '\0');
	SAFE_FREE(value);
	if (ret) {
		*puid = uid;
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

bool idmap_cache_find_uid2sid(uid_t uid, struct dom_sid *sid, bool *expired)
{
	char *key;
	char *value;
	time_t timeout;
	bool ret;

	key = talloc_asprintf(talloc_tos(), "IDMAP/UID2SID/%d", (int)uid);
	if (key == NULL) {
		return false;
	}
	ret = gencache_get(key, &value, &timeout);
	TALLOC_FREE(key);
	if (!ret) {
		return false;
	}
	ZERO_STRUCTP(sid);
	ret = string_to_sid(sid, value);
	SAFE_FREE(value);
	if (ret) {
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

void idmap_cache_set_sid2uid(const struct dom_sid *sid, uid_t uid)
{
	time_t now = time(NULL);
	time_t timeout;
	fstring sidstr, key, value;

	if (!is_null_sid(sid)) {
		fstr_sprintf(key, "IDMAP/SID2UID/%s",
			     sid_to_fstring(sidstr, sid));
		fstr_sprintf(value, "%d", (int)uid);
		timeout = (uid == -1)
			? lp_idmap_negative_cache_time()
			: lp_idmap_cache_time();
		gencache_set(key, value, now + timeout);
	}
	if (uid != -1) {
		fstr_sprintf(key, "IDMAP/UID2SID/%d", (int)uid);
		sid_to_fstring(value, sid);
		timeout = is_null_sid(sid)
			? lp_idmap_negative_cache_time()
			: lp_idmap_cache_time();
		gencache_set(key, value, now + timeout);
	}
}

bool idmap_cache_find_sid2gid(const struct dom_sid *sid, gid_t *pgid,
			      bool *expired)
{
	fstring sidstr;
	char *key;
	char *value;
	char *endptr;
	time_t timeout;
	gid_t gid;
	bool ret;

	key = talloc_asprintf(talloc_tos(), "IDMAP/SID2GID/%s",
			      sid_to_fstring(sidstr, sid));
	if (key == NULL) {
		return false;
	}
	ret = gencache_get(key, &value, &timeout);
	TALLOC_FREE(key);
	if (!ret) {
		return false;
	}
	gid = strtol(value, &endptr, 10);
	ret = (*endptr == '\0');
	SAFE_FREE(value);
	if (ret) {
		*pgid = gid;
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

bool idmap_cache_find_gid2sid(gid_t gid, struct dom_sid *sid, bool *expired)
{
	char *key;
	char *value;
	time_t timeout;
	bool ret;

	key = talloc_asprintf(talloc_tos(), "IDMAP/GID2SID/%d", (int)gid);
	if (key == NULL) {
		return false;
	}
	ret = gencache_get(key, &value, &timeout);
	TALLOC_FREE(key);
	if (!ret) {
		return false;
	}
	ZERO_STRUCTP(sid);
	ret = string_to_sid(sid, value);
	SAFE_FREE(value);
	if (ret) {
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

void idmap_cache_set_sid2gid(const struct dom_sid *sid, gid_t gid)
{
	time_t now = time(NULL);
	time_t timeout;
	fstring sidstr, key, value;

	if (!is_null_sid(sid)) {
		fstr_sprintf(key, "IDMAP/SID2GID/%s",
			     sid_to_fstring(sidstr, sid));
		fstr_sprintf(value, "%d", (int)gid);
		timeout = (gid == -1)
			? lp_idmap_negative_cache_time()
			: lp_idmap_cache_time();
		gencache_set(key, value, now + timeout);
	}
	if (gid != -1) {
		fstr_sprintf(key, "IDMAP/GID2SID/%d", (int)gid);
		sid_to_fstring(value, sid);
		timeout = is_null_sid(sid)
			? lp_idmap_negative_cache_time()
			: lp_idmap_cache_time();
		gencache_set(key, value, now + timeout);
	}
}
