/*
   Unix SMB/CIFS implementation.
   ID Mapping Cache

   Copyright (C) Volker Lendecke	2008

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
#include "idmap_cache.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/idmap.h"

/**
 * Find a sid2xid mapping
 * @param[in] sid		the sid to map
 * @param[out] id		where to put the result
 * @param[out] expired		is the cache entry expired?
 * @retval Was anything in the cache at all?
 *
 * If id->id == -1 this was a negative mapping.
 */

bool idmap_cache_find_sid2unixid(const struct dom_sid *sid, struct unixid *id,
				 bool *expired)
{
	fstring sidstr;
	char *key;
	char *value = NULL;
	char *endptr;
	time_t timeout;
	bool ret;
	struct unixid tmp_id;

	key = talloc_asprintf(talloc_tos(), "IDMAP/SID2XID/%s",
			      sid_to_fstring(sidstr, sid));
	if (key == NULL) {
		return false;
	}
	ret = gencache_get(key, &value, &timeout);
	if (!ret) {
		goto done;
	}

	DEBUG(10, ("Parsing value for key [%s]: value=[%s]\n", key, value));

	if (value[0] == '\0') {
		DEBUG(0, ("Failed to parse value for key [%s]: "
			  "value is empty\n", key));
		ret = false;
		goto done;
	}

	tmp_id.id = strtol(value, &endptr, 10);

	if ((value == endptr) && (tmp_id.id == 0)) {
		DEBUG(0, ("Failed to parse value for key [%s]: value[%s] does "
			  "not start with a number\n", key, value));
		ret = false;
		goto done;
	}

	DEBUG(10, ("Parsing value for key [%s]: id=[%llu], endptr=[%s]\n",
		   key, (unsigned long long)tmp_id.id, endptr));

	ret = (*endptr == ':');
	if (ret) {
		switch (endptr[1]) {
		case 'U':
			tmp_id.type = ID_TYPE_UID;
			break;

		case 'G':
			tmp_id.type = ID_TYPE_GID;
			break;

		case 'B':
			tmp_id.type = ID_TYPE_BOTH;
			break;

		case 'N':
			tmp_id.type = ID_TYPE_NOT_SPECIFIED;
			break;

		case '\0':
			DEBUG(0, ("FAILED to parse value for key [%s] "
				  "(id=[%llu], endptr=[%s]): "
				  "no type character after colon\n",
				  key, (unsigned long long)tmp_id.id, endptr));
			ret = false;
			goto done;
		default:
			DEBUG(0, ("FAILED to parse value for key [%s] "
				  "(id=[%llu], endptr=[%s]): "
				  "illegal type character '%c'\n",
				  key, (unsigned long long)tmp_id.id, endptr,
				  endptr[1]));
			ret = false;
			goto done;
		}
		if (endptr[2] != '\0') {
			DEBUG(0, ("FAILED to parse value for key [%s] "
				  "(id=[%llu], endptr=[%s]): "
				  "more than 1 type character after colon\n",
				  key, (unsigned long long)tmp_id.id, endptr));
			ret = false;
			goto done;
		}

		*id = tmp_id;
		*expired = (timeout <= time(NULL));
	} else {
		DEBUG(0, ("FAILED to parse value for key [%s] (value=[%s]): "
			  "colon missing after id=[%llu]\n",
			  key, value, (unsigned long long)tmp_id.id));
	}

done:
	TALLOC_FREE(key);
	SAFE_FREE(value);
	return ret;
}

/**
 * Find a sid2uid mapping
 * @param[in] sid		the sid to map
 * @param[out] puid		where to put the result
 * @param[out] expired		is the cache entry expired?
 * @retval Was anything in the cache at all?
 *
 * If *puid == -1 this was a negative mapping.
 */

bool idmap_cache_find_sid2uid(const struct dom_sid *sid, uid_t *puid,
			      bool *expired)
{
	bool ret;
	struct unixid id;
	ret = idmap_cache_find_sid2unixid(sid, &id, expired);
	if (!ret) {
		return false;
	}

	if (id.type == ID_TYPE_BOTH || id.type == ID_TYPE_UID) {
		*puid = id.id;
	} else {
		*puid = -1;
	}
	return true;
}

/**
 * Find a sid2gid mapping
 * @param[in] sid		the sid to map
 * @param[out] pgid		where to put the result
 * @param[out] expired		is the cache entry expired?
 * @retval Was anything in the cache at all?
 *
 * If *pgid == -1 this was a negative mapping.
 */

bool idmap_cache_find_sid2gid(const struct dom_sid *sid, gid_t *pgid,
			      bool *expired)
{
	bool ret;
	struct unixid id;
	ret = idmap_cache_find_sid2unixid(sid, &id, expired);
	if (!ret) {
		return false;
	}

	if (id.type == ID_TYPE_BOTH || id.type == ID_TYPE_GID) {
		*pgid = id.id;
	} else {
		*pgid = -1;
	}
	return true;
}

/**
 * Find a uid2sid mapping
 * @param[in] uid		the uid to map
 * @param[out] sid		where to put the result
 * @param[out] expired		is the cache entry expired?
 * @retval Was anything in the cache at all?
 *
 * If "is_null_sid(sid)", this was a negative mapping.
 */

bool idmap_cache_find_uid2sid(uid_t uid, struct dom_sid *sid, bool *expired)
{
	char *key;
	char *value;
	time_t timeout;
	bool ret = true;

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
	if (value[0] != '-') {
		ret = string_to_sid(sid, value);
	}
	SAFE_FREE(value);
	if (ret) {
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

/**
 * Find a gid2sid mapping
 * @param[in] gid		the gid to map
 * @param[out] sid		where to put the result
 * @param[out] expired		is the cache entry expired?
 * @retval Was anything in the cache at all?
 *
 * If "is_null_sid(sid)", this was a negative mapping.
 */

bool idmap_cache_find_gid2sid(gid_t gid, struct dom_sid *sid, bool *expired)
{
	char *key;
	char *value;
	time_t timeout;
	bool ret = true;

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
	if (value[0] != '-') {
		ret = string_to_sid(sid, value);
	}
	SAFE_FREE(value);
	if (ret) {
		*expired = (timeout <= time(NULL));
	}
	return ret;
}

/**
 * Store a mapping in the idmap cache
 * @param[in] sid		the sid to map
 * @param[in] gid		the gid to map
 *
 * If both parameters are valid values, then a positive mapping in both
 * directions is stored. If "is_null_sid(sid)" is true, then this will be a
 * negative mapping of gid, we want to cache that for this gid we could not
 * find anything. Likewise if "gid==-1", then we want to cache that we did not
 * find a mapping for the sid passed here.
 */

void idmap_cache_set_sid2unixid(const struct dom_sid *sid, struct unixid *unix_id)
{
	time_t now = time(NULL);
	time_t timeout;
	fstring sidstr, key, value;

	if (!is_null_sid(sid)) {
		fstr_sprintf(key, "IDMAP/SID2XID/%s",
			     sid_to_fstring(sidstr, sid));
		switch (unix_id->type) {
		case ID_TYPE_UID:
			fstr_sprintf(value, "%d:U", (int)unix_id->id);
			break;
		case ID_TYPE_GID:
			fstr_sprintf(value, "%d:G", (int)unix_id->id);
			break;
		case ID_TYPE_BOTH:
			fstr_sprintf(value, "%d:B", (int)unix_id->id);
			break;
		case ID_TYPE_NOT_SPECIFIED:
			fstr_sprintf(value, "%d:N", (int)unix_id->id);
			break;
		default:
			return;
		}
		timeout = (unix_id->id == -1)
			? lp_idmap_negative_cache_time()
			: lp_idmap_cache_time();
		gencache_set(key, value, now + timeout);
	}
	if (unix_id->id != -1) {
		if (is_null_sid(sid)) {
			/* negative gid mapping */
			fstrcpy(value, "-");
			timeout = lp_idmap_negative_cache_time();
		}
		else {
			sid_to_fstring(value, sid);
			timeout = lp_idmap_cache_time();
		}
		switch (unix_id->type) {
		case ID_TYPE_BOTH:
			fstr_sprintf(key, "IDMAP/UID2SID/%d", (int)unix_id->id);
			gencache_set(key, value, now + timeout);
			fstr_sprintf(key, "IDMAP/GID2SID/%d", (int)unix_id->id);
			gencache_set(key, value, now + timeout);
			return;

		case ID_TYPE_UID:
			fstr_sprintf(key, "IDMAP/UID2SID/%d", (int)unix_id->id);
			break;

		case ID_TYPE_GID:
			fstr_sprintf(key, "IDMAP/GID2SID/%d", (int)unix_id->id);
			break;

		default:
			return;
		}
		gencache_set(key, value, now + timeout);
	}
}

/**
 * Store a mapping in the idmap cache
 * @param[in] sid		the sid to map
 * @param[in] uid		the uid to map
 *
 * If both parameters are valid values, then a positive mapping in both
 * directions is stored. If "is_null_sid(sid)" is true, then this will be a
 * negative mapping of uid, we want to cache that for this uid we could not
 * find anything. Likewise if "uid==-1", then we want to cache that we did not
 * find a mapping for the sid passed here.
 */

void idmap_cache_set_sid2uid(const struct dom_sid *sid, uid_t uid)
{
	struct unixid id;
	id.type = ID_TYPE_UID;
	id.id = uid;

	if (uid == -1) {
		uid_t tmp_gid;
		bool expired;
		/* If we were asked to invalidate this SID -> UID
		 * mapping, it was because we found out that this was
		 * not a UID at all.  Do not overwrite a valid GID or
		 * BOTH mapping */
		if (idmap_cache_find_sid2gid(sid, &tmp_gid, &expired)) {
			if (!expired) {
				return;
			}
		}
	}

	idmap_cache_set_sid2unixid(sid, &id);
	return;
}

/**
 * Store a mapping in the idmap cache
 * @param[in] sid		the sid to map
 * @param[in] gid		the gid to map
 *
 * If both parameters are valid values, then a positive mapping in both
 * directions is stored. If "is_null_sid(sid)" is true, then this will be a
 * negative mapping of gid, we want to cache that for this gid we could not
 * find anything. Likewise if "gid==-1", then we want to cache that we did not
 * find a mapping for the sid passed here.
 */

void idmap_cache_set_sid2gid(const struct dom_sid *sid, gid_t gid)
{
	struct unixid id;
	id.type = ID_TYPE_GID;
	id.id = gid;

	if (gid == -1) {
		uid_t tmp_uid;
		bool expired;
		/* If we were asked to invalidate this SID -> GID
		 * mapping, it was because we found out that this was
		 * not a GID at all.  Do not overwrite a valid UID or
		 * BOTH mapping */
		if (idmap_cache_find_sid2uid(sid, &tmp_uid, &expired)) {
			if (!expired) {
				return;
			}
		}
	}

	idmap_cache_set_sid2unixid(sid, &id);
	return;
}

static char* key_xid2sid_str(TALLOC_CTX* mem_ctx, char t, const char* id) {
	return talloc_asprintf(mem_ctx, "IDMAP/%cID2SID/%s", t, id);
}

static char* key_xid2sid(TALLOC_CTX* mem_ctx, char t, int id) {
	char str[32];
	snprintf(str, sizeof(str), "%d", id);
	return key_xid2sid_str(mem_ctx, t, str);
}

static char* key_sid2xid_str(TALLOC_CTX* mem_ctx, const char* id) {
	return talloc_asprintf(mem_ctx, "IDMAP/SID2XID/%s", id);
}

static bool idmap_cache_del_xid(char t, int xid)
{
	TALLOC_CTX* mem_ctx = talloc_stackframe();
	const char* key = key_xid2sid(mem_ctx, t, xid);
	char* sid_str = NULL;
	time_t timeout;
	bool ret = true;

	if (!gencache_get(key, &sid_str, &timeout)) {
		DEBUG(3, ("no entry: %s\n", key));
		ret = false;
		goto done;
	}

	if (sid_str[0] != '-') {
		const char* sid_key = key_sid2xid_str(mem_ctx, sid_str);
		if (!gencache_del(sid_key)) {
			DEBUG(2, ("failed to delete: %s\n", sid_key));
			ret = false;
		} else {
			DEBUG(5, ("delete: %s\n", sid_key));
		}

	}

	if (!gencache_del(key)) {
		DEBUG(1, ("failed to delete: %s\n", key));
		ret = false;
	} else {
		DEBUG(5, ("delete: %s\n", key));
	}

done:
	talloc_free(mem_ctx);
	return ret;
}

bool idmap_cache_del_uid(uid_t uid) {
	return idmap_cache_del_xid('U', uid);
}

bool idmap_cache_del_gid(gid_t gid) {
	return idmap_cache_del_xid('G', gid);
}

bool idmap_cache_del_sid(const struct dom_sid *sid)
{
	TALLOC_CTX* mem_ctx = talloc_stackframe();
	bool ret = true;
	bool expired;
	struct unixid id;
	const char *sid_key;

	if (!idmap_cache_find_sid2unixid(sid, &id, &expired)) {
		ret = false;
		goto done;
	}

	if (id.id != -1) {
		switch (id.type) {
		case ID_TYPE_BOTH:
			idmap_cache_del_xid('U', id.id);
			idmap_cache_del_xid('G', id.id);
			break;
		case ID_TYPE_UID:
			idmap_cache_del_xid('U', id.id);
			break;
		case ID_TYPE_GID:
			idmap_cache_del_xid('G', id.id);
			break;
		default:
			break;
		}
	}

	sid_key = key_sid2xid_str(mem_ctx, dom_sid_string(mem_ctx, sid));
	if (sid_key == NULL) {
		return false;
	}
	/* If the mapping was symmetric, then this should fail */
	gencache_del(sid_key);
done:
	talloc_free(mem_ctx);
	return ret;
}
