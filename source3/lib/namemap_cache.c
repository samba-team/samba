/*
 * Unix SMB/CIFS implementation.
 * Utils for caching sid2name and name2sid
 * Copyright (C) Volker Lendecke 2017
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "namemap_cache.h"
#include "source3/lib/gencache.h"
#include "lib/util/debug.h"
#include "lib/util/strv.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/charset/charset.h"
#include "libcli/security/dom_sid.h"

bool namemap_cache_set_sid2name(const struct dom_sid *sid,
				const char *domain, const char *name,
				enum lsa_SidType type, time_t timeout)
{
	char typebuf[16];
	char sidbuf[DOM_SID_STR_BUFLEN];
	char keybuf[DOM_SID_STR_BUFLEN+10];
	char *val = NULL;
	DATA_BLOB data;
	int ret;
	bool ok = false;

	if ((sid == NULL) || is_null_sid(sid)) {
		return true;
	}
	if (domain == NULL) {
		domain = "";
	}
	if (name == NULL) {
		name = "";
	}
	if (type == SID_NAME_UNKNOWN) {
		domain = "";
		name = "";
	}

	snprintf(typebuf, sizeof(typebuf), "%d", (int)type);

	ret = strv_add(talloc_tos(), &val, domain);
	if (ret != 0) {
		DBG_DEBUG("strv_add failed: %s\n", strerror(ret));
		goto fail;
	}
	ret = strv_add(NULL, &val, name);
	if (ret != 0) {
		DBG_DEBUG("strv_add failed: %s\n", strerror(ret));
		goto fail;
	}
	ret = strv_add(NULL, &val, typebuf);
	if (ret != 0) {
		DBG_DEBUG("strv_add failed: %s\n", strerror(ret));
		goto fail;
	}

	dom_sid_string_buf(sid, sidbuf, sizeof(sidbuf));
	snprintf(keybuf, sizeof(keybuf), "SID2NAME/%s", sidbuf);

	data = data_blob_const(val, talloc_get_size(val));

	ok = gencache_set_data_blob(keybuf, data, timeout);
	if (!ok) {
		DBG_DEBUG("gencache_set_data_blob failed\n");
	}
fail:
	TALLOC_FREE(val);
	return ok;
}

struct namemap_cache_find_sid_state {
	void (*fn)(const char *domain, const char *name,
		   enum lsa_SidType type, time_t timeout,
		   void *private_data);
	void *private_data;
	bool ok;
};

static void namemap_cache_find_sid_parser(time_t timeout, DATA_BLOB blob,
					  void *private_data)
{
	struct namemap_cache_find_sid_state *state = private_data;
	const char *strv = (const char *)blob.data;
	size_t strv_len = blob.length;
	const char *domain;
	const char *name;
	const char *typebuf;
	char *endptr;
	unsigned long type;

	state->ok = false;

	domain = strv_len_next(strv, strv_len, NULL);
	if (domain == NULL) {
		return;
	}
	name = strv_len_next(strv, strv_len, domain);
	if (name == NULL) {
		return;
	}
	typebuf = strv_len_next(strv, strv_len, name);
	if (typebuf == NULL) {
		return;
	}

	type = strtoul(typebuf, &endptr, 10);
	if (*endptr != '\0') {
		return;
	}
	if ((type == ULONG_MAX) && (errno == ERANGE)) {
		return;
	}

	state->fn(domain, name, (enum lsa_SidType)type, timeout,
		  state->private_data);

	state->ok = true;
}

bool namemap_cache_find_sid(const struct dom_sid *sid,
			    void (*fn)(const char *domain, const char *name,
				       enum lsa_SidType type, time_t timeout,
				       void *private_data),
			    void *private_data)
{
	struct namemap_cache_find_sid_state state = {
		.fn = fn, .private_data = private_data
	};
	char sidbuf[DOM_SID_STR_BUFLEN];
	char keybuf[DOM_SID_STR_BUFLEN+10];
	bool ok;

	dom_sid_string_buf(sid, sidbuf, sizeof(sidbuf));
	snprintf(keybuf, sizeof(keybuf), "SID2NAME/%s", sidbuf);

	ok = gencache_parse(keybuf, namemap_cache_find_sid_parser, &state);
	if (!ok) {
		DBG_DEBUG("gencache_parse(%s) failed\n", keybuf);
		return false;
	}

	if (!state.ok) {
		DBG_DEBUG("Could not parse %s, deleting\n", keybuf);
		gencache_del(keybuf);
		return false;
	}

	return true;
}

bool namemap_cache_set_name2sid(const char *domain, const char *name,
				const struct dom_sid *sid,
				enum lsa_SidType type,
				time_t timeout)
{
	char typebuf[16];
	char sidbuf[DOM_SID_STR_BUFLEN];
	char *key;
	char *key_upper;
	char *val = NULL;
	DATA_BLOB data;
	int ret;
	bool ok = false;

	if (domain == NULL) {
		domain = "";
	}
	if (name == NULL) {
		name = "";
	}
	if (type == SID_NAME_UNKNOWN) {
		sidbuf[0] = '\0';
	} else {
		dom_sid_string_buf(sid, sidbuf, sizeof(sidbuf));
	}

	snprintf(typebuf, sizeof(typebuf), "%d", (int)type);

	key = talloc_asprintf(talloc_tos(), "NAME2SID/%s\\%s", domain, name);
	if (key == NULL) {
		DBG_DEBUG("talloc_asprintf failed\n");
		goto fail;
	}
	key_upper = strupper_talloc(key, key);
	if (key_upper == NULL) {
		DBG_DEBUG("strupper_talloc failed\n");
		goto fail;
	}

	ret = strv_add(key, &val, sidbuf);
	if (ret != 0) {
		DBG_DEBUG("strv_add failed: %s\n", strerror(ret));
		goto fail;
	}
	ret = strv_add(NULL, &val, typebuf);
	if (ret != 0) {
		DBG_DEBUG("strv_add failed: %s\n", strerror(ret));
		goto fail;
	}

	data = data_blob_const(val, talloc_get_size(val));

	ok = gencache_set_data_blob(key_upper, data, timeout);
	if (!ok) {
		DBG_DEBUG("gencache_set_data_blob failed\n");
	}
fail:
	TALLOC_FREE(key);
	return ok;
}

struct namemap_cache_find_name_state {
	void (*fn)(const struct dom_sid *sid,
		   enum lsa_SidType type, time_t timeout,
		   void *private_data);
	void *private_data;
	bool ok;
};

static void namemap_cache_find_name_parser(time_t timeout, DATA_BLOB blob,
					   void *private_data)
{
	struct namemap_cache_find_name_state *state = private_data;
	const char *strv = (const char *)blob.data;
	size_t strv_len = blob.length;
	const char *sidbuf;
	const char *sid_endptr;
	const char *typebuf;
	char *endptr;
	struct dom_sid sid;
	unsigned long type;
	bool ok;

	state->ok = false;

	sidbuf = strv_len_next(strv, strv_len, NULL);
	if (sidbuf == NULL) {
		return;
	}
	typebuf = strv_len_next(strv, strv_len, sidbuf);
	if (typebuf == NULL) {
		return;
	}

	ok = dom_sid_parse_endp(sidbuf, &sid, &sid_endptr);
	if (!ok) {
		return;
	}
	if (*sid_endptr != '\0') {
		return;
	}

	type = strtoul(typebuf, &endptr, 10);
	if (*endptr != '\0') {
		return;
	}
	if ((type == ULONG_MAX) && (errno == ERANGE)) {
		return;
	}

	state->fn(&sid, (enum lsa_SidType)type, timeout, state->private_data);

	state->ok = true;
}

bool namemap_cache_find_name(const char *domain, const char *name,
			     void (*fn)(const struct dom_sid *sid,
					enum lsa_SidType type, time_t timeout,
					void *private_data),
			     void *private_data)
{
	struct namemap_cache_find_name_state state = {
		.fn = fn, .private_data = private_data
	};
	char *key;
	char *key_upper;
	bool ret = false;
	bool ok;

	key = talloc_asprintf(talloc_tos(), "NAME2SID/%s\\%s", domain, name);
	if (key == NULL) {
		DBG_DEBUG("talloc_asprintf failed\n");
		return false;
	}
	key_upper = strupper_talloc(key, key);
	if (key_upper == NULL) {
		DBG_DEBUG("strupper_talloc failed\n");
		goto fail;
	}

	ok = gencache_parse(key_upper, namemap_cache_find_name_parser, &state);
	if (!ok) {
		DBG_DEBUG("gencache_parse(%s) failed\n", key_upper);
		goto fail;
	}

	if (!state.ok) {
		DBG_DEBUG("Could not parse %s, deleting\n", key_upper);
		goto fail;
	}

	ret = true;
fail:
	TALLOC_FREE(key);
	return ret;
}
