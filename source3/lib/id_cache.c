/*
 * Samba Unix/Linux SMB client library
 *
 * Copyright (C) Gregor Beck 2011
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

/**
 * @brief  Notify smbd about idmap changes
 * @file   msg_idmap.c
 * @author Gregor Beck <gb@sernet.de>
 * @date   Feb 2011
 *
 */

#include "includes.h"
#include "messages.h"
#include "lib/id_cache.h"
#include "include/memcache.h"
#include "idmap_cache.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../libcli/security/dom_sid.h"

bool id_cache_ref_parse(const char* str, struct id_cache_ref* id)
{
	struct dom_sid sid;
	unsigned long ul;
	char c, trash;

	if (sscanf(str, "%cID %lu%c", &c, &ul, &trash) == 2) {
		switch(c) {
		case 'G':
			id->id.gid = ul;
			id->type = GID;
			return true;
		case 'U':
			id->id.uid = ul;
			id->type = UID;
			return true;
		default:
			break;
		}
	} else if (string_to_sid(&sid, str)) {
		id->id.sid = sid;
		id->type = SID;
		return true;
	}
	return false;
}

static bool delete_uid_cache(uid_t puid)
{
	DATA_BLOB uid = data_blob_const(&puid, sizeof(puid));
	DATA_BLOB sid;

	if (!memcache_lookup(NULL, UID_SID_CACHE, uid, &sid)) {
		DEBUG(3, ("UID %d is not memcached!\n", (int)puid));
		return false;
	}
	DEBUG(3, ("Delete mapping UID %d <-> %s from memcache\n", (int)puid,
		  sid_string_dbg((struct dom_sid*)sid.data)));
	memcache_delete(NULL, SID_UID_CACHE, sid);
	memcache_delete(NULL, UID_SID_CACHE, uid);
	return true;
}

static bool delete_gid_cache(gid_t pgid)
{
	DATA_BLOB gid = data_blob_const(&pgid, sizeof(pgid));
	DATA_BLOB sid;
	if (!memcache_lookup(NULL, GID_SID_CACHE, gid, &sid)) {
		DEBUG(3, ("GID %d is not memcached!\n", (int)pgid));
		return false;
	}
	DEBUG(3, ("Delete mapping GID %d <-> %s from memcache\n", (int)pgid,
		  sid_string_dbg((struct dom_sid*)sid.data)));
	memcache_delete(NULL, SID_GID_CACHE, sid);
	memcache_delete(NULL, GID_SID_CACHE, gid);
	return true;
}

static bool delete_sid_cache(const struct dom_sid* psid)
{
	DATA_BLOB sid = data_blob_const(psid, ndr_size_dom_sid(psid, 0));
	DATA_BLOB id;
	if (memcache_lookup(NULL, SID_GID_CACHE, sid, &id)) {
		DEBUG(3, ("Delete mapping %s <-> GID %d from memcache\n",
			  sid_string_dbg(psid), *(int*)id.data));
		memcache_delete(NULL, SID_GID_CACHE, sid);
		memcache_delete(NULL, GID_SID_CACHE, id);
	} else if (memcache_lookup(NULL, SID_UID_CACHE, sid, &id)) {
		DEBUG(3, ("Delete mapping %s <-> UID %d from memcache\n",
			  sid_string_dbg(psid), *(int*)id.data));
		memcache_delete(NULL, SID_UID_CACHE, sid);
		memcache_delete(NULL, UID_SID_CACHE, id);
	} else {
		DEBUG(3, ("SID %s is not memcached!\n", sid_string_dbg(psid)));
		return false;
	}
	return true;
}

static void flush_gid_cache(void)
{
	DEBUG(3, ("Flush GID <-> SID memcache\n"));
	memcache_flush(NULL, SID_GID_CACHE);
	memcache_flush(NULL, GID_SID_CACHE);
}

static void flush_uid_cache(void)
{
	DEBUG(3, ("Flush UID <-> SID memcache\n"));
	memcache_flush(NULL, SID_UID_CACHE);
	memcache_flush(NULL, UID_SID_CACHE);
}
static void delete_from_cache(const struct id_cache_ref* id)
{
	switch(id->type) {
	case UID:
		delete_uid_cache(id->id.uid);
		idmap_cache_del_uid(id->id.uid);
		break;
	case GID:
		delete_gid_cache(id->id.gid);
		idmap_cache_del_gid(id->id.gid);
		break;
	case SID:
		delete_sid_cache(&id->id.sid);
		idmap_cache_del_sid(&id->id.sid);
		break;
	default:
		break;
	}
}


static void message_idmap_flush(struct messaging_context *msg_ctx,
				void* private_data,
				uint32_t msg_type,
				struct server_id server_id,
				DATA_BLOB* data)
{
	const char *msg = data ? (const char *)data->data : NULL;

	if ((msg == NULL) || (msg[0] == '\0')) {
		flush_gid_cache();
		flush_uid_cache();
	} else if (strncmp(msg, "GID", 3)) {
		flush_gid_cache();
	} else if (strncmp(msg, "UID", 3)) {
		flush_uid_cache();
	} else {
		DEBUG(0, ("Invalid argument: %s\n", msg));
	}
}

static void message_idmap_delete(struct messaging_context *msg_ctx,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id server_id,
				 DATA_BLOB* data)
{
	const char *msg = (data && data->data) ? (const char *)data->data : "<NULL>";
	struct id_cache_ref id;

	if (!id_cache_ref_parse(msg, &id)) {
		DEBUG(0, ("Invalid ?ID: %s\n", msg));
		return;
	}

	delete_from_cache(&id);
}

void msg_idmap_register_msgs(struct messaging_context *ctx)
{
	messaging_register(ctx, NULL, MSG_IDMAP_FLUSH,  message_idmap_flush);
	messaging_register(ctx, NULL, MSG_IDMAP_DELETE, message_idmap_delete);
}
