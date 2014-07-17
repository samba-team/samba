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
#include "../lib/util/memcache.h"
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
	} else if (strncmp(str, "USER ", 5) == 0) {
		id->id.name = str + 5;
		id->type = USERNAME;
		return true;
	}
	return false;
}

static bool delete_getpwnam_cache(const char *username)
{
	DATA_BLOB name = data_blob_string_const_null(username);
	DEBUG(6, ("Delete passwd struct for %s from memcache\n",
		  username));
	memcache_delete(NULL, GETPWNAM_CACHE, name);
	return true;
}

void id_cache_delete_from_cache(const struct id_cache_ref* id)
{
	switch(id->type) {
	case UID:
		idmap_cache_del_uid(id->id.uid);
		break;
	case GID:
		idmap_cache_del_gid(id->id.gid);
		break;
	case SID:
		idmap_cache_del_sid(&id->id.sid);
		break;
	case USERNAME:
		delete_getpwnam_cache(id->id.name);
	default:
		break;
	}
}

void id_cache_delete_message(struct messaging_context *msg_ctx,
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

	id_cache_delete_from_cache(&id);
}

void id_cache_register_msgs(struct messaging_context *ctx)
{
	messaging_register(ctx, NULL, ID_CACHE_DELETE, id_cache_delete_message);
}
