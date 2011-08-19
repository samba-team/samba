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

#include "includes.h"
#include "smbd/globals.h"
#include "smbd/smbd.h"
#include "../libcli/security/dom_sid.h"
#include "idmap_cache.h"
#include "passdb/lookup_sid.h"
#include "auth.h"
#include "messages.h"
#include "lib/id_cache.h"

static bool uid_in_use(const struct user_struct* user, uid_t uid)
{
	while (user) {
		if (user->session_info && (user->session_info->unix_token->uid == uid)) {
			return true;
		}
		user = user->next;
	}
	return false;
}

static bool gid_in_use(const struct user_struct* user, gid_t gid)
{
	while (user) {
		if (user->session_info != NULL) {
			int i;
			struct security_unix_token *utok = user->session_info->unix_token;
			if (utok->gid == gid) {
				return true;
			}
			for(i=0; i<utok->ngroups; i++) {
				if (utok->groups[i] == gid) {
					return true;
				}
			}
		}
		user = user->next;
	}
	return false;
}

static bool sid_in_use(const struct user_struct* user, const struct dom_sid* psid)
{
	uid_t uid;
	gid_t gid;
	if (sid_to_gid(psid, &gid)) {
		return gid_in_use(user, gid);
	} else if (sid_to_uid(psid, &uid)) {
		return uid_in_use(user, uid);
	}
	return false;
}

static bool id_in_use(const struct user_struct* user,
		      const struct id_cache_ref* id)
{
	switch(id->type) {
	case UID:
		return uid_in_use(user, id->id.uid);
	case GID:
		return gid_in_use(user, id->id.gid);
	case SID:
		return sid_in_use(user, &id->id.sid);
	default:
		break;
	}
	return false;
}

static void id_cache_kill(struct messaging_context *msg_ctx,
				 void *private_data,
				 uint32_t msg_type,
				 struct server_id server_id,
				 DATA_BLOB* data)
{
	const char *msg = (data && data->data) ? (const char *)data->data : "<NULL>";
	struct user_struct *validated_users = smbd_server_conn->smb1.sessions.validated_users;
	struct id_cache_ref id;

	if (!id_cache_ref_parse(msg, &id)) {
		DEBUG(0, ("Invalid ?ID: %s\n", msg));
		return;
	}

	if (id_in_use(validated_users, &id)) {
		exit_server_cleanly(msg);
	}
}

void id_cache_register_kill_msg(struct messaging_context *ctx)
{
	messaging_register(ctx, NULL, ID_CACHE_KILL, id_cache_kill);
}
