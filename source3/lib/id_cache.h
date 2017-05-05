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

struct id_cache_ref {
	union {
		uid_t uid;
		gid_t gid;
		struct dom_sid sid;
		const char *name;
	} id;
	enum {UID, GID, SID, USERNAME} type;
};

bool id_cache_ref_parse(const char* str, struct id_cache_ref* id);

void id_cache_delete_from_cache(const struct id_cache_ref* id);

void id_cache_register_msgs(struct messaging_context *ctx);

void id_cache_delete_message(struct messaging_context *msg_ctx,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id server_id,
			     DATA_BLOB* data);
