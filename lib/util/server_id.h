/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Bartlett 2011

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

#ifndef __LIB_UTIL_SERVER_ID_H__
#define __LIB_UTIL_SERVER_ID_H__

#include "replace.h"

struct server_id;

struct server_id_buf { char buf[48]; }; /* probably a bit too large ... */

bool server_id_same_process(const struct server_id *p1,
			    const struct server_id *p2);
int server_id_cmp(const struct server_id *p1, const struct server_id *p2);
bool server_id_equal(const struct server_id *p1, const struct server_id *p2);
char *server_id_str_buf(struct server_id id, struct server_id_buf *dst);
size_t server_id_str_buf_unique(struct server_id id, char *buf, size_t buflen);

struct server_id server_id_from_string(uint32_t local_vnn,
				       const char *pid_string);

/**
 * Set the serverid to the special value that represents a disconnected
 * client for (e.g.) durable handles.
 */
void server_id_set_disconnected(struct server_id *id);

/**
 * check whether a serverid is the special placeholder for
 * a disconnected client
 */
bool server_id_is_disconnected(const struct server_id *id);

#define SERVER_ID_BUF_LENGTH 24
void server_id_put(uint8_t buf[SERVER_ID_BUF_LENGTH],
		   const struct server_id id);
void server_id_get(struct server_id *id,
		   const uint8_t buf[SERVER_ID_BUF_LENGTH]);

#endif
