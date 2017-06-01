/*
 * Unix SMB/CIFS implementation.
 * messages_ctdb.c header
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

#ifndef _MESSAGES_CTDB_H_
#define _MESSAGES_CTDB_H_

#include "replace.h"
#include <talloc.h>

struct messaging_context;
struct messaging_backend;
struct ctdbd_connection;

int messaging_ctdbd_init(struct messaging_context *msg_ctx,
			 TALLOC_CTX *mem_ctx,
			 struct messaging_backend **presult);
int messaging_ctdbd_reinit(struct messaging_context *msg_ctx,
			   TALLOC_CTX *mem_ctx,
			   struct messaging_backend *backend);
struct ctdbd_connection *messaging_ctdbd_connection(void);

#endif
