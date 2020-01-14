/*
 * Unix SMB/CIFS implementation.
 * Wait for process death
 * Copyright (C) Volker Lendecke 2016
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

#ifndef __LIB_SERVER_ID_WATCH_H__
#define __LIB_SERVER_ID_WATCH_H__

#include "replace.h"
#include <tevent.h>
#include <talloc.h>
#include "librpc/gen_ndr/server_id.h"

struct tevent_req *server_id_watch_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct server_id pid);
int server_id_watch_recv(struct tevent_req *req, struct server_id *pid);

#endif
