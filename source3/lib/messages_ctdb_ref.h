/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2017 by Volker Lendecke
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

#ifndef __MESSAGES_CTDB_REF_H__
#define __MESSAGES_CTDB_REF_H__

#include "replace.h"
#include <tevent.h>

void *messaging_ctdb_ref(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			 const char *sockname, int timeout, uint64_t unique_id,
			 void (*recv_cb)(struct tevent_context *ev,
					 const uint8_t *msg, size_t msg_len,
					 int *fds, size_t num_fds,
					 void *private_data),
			 void *private_data,
			 int *err);

#endif
