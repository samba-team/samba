/*
 * Unix SMB/CIFS implementation.
 * Samba internal messaging functions
 * Copyright (C) 2014 by Volker Lendecke
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

#ifndef _MESSAGES_DGM_REF_H_
#define _MESSAGES_DGM_REF_H_

#include <talloc.h>
#include <tevent.h>
#include "replace.h"

void *messaging_dgm_ref(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			uint64_t *unique,
			const char *socket_dir,
			const char *lockfile_dir,
			void (*recv_cb)(struct tevent_context *ev,
					const uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
			void *recv_cb_private_data,
			int *err);

#endif
