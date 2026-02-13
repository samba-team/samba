/*
 * Samba rate limiting coordination daemon
 *
 * Copyright (c) 2026 Avan Thakkar <athakkar@redhat.com>
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

#ifndef __SMBD_RATELIMITD_H__
#define __SMBD_RATELIMITD_H__

#include "replace.h"
#include <tevent.h>
#include "messages.h"

struct tevent_req *smbd_ratelimitd_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct messaging_context *msg);

/*
 * Complete ratelimitd request
 */
int smbd_ratelimitd_recv(struct tevent_req *req);

#endif /* __SMBD_RATELIMITD_H__ */
