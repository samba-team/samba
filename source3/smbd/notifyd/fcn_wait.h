/*
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

#ifndef __NOTIFYD_FCN_WAIT_H__
#define __NOTIFYD_FCN_WAIT_H__

#include "replace.h"
#include "messages.h"
#include "librpc/gen_ndr/server_id.h"

struct tevent_req *fcn_wait_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct messaging_context *msg_ctx,
	struct server_id notifyd,
	const char *path,
	uint32_t filter,
	uint32_t subdir_filter);
NTSTATUS fcn_wait_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct timespec *when,
	uint32_t *action,
	char **path);

#endif
