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

#ifndef __NOTIFYD_NOTIFYD_DB_H__
#define __NOTIFYD_NOTIFYD_DB_H__
#include "replace.h"
#include "notifyd.h"

NTSTATUS notify_walk(struct messaging_context *msg_ctx,
		     bool (*fn)(const char *path, struct server_id server,
				const struct notify_instance *instance,
				void *private_data),
		     void *private_data);

#endif
