/* 
   samba -- Unix SMB/CIFS implementation.
   Copyright (C) 2001, 2002 by Martin Pool

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

#include "includes.h"
#include "messages.h"
#include "lib/util/talloc_report_printf.h"

static bool pool_usage_filter(struct messaging_rec *rec, void *private_data)
{
	FILE *f = NULL;
	int fd;

	if (rec->msg_type != MSG_REQ_POOL_USAGE) {
		return false;
	}

	DBG_DEBUG("Got MSG_REQ_POOL_USAGE\n");

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds, expected one\n", rec->num_fds);
		return false;
	}

	fd = dup(rec->fds[0]);
	if (fd == -1) {
		DBG_DEBUG("dup(%"PRIi64") failed: %s\n",
			  rec->fds[0],
			  strerror(errno));
		return false;
	}

	f = fdopen(fd, "w");
	if (f == NULL) {
		DBG_DEBUG("fdopen failed: %s\n", strerror(errno));
		close(fd);
		return false;
	}

	talloc_full_report_printf(NULL, f);

	fclose(f);
	/*
	 * Returning false, means messaging_dispatch_waiters()
	 * won't call messaging_filtered_read_done() and
	 * our messaging_filtered_read_send() stays alive
	 * and will get messages.
	 */
	return false;
}

/**
 * Register handler for MSG_REQ_POOL_USAGE
 **/
void register_msg_pool_usage(
	TALLOC_CTX *mem_ctx, struct messaging_context *msg_ctx)
{
	struct tevent_req *req = NULL;

	req = messaging_filtered_read_send(
		mem_ctx,
		messaging_tevent_context(msg_ctx),
		msg_ctx,
		pool_usage_filter,
		NULL);
	if (req == NULL) {
		DBG_WARNING("messaging_filtered_read_send failed\n");
		return;
	}
	DEBUG(2, ("Registered MSG_REQ_POOL_USAGE\n"));
}
