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
#ifdef HAVE_MALLINFO
#include <malloc.h>
#endif /* HAVE_MALLINFO */

static bool pool_usage_filter(struct messaging_rec *rec, void *private_data)
{
	if (rec->msg_type != MSG_REQ_POOL_USAGE) {
		return false;
	}

	DBG_DEBUG("Got MSG_REQ_POOL_USAGE\n");

	if (rec->num_fds != 1) {
		DBG_DEBUG("Got %"PRIu8" fds, expected one\n", rec->num_fds);
		return false;
	}

	return true;
}


static void msg_pool_usage_do(struct tevent_req *req)
{
	struct messaging_context *msg_ctx = tevent_req_callback_data(
		req, struct messaging_context);
	struct messaging_rec *rec = NULL;
	FILE *f = NULL;
	int ret;

	ret = messaging_filtered_read_recv(req, talloc_tos(), &rec);
	TALLOC_FREE(req);
	if (ret != 0) {
		DBG_DEBUG("messaging_filtered_read_recv returned %s\n",
			  strerror(ret));
		return;
	}

	f = fdopen(rec->fds[0], "w");
	if (f == NULL) {
		close(rec->fds[0]);
		TALLOC_FREE(rec);
		DBG_DEBUG("fdopen failed: %s\n", strerror(errno));
		return;
	}

	TALLOC_FREE(rec);

	talloc_full_report_printf(NULL, f);

	fclose(f);
	f = NULL;

	req = messaging_filtered_read_send(
		msg_ctx,
		messaging_tevent_context(msg_ctx),
		msg_ctx,
		pool_usage_filter,
		NULL);
	if (req == NULL) {
		DBG_WARNING("messaging_filtered_read_send failed\n");
		return;
	}
	tevent_req_set_callback(req, msg_pool_usage_do, msg_ctx);
}

/**
 * Register handler for MSG_REQ_POOL_USAGE
 **/
void register_msg_pool_usage(struct messaging_context *msg_ctx)
{
	struct tevent_req *req = NULL;

	req = messaging_filtered_read_send(
		msg_ctx,
		messaging_tevent_context(msg_ctx),
		msg_ctx,
		pool_usage_filter,
		NULL);
	if (req == NULL) {
		DBG_WARNING("messaging_filtered_read_send failed\n");
		return;
	}
	tevent_req_set_callback(req, msg_pool_usage_do, msg_ctx);
	DEBUG(2, ("Registered MSG_REQ_POOL_USAGE\n"));
}
