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
#include "lib/util/talloc_report.h"

/**
 * Respond to a POOL_USAGE message by sending back string form of memory
 * usage stats.
 **/
static void msg_pool_usage(struct messaging_context *msg_ctx,
			   void *private_data, 
			   uint32_t msg_type, 
			   struct server_id src,
			   DATA_BLOB *data)
{
	char *report = NULL;
	int iov_size = 0;
	struct iovec iov[1];

	SMB_ASSERT(msg_type == MSG_REQ_POOL_USAGE);

	DEBUG(2,("Got POOL_USAGE\n"));

	report = talloc_report_str(msg_ctx, NULL);
	if (report != NULL) {
		iov[iov_size].iov_base = report;
		iov[iov_size].iov_len = talloc_get_size(report) - 1;
		iov_size++;
	}

	if (iov_size) {
		messaging_send_iov(msg_ctx,
				   src,
				   MSG_POOL_USAGE,
				   iov,
				   iov_size,
				   NULL,
				   0);
	}

	TALLOC_FREE(report);
}

/**
 * Register handler for MSG_REQ_POOL_USAGE
 **/
void register_msg_pool_usage(struct messaging_context *msg_ctx)
{
	messaging_register(msg_ctx, NULL, MSG_REQ_POOL_USAGE, msg_pool_usage);
	DEBUG(2, ("Registered MSG_REQ_POOL_USAGE\n"));
}	
