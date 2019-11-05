/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Bartlett 2011
   Copyright (C) Andrew Tridgell 1992-2002

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
#include "lib/util/server_id.h"
#include "librpc/gen_ndr/messaging.h"
#include "messages.h"
#include "lib/util/memory.h"

/* This is the Samba3-specific implementation of reopen_logs(), which
 * calls out to the s3 loadparm code, and means that we don't depend
 * on loadparm directly. */

bool reopen_logs(void)
{
	if (lp_loaded()) {
		struct debug_settings settings = {
			.max_log_size = lp_max_log_size(),
			.timestamp_logs = lp_timestamp_logs(),
			.debug_prefix_timestamp = lp_debug_prefix_timestamp(),
			.debug_hires_timestamp = lp_debug_hires_timestamp(),
			.debug_pid = lp_debug_pid(),
			.debug_uid = lp_debug_uid(),
			.debug_class = lp_debug_class(),
		};
		const struct loadparm_substitution *lp_sub =
			loadparm_s3_global_substitution();

		debug_set_logfile(lp_logfile(talloc_tos(), lp_sub));
		debug_parse_levels(lp_log_level(talloc_tos(), lp_sub));
		debug_set_settings(&settings,
				   lp_logging(talloc_tos(), lp_sub),
				   lp_syslog(),
				   lp_syslog_only());
	} else {
		/*
		 * Parameters are not yet loaded - configure debugging with
		 * reasonable defaults to enable logging for early
		 * startup failures.
		 */
		struct debug_settings settings = {
			.max_log_size = 5000,
			.timestamp_logs = true,
			.debug_prefix_timestamp = false,
			.debug_hires_timestamp = true,
			.debug_pid = false,
			.debug_uid = false,
			.debug_class = false,
		};
		debug_set_settings(&settings,
				   "file",
				   1,
				   false);
	}
	return reopen_logs_internal();
}

/****************************************************************************
 Receive a "set debug level" message.
****************************************************************************/

void debug_message(struct messaging_context *msg_ctx,
			  void *private_data,
			  uint32_t msg_type,
			  struct server_id src,
			  DATA_BLOB *data)
{
	const char *params_str = (const char *)data->data;

	/* Check, it's a proper string! */
	if (params_str[(data->length)-1] != '\0') {
		DEBUG(1, ("Invalid debug message from pid %u to pid %u\n",
			  (unsigned int)procid_to_pid(&src),
			  (unsigned int)getpid()));
		return;
	}

	DEBUG(3, ("INFO: Remote set of debug to `%s'  (pid %u from pid %u)\n",
		  params_str, (unsigned int)getpid(),
		  (unsigned int)procid_to_pid(&src)));

	debug_parse_levels(params_str);
}

/****************************************************************************
 Return current debug level.
****************************************************************************/

static void debuglevel_message(struct messaging_context *msg_ctx,
			       void *private_data, 
			       uint32_t msg_type, 
			       struct server_id src,
			       DATA_BLOB *data)
{
	char *message = debug_list_class_names_and_levels();
	struct server_id_buf tmp;

	if (!message) {
		DEBUG(0,("debuglevel_message - debug_list_class_names_and_levels returned NULL\n"));
		return;
	}

	DEBUG(1, ("INFO: Received REQ_DEBUGLEVEL message from PID %s\n",
		  server_id_str_buf(src, &tmp)));
	messaging_send_buf(msg_ctx, src, MSG_DEBUGLEVEL,
			   (uint8_t *)message, strlen(message) + 1);

	TALLOC_FREE(message);
}

static void debug_ringbuf_log(struct messaging_context *msg_ctx,
			      void *private_data,
			      uint32_t msg_type,
			      struct server_id src,
			      DATA_BLOB *data)
{
	char *log = debug_get_ringbuf();
	size_t logsize = debug_get_ringbuf_size();

	if (log == NULL) {
		log = discard_const_p(char, "*disabled*\n");
		logsize = strlen(log) + 1;
	}

	messaging_send_buf(msg_ctx, src, MSG_RINGBUF_LOG, (uint8_t *)log,
			   logsize);
}

void debug_register_msgs(struct messaging_context *msg_ctx)
{
	messaging_register(msg_ctx, NULL, MSG_DEBUG, debug_message);
	messaging_register(msg_ctx, NULL, MSG_REQ_DEBUGLEVEL,
			   debuglevel_message);
	messaging_register(msg_ctx, NULL, MSG_REQ_RINGBUF_LOG,
			   debug_ringbuf_log);
}
