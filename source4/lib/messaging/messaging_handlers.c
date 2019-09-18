/*
   Unix SMB/CIFS implementation.

   Handers for non core Samba internal messages

   Handlers for messages that are only included in developer and self test
   builds.

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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
#include "messaging/messaging.h"
#include "messaging/messaging_internal.h"

#if defined(DEVELOPER) || defined(ENABLE_SELFTEST)

/*
 * Inject a fault into the currently running process
 */
static void do_inject_fault(struct imessaging_context *msg,
			    void *private_data,
			    uint32_t msg_type,
			    struct server_id src,
			    size_t num_fds,
			    int *fds,
			    DATA_BLOB *data)
{
	int sig;
	struct server_id_buf tmp;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (data->length != sizeof(sig)) {
		DBG_ERR("Process %s sent bogus signal injection request\n",
			server_id_str_buf(src, &tmp));
		return;
	}

	sig = *(int *)data->data;
	if (sig == -1) {
		DBG_ERR("Process %s requested an iternal failure, "
			"calling exit(1)\n",
			server_id_str_buf(src, &tmp));
		exit(1);
	}

#if HAVE_STRSIGNAL
	DBG_ERR("Process %s requested injection of signal %d (%s)\n",
		server_id_str_buf(src, &tmp),
		sig,
		strsignal(sig));
#else
	DBG_ERR("Process %s requested injection of signal %d\n",
		server_id_str_buf(src, &tmp),
		sig);
#endif

	kill(getpid(), sig);
}

/*
 * Cause the current process to sleep for a specified number of seconds
 */
static void do_sleep(struct imessaging_context *msg,
		     void *private_data,
		     uint32_t msg_type,
		     struct server_id src,
		     size_t num_fds,
		     int *fds,
		     DATA_BLOB *data)
{
	unsigned int seconds;
	struct server_id_buf tmp;

	if (num_fds != 0) {
		DBG_WARNING("Received %zu fds, ignoring message\n", num_fds);
		return;
	}

	if (data->length != sizeof(seconds)) {
		DBG_ERR("Process %s sent bogus sleep request\n",
			server_id_str_buf(src, &tmp));
		return;
	}

	seconds = *(unsigned int *)data->data;
	DBG_ERR("Process %s requested a sleep of %u seconds\n",
		server_id_str_buf(src, &tmp),
		seconds);
	sleep(seconds);
	DBG_ERR("Restarting after %u second sleep requested by process %s\n",
		seconds,
		server_id_str_buf(src, &tmp));
}

/*
 * Register the extra messaging handlers
 */
NTSTATUS imessaging_register_extra_handlers(struct imessaging_context *msg)
{
	NTSTATUS status;

	status = imessaging_register(
	    msg, NULL, MSG_SMB_INJECT_FAULT, do_inject_fault);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = imessaging_register(msg, NULL, MSG_SMB_SLEEP, do_sleep);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

#endif /* defined(DEVELOPER) || defined(ENABLE_SELFTEST) */
