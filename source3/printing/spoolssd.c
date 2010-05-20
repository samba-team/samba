/*
   Unix SMB/Netbios implementation.
   SPOOLSS Daemon
   Copyright (C) Simo Sorce 2010

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
#include "librpc/gen_ndr/messaging.h"
#include "include/printing.h"
#include "rpc_server/rpc_server.h"

#define SPOOLSS_PIPE_NAME "spoolss"

void start_spoolssd(void)
{
	pid_t pid;
	NTSTATUS status;
	int ret;

	DEBUG(1, ("Forking SPOOLSS Daemon\n"));

	pid = sys_fork();

	if (pid == -1) {
		DEBUG(0, ("Failed to fork SPOOLSS [%s], aborting ...\n",
			   strerror(errno)));
		exit(1);
	}

	if (pid) {
		/* parent */
		return;
	}

	/* child */
	status = reinit_after_fork(server_messaging_context(),
				   server_event_context(),
				   procid_self(), true);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		smb_panic("reinit_after_fork() failed");
	}

	smbd_setup_sig_term_handler();
	smbd_setup_sig_hup_handler();

	if (!serverid_register(procid_self(),
				FLAG_MSG_GENERAL|FLAG_MSG_SMBD
				|FLAG_MSG_PRINT_GENERAL)) {
		exit(1);
	}

	if (!locking_init()) {
		exit(1);
	}

	messaging_register(server_messaging_context(), NULL,
			   MSG_PRINTER_UPDATE, print_queue_receive);

	if (!setup_named_pipe_socket(SPOOLSS_PIPE_NAME, server_event_context())) {
		exit(1);
	}

	/* loop forever */
	ret = tevent_loop_wait(server_event_context());

	/* should not be reached */
	DEBUG(0,("background_queue: tevent_loop_wait() exited with %d - %s\n",
		 ret, (ret == 0) ? "out of events" : strerror(errno)));
	exit(1);
}
