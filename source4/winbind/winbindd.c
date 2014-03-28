/*
   Unix SMB/CIFS implementation.

   run s3 winbindd server within Samba4

   Copyright (C) Andrew Tridgell	2011
   Copyright (C) Andrew Bartlett	2014

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
#include "talloc.h"
#include "tevent.h"
#include "system/filesys.h"
#include "lib/param/param.h"
#include "source4/smbd/service.h"
#include "source4/smbd/process_model.h"
#include "file_server/file_server.h"
#include "dynconfig.h"
#include "nsswitch/winbind_client.h"

/*
  called if winbindd exits
 */
static void winbindd_done(struct tevent_req *subreq)
{
	struct task_server *task =
		tevent_req_callback_data(subreq,
		struct task_server);
	int sys_errno;
	int ret;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	if (ret != 0) {
		DEBUG(0,("winbindd daemon died with exit status %d\n", sys_errno));
	} else {
		DEBUG(0,("winbindd daemon exited normally\n"));
	}
	task_server_terminate(task, "winbindd child process exited", true);
}


/*
  startup a copy of winbindd as a child daemon
*/
static void winbindd_task_init(struct task_server *task)
{
	struct tevent_req *subreq;
	const char *winbindd_path;
	const char *winbindd_cmd[2] = { NULL, NULL };

	task_server_set_title(task, "task[winbindd_parent]");

	winbindd_path = talloc_asprintf(task, "%s/winbindd", dyn_SBINDIR);
	winbindd_cmd[0] = winbindd_path;

	/* start it as a child process */
	subreq = samba_runcmd_send(task, task->event_ctx, timeval_zero(), 1, 0,
				winbindd_cmd,
				"-D",
				"--option=server role check:inhibit=yes",
				"--foreground",
				debug_get_output_is_stdout()?"--stdout":NULL,
				NULL);
	if (subreq == NULL) {
		DEBUG(0, ("Failed to start winbindd as child daemon\n"));
		task_server_terminate(task, "Failed to startup winbindd task", true);
		return;
	}

	tevent_req_set_callback(subreq, winbindd_done, task);

	DEBUG(5,("Started file server child winbindd\n"));
}

/* called at winbindd startup - register ourselves as a server service */
NTSTATUS server_service_winbindd_init(void);

NTSTATUS server_service_winbindd_init(void)
{
	return register_server_service("winbindd", winbindd_task_init);
}
