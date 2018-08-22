/*
   Unix SMB/CIFS implementation.

   run s3 file server within Samba4

   Copyright (C) Andrew Tridgell	2011

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
#include "dynconfig.h"
#include "nsswitch/winbind_client.h"

/*
  called if smbd exits
 */
static void file_server_smbd_done(struct tevent_req *subreq)
{
	struct task_server *task =
		tevent_req_callback_data(subreq,
		struct task_server);
	int sys_errno;
	int ret;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	if (ret != 0) {
		DEBUG(0,("file_server smbd daemon died with exit status %d\n", sys_errno));
	} else {
		DEBUG(0,("file_server smbd daemon exited normally\n"));
	}
	task_server_terminate(task, "smbd child process exited", true);
}


/*
  startup a copy of smbd as a child daemon
*/
static NTSTATUS s3fs_task_init(struct task_server *task)
{
	struct tevent_req *subreq;
	const char *smbd_path;
	const char *smbd_cmd[2] = { NULL, NULL };

	task_server_set_title(task, "task[s3fs_parent]");

	smbd_path = talloc_asprintf(task, "%s/smbd", dyn_SBINDIR);
	smbd_cmd[0] = smbd_path;

	/* the child should be able to call through nss_winbind */
	(void)winbind_on();
	/* start it as a child process */
	subreq = samba_runcmd_send(task, task->event_ctx, timeval_zero(), 1, 0,
				smbd_cmd,
				"-D",
				"--option=server role check:inhibit=yes",
				"--foreground",
				debug_get_output_is_stdout()?"--log-stdout":NULL,
				NULL);
	/* the parent should not be able to call through nss_winbind */
	if (!winbind_off()) {
		DEBUG(0,("Failed to re-disable recursive winbindd calls after forking smbd\n"));
		task_server_terminate(task, "Failed to re-disable recursive winbindd calls", true);
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (subreq == NULL) {
		DEBUG(0, ("Failed to start smbd as child daemon\n"));
		task_server_terminate(task, "Failed to startup s3fs smb task", true);
		return NT_STATUS_UNSUCCESSFUL;
	}

	tevent_req_set_callback(subreq, file_server_smbd_done, task);

	DEBUG(5,("Started file server child smbd\n"));

	return NT_STATUS_OK;
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_s3fs_init(TALLOC_CTX *);

NTSTATUS server_service_s3fs_init(TALLOC_CTX *ctx)
{
	struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = s3fs_task_init,
		.post_fork = NULL
	};
	return register_server_service(ctx, "s3fs", &details);
}
