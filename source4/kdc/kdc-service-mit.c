/*
   Unix SMB/CIFS implementation.

   Start MIT krb5kdc server within Samba AD

   Copyright (c) 2014      Andreas Schneider <asn@samba.org>

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
#include "lib/util/samba_util.h"
#include "source4/smbd/service.h"
#include "source4/smbd/process_model.h"
#include "kdc/kdc-service-mit.h"
#include "dynconfig.h"
#include "libds/common/roles.h"

#include "source4/kdc/mit_kdc_irpc.h"

static void mitkdc_server_done(struct tevent_req *subreq);

/*
 * Startup a copy of the krb5kdc as a child daemon
 */
void mitkdc_task_init(struct task_server *task)
{
	struct tevent_req *subreq;
	const char * const *kdc_cmd;
	NTSTATUS status;

	task_server_set_title(task, "task[mitkdc_parent]");

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task,
				      "The KDC is not required in standalone "
				      "server configuration, terminate!",
				      false);
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task,
				      "The KDC is not required in member "
				      "server configuration",
				      false);
		return;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want to start the KDC */
		break;
	}

	/* start it as a child process */
	kdc_cmd = lpcfg_mit_kdc_command(task->lp_ctx);

	subreq = samba_runcmd_send(task,
				   task->event_ctx,
				   timeval_zero(),
				   1, /* stdout log level */
				   0, /* stderr log level */
				   kdc_cmd,
				   "-n", /* Don't go into background */
#if 0
				   "-w 2", /* Start two workers */
#endif
				   NULL);
	if (subreq == NULL) {
		DEBUG(0, ("Failed to start MIT KDC as child daemon\n"));

		task_server_terminate(task,
				      "Failed to startup mitkdc task",
				      true);
		return;
	}

	tevent_req_set_callback(subreq, mitkdc_server_done, task);

	DEBUG(5,("Started krb5kdc process\n"));

	status = samba_setup_mit_kdc_irpc(task);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task,
				      "Failed to setup kdc irpc service",
				      true);
	}

	DEBUG(5,("Started irpc service for kdc_server\n"));
}

/*
 * This gets called the kdc exits.
 */
static void mitkdc_server_done(struct tevent_req *subreq)
{
	struct task_server *task =
		tevent_req_callback_data(subreq,
		struct task_server);
	int sys_errno;
	int ret;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	if (ret != 0) {
		DEBUG(0, ("The MIT KDC daemon died with exit status %d\n",
			  sys_errno));
	} else {
		DEBUG(0,("The MIT KDC daemon exited normally\n"));
	}

	task_server_terminate(task, "mitkdc child process exited", true);
}

/* Called at MIT KRB5 startup - register ourselves as a server service */
NTSTATUS server_service_mitkdc_init(TALLOC_CTX *mem_ctx);

NTSTATUS server_service_mitkdc_init(TALLOC_CTX *mem_ctx)
{
	return register_server_service("kdc", mitkdc_task_init);
}
