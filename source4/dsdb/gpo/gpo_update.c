/*
   Unix SMB/CIFS mplementation.
   GPO update service

   Copyright (C) Luke Morrison 2013

   Inspired by dns_updates.c written by Andrew Trigell 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/

*/

#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/messaging/irpc.h"
#include "param/param.h"
#include "system/filesys.h"
#include "dsdb/common/util.h"
#include "libcli/composite/composite.h"
#include "libcli/security/dom_sid.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "libds/common/roles.h"

struct gpoupdate_service {
	struct auth_session_info *system_session_info;
	struct task_server *task;

	/* status for periodic sysvol/GPO scan update - >sysvscan */
	struct {
		uint32_t interval;
		struct tevent_timer *te;
		struct tevent_req *subreq;
		NTSTATUS status;
	} sysvscan;
};

/*
Called when the sysvol scan has finished
*/
static void gpoupdate_sysvscan_done(struct tevent_req *subreq)
{
	struct gpoupdate_service *service = tevent_req_callback_data(subreq,
								     struct
								     gpoupdate_service);
	int ret;
	int sys_errno;

	service->sysvscan.subreq = NULL;

	ret = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		service->sysvscan.status =
		    map_nt_error_from_unix_common(sys_errno);
	} else {
		service->sysvscan.status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(service->sysvscan.status)) {
		DEBUG(0, (__location__ ": Failed GPO update - %s\n",
			  nt_errstr(service->sysvscan.status)));
	} else {
		DEBUG(3, ("Completed GPO update check OK\n"));
	}
}

static NTSTATUS gpoupdate_sysvscan_schedule(struct gpoupdate_service *service);

static void gpoupdate_scan_apply(struct gpoupdate_service *service);

static void gpoupdate_sysvscan_handler_te(struct tevent_context *ev,
					  struct tevent_timer *te,
					  struct timeval t, void *ptr)
{
	struct gpoupdate_service *service =
	    talloc_get_type(ptr, struct gpoupdate_service);

	gpoupdate_scan_apply(service);
	gpoupdate_sysvscan_schedule(service);
}

static NTSTATUS gpoupdate_sysvscan_schedule(struct gpoupdate_service *service)
{
	/*
	 * This is configured, default to 900 sec (15 mins) in
	 * gpoupdate_task_init via gpoupdate:config interval
	 */
	service->sysvscan.te =
	    tevent_add_timer(service->task->event_ctx, service,
			     timeval_current_ofs(service->sysvscan.interval, 0),
			     gpoupdate_sysvscan_handler_te, service);
	NT_STATUS_HAVE_NO_MEMORY(service->sysvscan.te);
	return NT_STATUS_OK;
}

static void gpoupdate_scan_apply(struct gpoupdate_service *service)
{
	const char *const *gpo_update_command =
	    lpcfg_gpo_update_command(service->task->lp_ctx);
	const char *smbconf = lpcfg_configfile(service->task->lp_ctx);
	/* /home/john/samba/samba/source4/scripting/bin/gpoupdate */
	TALLOC_FREE(service->sysvscan.subreq);
	DEBUG(3, ("Calling GPO update script\n"));
	service->sysvscan.subreq = samba_runcmd_send(service,
						     service->task->event_ctx,
						     timeval_current_ofs(20, 0),
						     2, 0,
						     gpo_update_command,
						     smbconf, NULL);
	if (service->sysvscan.subreq == NULL) {
		DEBUG(0,
		      (__location__
		       ": samba_runcmd_send() failed with no memory\n"));
		return;
	}
	tevent_req_set_callback(service->sysvscan.subreq,
				gpoupdate_sysvscan_done, service);
}

static void gpoupdate_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct gpoupdate_service *service;

	if (lpcfg_server_role(task->lp_ctx) != ROLE_ACTIVE_DIRECTORY_DC) {
		/* not useful for non-DC */
		return;
	}

	task_server_set_title(task, "task[gpoupdate]");

	service = talloc_zero(task, struct gpoupdate_service);
	if (!service) {
		task_server_terminate(task,
				      "gpoupdate_task_init: out of memory",
				      true);
		return;
	}
	service->task = task;
	task->private_data = service;

	service->system_session_info = system_session(service->task->lp_ctx);
	if (!service->system_session_info) {
		task_server_terminate(task,
				      "gpoupdate: Failed to obtain server credentials\n",
				      true);
		return;
	}

	service->sysvscan.interval = lpcfg_parm_int(task->lp_ctx, NULL, "gpoupdate", "config interval", 900);	/* in seconds */
	status = gpoupdate_sysvscan_schedule(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
							    "gpoupdate: Failed to update sysvol scan schedule: %s\n",
							    nt_errstr(status)),
				      true);
		return;
	}
}

NTSTATUS server_service_gpoupdate_init(TALLOC_CTX *ctx);

/*
  register ourselves as a available server
*/
NTSTATUS server_service_gpoupdate_init(TALLOC_CTX *ctx)
{
	struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true
	};
	return register_server_service(ctx, "gpoupdate",
				       gpoupdate_task_init,
				       &details);
}
