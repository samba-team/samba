/*
   Unix SMB/CIFS Implementation.
   forest trust scanner service

   Copyright (C) Stefan Metzmacher 2025

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
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "samba/service.h"
#include "dsdb/ft_scanner/ft_scanner_service.h"
#include "dsdb/ft_scanner/ft_scanner_service_proto.h"
#include <ldb_errors.h>
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_irpc.h"
#include "param/param.h"
#include "libds/common/roles.h"

static NTSTATUS ft_scanner_connect_samdb(struct ft_scanner_service *service)
{
	struct auth_session_info *session_info = NULL;

	session_info = system_session(service->task->lp_ctx);
	if (session_info == NULL) {
		return NT_STATUS_DS_INIT_FAILURE;
	}

	service->l_samdb = samdb_connect(service,
					 service->task->event_ctx,
					 service->task->lp_ctx,
					 session_info,
					 NULL,
					 0);
	if (service->l_samdb == NULL) {
		return NT_STATUS_DS_UNAVAILABLE;
	}

	return NT_STATUS_OK;
}

/*
  startup the forest trust scanner service task
*/
static NTSTATUS ft_scanner_task_init(struct task_server *task)
{
	struct ft_scanner_service *service = NULL;
	uint32_t periodic_startup_interval;
	NTSTATUS status;
	bool am_rodc;
	int ret;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task,
				      "ft_scanner: no forest trust scanning "
				      "required in standalone configuration",
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task,
				      "ft_scanner: no forest trust scanning "
				      "required in domain member configuration",
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want forest trust scanning */
		break;
	}

	task_server_set_title(task, "task[ft_scanner]");

	service = talloc_zero(task, struct ft_scanner_service);
	if (!service) {
		task_server_terminate(task, "ft_scanner_task_init: out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}
	service->task		= task;
	service->startup_time	= timeval_current();
	task->private_data	= service;

	status = ft_scanner_connect_samdb(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "ft_scanner: Failed to connect to local samdb: %s\n",
				      nt_errstr(status)), true);
		return status;
	}

	ret = samdb_rodc(service->l_samdb, &am_rodc);
	if (ret != LDB_SUCCESS) {
		status = NT_STATUS_LDAP(ret);
		task_server_terminate(task, talloc_asprintf(task,
				      "ft_scanner: Failed to get rodc state: %s\n",
				      nt_errstr(status)), true);
		return status;
	}

	if (am_rodc) {
		task_server_terminate(task,
				      "ft_scanner: no forest trust scanning "
				      "required on RODC configuration",
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	}

	periodic_startup_interval = lpcfg_parm_int(task->lp_ctx,
						   NULL,
						   "ft_scanner",
						   "periodic_startup_interval",
						   15); /* in seconds */
	service->periodic.interval = lpcfg_parm_int(task->lp_ctx,
						    NULL,
						    "ft_scanner",
						    "periodic_interval",
						    900); /* in seconds */
	service->periodic.interval = MAX(service->periodic.interval, 60);

	status = ft_scanner_periodic_schedule(service, periodic_startup_interval);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "ft_scanner: Failed to periodic schedule: %s\n",
				      nt_errstr(status)), true);
		return status;
	}

	irpc_add_name(task->msg_ctx, "ft_scanner");

	return NT_STATUS_OK;
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_ft_scanner_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = ft_scanner_task_init,
		.post_fork = NULL,
	};
	return register_server_service(ctx, "ft_scanner", &details);
}
