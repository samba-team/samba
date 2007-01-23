/* 
   Unix SMB/CIFS mplementation.
   DSDB replication service
   
   Copyright (C) Stefan Metzmacher 2007
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "dsdb/repl/drepl_service.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

static WERROR dreplsrv_init_creds(struct dreplsrv_service *service)
{
	NTSTATUS status;

	status = auth_system_session_info(service, &service->system_session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	return WERR_OK;
}

static WERROR dreplsrv_connect_samdb(struct dreplsrv_service *service)
{
	service->samdb = samdb_connect(service, service->system_session_info);
	if (!service->samdb) {
		return WERR_DS_SERVICE_UNAVAILABLE;
	}

	return WERR_OK;
}

static void dreplsrv_periodic_handler_te(struct event_context *ev, struct timed_event *te,
					 struct timeval t, void *ptr)
{
	struct dreplsrv_service *service = talloc_get_type(ptr, struct dreplsrv_service);
	WERROR status;

	service->periodic.te = NULL;

	status = dreplsrv_periodic_schedule(service, service->periodic.interval);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(service->task, win_errstr(status));
		return;
	}
}

WERROR dreplsrv_periodic_schedule(struct dreplsrv_service *service, uint32_t next_interval)
{
	TALLOC_CTX *tmp_mem;
	struct timed_event *new_te;
	struct timeval next_time;

	/* prevent looping */
	if (next_interval == 0) next_interval = 1;

	next_time = timeval_current_ofs(next_interval, 5000);

	if (service->periodic.te) {
		/*
		 * if the timestamp of the new event is higher,
		 * as current next we don't need to reschedule
		 */
		if (timeval_compare(&next_time, &service->periodic.next_event) > 0) {
			return WERR_OK;
		}
	}

	/* reset the next scheduled timestamp */
	service->periodic.next_event = next_time;

	new_te = event_add_timed(service->task->event_ctx, service,
			         service->periodic.next_event,
			         dreplsrv_periodic_handler_te, service);
	W_ERROR_HAVE_NO_MEMORY(new_te);

	tmp_mem = talloc_new(service);
	DEBUG(4,("dreplsrv_periodic_schedule(%u) %sscheduled for: %s\n",
		next_interval,
		(service->periodic.te?"re":""),
		nt_time_string(tmp_mem, timeval_to_nttime(&next_time))));
	talloc_free(tmp_mem);

	talloc_free(service->periodic.te);
	service->periodic.te = new_te;

	return WERR_OK;
}
/*
  startup the dsdb replicator service task
*/
static void dreplsrv_task_init(struct task_server *task)
{
	WERROR status;
	struct dreplsrv_service *service;

	switch (lp_server_role()) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "dreplsrv: no DSDB replication required in standalone configuration");
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "dreplsrv: no DSDB replication required in domain member configuration");
		return;
	case ROLE_DOMAIN_CONTROLLER:
		/* Yes, we want DSDB replication */
		break;
	}

	task_server_set_title(task, "task[dreplsrv]");

	service = talloc_zero(task, struct dreplsrv_service);
	if (!service) {
		task_server_terminate(task, "dreplsrv_task_init: out of memory");
		return;
	}
	service->task		= task;
	service->startup_time	= timeval_current();
	task->private		= service;

	status = dreplsrv_init_creds(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to obtain server credentials: %s\n",
				      win_errstr(status)));
		return;
	}

	status = dreplsrv_connect_samdb(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to connect to local samdb: %s\n",
				      win_errstr(status)));
		return;
	}

	service->periodic.interval	= 30; /* in seconds */

	status = dreplsrv_periodic_schedule(service, service->periodic.interval);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to periodic schedule: %s\n",
				      win_errstr(status)));
		return;
	}

	irpc_add_name(task->msg_ctx, "dreplsrv");
}

/*
  initialise the dsdb replicator service
 */
static NTSTATUS dreplsrv_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, dreplsrv_task_init);
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_drepl_init(void)
{
	return register_server_service("drepl", dreplsrv_init);
}
