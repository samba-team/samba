/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "libcli/composite/composite.h"
#include "libcli/wrepl/winsrepl.h"
#include "wrepl_server/wrepl_out_helpers.h"

static uint32_t wreplsrv_periodic_run(struct wreplsrv_service *service, uint32_t next_interval)
{
	DEBUG(2,("wreplsrv_periodic_run: next in %u secs\n", next_interval));
	return next_interval;
}

static void wreplsrv_periodic_handler_te(struct event_context *ev, struct timed_event *te,
					 struct timeval t, void *ptr)
{
	struct wreplsrv_service *service = talloc_get_type(ptr, struct wreplsrv_service);
	uint32_t next_interval;

	service->periodic.te = NULL;

	next_interval = wreplsrv_periodic_run(service, service->config.periodic_interval);

	service->periodic.next_event = timeval_current_ofs(next_interval, 0);
	service->periodic.te = event_add_timed(service->task->event_ctx, service,
					       service->periodic.next_event,
					       wreplsrv_periodic_handler_te, service);
	if (!service->periodic.te) {
		task_server_terminate(service->task,"event_add_timed() failed! no memory!\n");
		return;
	}
}

NTSTATUS wreplsrv_setup_periodic(struct wreplsrv_service *service)
{
	NTSTATUS status;

	/*
	 * TODO: this should go away, and we should do everything
	 *        within the wreplsrv_periodic_run()
	 */
	status = wreplsrv_setup_out_connections(service);
	NT_STATUS_NOT_OK_RETURN(status);

	service->periodic.next_event = timeval_current();
	service->periodic.te = event_add_timed(service->task->event_ctx, service,
					       service->periodic.next_event,
					       wreplsrv_periodic_handler_te, service);
	NT_STATUS_HAVE_NO_MEMORY(service->periodic.te);

	return NT_STATUS_OK;
}
