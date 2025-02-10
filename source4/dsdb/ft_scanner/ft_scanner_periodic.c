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
#include "samba/service.h"
#include "dsdb/ft_scanner/ft_scanner_service.h"
#include "dsdb/ft_scanner/ft_scanner_service_proto.h"
#include <ldb_errors.h>

static void ft_scanner_periodic_run(struct ft_scanner_service *service);

static void ft_scanner_periodic_handler_te(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval t,
					   void *ptr)
{
	struct ft_scanner_service *service =
		talloc_get_type_abort(ptr,
		struct ft_scanner_service);
	NTSTATUS status;

	service->periodic.te = NULL;

	ft_scanner_periodic_run(service);

	status = ft_scanner_periodic_schedule(service,
					      service->periodic.interval);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(service->task, nt_errstr(status), false);
		return;
	}
}

NTSTATUS ft_scanner_periodic_schedule(struct ft_scanner_service *service,
				      uint32_t next_interval)
{
	TALLOC_CTX *frame = NULL;
	struct tevent_timer *new_te = NULL;
	struct timeval next_time;

	/* prevent looping */
	if (next_interval == 0) next_interval = 1;

	next_time = timeval_current_ofs(next_interval, 50);

	if (service->periodic.te) {
		/*
		 * if the timestamp of the new event is higher,
		 * as current next we don't need to reschedule
		 */
		if (timeval_compare(&next_time, &service->periodic.next_event) > 0) {
			return NT_STATUS_OK;
		}
	}

	/* reset the next scheduled timestamp */
	service->periodic.next_event = next_time;

	new_te = tevent_add_timer(service->task->event_ctx, service,
			         service->periodic.next_event,
			         ft_scanner_periodic_handler_te, service);
	if (new_te == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	frame = talloc_stackframe();
	D_DEBUG("ft_scanner_periodic_schedule(%u) %sscheduled for: %s\n",
		next_interval,
		(service->periodic.te?"re":""),
		nt_time_string(frame, timeval_to_nttime(&next_time)));
	TALLOC_FREE(frame);

	TALLOC_FREE(service->periodic.te);
	service->periodic.te = new_te;

	return NT_STATUS_OK;
}

static void ft_scanner_periodic_run(struct ft_scanner_service *service)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	bool is_pdc;

	is_pdc = samdb_is_pdc(service->l_samdb);
	if (!is_pdc) {
		DBG_DEBUG("NO-OP: we are not the current PDC\n");
		TALLOC_FREE(frame);
		return;
	}

	DBG_DEBUG("Running ft_scanner_check_trusts()\n");
	status = ft_scanner_check_trusts(service);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("ft_scanner_check_trusts() => %s\n",
			    nt_errstr(status));
		TALLOC_FREE(frame);
		return;
	}
	DBG_DEBUG("ft_scanner_check_trusts() => %s\n",
		  nt_errstr(status));

	TALLOC_FREE(frame);
}
