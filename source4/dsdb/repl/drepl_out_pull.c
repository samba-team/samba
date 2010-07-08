/* 
   Unix SMB/CIFS mplementation.
   DSDB replication service outgoing Pull-Replication
   
   Copyright (C) Stefan Metzmacher 2007
    
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
#include "smbd/service.h"
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "dsdb/repl/drepl_service.h"
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "libcli/composite/composite.h"
#include "libcli/security/dom_sid.h"

WERROR dreplsrv_schedule_partition_pull_source(struct dreplsrv_service *s,
					       struct dreplsrv_partition_source_dsa *source,
					       enum drsuapi_DsExtendedOperation extended_op,
					       uint64_t fsmo_info,
					       dreplsrv_fsmo_callback_t callback)
{
	struct dreplsrv_out_operation *op;

	op = talloc_zero(s, struct dreplsrv_out_operation);
	W_ERROR_HAVE_NO_MEMORY(op);

	op->service	= s;
	op->source_dsa	= source;
	op->extended_op = extended_op;
	op->fsmo_info   = fsmo_info;
	op->callback    = callback;

	DLIST_ADD_END(s->ops.pending, op, struct dreplsrv_out_operation *);

	return WERR_OK;
}

static WERROR dreplsrv_schedule_partition_pull(struct dreplsrv_service *s,
					       struct dreplsrv_partition *p,
					       TALLOC_CTX *mem_ctx)
{
	WERROR status;
	struct dreplsrv_partition_source_dsa *cur;

	for (cur = p->sources; cur; cur = cur->next) {
		status = dreplsrv_schedule_partition_pull_source(s, cur, DRSUAPI_EXOP_NONE, 0, NULL);
		W_ERROR_NOT_OK_RETURN(status);
	}

	return WERR_OK;
}

WERROR dreplsrv_schedule_pull_replication(struct dreplsrv_service *s, TALLOC_CTX *mem_ctx)
{
	WERROR status;
	struct dreplsrv_partition *p;

	for (p = s->partitions; p; p = p->next) {
		status = dreplsrv_schedule_partition_pull(s, p, mem_ctx);
		W_ERROR_NOT_OK_RETURN(status);
	}

	return WERR_OK;
}


/* force an immediate of the specified partition by GUID  */
WERROR dreplsrv_schedule_partition_pull_by_guid(struct dreplsrv_service *s, TALLOC_CTX *mem_ctx,
						struct GUID *guid)
{
	struct dreplsrv_partition *p;
	
	for (p = s->partitions; p; p = p->next) {
		if (GUID_compare(&p->nc.guid, guid) == 0) {
			return dreplsrv_schedule_partition_pull(s, p, mem_ctx);
		}
	}

	return WERR_NOT_FOUND;
}

/* force an immediate of the specified partition by Naming Context */
WERROR dreplsrv_schedule_partition_pull_by_nc(struct dreplsrv_service *s, TALLOC_CTX *mem_ctx,
					      struct drsuapi_DsReplicaObjectIdentifier *nc)
{
	struct dreplsrv_partition *p;
	bool valid_sid, valid_guid;
	struct dom_sid null_sid;
	ZERO_STRUCT(null_sid);

	valid_sid  = !dom_sid_equal(&null_sid, &nc->sid);
	valid_guid = !GUID_all_zero(&nc->guid);

	if (!valid_sid && !valid_guid && !nc->dn) {
		return WERR_DS_DRA_INVALID_PARAMETER;
	}

	for (p = s->partitions; p; p = p->next) {
		if ((valid_guid && GUID_equal(&p->nc.guid, &nc->guid))
		    || strequal(p->nc.dn, nc->dn)
		    || (valid_sid && dom_sid_equal(&p->nc.sid, &nc->sid))) {
			return dreplsrv_schedule_partition_pull(s, p, mem_ctx);
		}
	}

	return WERR_DS_DRA_BAD_NC;
}


static void dreplsrv_pending_op_callback(struct tevent_req *subreq)
{
	struct dreplsrv_out_operation *op = tevent_req_callback_data(subreq,
					    struct dreplsrv_out_operation);
	struct repsFromTo1 *rf = op->source_dsa->repsFrom1;
	struct dreplsrv_service *s = op->service;
	time_t t;
	NTTIME now;

	t = time(NULL);
	unix_to_nt_time(&now, t);

	rf->result_last_attempt = dreplsrv_op_pull_source_recv(subreq);
	TALLOC_FREE(subreq);
	if (W_ERROR_IS_OK(rf->result_last_attempt)) {
		rf->consecutive_sync_failures	= 0;
		rf->last_success		= now;
		DEBUG(3,("dreplsrv_op_pull_source(%s)\n",
			win_errstr(rf->result_last_attempt)));
		goto done;
	}

	rf->consecutive_sync_failures++;

	DEBUG(1,("dreplsrv_op_pull_source(%s/%s) for %s failures[%u]\n",
		 win_errstr(rf->result_last_attempt),
		 nt_errstr(werror_to_ntstatus(rf->result_last_attempt)),
		 ldb_dn_get_linearized(op->source_dsa->partition->dn),
		 rf->consecutive_sync_failures));

done:
	if (op->callback) {
		op->callback(s, rf->result_last_attempt, op->extended_ret);
	}
	talloc_free(op);
	s->ops.current = NULL;
	dreplsrv_run_pending_ops(s);
	dreplsrv_notify_run_ops(s);
}

void dreplsrv_run_pending_ops(struct dreplsrv_service *s)
{
	struct dreplsrv_out_operation *op;
	time_t t;
	NTTIME now;
	struct tevent_req *subreq;

	if (s->ops.current || s->ops.n_current) {
		/* if there's still one running, we're done */
		return;
	}

	if (!s->ops.pending) {
		/* if there're no pending operations, we're done */
		return;
	}

	t = time(NULL);
	unix_to_nt_time(&now, t);

	op = s->ops.pending;
	s->ops.current = op;
	DLIST_REMOVE(s->ops.pending, op);

	op->source_dsa->repsFrom1->last_attempt = now;

	subreq = dreplsrv_op_pull_source_send(op, s->task->event_ctx, op);
	if (!subreq) {
		struct repsFromTo1 *rf = op->source_dsa->repsFrom1;

		rf->result_last_attempt = WERR_NOMEM;
		rf->consecutive_sync_failures++;
		s->ops.current = NULL;

		DEBUG(1,("dreplsrv_op_pull_source(%s/%s) failures[%u]\n",
			win_errstr(rf->result_last_attempt),
			nt_errstr(werror_to_ntstatus(rf->result_last_attempt)),
			rf->consecutive_sync_failures));
		return;
	}
	tevent_req_set_callback(subreq, dreplsrv_pending_op_callback, op);
}
