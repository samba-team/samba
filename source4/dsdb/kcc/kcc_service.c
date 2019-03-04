/* 
   Unix SMB/CIFS mplementation.

   KCC service
   
   Copyright (C) Andrew Tridgell 2009
   based on repl service code
    
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
#include "dsdb/kcc/kcc_service.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "libds/common/roles.h"

/*
  establish system creds
 */
static WERROR kccsrv_init_creds(struct kccsrv_service *service)
{
	service->system_session_info = system_session(service->task->lp_ctx);
	if (!service->system_session_info) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	return WERR_OK;
}

/*
  connect to the local SAM
 */
static WERROR kccsrv_connect_samdb(struct kccsrv_service *service, struct loadparm_context *lp_ctx)
{
	const struct GUID *ntds_guid;

	service->samdb = samdb_connect(service,
				       service->task->event_ctx,
				       lp_ctx,
				       service->system_session_info,
				       NULL,
				       0);
	if (!service->samdb) {
		return WERR_DS_UNAVAILABLE;
	}

	ntds_guid = samdb_ntds_objectGUID(service->samdb);
	if (!ntds_guid) {
		DBG_ERR("Failed to determine own NTDS objectGUID\n");
		return WERR_DS_UNAVAILABLE;
	}

	service->ntds_guid = *ntds_guid;

	if (samdb_rodc(service->samdb, &service->am_rodc) != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to determine RODC status\n"));
		return WERR_DS_UNAVAILABLE;
	}

	return WERR_OK;
}


/*
  load our local partition list
 */
static WERROR kccsrv_load_partitions(struct kccsrv_service *s)
{
	struct ldb_dn *basedn;
	struct ldb_result *r;
	struct ldb_message_element *el;
	static const char *attrs[] = { "namingContexts", "configurationNamingContext", NULL };
	unsigned int i;
	int ret;

	basedn = ldb_dn_new(s, s->samdb, NULL);
	W_ERROR_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->samdb, s, &r, basedn, LDB_SCOPE_BASE, attrs,
			 "(objectClass=*)");
	talloc_free(basedn);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	} else if (r->count != 1) {
		talloc_free(r);
		return WERR_FOOBAR;
	}

	el = ldb_msg_find_element(r->msgs[0], "namingContexts");
	if (!el) {
		return WERR_FOOBAR;
	}

	for (i=0; i < el->num_values; i++) {
		const char *v = (const char *)el->values[i].data;
		struct ldb_dn *pdn;
		struct dsdb_ldb_dn_list_node *p;

		pdn = ldb_dn_new(s, s->samdb, v);
		if (!ldb_dn_validate(pdn)) {
			return WERR_FOOBAR;
		}

		p = talloc_zero(s, struct dsdb_ldb_dn_list_node);
		W_ERROR_HAVE_NO_MEMORY(p);

		p->dn = talloc_steal(p, pdn);

		DLIST_ADD(s->partitions, p);

		DEBUG(2, ("kccsrv_partition[%s] loaded\n", v));
	}

	el = ldb_msg_find_element(r->msgs[0], "configurationNamingContext");
	if (!el) {
		return WERR_FOOBAR;
	}
	s->config_dn = ldb_dn_new(s, s->samdb, (const char *)el->values[0].data);
	if (!ldb_dn_validate(s->config_dn)) {
		return WERR_FOOBAR;
	}

	talloc_free(r);

	return WERR_OK;
}


struct kcc_manual_runcmd_state {
	struct irpc_message *msg;
	struct drsuapi_DsExecuteKCC *r;
	struct kccsrv_service *service;
};


/*
 * Called when samba_kcc script has finished
 */
static void manual_samba_kcc_done(struct tevent_req *subreq)
{
	struct kcc_manual_runcmd_state *st =
		tevent_req_callback_data(subreq,
		struct kcc_manual_runcmd_state);
        int rc;
        int sys_errno;
	NTSTATUS status;

        st->service->periodic.subreq = NULL;

	rc = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);

	if (rc != 0) {
		status = map_nt_error_from_unix_common(sys_errno);
	} else {
		status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed manual run of samba_kcc - %s\n",
			nt_errstr(status)));
	} else {
		DEBUG(3,("Completed manual run of samba_kcc OK\n"));
	}

	if (!(st->r->in.req->ctr1.flags & DRSUAPI_DS_EXECUTE_KCC_ASYNCHRONOUS_OPERATION)) {
		irpc_send_reply(st->msg, status);
	}
}

static NTSTATUS kccsrv_execute_kcc(struct irpc_message *msg, struct drsuapi_DsExecuteKCC *r)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status = NT_STATUS_OK;
	struct kccsrv_service *service = talloc_get_type(msg->private_data, struct kccsrv_service);

	const char * const *samba_kcc_command;
	struct kcc_manual_runcmd_state *st;

	if (!service->samba_kcc_code) {
		mem_ctx = talloc_new(service);

		status = kccsrv_simple_update(service, mem_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("kccsrv_execute_kcc failed - %s\n",
				nt_errstr(status)));
		}
		talloc_free(mem_ctx);

		return NT_STATUS_OK;
	}

	/* Invocation of the samba_kcc python script for replication
	 * topology generation.
	 */

	samba_kcc_command =
		lpcfg_samba_kcc_command(service->task->lp_ctx);

	st = talloc(msg, struct kcc_manual_runcmd_state);
	if (st == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	st->msg = msg;
	st->r = r;
	st->service = service;

	/* don't run at the same time as an existing child */
	if (service->periodic.subreq) {
		status = NT_STATUS_DS_BUSY;
		return status;
	}

	DEBUG(2, ("Calling samba_kcc script\n"));
	service->periodic.subreq = samba_runcmd_send(service,
						     service->task->event_ctx,
						     timeval_current_ofs(40, 0),
						     2, 0, samba_kcc_command, NULL);

	if (service->periodic.subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		DEBUG(0,(__location__ ": failed - %s\n", nt_errstr(status)));
		return status;
	} else {
		tevent_req_set_callback(service->periodic.subreq,
					manual_samba_kcc_done, st);
	}

	if (r->in.req->ctr1.flags & DRSUAPI_DS_EXECUTE_KCC_ASYNCHRONOUS_OPERATION) {
		/* This actually means reply right away, let it run in the background */
	} else {
		/* mark the request as replied async, the caller wants to know when this is finished */
		msg->defer_reply = true;
	}
	return status;

}

static NTSTATUS kccsrv_replica_get_info(struct irpc_message *msg, struct drsuapi_DsReplicaGetInfo *r)
{
	return kccdrs_replica_get_info(msg, r);
}

/*
  startup the kcc service task
*/
static NTSTATUS kccsrv_task_init(struct task_server *task)
{
	WERROR status;
	struct kccsrv_service *service;
	uint32_t periodic_startup_interval;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "kccsrv: no KCC required in standalone configuration", false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "kccsrv: no KCC required in domain member configuration", false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want a KCC */
		break;
	}

	task_server_set_title(task, "task[kccsrv]");

	service = talloc_zero(task, struct kccsrv_service);
	if (!service) {
		task_server_terminate(task, "kccsrv_task_init: out of memory", true);
		return NT_STATUS_NO_MEMORY;
	}
	service->task		= task;
	service->startup_time	= timeval_current();
	task->private_data	= service;

	status = kccsrv_init_creds(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, 
				      talloc_asprintf(task,
						      "kccsrv: Failed to obtain server credentials: %s\n",
						      win_errstr(status)), true);
		return werror_to_ntstatus(status);
	}

	status = kccsrv_connect_samdb(service, task->lp_ctx);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "kccsrv: Failed to connect to local samdb: %s\n",
							    win_errstr(status)), true);
		return werror_to_ntstatus(status);
	}

	status = kccsrv_load_partitions(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "kccsrv: Failed to load partitions: %s\n",
							    win_errstr(status)), true);
		return werror_to_ntstatus(status);
	}

	periodic_startup_interval =
		lpcfg_parm_int(task->lp_ctx, NULL, "kccsrv",
			      "periodic_startup_interval", 15); /* in seconds */
	service->periodic.interval =
		lpcfg_parm_int(task->lp_ctx, NULL, "kccsrv",
			      "periodic_interval", 300); /* in seconds */

	/* (kccsrv:samba_kcc=true) will run newer samba_kcc replication
	 * topology generation code.
	 */
	service->samba_kcc_code = lpcfg_parm_bool(task->lp_ctx, NULL,
						"kccsrv", "samba_kcc", true);

	status = kccsrv_periodic_schedule(service, periodic_startup_interval);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "kccsrv: Failed to periodic schedule: %s\n",
							    win_errstr(status)), true);
		return werror_to_ntstatus(status);
	}

	irpc_add_name(task->msg_ctx, "kccsrv");

	IRPC_REGISTER(task->msg_ctx, drsuapi, DRSUAPI_DSEXECUTEKCC, kccsrv_execute_kcc, service);
	IRPC_REGISTER(task->msg_ctx, drsuapi, DRSUAPI_DSREPLICAGETINFO, kccsrv_replica_get_info, service);
	return NT_STATUS_OK;
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_kcc_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = true,
		.inhibit_pre_fork = true,
		.task_init = kccsrv_task_init,
		.post_fork = NULL
	};
	return register_server_service(ctx, "kcc", &details);
}
