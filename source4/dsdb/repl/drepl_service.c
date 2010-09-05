/* 
   Unix SMB/CIFS mplementation.
   DSDB replication service
   
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
#include "librpc/gen_ndr/ndr_irpc.h"
#include "param/param.h"

static WERROR dreplsrv_init_creds(struct dreplsrv_service *service)
{
	service->system_session_info = system_session(service->task->lp_ctx);
	if (service->system_session_info == NULL) {
		return WERR_NOMEM;
	}

	return WERR_OK;
}

static WERROR dreplsrv_connect_samdb(struct dreplsrv_service *service, struct loadparm_context *lp_ctx)
{
	const struct GUID *ntds_guid;
	struct drsuapi_DsBindInfo28 *bind_info28;

	service->samdb = samdb_connect(service, service->task->event_ctx, lp_ctx, service->system_session_info);
	if (!service->samdb) {
		return WERR_DS_UNAVAILABLE;
	}

	ntds_guid = samdb_ntds_objectGUID(service->samdb);
	if (!ntds_guid) {
		return WERR_DS_UNAVAILABLE;
	}

	service->ntds_guid = *ntds_guid;

	bind_info28				= &service->bind_info28;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_BASE;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V5;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7;
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT;
#if 0 /* we don't support XPRESS compression yet */
	bind_info28->supported_extensions	|= DRSUAPI_SUPPORTED_EXTENSION_XPRESS_COMPRESS;
#endif
	/* TODO: fill in site_guid */
	bind_info28->site_guid			= GUID_zero();
	/* TODO: find out how this is really triggered! */
	bind_info28->pid			= 0;
	bind_info28->repl_epoch			= 0;

	return WERR_OK;
}


/*
  DsReplicaSync messages from the DRSUAPI server are forwarded here
 */
static NTSTATUS drepl_replica_sync(struct irpc_message *msg, 
				   struct drsuapi_DsReplicaSync *r)
{
	WERROR werr;
	struct dreplsrv_partition *p;
	struct dreplsrv_partition_source_dsa *dsa;
	struct drsuapi_DsReplicaSyncRequest1 *req1;
	struct drsuapi_DsReplicaObjectIdentifier *nc;
	struct dreplsrv_service *service = talloc_get_type(msg->private_data,
							   struct dreplsrv_service);

#define REPLICA_SYNC_FAIL(_werr) do {r->out.result = _werr; goto done;} while(0)

	if (r->in.level != 1) {
		DEBUG(0,("%s: Level %d is not supported yet.\n",
			 __FUNCTION__, r->in.level));
		REPLICA_SYNC_FAIL(WERR_DS_DRA_INVALID_PARAMETER);
	}

	req1 = &r->in.req->req1;
	nc   = req1->naming_context;

	/* Check input parameters */
	if (!nc) {
		REPLICA_SYNC_FAIL(WERR_DS_DRA_INVALID_PARAMETER);
	}

	/* Find Naming context to be synchronized */
	werr = dreplsrv_partition_find_for_nc(service,
	                                      &nc->guid, &nc->sid, nc->dn,
	                                      &p);
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(0,("%s: failed to find NC for (%s, %s) - %s\n",
			 __FUNCTION__,
			 GUID_string(msg, &nc->guid),
			 nc->dn,
			 win_errstr(werr)));
		REPLICA_SYNC_FAIL(werr);
	}

	/* collect source DSAs to sync with */
	if (req1->options & DRSUAPI_DRS_SYNC_ALL) {
		for (dsa = p->sources; dsa; dsa = dsa->next) {
			/* schedule replication item */
			werr = dreplsrv_schedule_partition_pull_source(service, dsa,
			                                               DRSUAPI_EXOP_NONE, 0,
			                                               NULL, NULL);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,("%s: failed setup of sync of partition (%s, %s, %s) - %s\n",
					 __FUNCTION__,
					 GUID_string(msg, &nc->guid),
					 nc->dn,
					 dsa->repsFrom1->other_info->dns_name,
					 win_errstr(werr)));
				REPLICA_SYNC_FAIL(werr);
			}
			/* log we've scheduled replication item */
			DEBUG(3,("%s: forcing sync of partition (%s, %s, %s)\n",
				 __FUNCTION__,
				 GUID_string(msg, &nc->guid),
				 nc->dn,
				 dsa->repsFrom1->other_info->dns_name));
		}
	} else {
		if (req1->options & DRSUAPI_DRS_SYNC_BYNAME) {
			/* client should pass at least valid string */
			if (!req1->source_dsa_dns) {
				REPLICA_SYNC_FAIL(WERR_DS_DRA_INVALID_PARAMETER);
			}

			werr = dreplsrv_partition_source_dsa_by_dns(p,
			                                            req1->source_dsa_dns,
			                                            &dsa);
		} else {
			/* client should pass at least some GUID */
			if (GUID_all_zero(&req1->source_dsa_guid)) {
				REPLICA_SYNC_FAIL(WERR_DS_DRA_INVALID_PARAMETER);
			}

			werr = dreplsrv_partition_source_dsa_by_guid(p,
			                                             &req1->source_dsa_guid,
			                                             &dsa);
		}
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("%s: Failed to locate source DSA %s for NC %s.\n",
				 __FUNCTION__,
				 (req1->options & DRSUAPI_DRS_SYNC_BYNAME)
					 ? req1->source_dsa_dns
					 : GUID_string(r, &req1->source_dsa_guid),
				 nc->dn));
			REPLICA_SYNC_FAIL(WERR_DS_DRA_NO_REPLICA);
		}

		/* schedule replication item */
		werr = dreplsrv_schedule_partition_pull_source(service, dsa,
		                                               DRSUAPI_EXOP_NONE, 0,
		                                               NULL, NULL);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,("%s: failed setup of sync of partition (%s, %s, %s) - %s\n",
				 __FUNCTION__,
				 GUID_string(msg, &nc->guid),
				 nc->dn,
				 dsa->repsFrom1->other_info->dns_name,
				 win_errstr(werr)));
			REPLICA_SYNC_FAIL(werr);
		}
		/* log we've scheduled replication item */
		DEBUG(3,("%s: forcing sync of partition (%s, %s, %s)\n",
			 __FUNCTION__,
			 GUID_string(msg, &nc->guid),
			 nc->dn,
			 dsa->repsFrom1->other_info->dns_name));
	}

	/* if we got here, everything is OK */
	r->out.result = WERR_OK;

	/* force execution of scheduled replications */
	dreplsrv_run_pending_ops(service);

done:
	return NT_STATUS_OK;
}

/**
 * Called when drplsrv should refresh its state.
 * For example, when KCC change topology, dreplsrv
 * should update its cache
 *
 * @param partition_dn If not empty/NULL, partition to update
 */
static NTSTATUS dreplsrv_refresh(struct irpc_message *msg,
				 struct dreplsrv_refresh *r)
{
	struct dreplsrv_service *s = talloc_get_type(msg->private_data,
						     struct dreplsrv_service);

	r->out.result = dreplsrv_refresh_partitions(s);

	return NT_STATUS_OK;
}

/*
  startup the dsdb replicator service task
*/
static void dreplsrv_task_init(struct task_server *task)
{
	WERROR status;
	struct dreplsrv_service *service;
	uint32_t periodic_startup_interval;
	bool am_rodc;
	int ret;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "dreplsrv: no DSDB replication required in standalone configuration", 
				      false);
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "dreplsrv: no DSDB replication required in domain member configuration", 
				      false);
		return;
	case ROLE_DOMAIN_CONTROLLER:
		/* Yes, we want DSDB replication */
		break;
	}

	task_server_set_title(task, "task[dreplsrv]");

	service = talloc_zero(task, struct dreplsrv_service);
	if (!service) {
		task_server_terminate(task, "dreplsrv_task_init: out of memory", true);
		return;
	}
	service->task		= task;
	service->startup_time	= timeval_current();
	task->private_data	= service;

	status = dreplsrv_init_creds(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to obtain server credentials: %s\n",
							    win_errstr(status)), true);
		return;
	}

	status = dreplsrv_connect_samdb(service, task->lp_ctx);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to connect to local samdb: %s\n",
							    win_errstr(status)), true);
		return;
	}

	status = dreplsrv_load_partitions(service);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to load partitions: %s\n",
							    win_errstr(status)), true);
		return;
	}

	periodic_startup_interval	= lpcfg_parm_int(task->lp_ctx, NULL, "dreplsrv", "periodic_startup_interval", 15); /* in seconds */
	service->periodic.interval	= lpcfg_parm_int(task->lp_ctx, NULL, "dreplsrv", "periodic_interval", 300); /* in seconds */

	status = dreplsrv_periodic_schedule(service, periodic_startup_interval);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(task, talloc_asprintf(task,
				      "dreplsrv: Failed to periodic schedule: %s\n",
							    win_errstr(status)), true);
		return;
	}

	/* if we are a RODC then we do not send DSReplicaSync*/
	ret = samdb_rodc(service->samdb, &am_rodc);
	if (ret == LDB_SUCCESS && !am_rodc) {
		service->notify.interval = lpcfg_parm_int(task->lp_ctx, NULL, "dreplsrv",
							   "notify_interval", 5); /* in seconds */
		status = dreplsrv_notify_schedule(service, service->notify.interval);
		if (!W_ERROR_IS_OK(status)) {
			task_server_terminate(task, talloc_asprintf(task,
						  "dreplsrv: Failed to setup notify schedule: %s\n",
									win_errstr(status)), true);
			return;
		}
	}

	irpc_add_name(task->msg_ctx, "dreplsrv");

	IRPC_REGISTER(task->msg_ctx, irpc, DREPLSRV_REFRESH, dreplsrv_refresh, service);
	IRPC_REGISTER(task->msg_ctx, drsuapi, DRSUAPI_DSREPLICASYNC, drepl_replica_sync, service);
	messaging_register(task->msg_ctx, service, MSG_DREPL_ALLOCATE_RID, dreplsrv_allocate_rid);
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_drepl_init(void)
{
	return register_server_service("drepl", dreplsrv_task_init);
}
