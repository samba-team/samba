/* 
   Unix SMB/CIFS mplementation.
   KCC service periodic handling
   
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
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/messaging/irpc.h"
#include "dsdb/kcc/kcc_connection.h"
#include "dsdb/kcc/kcc_service.h"
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_irpc_c.h"
#include "param/param.h"
#include "dsdb/common/util.h"

/*
 * see if two repsFromToBlob blobs are for the same source DSA
 */
static bool kccsrv_same_source_dsa(struct repsFromToBlob *r1, struct repsFromToBlob *r2)
{
	return GUID_equal(&r1->ctr.ctr1.source_dsa_obj_guid,
			  &r2->ctr.ctr1.source_dsa_obj_guid);
}

/*
 * see if a repsFromToBlob is in a list
 */
static bool reps_in_list(struct repsFromToBlob *r, struct repsFromToBlob *reps, uint32_t count)
{
	uint32_t i;
	for (i=0; i<count; i++) {
		if (kccsrv_same_source_dsa(r, &reps[i])) {
			return true;
		}
	}
	return false;
}

/*
  make sure we only add repsFrom entries for DCs who are masters for
  the partition
 */
static bool check_MasterNC(struct kccsrv_partition *p, struct repsFromToBlob *r,
			   struct ldb_result *res)
{
	struct repsFromTo1 *r1 = &r->ctr.ctr1;
	struct GUID invocation_id = r1->source_dsa_invocation_id;
	unsigned int i, j;
	TALLOC_CTX *tmp_ctx;

	/* we are expecting only version 1 */
	SMB_ASSERT(r->version == 1);

	tmp_ctx = talloc_new(p);
	if (!tmp_ctx) {
		return false;
	}

	for (i=0; i<res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		struct ldb_message_element *el;
		struct ldb_dn *dn;

		struct GUID id2 = samdb_result_guid(msg, "invocationID");
		if (GUID_all_zero(&id2) ||
		    !GUID_equal(&invocation_id, &id2)) {
			continue;
		}

		el = ldb_msg_find_element(msg, "msDS-hasMasterNCs");
		if (!el || el->num_values == 0) {
			el = ldb_msg_find_element(msg, "hasMasterNCs");
			if (!el || el->num_values == 0) {
				continue;
			}
		}
		for (j=0; j<el->num_values; j++) {
			dn = ldb_dn_from_ldb_val(tmp_ctx, p->service->samdb, &el->values[j]);
			if (!ldb_dn_validate(dn)) {
				talloc_free(dn);
				continue;
			}
			if (ldb_dn_compare(dn, p->dn) == 0) {
				DEBUG(5,("%s %s match on %s in %s\n",
					 r1->other_info->dns_name,
					 el->name,
					 ldb_dn_get_linearized(dn),
					 ldb_dn_get_linearized(msg->dn)));
				talloc_free(tmp_ctx);
				return true;
			}
			talloc_free(dn);
		}
	}
	talloc_free(tmp_ctx);
	return false;
}

struct kccsrv_notify_drepl_server_state {
	struct dreplsrv_refresh r;
};

static void kccsrv_notify_drepl_server_done(struct tevent_req *subreq);

/**
 * Force dreplsrv to update its state as topology is changed
 */
static void kccsrv_notify_drepl_server(struct kccsrv_service *s,
				       TALLOC_CTX *mem_ctx)
{
	struct kccsrv_notify_drepl_server_state *state;
	struct dcerpc_binding_handle *irpc_handle;
	struct tevent_req *subreq;

	state = talloc_zero(s, struct kccsrv_notify_drepl_server_state);
	if (state == NULL) {
		return;
	}

	irpc_handle = irpc_binding_handle_by_name(state, s->task->msg_ctx,
						  "dreplsrv", &ndr_table_irpc);
	if (irpc_handle == NULL) {
		/* dreplsrv is not running yet */
		TALLOC_FREE(state);
		return;
	}

	subreq = dcerpc_dreplsrv_refresh_r_send(state, s->task->event_ctx,
						irpc_handle, &state->r);
	if (subreq == NULL) {
		TALLOC_FREE(state);
		return;
	}
	tevent_req_set_callback(subreq, kccsrv_notify_drepl_server_done, state);
}

static void kccsrv_notify_drepl_server_done(struct tevent_req *subreq)
{
	struct kccsrv_notify_drepl_server_state *state =
		tevent_req_callback_data(subreq,
		struct kccsrv_notify_drepl_server_state);

	dcerpc_dreplsrv_refresh_r_recv(subreq, state);
	TALLOC_FREE(subreq);

	/* we don't care about errors */
	TALLOC_FREE(state);
}

uint32_t kccsrv_replica_flags(struct kccsrv_service *s)
{
	if (s->am_rodc) {
		return DRSUAPI_DRS_INIT_SYNC |
			DRSUAPI_DRS_PER_SYNC |
			DRSUAPI_DRS_ADD_REF |
			DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING |
			DRSUAPI_DRS_GET_ALL_GROUP_MEMBERSHIP |
			DRSUAPI_DRS_NONGC_RO_REP;
	}
	return DRSUAPI_DRS_INIT_SYNC |
		DRSUAPI_DRS_PER_SYNC |
		DRSUAPI_DRS_ADD_REF |
		DRSUAPI_DRS_WRIT_REP;
}

/*
 * add any missing repsFrom structures to our partitions
 */
NTSTATUS kccsrv_add_repsFrom(struct kccsrv_service *s, TALLOC_CTX *mem_ctx,
			    struct repsFromToBlob *reps, uint32_t count,
			    struct ldb_result *res)
{
	struct kccsrv_partition *p;
	bool notify_dreplsrv = false;
	uint32_t replica_flags = kccsrv_replica_flags(s);

	/* update the repsFrom on all partitions */
	for (p=s->partitions; p; p=p->next) {
		struct repsFromToBlob *our_reps;
		uint32_t our_count;
		WERROR werr;
		uint32_t i, j;
		bool modified = false;

		werr = dsdb_loadreps(s->samdb, mem_ctx, p->dn, "repsFrom", &our_reps, &our_count);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed to load repsFrom from %s - %s\n", 
				 ldb_dn_get_linearized(p->dn), ldb_errstring(s->samdb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		/* see if the entry already exists */
		for (i=0; i<count; i++) {
			for (j=0; j<our_count; j++) {
				if (kccsrv_same_source_dsa(&reps[i], &our_reps[j])) {
					/* we already have this one -
					   check the replica_flags are right */
					if (replica_flags != our_reps[j].ctr.ctr1.replica_flags) {
						/* we need to update the old one with
						 * the new flags
						 */
						our_reps[j].ctr.ctr1.replica_flags = replica_flags;
						modified = true;
					}
					break;
				}
			}
			if (j == our_count) {
				/* we don't have the new one - add it
				 * if it is a master
				 */
				if (res && !check_MasterNC(p, &reps[i], res)) {
					/* its not a master, we don't
					   want to pull from it */
					continue;
				}
				/* we need to add it to our repsFrom */
				our_reps = talloc_realloc(mem_ctx, our_reps, struct repsFromToBlob, our_count+1);
				NT_STATUS_HAVE_NO_MEMORY(our_reps);
				our_reps[our_count] = reps[i];
				our_reps[our_count].ctr.ctr1.replica_flags = replica_flags;
				our_count++;
				modified = true;
				DEBUG(4,(__location__ ": Added repsFrom for %s\n",
					 reps[i].ctr.ctr1.other_info->dns_name));
			}
		}

		/* remove any stale ones */
		for (i=0; i<our_count; i++) {
			if (!reps_in_list(&our_reps[i], reps, count) ||
			    (res && !check_MasterNC(p, &our_reps[i], res))) {
				DEBUG(4,(__location__ ": Removed repsFrom for %s\n",
					 our_reps[i].ctr.ctr1.other_info->dns_name));
				memmove(&our_reps[i], &our_reps[i+1], (our_count-(i+1))*sizeof(our_reps[0]));
				our_count--;
				i--;
				modified = true;
			}
		}

		if (modified) {
			werr = dsdb_savereps(s->samdb, mem_ctx, p->dn, "repsFrom", our_reps, our_count);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__ ": Failed to save repsFrom to %s - %s\n", 
					 ldb_dn_get_linearized(p->dn), ldb_errstring(s->samdb)));
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}
			/* dreplsrv should refresh its state */
			notify_dreplsrv = true;
		}

		/* remove stale repsTo entries */
		modified = false;
		werr = dsdb_loadreps(s->samdb, mem_ctx, p->dn, "repsTo", &our_reps, &our_count);
		if (!W_ERROR_IS_OK(werr)) {
			DEBUG(0,(__location__ ": Failed to load repsTo from %s - %s\n", 
				 ldb_dn_get_linearized(p->dn), ldb_errstring(s->samdb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		/* remove any stale ones */
		for (i=0; i<our_count; i++) {
			if (!reps_in_list(&our_reps[i], reps, count)) {
				DEBUG(4,(__location__ ": Removed repsTo for %s\n",
					 our_reps[i].ctr.ctr1.other_info->dns_name));
				memmove(&our_reps[i], &our_reps[i+1], (our_count-(i+1))*sizeof(our_reps[0]));
				our_count--;
				i--;
				modified = true;
			}
		}

		if (modified) {
			werr = dsdb_savereps(s->samdb, mem_ctx, p->dn, "repsTo", our_reps, our_count);
			if (!W_ERROR_IS_OK(werr)) {
				DEBUG(0,(__location__ ": Failed to save repsTo to %s - %s\n", 
					 ldb_dn_get_linearized(p->dn), ldb_errstring(s->samdb)));
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}
			/* dreplsrv should refresh its state */
			notify_dreplsrv = true;
		}
	}

	/* notify dreplsrv toplogy has changed */
	if (notify_dreplsrv) {
		kccsrv_notify_drepl_server(s, mem_ctx);
	}

	return NT_STATUS_OK;

}


/*
  form a unique list of DNs from a search result and a given set of attributes
 */
static int kccsrv_dn_list(struct ldb_context *ldb, struct ldb_result *res,
			  TALLOC_CTX *mem_ctx,
			  const char **attrs,
			  struct ldb_dn ***dn_list, int *dn_count)
{
	int i;
	struct ldb_dn **nc_list = NULL;
	int nc_count = 0;

	nc_list = talloc_array(mem_ctx, struct ldb_dn *, 0);
	if (nc_list == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	/* gather up a list of all NCs in this forest */
	for (i=0; i<res->count; i++) {
		struct ldb_message *msg = res->msgs[i];
		int j;
		for (j=0; attrs[j]; j++) {
			struct ldb_message_element *el;
			int k;

			el = ldb_msg_find_element(msg, attrs[j]);
			if (el == NULL) continue;
			for (k=0; k<el->num_values; k++) {
				struct ldb_dn *dn;
				dn = ldb_dn_from_ldb_val(nc_list, ldb, &el->values[k]);
				if (dn != NULL) {
					int l;
					for (l=0; l<nc_count; l++) {
						if (ldb_dn_compare(nc_list[l], dn) == 0) break;
					}
					if (l < nc_count) continue;
					nc_list = talloc_realloc(mem_ctx, nc_list, struct ldb_dn *, nc_count+1);
					if (nc_list == NULL) {
						return LDB_ERR_OPERATIONS_ERROR;
					}
					nc_list[nc_count] = dn;
					nc_count++;
				}
			}
		}
	}

	(*dn_list) = nc_list;
	(*dn_count) = nc_count;
	return LDB_SUCCESS;
}


/*
  look for any additional global catalog partitions that we should be
  replicating (by looking for msDS-HasDomainNCs), and add them to our
  hasPartialReplicaNCs NTDS attribute
 */
static int kccsrv_gc_update(struct kccsrv_service *s, struct ldb_result *res)
{
	int i;
	struct ldb_dn **nc_list = NULL;
	int nc_count = 0;
	struct ldb_dn **our_nc_list = NULL;
	int our_nc_count = 0;
	const char *attrs1[] = { "msDS-hasMasterNCs", "hasMasterNCs", "msDS-HasDomainNCs", NULL };
	const char *attrs2[] = { "msDS-hasMasterNCs", "hasMasterNCs", "msDS-HasDomainNCs", "hasPartialReplicaNCs", NULL };
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(res);
	struct ldb_result *res2;
	struct ldb_message *msg;

	/* get a complete list of NCs for the forest */
	ret = kccsrv_dn_list(s->samdb, res, tmp_ctx, attrs1, &nc_list, &nc_count);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to get NC list for GC update - %s\n", ldb_errstring(s->samdb)));
		talloc_free(tmp_ctx);
		return ret;
	}

	/* get a list of what NCs we are already replicating */
	ret = dsdb_search_dn(s->samdb, tmp_ctx, &res2, samdb_ntds_settings_dn(s->samdb, tmp_ctx), attrs2, 0);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to get our NC list attributes for GC update - %s\n", ldb_errstring(s->samdb)));
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = kccsrv_dn_list(s->samdb, res2, tmp_ctx, attrs2, &our_nc_list, &our_nc_count);
	if (ret != LDB_SUCCESS) {
		DEBUG(1,("Failed to get our NC list for GC update - %s\n", ldb_errstring(s->samdb)));
		talloc_free(tmp_ctx);
		return ret;
	}

	msg = ldb_msg_new(tmp_ctx);
	if (msg == NULL) {
		talloc_free(tmp_ctx);
		return LDB_ERR_OPERATIONS_ERROR;
	}
	msg->dn = res2->msgs[0]->dn;

	/* see if we are missing any */
	for (i=0; i<nc_count; i++) {
		int j;
		for (j=0; j<our_nc_count; j++) {
			if (ldb_dn_compare(nc_list[i], our_nc_list[j]) == 0) break;
		}
		if (j == our_nc_count) {
			/* its a new one */
			ret = ldb_msg_add_string(msg, "hasPartialReplicaNCs",
						 ldb_dn_get_extended_linearized(msg, nc_list[i], 1));
			if (ret != LDB_SUCCESS) {
				talloc_free(tmp_ctx);
				return ret;
			}

		}
	}

	if (msg->num_elements == 0) {
		/* none to add */
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	if (s->am_rodc) {
		DEBUG(5, ("%d partial replica should be added but we are RODC so we skip\n", msg->num_elements));
		talloc_free(tmp_ctx);
		return LDB_SUCCESS;
	}

	msg->elements[0].flags = LDB_FLAG_MOD_ADD;

	ret = dsdb_modify(s->samdb, msg, 0);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to add hasPartialReplicaNCs - %s\n",
			 ldb_errstring(s->samdb)));
	}

	talloc_free(tmp_ctx);
	return ret;
}


/*
  this is the core of our initial simple KCC
  We just add a repsFrom entry for all DCs we find that have nTDSDSA
  objects, except for ourselves
 */
NTSTATUS kccsrv_simple_update(struct kccsrv_service *s, TALLOC_CTX *mem_ctx)
{
	struct ldb_result *res;
	unsigned int i;
	int ret;
	const char *attrs[] = { "objectGUID", "invocationID", "msDS-hasMasterNCs", "hasMasterNCs", "msDS-HasDomainNCs", NULL };
	struct repsFromToBlob *reps = NULL;
	uint32_t count = 0;
	struct kcc_connection_list *ntds_conn, *dsa_conn;

	ret = dsdb_search(s->samdb, mem_ctx, &res, s->config_dn, LDB_SCOPE_SUBTREE,
			  attrs, DSDB_SEARCH_SHOW_EXTENDED_DN, "objectClass=nTDSDSA");
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed nTDSDSA search - %s\n", ldb_errstring(s->samdb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (samdb_is_gc(s->samdb)) {
		kccsrv_gc_update(s, res);
	}

	/* get the current list of connections */
	ntds_conn = kccsrv_find_connections(s, mem_ctx);

	dsa_conn = talloc_zero(mem_ctx, struct kcc_connection_list);

	for (i=0; i<res->count; i++) {
		struct repsFromTo1 *r1;
		struct GUID ntds_guid, invocation_id;

		ntds_guid = samdb_result_guid(res->msgs[i], "objectGUID");
		if (GUID_equal(&ntds_guid, &s->ntds_guid)) {
			/* don't replicate with ourselves */
			continue;
		}

		invocation_id = samdb_result_guid(res->msgs[i], "invocationID");

		reps = talloc_realloc(mem_ctx, reps, struct repsFromToBlob, count+1);
		NT_STATUS_HAVE_NO_MEMORY(reps);

		ZERO_STRUCT(reps[count]);
		reps[count].version = 1;
		r1 = &reps[count].ctr.ctr1;

		r1->other_info               = talloc_zero(reps, struct repsFromTo1OtherInfo);
		r1->other_info->dns_name     = samdb_ntds_msdcs_dns_name(s->samdb, reps, &ntds_guid);
		r1->source_dsa_obj_guid      = ntds_guid;
		r1->source_dsa_invocation_id = invocation_id;
		r1->replica_flags = kccsrv_replica_flags(s);
		memset(r1->schedule, 0x11, sizeof(r1->schedule));

		dsa_conn->servers = talloc_realloc(dsa_conn, dsa_conn->servers,
						  struct kcc_connection,
						  dsa_conn->count + 1);
		NT_STATUS_HAVE_NO_MEMORY(dsa_conn->servers);
		dsa_conn->servers[dsa_conn->count].dsa_guid = r1->source_dsa_obj_guid;
		dsa_conn->count++;

		count++;
	}

	kccsrv_apply_connections(s, ntds_conn, dsa_conn);

	return kccsrv_add_repsFrom(s, mem_ctx, reps, count, res);
}


static void kccsrv_periodic_run(struct kccsrv_service *service);

static void kccsrv_periodic_handler_te(struct tevent_context *ev, struct tevent_timer *te,
					 struct timeval t, void *ptr)
{
	struct kccsrv_service *service = talloc_get_type(ptr, struct kccsrv_service);
	WERROR status;

	service->periodic.te = NULL;

	kccsrv_periodic_run(service);

	status = kccsrv_periodic_schedule(service, service->periodic.interval);
	if (!W_ERROR_IS_OK(status)) {
		task_server_terminate(service->task, win_errstr(status), true);
		return;
	}
}

WERROR kccsrv_periodic_schedule(struct kccsrv_service *service, uint32_t next_interval)
{
	TALLOC_CTX *tmp_mem;
	struct tevent_timer *new_te;
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
			return WERR_OK;
		}
	}

	/* reset the next scheduled timestamp */
	service->periodic.next_event = next_time;

	new_te = tevent_add_timer(service->task->event_ctx, service,
			         service->periodic.next_event,
			         kccsrv_periodic_handler_te, service);
	W_ERROR_HAVE_NO_MEMORY(new_te);

	tmp_mem = talloc_new(service);
	DEBUG(4,("kccsrv_periodic_schedule(%u) %sscheduled for: %s\n",
		next_interval,
		(service->periodic.te?"re":""),
		nt_time_string(tmp_mem, timeval_to_nttime(&next_time))));
	talloc_free(tmp_mem);

	talloc_free(service->periodic.te);
	service->periodic.te = new_te;

	return WERR_OK;
}

static void kccsrv_periodic_run(struct kccsrv_service *service)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	DEBUG(4,("kccsrv_periodic_run(): update\n"));

	mem_ctx = talloc_new(service);

        if (service->samba_kcc_code)
		status = kccsrv_samba_kcc(service, mem_ctx);
	else {
		status = kccsrv_simple_update(service, mem_ctx);
		if (!NT_STATUS_IS_OK(status))
			DEBUG(0,("kccsrv_simple_update failed - %s\n",
				nt_errstr(status)));
	}

	status = kccsrv_check_deleted(service, mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("kccsrv_check_deleted failed - %s\n", nt_errstr(status)));
	}
	talloc_free(mem_ctx);
}

/* Called when samba_kcc script has finished
 */
static void samba_kcc_done(struct tevent_req *subreq)
{
        struct kccsrv_service *service =
		tevent_req_callback_data(subreq, struct kccsrv_service);
        int rc;
        int sys_errno;

        service->periodic.subreq = NULL;

	rc = samba_runcmd_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);

	if (rc != 0)
		service->periodic.status =
			map_nt_error_from_unix_common(sys_errno);
	else
		service->periodic.status = NT_STATUS_OK;

	if (!NT_STATUS_IS_OK(service->periodic.status))
		DEBUG(0,(__location__ ": Failed samba_kcc - %s\n",
			nt_errstr(service->periodic.status)));
	else
		DEBUG(3,("Completed samba_kcc OK\n"));
}

/* Invocation of the samba_kcc python script for replication
 * topology generation.
 */
NTSTATUS kccsrv_samba_kcc(struct kccsrv_service *service,
			TALLOC_CTX *ctxp)
{
	NTSTATUS status = NT_STATUS_OK;
	const char * const *samba_kcc_command =
		lpcfg_samba_kcc_command(service->task->lp_ctx);

	/* kill any existing child */
	TALLOC_FREE(service->periodic.subreq);

	DEBUG(2, ("Calling samba_kcc script\n"));
	service->periodic.subreq = samba_runcmd_send(service,
					service->task->event_ctx,
					timeval_current_ofs(40, 0),
					2, 0, samba_kcc_command, NULL);

        if (service->periodic.subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto xerror;
        }
        tevent_req_set_callback(service->periodic.subreq,
				samba_kcc_done, service);

xerror:
	if (!NT_STATUS_IS_OK(status))
		DEBUG(0,(__location__ ": failed - %s\n", nt_errstr(status)));
	return status;
}
