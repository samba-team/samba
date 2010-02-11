/*
 Unix SMB/CIFS implementation.

 DRS Replica Information

 Copyright (C) Erick Nogueira do Nascimento 2009

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
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"


/*
  get cursors info for a specified DN
*/
static WERROR kccdrs_replica_get_info_cursors(TALLOC_CTX *mem_ctx,
					      struct ldb_context *samdb,
					      struct drsuapi_DsReplicaGetInfo *r,
					      union drsuapi_DsReplicaInfo *reply,
					      struct ldb_dn *dn)
{
	int ret;

	if (!ldb_dn_validate(dn)) {
		return WERR_INVALID_PARAMETER;
	}
	reply->cursors = talloc(mem_ctx, struct drsuapi_DsReplicaCursorCtr);
	W_ERROR_HAVE_NO_MEMORY(reply->cursors);

	reply->cursors->reserved = 0;

	ret = dsdb_load_udv_v1(samdb, dn, reply->cursors, &reply->cursors->array, &reply->cursors->count);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_BAD_NC;
	}
	return WERR_OK;
}

/*
  get cursors2 info for a specified DN
*/
static WERROR kccdrs_replica_get_info_cursors2(TALLOC_CTX *mem_ctx,
					       struct ldb_context *samdb,
					       struct drsuapi_DsReplicaGetInfo *r,
					       union drsuapi_DsReplicaInfo *reply,
					       struct ldb_dn *dn)
{
	int ret;

	if (!ldb_dn_validate(dn)) {
		return WERR_INVALID_PARAMETER;
	}
	reply->cursors2 = talloc(mem_ctx, struct drsuapi_DsReplicaCursor2Ctr);
	W_ERROR_HAVE_NO_MEMORY(reply->cursors2);

	ret = dsdb_load_udv_v2(samdb, dn, reply->cursors2, &reply->cursors2->array, &reply->cursors2->count);
	if (ret != LDB_SUCCESS) {
		return WERR_DS_DRA_BAD_NC;
	}

	reply->cursors2->enumeration_context = reply->cursors2->count;
	return WERR_OK;
}

/*
  get pending ops info for a specified DN
*/
static WERROR kccdrs_replica_get_info_pending_ops(TALLOC_CTX *mem_ctx,
						  struct ldb_context *samdb,
						  struct drsuapi_DsReplicaGetInfo *r,
						  union drsuapi_DsReplicaInfo *reply,
						  struct ldb_dn *dn)
{
	struct timeval now = timeval_current();

	if (!ldb_dn_validate(dn)) {
		return WERR_INVALID_PARAMETER;
	}
	reply->pendingops = talloc(mem_ctx, struct drsuapi_DsReplicaOpCtr);
	W_ERROR_HAVE_NO_MEMORY(reply->pendingops);

	/* claim no pending ops for now */
	reply->pendingops->time = timeval_to_nttime(&now);
	reply->pendingops->count = 0;
	reply->pendingops->array = NULL;

	return WERR_OK;
}

struct ncList {
	struct ldb_dn *dn;
	struct ncList *prev, *next;
};

/*
  Fill 'master_nc_list' with the master ncs hosted by this server
*/
static WERROR get_master_ncs(TALLOC_CTX *mem_ctx, struct ldb_context *samdb,
			     const char *ntds_guid_str, struct ncList **master_nc_list)
{
	const char *attrs[] = { "hasMasterNCs", NULL };
	struct ldb_result *res;
	struct ncList *nc_list = NULL;
	struct ncList *nc_list_elem;
	int ret;
	int i;
	char *nc_str;

	ret = ldb_search(samdb, mem_ctx, &res, ldb_get_config_basedn(samdb),
			LDB_SCOPE_DEFAULT, attrs, "(objectguid=%s)", ntds_guid_str);

	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed objectguid search - %s\n", ldb_errstring(samdb)));
		return WERR_INTERNAL_ERROR;
	}

	if (res->count == 0) {
		DEBUG(0,(__location__ ": Failed: objectguid=%s not found\n", ntds_guid_str));
		return WERR_INTERNAL_ERROR;
	}

	for (i = 0; i < res->count; i++) {
		struct ldb_message_element *msg_elem = ldb_msg_find_element(res->msgs[i], "hasMasterNCs");
		int k;

		if (!msg_elem || msg_elem->num_values == 0) {
			DEBUG(0,(__location__ ": Failed: Attribute hasMasterNCs not found - %s\n",
			      ldb_errstring(samdb)));
			return WERR_INTERNAL_ERROR;
		}

		for (k = 0; k < msg_elem->num_values; k++) {
			int len = msg_elem->values[k].length;

			/* copy the string on msg_elem->values[k]->data to nc_str */
			nc_str = talloc_array(mem_ctx, char, len);
			W_ERROR_HAVE_NO_MEMORY(nc_str);
			memcpy(nc_str, msg_elem->values[k].data, len);
			nc_str[len] = '\0';

			nc_list_elem = talloc_zero(mem_ctx, struct ncList);
			W_ERROR_HAVE_NO_MEMORY(nc_list_elem);
			nc_list_elem->dn = ldb_dn_new(mem_ctx, samdb, nc_str);
			W_ERROR_HAVE_NO_MEMORY(nc_list_elem);
			DLIST_ADD(nc_list, nc_list_elem);
		}

	}

	*master_nc_list = nc_list;
	return WERR_OK;
}

/*
  Fill 'nc_list' with the ncs list. (MS-DRSR 4.1.13.3)
  if the object dn is specified, fill 'nc_list' only with this dn
  otherwise, fill 'nc_list' with all master ncs hosted by this server
*/
static WERROR get_ncs_list(TALLOC_CTX *mem_ctx,
		struct ldb_context *samdb,
		struct kccsrv_service *service,
		const char *object_dn_str,
		struct ncList **nc_list)
{
	WERROR status;
	struct ncList *nc_list_elem;
	struct ldb_dn *nc_dn;

	if (object_dn_str != NULL) {
		/* ncs := { object_dn } */
		*nc_list = NULL;
		nc_dn = ldb_dn_new(mem_ctx, samdb, object_dn_str);
		nc_list_elem = talloc_zero(mem_ctx, struct ncList);
		W_ERROR_HAVE_NO_MEMORY(nc_list_elem);
		nc_list_elem->dn = nc_dn;
		DLIST_ADD_END(*nc_list, nc_list_elem, struct ncList*);
	} else {
		/* ncs := getNCs() from ldb database.
		 * getNCs() must return an array containing
		 * the DSNames of all NCs hosted by this
		 * server.
		 */
		char *ntds_guid_str = GUID_string(mem_ctx, &service->ntds_guid);
		W_ERROR_HAVE_NO_MEMORY(ntds_guid_str);
		status = get_master_ncs(mem_ctx, samdb, ntds_guid_str, nc_list);
		W_ERROR_NOT_OK_RETURN(status);
	}

	return WERR_OK;
}

/*
  Copy the fields from 'reps1' to 'reps2', leaving zeroed the fields on
  'reps2' that aren't available on 'reps1'.
*/
static WERROR copy_repsfrom_1_to_2(TALLOC_CTX *mem_ctx,
				 struct repsFromTo2 **reps2,
				 struct repsFromTo1 *reps1)
{
	struct repsFromTo2* reps;

	reps = talloc_zero(mem_ctx, struct repsFromTo2);
	W_ERROR_HAVE_NO_MEMORY(reps);

	reps->blobsize = reps1->blobsize;
	reps->consecutive_sync_failures = reps1->consecutive_sync_failures;
	reps->last_attempt = reps1->last_attempt;
	reps->last_success = reps1->last_success;
	reps->other_info = talloc_zero(mem_ctx, struct repsFromTo2OtherInfo);
	W_ERROR_HAVE_NO_MEMORY(reps->other_info);
	reps->other_info->dns_name1 = reps1->other_info->dns_name;
	reps->replica_flags = reps1->replica_flags;
	memcpy(reps->schedule, reps1->schedule, sizeof(reps1->schedule));
	reps->reserved = reps1->reserved;
	reps->highwatermark = reps1->highwatermark;
	reps->source_dsa_obj_guid = reps1->source_dsa_obj_guid;
	reps->source_dsa_invocation_id = reps1->source_dsa_invocation_id;
	reps->transport_guid = reps1->transport_guid;

	*reps2 = reps;
	return WERR_OK;
}

static WERROR fill_neighbor_from_repsFrom(TALLOC_CTX *mem_ctx,
					  struct ldb_context *samdb,
					  struct ldb_dn *nc_dn,
					  struct drsuapi_DsReplicaNeighbour *neigh,
					  struct repsFromTo2 *reps_from)
{
	struct ldb_dn *source_dsa_dn;
	int ret;
	char *dsa_guid_str;
	struct ldb_dn *transport_obj_dn = NULL;

	neigh->source_dsa_address = reps_from->other_info->dns_name1;
	neigh->replica_flags = reps_from->replica_flags;
	neigh->last_attempt = reps_from->last_attempt;
	neigh->source_dsa_obj_guid = reps_from->source_dsa_obj_guid;

	dsa_guid_str = GUID_string(mem_ctx, &reps_from->source_dsa_obj_guid);
	W_ERROR_HAVE_NO_MEMORY(dsa_guid_str);
	ret = dsdb_find_dn_by_guid(samdb, mem_ctx, dsa_guid_str, &source_dsa_dn);

	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find DN for neighbor GUID %s\n",
		      dsa_guid_str));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	neigh->source_dsa_obj_dn = ldb_dn_get_linearized(source_dsa_dn);
	neigh->naming_context_dn = ldb_dn_get_linearized(nc_dn);

	if (dsdb_find_guid_by_dn(samdb, nc_dn, &neigh->naming_context_obj_guid)
			!= LDB_SUCCESS) {
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	if (!GUID_all_zero(&reps_from->transport_guid)) {
		char *transp_guid_str = GUID_string(mem_ctx, &reps_from->transport_guid);
		W_ERROR_HAVE_NO_MEMORY(transp_guid_str);
		if (dsdb_find_dn_by_guid(samdb, mem_ctx, transp_guid_str,
					 &transport_obj_dn) != LDB_SUCCESS)
		{
			return WERR_DS_DRA_INTERNAL_ERROR;
		}
	}

	neigh->transport_obj_dn = ldb_dn_get_linearized(transport_obj_dn);
	neigh->source_dsa_invocation_id = reps_from->source_dsa_invocation_id;
	neigh->transport_obj_guid = reps_from->transport_guid;
	neigh->highest_usn = reps_from->highwatermark.highest_usn;
	neigh->tmp_highest_usn = reps_from->highwatermark.tmp_highest_usn;
	neigh->last_success = reps_from->last_success;
	neigh->result_last_attempt = reps_from->result_last_attempt;
	neigh->consecutive_sync_failures = reps_from->consecutive_sync_failures;
	neigh->reserved = 0; /* Unused. MUST be 0. */

	return WERR_OK;
}

/*
  Get the inbound neighbours of this DC
  See details on MS-DRSR 4.1.13.3, for infoType DS_REPL_INFO_NEIGHBORS
*/
static WERROR kccdrs_replica_get_info_neighbours(TALLOC_CTX *mem_ctx,
						 struct kccsrv_service *service,
						 struct ldb_context *samdb,
						 struct drsuapi_DsReplicaGetInfo *r,
						 union drsuapi_DsReplicaInfo *reply,
						 int base_index,
						 struct GUID req_src_dsa_guid,
						 const char *object_dn_str)
{
	WERROR status;
	int i, j;
	struct ldb_dn *nc_dn = NULL;
	struct ncList *p_nc_list = NULL;
	struct repsFromToBlob *reps_from_blob = NULL;
	struct repsFromTo2 *reps_from = NULL;
	uint32_t c_reps_from;
	int i_rep;
	struct drsuapi_DsReplicaNeighbour neigh;
	struct ncList *nc_list = NULL;

	status = get_ncs_list(mem_ctx, samdb, service, object_dn_str, &nc_list);
	W_ERROR_NOT_OK_RETURN(status);

	i = j = 0;

	reply->neighbours = talloc_zero(mem_ctx, struct drsuapi_DsReplicaNeighbourCtr);
	W_ERROR_HAVE_NO_MEMORY(reply->neighbours);
	reply->neighbours->reserved = 0;
	reply->neighbours->count = 0;

	/* foreach nc in ncs */
	for (p_nc_list = nc_list; p_nc_list != NULL; p_nc_list = p_nc_list->next) {

		nc_dn = p_nc_list->dn;

		/* load the nc's repsFromTo blob */
		status = dsdb_loadreps(samdb, mem_ctx, nc_dn, "repsFrom",
				&reps_from_blob, &c_reps_from);
		W_ERROR_NOT_OK_RETURN(status);

		/* foreach r in nc!repsFrom */
		for (i_rep = 0; i_rep < c_reps_from; i_rep++) {

			/* put all info on reps_from */
			if (reps_from_blob[i_rep].version == 1) {
				status = copy_repsfrom_1_to_2(mem_ctx, &reps_from,
							      &reps_from_blob[i_rep].ctr.ctr1);
				W_ERROR_NOT_OK_RETURN(status);
			} else { /* reps_from->version == 2 */
				reps_from = &reps_from_blob[i_rep].ctr.ctr2;
			}

			if (GUID_all_zero(&req_src_dsa_guid) ||
			    GUID_compare(&req_src_dsa_guid, &reps_from->source_dsa_obj_guid) == 0)
			{

				if (i >= base_index) {
					status = fill_neighbor_from_repsFrom(mem_ctx, samdb,
									     nc_dn, &neigh,
									     reps_from);
					W_ERROR_NOT_OK_RETURN(status);

					/* append the neighbour to the neighbours array */
					reply->neighbours->array = talloc_realloc(mem_ctx,
										    reply->neighbours->array,
										    struct drsuapi_DsReplicaNeighbour,
										    reply->neighbours->count + 1);
					reply->neighbours->array[reply->neighbours->count++] = neigh;
					j++;
				}

				i++;
			}
		}
	}

	return WERR_OK;
}

static WERROR fill_neighbor_from_repsTo(TALLOC_CTX *mem_ctx,
					struct ldb_context *samdb, struct ldb_dn *nc_dn,
					struct drsuapi_DsReplicaNeighbour *neigh,
					struct repsFromTo2 *reps_to)
{
	char *dsa_guid_str;
	int ret;
	struct ldb_dn *source_dsa_dn;

	neigh->source_dsa_address = reps_to->other_info->dns_name1;
	neigh->replica_flags = reps_to->replica_flags;
	neigh->last_attempt = reps_to->last_attempt;
	neigh->source_dsa_obj_guid = reps_to->source_dsa_obj_guid;

	dsa_guid_str = GUID_string(mem_ctx, &reps_to->source_dsa_obj_guid);
	W_ERROR_HAVE_NO_MEMORY(dsa_guid_str);

	ret = dsdb_find_dn_by_guid(samdb, mem_ctx, dsa_guid_str, &source_dsa_dn);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find DN for neighbor GUID %s\n",
			 dsa_guid_str));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	neigh->source_dsa_obj_dn = ldb_dn_get_linearized(source_dsa_dn);
	neigh->naming_context_dn = ldb_dn_get_linearized(nc_dn);

	ret = dsdb_find_guid_by_dn(samdb, nc_dn,
			&neigh->naming_context_obj_guid);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,(__location__ ": Failed to find GUID for DN %s\n",
			 ldb_dn_get_linearized(nc_dn)));
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	return WERR_OK;
}

/*
  Get the outbound neighbours of this DC
  See details on MS-DRSR 4.1.13.3, for infoType DS_REPL_INFO_REPSTO
*/
static WERROR kccdrs_replica_get_info_repsto(TALLOC_CTX *mem_ctx,
					     struct kccsrv_service *service,
					     struct ldb_context *samdb,
					     struct drsuapi_DsReplicaGetInfo *r,
					     union drsuapi_DsReplicaInfo *reply,
					     int base_index,
					     struct GUID req_src_dsa_guid,
					     const char *object_dn_str)
{
	WERROR status;
	int i, j;
	struct ncList *p_nc_list = NULL;
	struct ldb_dn *nc_dn = NULL;
	struct repsFromToBlob *reps_to_blob;
	struct repsFromTo2 *reps_to;
	uint32_t c_reps_to;
	int i_rep;
	struct drsuapi_DsReplicaNeighbour neigh;
	struct ncList *nc_list = NULL;

	status = get_ncs_list(mem_ctx, samdb, service, object_dn_str, &nc_list);
	W_ERROR_NOT_OK_RETURN(status);

	i = j = 0;

	reply->neighbours02 = talloc_zero(mem_ctx, struct drsuapi_DsReplicaNeighbourCtr);
	W_ERROR_HAVE_NO_MEMORY(reply->neighbours02);
	reply->neighbours02->reserved = 0;
	reply->neighbours02->count = 0;

	/* foreach nc in ncs */
	for (p_nc_list = nc_list; p_nc_list != NULL; p_nc_list = p_nc_list->next) {

		nc_dn = p_nc_list->dn;

		status = dsdb_loadreps(samdb, mem_ctx, nc_dn, "repsTo",
				&reps_to_blob, &c_reps_to);
		W_ERROR_NOT_OK_RETURN(status);

		/* foreach r in nc!repsTo */
		for (i_rep = 0; i_rep < c_reps_to; i_rep++) {

			/* put all info on reps_to */
			if (reps_to_blob[i_rep].version == 1) {
				status = copy_repsfrom_1_to_2(mem_ctx,
							      &reps_to,
							      &reps_to_blob[i_rep].ctr.ctr1);
				W_ERROR_NOT_OK_RETURN(status);
			} else { /* reps_to->version == 2 */
				reps_to = &reps_to_blob[i_rep].ctr.ctr2;
			}

			if (i >= base_index) {
				status = fill_neighbor_from_repsTo(mem_ctx,
								   samdb, nc_dn,
								   &neigh, reps_to);
				W_ERROR_NOT_OK_RETURN(status);

				/* append the neighbour to the neighbours array */
				reply->neighbours02->array = talloc_realloc(mem_ctx,
									    reply->neighbours02->array,
									    struct drsuapi_DsReplicaNeighbour,
									    reply->neighbours02->count + 1);
				reply->neighbours02->array[reply->neighbours02->count++] = neigh;
				j++;
			}
			i++;
		}
	}

	return WERR_OK;
}

NTSTATUS kccdrs_replica_get_info(struct irpc_message *msg,
				 struct drsuapi_DsReplicaGetInfo *req)
{
	WERROR status;
	struct drsuapi_DsReplicaGetInfoRequest1 *req1;
	struct drsuapi_DsReplicaGetInfoRequest2 *req2;
	int base_index;
	union drsuapi_DsReplicaInfo *reply;
	struct GUID req_src_dsa_guid;
	const char *object_dn_str = NULL;
	struct kccsrv_service *service;
	struct ldb_context *samdb;
	TALLOC_CTX *mem_ctx;
	enum drsuapi_DsReplicaInfoType info_type;

	service = talloc_get_type(msg->private_data, struct kccsrv_service);
	samdb = service->samdb;
	mem_ctx = talloc_new(msg);
	NT_STATUS_HAVE_NO_MEMORY(mem_ctx);

	NDR_PRINT_IN_DEBUG(drsuapi_DsReplicaGetInfo, req);

	/* check request version */
	if (req->in.level != DRSUAPI_DS_REPLICA_GET_INFO &&
	    req->in.level != DRSUAPI_DS_REPLICA_GET_INFO2)
	{
		DEBUG(1,(__location__ ": Unsupported DsReplicaGetInfo level %u\n",
			 req->in.level));
		status = WERR_REVISION_MISMATCH;
		goto done;
	}

	if (req->in.level == DRSUAPI_DS_REPLICA_GET_INFO) {
		req1 = &req->in.req->req1;
		base_index = 0;
		info_type = req1->info_type;
		object_dn_str = req1->object_dn;
		req_src_dsa_guid = req1->guid1;

	} else { /* r->in.level == DRSUAPI_DS_REPLICA_GET_INFO2 */
		req2 = &req->in.req->req2;
		if (req2->enumeration_context == 0xffffffff) {
			/* no more data is available */
			status = WERR_NO_MORE_ITEMS; /* on MS-DRSR it is ERROR_NO_MORE_ITEMS */
			goto done;
		}

		base_index = req2->enumeration_context;
		info_type = req2->info_type;
		object_dn_str = req2->object_dn;
		req_src_dsa_guid = req2->guid1;
	}

	/* allocate the reply and fill in some fields */
	reply = talloc_zero(mem_ctx, union drsuapi_DsReplicaInfo);
	NT_STATUS_HAVE_NO_MEMORY(reply);
	req->out.info = reply;
	req->out.info_type = talloc(mem_ctx, enum drsuapi_DsReplicaInfoType);
	NT_STATUS_HAVE_NO_MEMORY(req->out.info_type);
	*req->out.info_type = info_type;

	/* Based on the infoType requested, retrieve the corresponding
	 * information and construct the response message */
	switch (info_type) {

	case DRSUAPI_DS_REPLICA_INFO_NEIGHBORS:
		status = kccdrs_replica_get_info_neighbours(mem_ctx, service, samdb, req,
							    reply, base_index, req_src_dsa_guid,
							    object_dn_str);
		break;
	case DRSUAPI_DS_REPLICA_INFO_NEIGHBORS02: /* On MS-DRSR it is DS_REPL_INFO_REPSTO */
		status = kccdrs_replica_get_info_repsto(mem_ctx, service, samdb, req,
							reply, base_index, req_src_dsa_guid,
							object_dn_str);
		break;
	case DRSUAPI_DS_REPLICA_INFO_CURSORS: /* On MS-DRSR it is DS_REPL_INFO_CURSORS_FOR_NC */
		status = kccdrs_replica_get_info_cursors(mem_ctx, samdb, req, reply,
							 ldb_dn_new(mem_ctx, samdb, object_dn_str));
		break;
	case DRSUAPI_DS_REPLICA_INFO_CURSORS2: /* On MS-DRSR it is DS_REPL_INFO_CURSORS_2_FOR_NC */
		status = kccdrs_replica_get_info_cursors2(mem_ctx, samdb, req, reply,
							  ldb_dn_new(mem_ctx, samdb, object_dn_str));
		break;
	case DRSUAPI_DS_REPLICA_INFO_PENDING_OPS: /* On MS-DRSR it is DS_REPL_INFO_PENDING_OPS */
		status = kccdrs_replica_get_info_pending_ops(mem_ctx, samdb, req, reply,
							     ldb_dn_new(mem_ctx, samdb, object_dn_str));
		break;

	case DRSUAPI_DS_REPLICA_INFO_CURSORS3: /* On MS-DRSR it is DS_REPL_INFO_CURSORS_3_FOR_NC */
	case DRSUAPI_DS_REPLICA_INFO_CURSORS05: /* On MS-DRSR it is DS_REPL_INFO_UPTODATE_VECTOR_V1 */
	case DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA: /* On MS-DRSR it is DS_REPL_INFO_METADATA_FOR_OBJ */
	case DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA2: /* On MS-DRSR it is DS_REPL_INFO_METADATA_FOR_OBJ */
	case DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA: /* On MS-DRSR it is DS_REPL_INFO_METADATA_FOR_ATTR_VALUE */
	case DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA2: /* On MS-DRSR it is DS_REPL_INFO_METADATA_2_FOR_ATTR_VALUE */
	case DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES: /* On MS-DRSR it is DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES */
	case DRSUAPI_DS_REPLICA_INFO_KCC_DSA_LINK_FAILURES: /* On MS-DRSR it is DS_REPL_INFO_KCC_LINK_FAILURES */
	case DRSUAPI_DS_REPLICA_INFO_CONNECTIONS04: /* On MS-DRSR it is DS_REPL_INFO_CLIENT_CONTEXTS */
	case DRSUAPI_DS_REPLICA_INFO_06: /* On MS-DRSR it is DS_REPL_INFO_SERVER_OUTGOING_CALLS */
	default:
		DEBUG(1,(__location__ ": Unsupported DsReplicaGetInfo info_type %u\n",
			 info_type));
		status = WERR_INVALID_LEVEL;
		break;
	}

done:
	/* put the status on the result field of the reply */
	req->out.result = status;
	NDR_PRINT_OUT_DEBUG(drsuapi_DsReplicaGetInfo, req);
	return NT_STATUS_OK;
}
