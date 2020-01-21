/*
   Unix SMB/CIFS implementation.

   DNS tombstoning routines

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2018

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
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"
#include "lib/util/dlinklist.h"
#include "ldb.h"
#include "dsdb/kcc/scavenge_dns_records.h"
#include "lib/ldb-samba/ldb_matching_rules.h"
#include "lib/util/time.h"
#include "dns_server/dnsserver_common.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "param/param.h"

#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"

/*
 * Copy only non-expired dns records from one message element to another.
 */
NTSTATUS copy_current_records(TALLOC_CTX *mem_ctx,
			      struct ldb_message_element *old_el,
			      struct ldb_message_element *el,
			      NTTIME t)
{
	unsigned int i, num_kept = 0;
	struct dnsp_DnssrvRpcRecord *recs = NULL;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	recs = talloc_zero_array(
	    tmp_ctx, struct dnsp_DnssrvRpcRecord, el->num_values);
	if (recs == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < el->num_values; i++) {
		ndr_err = ndr_pull_struct_blob(
		    &(old_el->values[i]),
		    tmp_ctx,
		    &(recs[num_kept]),
		    (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(tmp_ctx);
			DBG_ERR("Failed to pull dns rec blob.\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
		if (recs[num_kept].dwTimeStamp > t ||
		    recs[num_kept].dwTimeStamp == 0) {
			num_kept++;
		}
	}

	if (num_kept == el->num_values) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_OK;
	}

	el->values = talloc_zero_array(mem_ctx, struct ldb_val, num_kept);
	if (el->values == NULL) {
		TALLOC_FREE(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	el->num_values = num_kept;
	for (i = 0; i < el->num_values; i++) {
		ndr_err = ndr_push_struct_blob(
		    &(el->values[i]),
		    mem_ctx,
		    &(recs[i]),
		    (ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(tmp_ctx);
			DBG_ERR("Failed to push dnsp_DnssrvRpcRecord\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * Check all records in a zone and tombstone them if they're expired.
 */
NTSTATUS dns_tombstone_records_zone(TALLOC_CTX *mem_ctx,
				    struct ldb_context *samdb,
				    struct dns_server_zone *zone,
				    struct ldb_val *true_struct,
				    struct ldb_val *tombstone_blob,
				    NTTIME t,
				    char **error_string)
{
	WERROR werr;
	NTSTATUS status;
	unsigned int i;
	struct dnsserver_zoneinfo *zi = NULL;
	struct ldb_result *res = NULL;
	struct ldb_message_element *el = NULL;
	struct ldb_message_element *tombstone_el = NULL;
	struct ldb_message_element *old_el = NULL;
	struct ldb_message *new_msg = NULL;
	struct ldb_message *old_msg = NULL;
	int ret;
	struct GUID guid;
	struct GUID_txt_buf buf_guid;
	const char *attrs[] = {"dnsRecord",
			       "dNSTombstoned",
			       "objectGUID",
			       NULL};

	*error_string = NULL;

	/* Get NoRefreshInterval and RefreshInterval from zone properties.*/
	zi = talloc(mem_ctx, struct dnsserver_zoneinfo);
	if (zi == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	werr = dns_get_zone_properties(samdb, mem_ctx, zone->dn, zi);
	if (W_ERROR_EQUAL(DNS_ERR(NOTZONE), werr)) {
		return NT_STATUS_PROPSET_NOT_FOUND;
	} else if (!W_ERROR_IS_OK(werr)) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* Subtract them from current time to get the earliest possible.
	 * timestamp allowed for a non-expired DNS record. */
	t -= zi->dwNoRefreshInterval + zi->dwRefreshInterval;

	/* Custom match gets dns records in the zone with dwTimeStamp < t. */
	ret = ldb_search(samdb,
			 mem_ctx,
			 &res,
			 zone->dn,
			 LDB_SCOPE_SUBTREE,
			 attrs,
			 "(&(objectClass=dnsNode)"
			 "(&(!(dnsTombstoned=TRUE))"
			 "(dnsRecord:" DSDB_MATCH_FOR_DNS_TO_TOMBSTONE_TIME
			 ":=%"PRIu64")))",
			 t);
	if (ret != LDB_SUCCESS) {
		*error_string = talloc_asprintf(mem_ctx,
						"Failed to search for dns "
						"objects in zone %s: %s",
						ldb_dn_get_linearized(zone->dn),
						ldb_errstring(samdb));
		return NT_STATUS_INTERNAL_ERROR;
	}

	/*
	 * Do a constrained update on each expired DNS node. To do a constrained
	 * update we leave the dnsRecord element as is, and just change the flag
	 * to MOD_DELETE, then add a new element with the changes we want.  LDB
	 * will run the deletion first, and bail out if a binary comparison
	 * between the attribute we pass and the one in the database shows a
	 * change.  This prevents race conditions.
	 */
	for (i = 0; i < res->count; i++) {
		old_msg = ldb_msg_copy(mem_ctx, res->msgs[i]);
		if (old_msg == NULL) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		old_el = ldb_msg_find_element(old_msg, "dnsRecord");
		if (old_el == NULL) {
			TALLOC_FREE(old_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		old_el->flags = LDB_FLAG_MOD_DELETE;
		new_msg = ldb_msg_copy(mem_ctx, old_msg);
		if (new_msg == NULL) {
			TALLOC_FREE(old_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		ret = ldb_msg_add_empty(
		    new_msg, "dnsRecord", LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		el->num_values = old_el->num_values;
		status = copy_current_records(mem_ctx, old_el, el, t);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* If nothing was expired, do nothing. */
		if (el->num_values == old_el->num_values &&
		    el->num_values != 0) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			continue;
		}

		el->flags = LDB_FLAG_MOD_ADD;

		/* If everything was expired, we tombstone the node. */
		if (el->num_values == 0) {
			el->values = tombstone_blob;
			el->num_values = 1;

			tombstone_el = ldb_msg_find_element(new_msg,
						  "dnsTombstoned");
			if (tombstone_el == NULL) {
				ret = ldb_msg_add_value(new_msg,
							"dnsTombstoned",
							true_struct,
							&tombstone_el);
				if (ret != LDB_SUCCESS) {
					TALLOC_FREE(old_msg);
					TALLOC_FREE(new_msg);
					return NT_STATUS_INTERNAL_ERROR;
				}
				tombstone_el->flags = LDB_FLAG_MOD_ADD;
			} else {
				tombstone_el->flags = LDB_FLAG_MOD_REPLACE;
				tombstone_el->values = true_struct;
			}
			tombstone_el->num_values = 1;
		} else {
			/*
			 * Do not change the status of dnsTombstoned
			 * if we found any live records
			 */
			ldb_msg_remove_attr(new_msg,
					    "dnsTombstoned");
		}

		/* Set DN to the GUID in case the object was moved. */
		el = ldb_msg_find_element(new_msg, "objectGUID");
		if (el == NULL) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			*error_string =
			    talloc_asprintf(mem_ctx,
					    "record has no objectGUID "
					    "in zone %s",
					    ldb_dn_get_linearized(zone->dn));
			return NT_STATUS_INTERNAL_ERROR;
		}

		status = GUID_from_ndr_blob(el->values, &guid);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			*error_string =
			    discard_const_p(char, "Error: Invalid GUID.\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		GUID_buf_string(&guid, &buf_guid);
		new_msg->dn =
		    ldb_dn_new_fmt(mem_ctx, samdb, "<GUID=%s>", buf_guid.buf);

		/* Remove the GUID so we're not trying to modify it. */
		ldb_msg_remove_attr(new_msg, "objectGUID");

		ret = ldb_modify(samdb, new_msg);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(old_msg);
			TALLOC_FREE(new_msg);
			*error_string =
			    talloc_asprintf(mem_ctx,
					    "Failed to modify dns record "
					    "in zone %s: %s",
					    ldb_dn_get_linearized(zone->dn),
					    ldb_errstring(samdb));
			return NT_STATUS_INTERNAL_ERROR;
		}
		TALLOC_FREE(old_msg);
		TALLOC_FREE(new_msg);
	}

	return NT_STATUS_OK;
}

/*
 * Tombstone all expired DNS records.
 */
NTSTATUS dns_tombstone_records(TALLOC_CTX *mem_ctx,
			       struct ldb_context *samdb,
			       char **error_string)
{
	struct dns_server_zone *zones = NULL;
	struct dns_server_zone *z = NULL;
	NTSTATUS ret;
	struct dnsp_DnssrvRpcRecord tombstone_struct;
	struct ldb_val tombstone_blob;
	struct ldb_val true_struct;
	NTTIME t;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *tmp_ctx = NULL;
	uint8_t true_str[4] = "TRUE";

	unix_to_nt_time(&t, time(NULL));
	t /= 10 * 1000 * 1000;
	t /= 3600;

	tombstone_struct = (struct dnsp_DnssrvRpcRecord){
	    .wType = DNS_TYPE_TOMBSTONE, .data = {.timestamp = t}};

	true_struct = (struct ldb_val){.data = true_str, .length = 4};

	ndr_err = ndr_push_struct_blob(
	    &tombstone_blob,
	    mem_ctx,
	    &tombstone_struct,
	    (ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		*error_string = discard_const_p(char,
						"Failed to push "
						"dnsp_DnssrvRpcRecord\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	dns_common_zones(samdb, mem_ctx, NULL, &zones);
	for (z = zones; z; z = z->next) {
		tmp_ctx = talloc_new(NULL);
		ret = dns_tombstone_records_zone(tmp_ctx,
						 samdb,
						 z,
						 &true_struct,
						 &tombstone_blob,
						 t,
						 error_string);
		TALLOC_FREE(tmp_ctx);
		if (NT_STATUS_EQUAL(ret, NT_STATUS_PROPSET_NOT_FOUND)) {
			continue;
		} else if (!NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}
	return NT_STATUS_OK;
}

/*
 * Delete all DNS tombstones that have been around for longer than the server
 * property 'DsTombstoneInterval' which we store in smb.conf
 */
NTSTATUS dns_delete_tombstones(TALLOC_CTX *mem_ctx,
			       struct ldb_context *samdb,
			       char **error_string)
{
	struct dns_server_zone *zones = NULL;
	struct dns_server_zone *z = NULL;
	int ret, i;
	NTTIME current_time;
	enum ndr_err_code ndr_err;
	struct ldb_result *res = NULL;
	int tombstone_time;
	TALLOC_CTX *tmp_ctx = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct ldb_message_element *el = NULL;
	struct dnsp_DnssrvRpcRecord *rec = NULL;
	const char *attrs[] = {"dnsRecord", "dNSTombstoned", NULL};
	rec = talloc_zero(mem_ctx, struct dnsp_DnssrvRpcRecord);

	unix_to_nt_time(&current_time, time(NULL));
	current_time /= 10 * 1000 * 1000;
	current_time /= 3600;

	lp_ctx = (struct loadparm_context *)ldb_get_opaque(samdb, "loadparm");
	tombstone_time =
	    current_time -
	    lpcfg_parm_int(
		lp_ctx, NULL, "dnsserver", "dns_tombstone_interval", 24 * 14);

	dns_common_zones(samdb, mem_ctx, NULL, &zones);
	for (z = zones; z; z = z->next) {
		tmp_ctx = talloc_new(NULL);
		if (tmp_ctx == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * This can load a very large set, but on the
		 * assumption that the number of tombstones is
		 * relatively small compared with the number of active
		 * records, and that this is an indexed lookup, this
		 * should be OK.  We can make a match rule if
		 * returning the set of tombstones becomes an issue.
		 */

		ret = ldb_search(samdb,
				 tmp_ctx,
				 &res,
				 z->dn,
				 LDB_SCOPE_SUBTREE,
				 attrs,
				 "(&(objectClass=dnsNode)(dNSTombstoned=TRUE))");

		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(tmp_ctx);
			*error_string =
			    talloc_asprintf(mem_ctx,
					    "Failed to "
					    "search for tombstoned "
					    "dns objects in zone %s: %s",
					    ldb_dn_get_linearized(z->dn),
					    ldb_errstring(samdb));
			return NT_STATUS_INTERNAL_ERROR;
		}

		for (i = 0; i < res->count; i++) {
			el = ldb_msg_find_element(res->msgs[i], "dnsRecord");
			ndr_err = ndr_pull_struct_blob(
			    el->values,
			    tmp_ctx,
			    rec,
			    (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				TALLOC_FREE(tmp_ctx);
				DBG_ERR("Failed to pull dns rec blob.\n");
				return NT_STATUS_INTERNAL_ERROR;
			}

			if (rec->wType != DNS_TYPE_TOMBSTONE) {
				continue;
			}

			if (rec->data.timestamp > tombstone_time) {
				continue;
			}

			ret = dsdb_delete(samdb, res->msgs[i]->dn, 0);
			if (ret != LDB_ERR_NO_SUCH_OBJECT &&
			    ret != LDB_SUCCESS) {
				TALLOC_FREE(tmp_ctx);
				DBG_ERR("Failed to delete dns node \n");
				return NT_STATUS_INTERNAL_ERROR;
			}
		}

		TALLOC_FREE(tmp_ctx);
	}
	return NT_STATUS_OK;
}
