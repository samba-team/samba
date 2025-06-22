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
static NTSTATUS copy_current_records(TALLOC_CTX *mem_ctx,
				     struct ldb_message_element *old_el,
				     struct ldb_message_element *el,
				     uint32_t dns_timestamp)
{
	unsigned int i;
	struct dnsp_DnssrvRpcRecord rec;
	enum ndr_err_code ndr_err;

	el->values = talloc_zero_array(mem_ctx, struct ldb_val,
				       old_el->num_values);
	if (el->values == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < old_el->num_values; i++) {
		ndr_err = ndr_pull_struct_blob(
		    &(old_el->values[i]),
		    mem_ctx,
		    &rec,
		    (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DBG_ERR("Failed to pull dns rec blob.\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
		if (rec.dwTimeStamp > dns_timestamp ||
		    rec.dwTimeStamp == 0) {
			el->values[el->num_values] = old_el->values[i];
			el->num_values++;
		}
	}

	return NT_STATUS_OK;
}

/*
 * Check all records in a zone and tombstone them if they're expired.
 */
static NTSTATUS dns_tombstone_records_zone(TALLOC_CTX *mem_ctx,
					   struct ldb_context *samdb,
					   struct dns_server_zone *zone,
					   uint32_t dns_timestamp,
					   NTTIME entombed_time,
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
	enum ndr_err_code ndr_err;
	int ret;
	struct GUID guid;
	struct GUID_txt_buf buf_guid;
	const char *attrs[] = {"dnsRecord",
			       "dNSTombstoned",
			       "objectGUID",
			       NULL};

	struct ldb_val true_val = {
		.data = discard_const_p(uint8_t, "TRUE"),
		.length = 4
	};

	struct ldb_val tombstone_blob;
	struct dnsp_DnssrvRpcRecord tombstone_struct = {
		.wType = DNS_TYPE_TOMBSTONE,
		.data = {.EntombedTime = entombed_time}
	};

	ndr_err = ndr_push_struct_blob(
	    &tombstone_blob,
	    mem_ctx,
	    &tombstone_struct,
	    (ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		*error_string = discard_const_p(char,
						"Failed to push TOMBSTONE"
						"dnsp_DnssrvRpcRecord\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

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
	dns_timestamp -= zi->dwNoRefreshInterval + zi->dwRefreshInterval;

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
			 ":=%"PRIu32")))",
			 dns_timestamp);
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
		new_msg = ldb_msg_copy(mem_ctx, res->msgs[i]);
		if (new_msg == NULL) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		/*
		 * This empty record will become the replacement for old_el.
		 * (we add it first because it reallocs).
		 */
		ret = ldb_msg_add_empty(
		    new_msg, "dnsRecord", LDB_FLAG_MOD_ADD, &el);
		if (ret != LDB_SUCCESS) {
			TALLOC_FREE(new_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		old_el = ldb_msg_find_element(new_msg, "dnsRecord");
		if (old_el == NULL || old_el == el) {
			TALLOC_FREE(new_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}
		old_el->flags = LDB_FLAG_MOD_DELETE;

		status = copy_current_records(new_msg, old_el, el, dns_timestamp);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(new_msg);
			return NT_STATUS_INTERNAL_ERROR;
		}

		/* If nothing was expired, do nothing. */
		if (el->num_values == old_el->num_values &&
		    el->num_values != 0) {
			TALLOC_FREE(new_msg);
			continue;
		}

		/*
		 * If everything was expired, we tombstone the node, which
		 * involves adding a tombstone dnsRecord and a 'dnsTombstoned:
		 * TRUE' attribute. That is, we want to end up with this:
		 *
		 *  objectClass: dnsNode
		 *  dnsRecord:  { .wType = DNSTYPE_TOMBSTONE,
		 *                .data.EntombedTime = <now> }
		 *  dnsTombstoned: TRUE
		 *
		 * and no other dnsRecords.
		 */
		if (el->num_values == 0) {
			struct ldb_val *vals = talloc_realloc(new_msg->elements,
							      el->values,
							      struct ldb_val,
							      1);
			if (!vals) {
				TALLOC_FREE(new_msg);
				return NT_STATUS_INTERNAL_ERROR;
			}
			el->values = vals;
			el->values[0] = tombstone_blob;
			el->num_values = 1;

			tombstone_el = ldb_msg_find_element(new_msg,
						  "dnsTombstoned");

			if (tombstone_el == NULL) {
				ret = ldb_msg_add_value(new_msg,
							"dnsTombstoned",
							&true_val,
							&tombstone_el);
				if (ret != LDB_SUCCESS) {
					TALLOC_FREE(new_msg);
					return NT_STATUS_INTERNAL_ERROR;
				}
				tombstone_el->flags = LDB_FLAG_MOD_ADD;
			} else {
				if (tombstone_el->num_values != 1) {
					vals = talloc_realloc(
						new_msg->elements,
						tombstone_el->values,
						struct ldb_val,
						1);
					if (!vals) {
						TALLOC_FREE(new_msg);
						return NT_STATUS_INTERNAL_ERROR;
					}
					tombstone_el->values = vals;
					tombstone_el->num_values = 1;
				}
				tombstone_el->flags = LDB_FLAG_MOD_REPLACE;
				tombstone_el->values[0] = true_val;
			}
		} else {
			/*
			 * Do not change the status of dnsTombstoned if we
			 * found any live records. If it exists, its value
			 * will be the harmless "FALSE", which is what we end
			 * up with when a tombstoned record is untombstoned.
			 * (in dns_common_replace).
			 */
			ldb_msg_remove_attr(new_msg,
					    "dnsTombstoned");
		}

		/* Set DN to the GUID in case the object was moved. */
		el = ldb_msg_find_element(new_msg, "objectGUID");
		if (el == NULL) {
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
			TALLOC_FREE(new_msg);
			*error_string =
			    talloc_asprintf(mem_ctx,
					    "Failed to modify dns record "
					    "in zone %s: %s",
					    ldb_dn_get_linearized(zone->dn),
					    ldb_errstring(samdb));
			return NT_STATUS_INTERNAL_ERROR;
		}
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
	uint32_t dns_timestamp;
	NTTIME entombed_time;
	TALLOC_CTX *tmp_ctx = NULL;
	time_t unix_now = time(NULL);

	unix_to_nt_time(&entombed_time, unix_now);
	dns_timestamp = unix_to_dns_timestamp(unix_now);

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = dns_common_zones(samdb, tmp_ctx, NULL, &zones);
	if (!NT_STATUS_IS_OK(ret)) {
		TALLOC_FREE(tmp_ctx);
		return ret;
	}

	for (z = zones; z; z = z->next) {
		ret = dns_tombstone_records_zone(tmp_ctx,
						 samdb,
						 z,
						 dns_timestamp,
						 entombed_time,
						 error_string);
		if (NT_STATUS_EQUAL(ret, NT_STATUS_PROPSET_NOT_FOUND)) {
			continue;
		} else if (!NT_STATUS_IS_OK(ret)) {
			TALLOC_FREE(tmp_ctx);
			return ret;
		}
	}
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * Delete all DNS tombstones that have been around for longer than the server
 * property 'dns_tombstone_interval' which we store in smb.conf, which
 * corresponds to DsTombstoneInterval in [MS-DNSP] 3.1.1.1.1 "DNS Server
 * Integer Properties".
 */
NTSTATUS dns_delete_tombstones(TALLOC_CTX *mem_ctx,
			       struct ldb_context *samdb,
			       char **error_string)
{
	struct dns_server_zone *zones = NULL;
	struct dns_server_zone *z = NULL;
	int ret, i;
	NTSTATUS status;
	uint32_t current_time;
	uint32_t tombstone_interval;
	uint32_t tombstone_hours;
	NTTIME tombstone_nttime;
	enum ndr_err_code ndr_err;
	struct ldb_result *res = NULL;
	TALLOC_CTX *tmp_ctx = NULL;
	struct loadparm_context *lp_ctx = NULL;
	struct ldb_message_element *el = NULL;
	struct dnsp_DnssrvRpcRecord rec = {0};
	const char *attrs[] = {"dnsRecord", "dNSTombstoned", NULL};

	current_time = unix_to_dns_timestamp(time(NULL));

	lp_ctx = (struct loadparm_context *)ldb_get_opaque(samdb, "loadparm");
	tombstone_interval = lpcfg_parm_ulong(lp_ctx, NULL,
					      "dnsserver",
					      "dns_tombstone_interval",
					      24 * 14);

	tombstone_hours = current_time - tombstone_interval;
	status = dns_timestamp_to_nt_time(&tombstone_nttime,
					  tombstone_hours);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("DNS timestamp exceeds NTTIME epoch.\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dns_common_zones(samdb, tmp_ctx, NULL, &zones);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	for (z = zones; z; z = z->next) {
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
			*error_string =
			    talloc_asprintf(mem_ctx,
					    "Failed to "
					    "search for tombstoned "
					    "dns objects in zone %s: %s",
					    ldb_dn_get_linearized(z->dn),
					    ldb_errstring(samdb));
			TALLOC_FREE(tmp_ctx);
			return NT_STATUS_INTERNAL_ERROR;
		}

		for (i = 0; i < res->count; i++) {
			struct ldb_message *msg = res->msgs[i];
			el = ldb_msg_find_element(msg, "dnsRecord");
			if (el == NULL) {
				DBG_ERR("The tombstoned dns node %s has no dns "
					"records, which should not happen.\n",
					ldb_dn_get_linearized(msg->dn)
					);
				continue;
			}
			/*
			 * Below we assume the element has one value, which we
			 * expect because when we tombstone a node we remove
			 * all the records except for the tombstone.
			 */
			if (el->num_values != 1) {
				DBG_ERR("The tombstoned dns node %s has %u "
					"dns records, expected one.\n",
					ldb_dn_get_linearized(msg->dn),
					el->num_values
					);
				continue;
			}

			ndr_err = ndr_pull_struct_blob(
			    el->values,
			    tmp_ctx,
			    &rec,
			    (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				TALLOC_FREE(tmp_ctx);
				DBG_ERR("Failed to pull dns rec blob.\n");
				return NT_STATUS_INTERNAL_ERROR;
			}

			if (rec.wType != DNS_TYPE_TOMBSTONE) {
				DBG_ERR("A tombstoned dnsNode has non-tombstoned"
					" records, which should not happen.\n");
				continue;
			}

			if (rec.data.EntombedTime > tombstone_nttime) {
				continue;
			}
			/*
			 * Between 4.9 and 4.14 in some places we saved the
			 * tombstone time as hours since the start of 1601,
			 * not in NTTIME ten-millionths of a second units.
			 *
			 * We can accommodate these bad values by noting that
			 * all the realistic timestamps in that measurement
			 * fall within the first *second* of NTTIME, that is,
			 * before 1601-01-01 00:00:01; and that these
			 * timestamps are not realistic for NTTIME timestamps.
			 *
			 * Calculation: there are roughly 365.25 * 24 = 8766
			 * hours per year, and < 500 years since 1601, so
			 * 4383000 would be a fine threshold. We round up to
			 * the crore-second (c. 2741CE) in honour of NTTIME.
			 */
			if ((rec.data.EntombedTime < 10000000) &&
			    (rec.data.EntombedTime > tombstone_hours)) {
				continue;
			}

			ret = dsdb_delete(samdb, msg->dn, 0);
			if (ret != LDB_ERR_NO_SUCH_OBJECT &&
			    ret != LDB_SUCCESS) {
				TALLOC_FREE(tmp_ctx);
				DBG_ERR("Failed to delete dns node \n");
				return NT_STATUS_INTERNAL_ERROR;
			}
		}

	}
	TALLOC_FREE(tmp_ctx);
	return NT_STATUS_OK;
}
