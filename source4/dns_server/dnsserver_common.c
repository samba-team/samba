/*
   Unix SMB/CIFS implementation.

   DNS server utils

   Copyright (C) 2010 Kai Blin
   Copyright (C) 2014 Stefan Metzmacher

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
#include "libcli/util/ntstatus.h"
#include "libcli/util/werror.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dns_server/dnsserver_common.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

uint8_t werr_to_dns_err(WERROR werr)
{
	if (W_ERROR_EQUAL(WERR_OK, werr)) {
		return DNS_RCODE_OK;
	} else if (W_ERROR_EQUAL(DNS_ERR(FORMAT_ERROR), werr)) {
		return DNS_RCODE_FORMERR;
	} else if (W_ERROR_EQUAL(DNS_ERR(SERVER_FAILURE), werr)) {
		return DNS_RCODE_SERVFAIL;
	} else if (W_ERROR_EQUAL(DNS_ERR(NAME_ERROR), werr)) {
		return DNS_RCODE_NXDOMAIN;
	} else if (W_ERROR_EQUAL(WERR_DNS_ERROR_NAME_DOES_NOT_EXIST, werr)) {
		return DNS_RCODE_NXDOMAIN;
	} else if (W_ERROR_EQUAL(DNS_ERR(NOT_IMPLEMENTED), werr)) {
		return DNS_RCODE_NOTIMP;
	} else if (W_ERROR_EQUAL(DNS_ERR(REFUSED), werr)) {
		return DNS_RCODE_REFUSED;
	} else if (W_ERROR_EQUAL(DNS_ERR(YXDOMAIN), werr)) {
		return DNS_RCODE_YXDOMAIN;
	} else if (W_ERROR_EQUAL(DNS_ERR(YXRRSET), werr)) {
		return DNS_RCODE_YXRRSET;
	} else if (W_ERROR_EQUAL(DNS_ERR(NXRRSET), werr)) {
		return DNS_RCODE_NXRRSET;
	} else if (W_ERROR_EQUAL(DNS_ERR(NOTAUTH), werr)) {
		return DNS_RCODE_NOTAUTH;
	} else if (W_ERROR_EQUAL(DNS_ERR(NOTZONE), werr)) {
		return DNS_RCODE_NOTZONE;
	} else if (W_ERROR_EQUAL(DNS_ERR(BADKEY), werr)) {
		return DNS_RCODE_BADKEY;
	}
	DEBUG(5, ("No mapping exists for %s\n", win_errstr(werr)));
	return DNS_RCODE_SERVFAIL;
}

WERROR dns_common_extract(const struct ldb_message_element *el,
			  TALLOC_CTX *mem_ctx,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *num_records)
{
	uint16_t ri;
	struct dnsp_DnssrvRpcRecord *recs;

	*records = NULL;
	*num_records = 0;

	recs = talloc_zero_array(mem_ctx, struct dnsp_DnssrvRpcRecord,
				 el->num_values);
	if (recs == NULL) {
		return WERR_NOMEM;
	}
	for (ri = 0; ri < el->num_values; ri++) {
		struct ldb_val *v = &el->values[ri];
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob(v, recs, &recs[ri],
				(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(recs);
			DEBUG(0, ("Failed to grab dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}
	}
	*records = recs;
	*num_records = el->num_values;
	return WERR_OK;
}

WERROR dns_common_lookup(struct ldb_context *samdb,
			 TALLOC_CTX *mem_ctx,
			 struct ldb_dn *dn,
			 struct dnsp_DnssrvRpcRecord **records,
			 uint16_t *num_records,
			 bool *tombstoned)
{
	static const char * const attrs[] = {
		"dnsRecord",
		"dNSTombstoned",
		NULL
	};
	int ret;
	WERROR werr;
	struct ldb_message *msg = NULL;
	struct ldb_message_element *el;

	*records = NULL;
	*num_records = 0;

	if (tombstoned != NULL) {
		*tombstoned = false;
		ret = dsdb_search_one(samdb, mem_ctx, &msg, dn,
			LDB_SCOPE_BASE, attrs, 0,
			"(objectClass=dnsNode)");
	} else {
		ret = dsdb_search_one(samdb, mem_ctx, &msg, dn,
			LDB_SCOPE_BASE, attrs, 0,
			"(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))");
	}
	if (ret == LDB_ERR_NO_SUCH_OBJECT) {
		return WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
	}
	if (ret != LDB_SUCCESS) {
		/* TODO: we need to check if there's a glue record we need to
		 * create a referral to */
		return DNS_ERR(NAME_ERROR);
	}

	if (tombstoned != NULL) {
		*tombstoned = ldb_msg_find_attr_as_bool(msg,
					"dNSTombstoned", false);
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	if (el == NULL) {
		TALLOC_FREE(msg);
		if (tombstoned != NULL) {
			struct dnsp_DnssrvRpcRecord *recs;
			/*
			 * records produced by older Samba releases
			 * keep dnsNode objects without dnsRecord and
			 * without setting dNSTombstoned=TRUE.
			 *
			 * We just pretend they're tombstones.
			 */
			recs = talloc_array(mem_ctx,
					    struct dnsp_DnssrvRpcRecord,
					    1);
			if (recs == NULL) {
				return WERR_NOMEM;
			}
			recs[0] = (struct dnsp_DnssrvRpcRecord) {
				.wType = DNS_TYPE_TOMBSTONE,
				/*
				 * A value of timestamp != 0
				 * indicated that the object was already
				 * a tombstone, this will be used
				 * in dns_common_replace()
				 */
				.data.timestamp = 1,
			};

			*tombstoned = true;
			*records = recs;
			*num_records = 1;
			return WERR_OK;
		}
		return DNS_ERR(NAME_ERROR);
	}

	werr = dns_common_extract(el, mem_ctx, records, num_records);
	TALLOC_FREE(msg);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	return WERR_OK;
}

static int rec_cmp(const struct dnsp_DnssrvRpcRecord *r1,
		   const struct dnsp_DnssrvRpcRecord *r2)
{
	if (r1->wType != r2->wType) {
		/*
		 * The records are sorted with higher types first
		 */
		return r2->wType - r1->wType;
	}

	/*
	 * Then we need to sort from the oldest to newest timestamp
	 */
	return r1->dwTimeStamp - r2->dwTimeStamp;
}

WERROR dns_common_replace(struct ldb_context *samdb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  bool needs_add,
			  uint32_t serial,
			  struct dnsp_DnssrvRpcRecord *records,
			  uint16_t rec_count)
{
	struct ldb_message_element *el;
	uint16_t i;
	int ret;
	struct ldb_message *msg = NULL;
	bool was_tombstoned = false;
	bool become_tombstoned = false;

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn = dn;

	ret = ldb_msg_add_empty(msg, "dnsRecord", LDB_FLAG_MOD_REPLACE, &el);
	if (ret != LDB_SUCCESS) {
		return DNS_ERR(SERVER_FAILURE);
	}

	/*
	 * we have at least one value,
	 * which might be used for the tombstone marker
	 */
	el->values = talloc_zero_array(el, struct ldb_val, MAX(1, rec_count));
	if (rec_count > 0) {
		W_ERROR_HAVE_NO_MEMORY(el->values);

		/*
		 * We store a sorted list with the high wType values first
		 * that's what windows does. It also simplifies the
		 * filtering of DNS_TYPE_TOMBSTONE records
		 */
		TYPESAFE_QSORT(records, rec_count, rec_cmp);
	}

	for (i = 0; i < rec_count; i++) {
		struct ldb_val *v = &el->values[el->num_values];
		enum ndr_err_code ndr_err;

		if (records[i].wType == DNS_TYPE_TOMBSTONE) {
			if (records[i].data.timestamp != 0) {
				was_tombstoned = true;
			}
			continue;
		}

		records[i].dwSerial = serial;
		ndr_err = ndr_push_struct_blob(v, el->values, &records[i],
				(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to push dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}
		el->num_values++;
	}

	if (needs_add) {
		if (el->num_values == 0) {
			return WERR_OK;
		}

		ret = ldb_msg_add_string(msg, "objectClass", "dnsNode");
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}

		ret = ldb_add(samdb, msg);
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}

		return WERR_OK;
	}

	if (el->num_values == 0) {
		struct dnsp_DnssrvRpcRecord tbs;
		struct ldb_val *v = &el->values[el->num_values];
		enum ndr_err_code ndr_err;
		struct timeval tv;

		if (was_tombstoned) {
			/*
			 * This is already a tombstoned object.
			 * Just leave it instead of updating the time stamp.
			 */
			return WERR_OK;
		}

		tv = timeval_current();
		tbs = (struct dnsp_DnssrvRpcRecord) {
			.wType = DNS_TYPE_TOMBSTONE,
			.dwSerial = serial,
			.data.timestamp = timeval_to_nttime(&tv),
		};

		ndr_err = ndr_push_struct_blob(v, el->values, &tbs,
				(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to push dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}
		el->num_values++;

		become_tombstoned = true;
	}

	if (was_tombstoned || become_tombstoned) {
		ret = ldb_msg_add_empty(msg, "dNSTombstoned",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}

		ret = ldb_msg_add_fmt(msg, "dNSTombstoned", "%s",
				      become_tombstoned ? "TRUE" : "FALSE");
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}
	}

	ret = ldb_modify(samdb, msg);
	if (ret != LDB_SUCCESS) {
		NTSTATUS nt = dsdb_ldb_err_to_ntstatus(ret);
		return ntstatus_to_werror(nt);
	}

	return WERR_OK;
}
