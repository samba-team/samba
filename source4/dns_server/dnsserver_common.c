/*
   Unix SMB/CIFS implementation.

   DNS server utils

   Copyright (C) 2010 Kai Blin
   Copyright (C) 2014 Stefan Metzmacher
   Copyright (C) 2015 Andrew Bartlett

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
#include "rpc_server/dnsserver/dnsserver.h"
#include "lib/util/dlinklist.h"

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

WERROR dns_common_extract(struct ldb_context *samdb,
			  const struct ldb_message_element *el,
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
		return WERR_NOT_ENOUGH_MEMORY;
	}
	for (ri = 0; ri < el->num_values; ri++) {
		bool am_rodc;
		int ret;
		const char *dnsHostName = NULL;
		struct ldb_val *v = &el->values[ri];
		enum ndr_err_code ndr_err;
		ndr_err = ndr_pull_struct_blob(v, recs, &recs[ri],
				(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			TALLOC_FREE(recs);
			DEBUG(0, ("Failed to grab dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}

		/*
		 * In AD, except on an RODC (where we should list a random RWDC,
		 * we should over-stamp the MNAME with our own hostname
		 */
		if (recs[ri].wType != DNS_TYPE_SOA) {
			continue;
		}

		ret = samdb_rodc(samdb, &am_rodc);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Failed to confirm we are not an RODC: %s\n",
				  ldb_errstring(samdb)));
			return DNS_ERR(SERVER_FAILURE);
		}

		if (am_rodc) {
			continue;
		}

		ret = samdb_dns_host_name(samdb, &dnsHostName);
		if (ret != LDB_SUCCESS || dnsHostName == NULL) {
			DEBUG(0, ("Failed to get dnsHostName from rootDSE"));
			return DNS_ERR(SERVER_FAILURE);
		}

		recs[ri].data.soa.mname = talloc_strdup(recs, dnsHostName);
	}

	*records = recs;
	*num_records = el->num_values;
	return WERR_OK;
}

/*
 * Lookup a DNS record, performing an exact match.
 * i.e. DNS wild card records are not considered.
 */
WERROR dns_common_lookup(struct ldb_context *samdb,
			 TALLOC_CTX *mem_ctx,
			 struct ldb_dn *dn,
			 struct dnsp_DnssrvRpcRecord **records,
			 uint16_t *num_records,
			 bool *tombstoned)
{
	const struct timeval start = timeval_current();
	static const char * const attrs[] = {
		"dnsRecord",
		"dNSTombstoned",
		NULL
	};
	int ret;
	WERROR werr = WERR_OK;
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
		werr = WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
		goto exit;
	}
	if (ret != LDB_SUCCESS) {
		/* TODO: we need to check if there's a glue record we need to
		 * create a referral to */
		werr = DNS_ERR(NAME_ERROR);
		goto exit;
	}

	if (tombstoned != NULL) {
		*tombstoned = ldb_msg_find_attr_as_bool(msg,
					"dNSTombstoned", false);
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	if (el == NULL) {
		TALLOC_FREE(msg);
		/*
		 * records produced by older Samba releases
		 * keep dnsNode objects without dnsRecord and
		 * without setting dNSTombstoned=TRUE.
		 *
		 * We just pretend they're tombstones.
		 */
		if (tombstoned != NULL) {
			struct dnsp_DnssrvRpcRecord *recs;
			recs = talloc_array(mem_ctx,
					    struct dnsp_DnssrvRpcRecord,
					    1);
			if (recs == NULL) {
				werr = WERR_NOT_ENOUGH_MEMORY;
				goto exit;
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
			werr = WERR_OK;
			goto exit;
		} else {
			/*
			 * Because we are not looking for a tombstone
			 * in this codepath, we just pretend it does
			 * not exist at all.
			 */
			werr = WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
			goto exit;
		}
	}

	werr = dns_common_extract(samdb, el, mem_ctx, records, num_records);
	TALLOC_FREE(msg);
	if (!W_ERROR_IS_OK(werr)) {
		goto exit;
	}

	werr = WERR_OK;
exit:
	DNS_COMMON_LOG_OPERATION(
		win_errstr(werr),
		&start,
		NULL,
		dn == NULL ? NULL : ldb_dn_get_linearized(dn),
		NULL);
	return werr;
}

/*
 * Build an ldb_parse_tree node for an equality check
 *
 * Note: name is assumed to have been validated by dns_name_check
 *       so will be zero terminated and of a reasonable size.
 */
static struct ldb_parse_tree *build_equality_operation(
	TALLOC_CTX *mem_ctx,
	bool add_asterix,     /* prepend an '*' to the name          */
	const uint8_t *name,  /* the value being matched             */
	const char *attr,     /* the attribute to check name against */
	size_t size)          /* length of name                      */
{

	struct ldb_parse_tree *el = NULL;  /* Equality node being built */
	struct ldb_val *value = NULL;      /* Value the attr will be compared
					      with */
	size_t length = 0;                 /* calculated length of the value
	                                      including option '*' prefix and
					      '\0' string terminator */

	el = talloc(mem_ctx, struct ldb_parse_tree);
	if (el == NULL) {
		DBG_ERR("Unable to allocate ldb_parse_tree\n");
		return NULL;
	}

	el->operation = LDB_OP_EQUALITY;
	el->u.equality.attr = talloc_strdup(mem_ctx, attr);
	value = &el->u.equality.value;
	length = (add_asterix) ? size + 2 : size + 1;
	value->data = talloc_zero_array(el, uint8_t, length);
	if (el == NULL) {
		DBG_ERR("Unable to allocate value->data\n");
		TALLOC_FREE(el);
		return NULL;
	}

	value->length = length;
	if (add_asterix) {
		value->data[0] = '*';
		memcpy(&value->data[1], name, size);
	} else {
		memcpy(value->data, name, size);
	}
	return el;
}

/*
 * Determine the number of levels in name
 * essentially the number of '.'s in the name + 1
 *
 * name is assumed to have been validated by dns_name_check
 */
static unsigned int number_of_labels(const struct ldb_val *name) {
	int x  = 0;
	unsigned int labels = 1;
	for (x = 0; x < name->length; x++) {
		if (name->data[x] == '.') {
			labels++;
		}
	}
	return labels;
}
/*
 * Build a query that matches the target name, and any possible
 * DNS wild card entries
 *
 * Builds a parse tree equivalent to the example query.
 *
 * x.y.z -> (|(name=x.y.z)(name=\2a.y.z)(name=\2a.z)(name=\2a))
 *
 * The attribute 'name' is used as this is what the LDB index is on
 * (the RDN, being 'dc' in this use case, does not have an index in
 * the AD schema).
 *
 * Returns NULL if unable to build the query.
 *
 * The first component of the DN is assumed to be the name being looked up
 * and also that it has been validated by dns_name_check
 *
 */
#define BASE "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE))(|(a=b)(c=d)))"
static struct ldb_parse_tree *build_wildcard_query(
	TALLOC_CTX *mem_ctx,
	struct ldb_dn *dn)
{
	const struct ldb_val *name = NULL;            /* The DNS name being
							 queried */
	const char *attr = "name";                    /* The attribute name */
	struct ldb_parse_tree *query = NULL;          /* The constructed query
							 parse tree*/
	struct ldb_parse_tree *wildcard_query = NULL; /* The parse tree for the
							 name and wild card
							 entries */
	int labels = 0;         /* The number of labels in the name */

	name = ldb_dn_get_rdn_val(dn);
	if (name == NULL) {
		DBG_ERR("Unable to get domain name value\n");
		return NULL;
	}
	labels = number_of_labels(name);

	query = ldb_parse_tree(mem_ctx, BASE);
	if (query == NULL) {
		DBG_ERR("Unable to parse query %s\n", BASE);
		return NULL;
	}

	/*
	 * The 3rd element of BASE is a place holder which is replaced with
	 * the actual wild card query
	 */
	wildcard_query = query->u.list.elements[2];
	TALLOC_FREE(wildcard_query->u.list.elements);

	wildcard_query->u.list.num_elements = labels + 1;
	wildcard_query->u.list.elements = talloc_array(
		wildcard_query,
		struct ldb_parse_tree *,
		labels + 1);
	/*
	 * Build the wild card query
	 */
	{
		int x = 0;   /* current character in the name               */
		int l = 0;   /* current equality operator index in elements */
		struct ldb_parse_tree *el = NULL; /* Equality operator being
						     built */
		bool add_asterix = true;  /* prepend an '*' to the value    */
		for (l = 0, x = 0; l < labels && x < name->length; l++) {
			unsigned int size = name->length - x;
			add_asterix = (name->data[x] == '.');
			el = build_equality_operation(
				mem_ctx,
				add_asterix,
				&name->data[x],
				attr,
				size);
			if (el == NULL) {
				return NULL;  /* Reason will have been logged */
			}
			wildcard_query->u.list.elements[l] = el;

			/* skip to the start of the next label */
			x++;
			for (;x < name->length && name->data[x] != '.'; x++);
		}

		/* Add the base level "*" only query */
		el = build_equality_operation(mem_ctx, true, NULL, attr, 0);
		if (el == NULL) {
			TALLOC_FREE(query);
			return NULL;  /* Reason will have been logged */
		}
		wildcard_query->u.list.elements[l] = el;
	}
	return query;
}

/*
 * Scan the list of records matching a dns wildcard query and return the
 * best match.
 *
 * The best match is either an exact name match, or the longest wild card
 * entry returned
 *
 * i.e. name = a.b.c candidates *.b.c, *.c,        - *.b.c would be selected
 *      name = a.b.c candidates a.b.c, *.b.c, *.c  - a.b.c would be selected
 */
static struct ldb_message *get_best_match(struct ldb_dn *dn,
		                          struct ldb_result *result)
{
	int matched = 0;    /* Index of the current best match in result */
	size_t length = 0;  /* The length of the current candidate       */
	const struct ldb_val *target = NULL;    /* value we're looking for */
	const struct ldb_val *candidate = NULL; /* current candidate value */
	int x = 0;

	target = ldb_dn_get_rdn_val(dn);
	for(x = 0; x < result->count; x++) {
		candidate = ldb_dn_get_rdn_val(result->msgs[x]->dn);
		if (strncasecmp((char *) target->data,
				(char *) candidate->data,
				target->length) == 0) {
			/* Exact match stop searching and return */
			return result->msgs[x];
		}
		if (candidate->length > length) {
			matched = x;
			length  = candidate->length;
		}
	}
	return result->msgs[matched];
}

/*
 * Look up a DNS entry, if an exact match does not exist, return the
 * closest matching DNS wildcard entry if available
 *
 * Returns: LDB_ERR_NO_SUCH_OBJECT     If no matching record exists
 *          LDB_ERR_OPERATIONS_ERROR   If the query fails
 *          LDB_SUCCESS                If a matching record was retrieved
 *
 */
static int dns_wildcard_lookup(struct ldb_context *samdb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_dn *dn,
			       struct ldb_message **msg)
{
	static const char * const attrs[] = {
		"dnsRecord",
		"dNSTombstoned",
		NULL
	};
	struct ldb_dn *parent = NULL;     /* The parent dn                    */
	struct ldb_result *result = NULL; /* Results of the search            */
	int ret;                          /* Return code                      */
	struct ldb_parse_tree *query = NULL; /* The query to run              */
	struct ldb_request *request = NULL;  /* LDB request for the query op  */
	struct ldb_message *match = NULL;    /* the best matching DNS record  */
	TALLOC_CTX *frame = talloc_stackframe();

	parent = ldb_dn_get_parent(frame, dn);
	if (parent == NULL) {
		DBG_ERR("Unable to extract parent from dn\n");
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	query = build_wildcard_query(frame, dn);
	if (query == NULL) {
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	result = talloc_zero(mem_ctx, struct ldb_result);
	if (result == NULL) {
		TALLOC_FREE(frame);
		DBG_ERR("Unable to allocate ldb_result\n");
		return LDB_ERR_OPERATIONS_ERROR;
	}

	ret = ldb_build_search_req_ex(&request,
				      samdb,
				      frame,
				      parent,
				      LDB_SCOPE_SUBTREE,
				      query,
				      attrs,
				      NULL,
				      result,
				      ldb_search_default_callback,
				      NULL);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		DBG_ERR("ldb_build_search_req_ex returned %d\n", ret);
		return ret;
	}

	ret = ldb_request(samdb, request);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return ret;
	}

	ret = ldb_wait(request->handle, LDB_WAIT_ALL);
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		return ret;
	}

	if (result->count == 0) {
		TALLOC_FREE(frame);
		return LDB_ERR_NO_SUCH_OBJECT;
	}

	match = get_best_match(dn, result);
	if (match == NULL) {
		TALLOC_FREE(frame);
		return LDB_ERR_OPERATIONS_ERROR;
	}

	*msg = talloc_move(mem_ctx, &match);
	TALLOC_FREE(frame);
	return LDB_SUCCESS;
}

/*
 * Lookup a DNS record, will match DNS wild card records if an exact match
 * is not found.
 */
WERROR dns_common_wildcard_lookup(struct ldb_context *samdb,
				  TALLOC_CTX *mem_ctx,
				  struct ldb_dn *dn,
				  struct dnsp_DnssrvRpcRecord **records,
				  uint16_t *num_records)
{
	const struct timeval start = timeval_current();
	int ret;
	WERROR werr = WERR_OK;
	struct ldb_message *msg = NULL;
	struct ldb_message_element *el = NULL;
	const struct ldb_val *name = NULL;

	*records = NULL;
	*num_records = 0;

	name = ldb_dn_get_rdn_val(dn);
	if (name == NULL) {
		werr = DNS_ERR(NAME_ERROR);
		goto exit;
	}

	/* Don't look for a wildcard for @ */
	if (name->length == 1 && name->data[0] == '@') {
		werr = dns_common_lookup(samdb,
					 mem_ctx,
					 dn,
					 records,
					 num_records,
					 NULL);
		goto exit;
	}

	werr =  dns_name_check(
			mem_ctx,
			strlen((const char*)name->data),
			(const char*) name->data);
	if (!W_ERROR_IS_OK(werr)) {
		goto exit;
	}

	/*
	 * Do a point search first, then fall back to a wildcard
	 * lookup if it does not exist
	 */
	werr = dns_common_lookup(samdb,
				 mem_ctx,
				 dn,
				 records,
				 num_records,
				 NULL);
	if (!W_ERROR_EQUAL(werr, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
		goto exit;
	}

	ret = dns_wildcard_lookup(samdb, mem_ctx, dn, &msg);
	if (ret == LDB_ERR_OPERATIONS_ERROR) {
		werr = DNS_ERR(SERVER_FAILURE);
		goto exit;
	}
	if (ret != LDB_SUCCESS) {
		werr = DNS_ERR(NAME_ERROR);
		goto exit;
	}

	el = ldb_msg_find_element(msg, "dnsRecord");
	if (el == NULL) {
		werr = WERR_DNS_ERROR_NAME_DOES_NOT_EXIST;
		goto exit;
	}

	werr = dns_common_extract(samdb, el, mem_ctx, records, num_records);
	TALLOC_FREE(msg);
	if (!W_ERROR_IS_OK(werr)) {
		goto exit;
	}

	werr = WERR_OK;
exit:
	DNS_COMMON_LOG_OPERATION(
		win_errstr(werr),
		&start,
		NULL,
		dn == NULL ? NULL : ldb_dn_get_linearized(dn),
		NULL);
	return werr;
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

/*
 * Check for valid DNS names. These are names which:
 *   - are non-empty
 *   - do not start with a dot
 *   - do not have any empty labels
 *   - have no more than 127 labels
 *   - are no longer than 253 characters
 *   - none of the labels exceed 63 characters
 */
WERROR dns_name_check(TALLOC_CTX *mem_ctx, size_t len, const char *name)
{
	size_t i;
	unsigned int labels    = 0;
	unsigned int label_len = 0;

	if (len == 0) {
		return WERR_DS_INVALID_DN_SYNTAX;
	}

	if (len > 1 && name[0] == '.') {
		return WERR_DS_INVALID_DN_SYNTAX;
	}

	if ((len - 1) > DNS_MAX_DOMAIN_LENGTH) {
		return WERR_DS_INVALID_DN_SYNTAX;
	}

	for (i = 0; i < len - 1; i++) {
		if (name[i] == '.' && name[i+1] == '.') {
			return WERR_DS_INVALID_DN_SYNTAX;
		}
		if (name[i] == '.') {
			labels++;
			if (labels > DNS_MAX_LABELS) {
				return WERR_DS_INVALID_DN_SYNTAX;
			}
			label_len = 0;
		} else {
			label_len++;
			if (label_len > DNS_MAX_LABEL_LENGTH) {
				return WERR_DS_INVALID_DN_SYNTAX;
			}
		}
	}

	return WERR_OK;
}

static WERROR check_name_list(TALLOC_CTX *mem_ctx, uint16_t rec_count,
			      struct dnsp_DnssrvRpcRecord *records)
{
	WERROR werr;
	uint16_t i;
	size_t len;
	struct dnsp_DnssrvRpcRecord record;

	werr = WERR_OK;
	for (i = 0; i < rec_count; i++) {
		record = records[i];

		switch (record.wType) {

		case DNS_TYPE_NS:
			len = strlen(record.data.ns);
			werr = dns_name_check(mem_ctx, len, record.data.ns);
			break;
		case DNS_TYPE_CNAME:
			len = strlen(record.data.cname);
			werr = dns_name_check(mem_ctx, len, record.data.cname);
			break;
		case DNS_TYPE_SOA:
			len = strlen(record.data.soa.mname);
			werr = dns_name_check(mem_ctx, len, record.data.soa.mname);
			if (!W_ERROR_IS_OK(werr)) {
				break;
			}
			len = strlen(record.data.soa.rname);
			werr = dns_name_check(mem_ctx, len, record.data.soa.rname);
			break;
		case DNS_TYPE_PTR:
			len = strlen(record.data.ptr);
			werr = dns_name_check(mem_ctx, len, record.data.ptr);
			break;
		case DNS_TYPE_MX:
			len = strlen(record.data.mx.nameTarget);
			werr = dns_name_check(mem_ctx, len, record.data.mx.nameTarget);
			break;
		case DNS_TYPE_SRV:
			len = strlen(record.data.srv.nameTarget);
			werr = dns_name_check(mem_ctx, len,
					      record.data.srv.nameTarget);
			break;
		/*
		 * In the default case, the record doesn't have a DN, so it
		 * must be ok.
		 */
		default:
			break;
		}

		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	}

	return WERR_OK;
}

bool dns_name_is_static(struct dnsp_DnssrvRpcRecord *records,
			uint16_t rec_count)
{
	int i = 0;
	for (i = 0; i < rec_count; i++) {
		if (records[i].wType == DNS_TYPE_TOMBSTONE) {
			continue;
		}

		if (records[i].wType == DNS_TYPE_SOA ||
		    records[i].dwTimeStamp == 0) {
			return true;
		}
	}
	return false;
}

/*
 * Helper function to copy a dnsp_ip4_array struct to an IP4_ARRAY struct.
 * The new structure and it's data are allocated on the supplied talloc context
 */
static struct IP4_ARRAY *copy_ip4_array(TALLOC_CTX *ctx,
					const char *name,
					struct dnsp_ip4_array array)
{

	struct IP4_ARRAY *ip4_array = NULL;
	unsigned int i;

	ip4_array = talloc_zero(ctx, struct IP4_ARRAY);
	if (ip4_array == NULL) {
		DBG_ERR("Out of memory copying property [%s]\n", name);
		return NULL;
	}

	ip4_array->AddrCount = array.addrCount;
	if (ip4_array->AddrCount == 0) {
		return ip4_array;
	}

	ip4_array->AddrArray =
	    talloc_array(ip4_array, uint32_t, ip4_array->AddrCount);
	if (ip4_array->AddrArray == NULL) {
		TALLOC_FREE(ip4_array);
		DBG_ERR("Out of memory copying property [%s] values\n", name);
		return NULL;
	}

	for (i = 0; i < ip4_array->AddrCount; i++) {
		ip4_array->AddrArray[i] = array.addrArray[i];
	}

	return ip4_array;
}

bool dns_zoneinfo_load_zone_property(struct dnsserver_zoneinfo *zoneinfo,
				     struct dnsp_DnsProperty *prop)
{
	switch (prop->id) {
	case DSPROPERTY_ZONE_TYPE:
		zoneinfo->dwZoneType = prop->data.zone_type;
		break;
	case DSPROPERTY_ZONE_ALLOW_UPDATE:
		zoneinfo->fAllowUpdate = prop->data.allow_update_flag;
		break;
	case DSPROPERTY_ZONE_NOREFRESH_INTERVAL:
		zoneinfo->dwNoRefreshInterval = prop->data.norefresh_hours;
		break;
	case DSPROPERTY_ZONE_REFRESH_INTERVAL:
		zoneinfo->dwRefreshInterval = prop->data.refresh_hours;
		break;
	case DSPROPERTY_ZONE_AGING_STATE:
		zoneinfo->fAging = prop->data.aging_enabled;
		break;
	case DSPROPERTY_ZONE_SCAVENGING_SERVERS:
		zoneinfo->aipScavengeServers = copy_ip4_array(
		    zoneinfo, "ZONE_SCAVENGING_SERVERS", prop->data.servers);
		if (zoneinfo->aipScavengeServers == NULL) {
			return false;
		}
		break;
	case DSPROPERTY_ZONE_AGING_ENABLED_TIME:
		zoneinfo->dwAvailForScavengeTime =
		    prop->data.next_scavenging_cycle_hours;
		break;
	case DSPROPERTY_ZONE_MASTER_SERVERS:
		zoneinfo->aipLocalMasters = copy_ip4_array(
		    zoneinfo, "ZONE_MASTER_SERVERS", prop->data.master_servers);
		if (zoneinfo->aipLocalMasters == NULL) {
			return false;
		}
		break;
	case DSPROPERTY_ZONE_EMPTY:
	case DSPROPERTY_ZONE_SECURE_TIME:
	case DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME:
	case DSPROPERTY_ZONE_AUTO_NS_SERVERS:
	case DSPROPERTY_ZONE_DCPROMO_CONVERT:
	case DSPROPERTY_ZONE_SCAVENGING_SERVERS_DA:
	case DSPROPERTY_ZONE_MASTER_SERVERS_DA:
	case DSPROPERTY_ZONE_NS_SERVERS_DA:
	case DSPROPERTY_ZONE_NODE_DBFLAGS:
		break;
	}
	return true;
}
WERROR dns_get_zone_properties(struct ldb_context *samdb,
			       TALLOC_CTX *mem_ctx,
			       struct ldb_dn *zone_dn,
			       struct dnsserver_zoneinfo *zoneinfo)
{

	int ret, i;
	struct dnsp_DnsProperty *prop = NULL;
	struct ldb_message_element *element = NULL;
	const char *const attrs[] = {"dNSProperty", NULL};
	struct ldb_result *res = NULL;
	enum ndr_err_code err;

	ret = ldb_search(samdb,
			 mem_ctx,
			 &res,
			 zone_dn,
			 LDB_SCOPE_BASE,
			 attrs,
			 "(objectClass=dnsZone)");
	if (ret != LDB_SUCCESS) {
		DBG_ERR("dnsserver: Failed to find DNS zone: %s\n",
			ldb_dn_get_linearized(zone_dn));
		return DNS_ERR(SERVER_FAILURE);
	}

	element = ldb_msg_find_element(res->msgs[0], "dNSProperty");
	if (element == NULL) {
		return DNS_ERR(NOTZONE);
	}

	for (i = 0; i < element->num_values; i++) {
		bool valid_property;
		prop = talloc_zero(mem_ctx, struct dnsp_DnsProperty);
		if (prop == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		err = ndr_pull_struct_blob(
		    &(element->values[i]),
		    mem_ctx,
		    prop,
		    (ndr_pull_flags_fn_t)ndr_pull_dnsp_DnsProperty);
		if (!NDR_ERR_CODE_IS_SUCCESS(err)) {
			/*
			 * If we can't pull it, then there is no valid
			 * data to load into the zone, so ignore this
			 * as Micosoft does.  Windows can load an
			 * invalid property with a zero length into
			 * the dnsProperty attribute.
			 */
			continue;
		}

		valid_property =
		    dns_zoneinfo_load_zone_property(zoneinfo, prop);
		if (!valid_property) {
			return DNS_ERR(SERVER_FAILURE);
		}
	}

	return WERR_OK;
}

WERROR dns_common_replace(struct ldb_context *samdb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  bool needs_add,
			  uint32_t serial,
			  struct dnsp_DnssrvRpcRecord *records,
			  uint16_t rec_count)
{
	const struct timeval start = timeval_current();
	struct ldb_message_element *el;
	uint16_t i;
	int ret;
	WERROR werr;
	struct ldb_message *msg = NULL;
	bool was_tombstoned = false;
	bool become_tombstoned = false;
	struct ldb_dn *zone_dn = NULL;
	struct dnsserver_zoneinfo *zoneinfo = NULL;
	NTTIME t;

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn = dn;

	zone_dn = ldb_dn_copy(mem_ctx, dn);
	if (zone_dn == NULL) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto exit;
	}
	if (!ldb_dn_remove_child_components(zone_dn, 1)) {
		werr = DNS_ERR(SERVER_FAILURE);
		goto exit;
	}
	zoneinfo = talloc(mem_ctx, struct dnsserver_zoneinfo);
	if (zoneinfo == NULL) {
		werr = WERR_NOT_ENOUGH_MEMORY;
		goto exit;
	}
	werr = dns_get_zone_properties(samdb, mem_ctx, zone_dn, zoneinfo);
	if (W_ERROR_EQUAL(DNS_ERR(NOTZONE), werr)) {
		/*
		 * We only got zoneinfo for aging so if we didn't find any
		 * properties then just disable aging and keep going.
		 */
		zoneinfo->fAging = 0;
	} else if (!W_ERROR_IS_OK(werr)) {
		goto exit;
	}

	werr = check_name_list(mem_ctx, rec_count, records);
	if (!W_ERROR_IS_OK(werr)) {
		goto exit;
	}

	ret = ldb_msg_add_empty(msg, "dnsRecord", LDB_FLAG_MOD_REPLACE, &el);
	if (ret != LDB_SUCCESS) {
		werr = DNS_ERR(SERVER_FAILURE);
		goto exit;
	}

	/*
	 * we have at least one value,
	 * which might be used for the tombstone marker
	 */
	el->values = talloc_zero_array(el, struct ldb_val, MAX(1, rec_count));
	if (rec_count > 0) {
		if (el->values == NULL) {
			werr = WERR_NOT_ENOUGH_MEMORY;
			goto exit;
		}

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

		if (zoneinfo->fAging == 1 && records[i].dwTimeStamp != 0) {
			unix_to_nt_time(&t, time(NULL));
			t /= 10 * 1000 * 1000;
			t /= 3600;
			if (t - records[i].dwTimeStamp >
			    zoneinfo->dwNoRefreshInterval) {
				records[i].dwTimeStamp = t;
			}
		}

		records[i].dwSerial = serial;
		ndr_err = ndr_push_struct_blob(v, el->values, &records[i],
				(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to push dnsp_DnssrvRpcRecord\n"));
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}
		el->num_values++;
	}

	if (needs_add) {
		if (el->num_values == 0) {
			werr = WERR_OK;
			goto exit;
		}

		ret = ldb_msg_add_string(msg, "objectClass", "dnsNode");
		if (ret != LDB_SUCCESS) {
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}

		ret = ldb_add(samdb, msg);
		if (ret != LDB_SUCCESS) {
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}

		return WERR_OK;
		goto exit;
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
			werr = WERR_OK;
			goto exit;
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
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}
		el->num_values++;

		become_tombstoned = true;
	}

	if (was_tombstoned || become_tombstoned) {
		ret = ldb_msg_add_empty(msg, "dNSTombstoned",
					LDB_FLAG_MOD_REPLACE, NULL);
		if (ret != LDB_SUCCESS) {
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}

		ret = ldb_msg_add_fmt(msg, "dNSTombstoned", "%s",
				      become_tombstoned ? "TRUE" : "FALSE");
		if (ret != LDB_SUCCESS) {
			werr = DNS_ERR(SERVER_FAILURE);
			goto exit;
		}
	}

	ret = ldb_modify(samdb, msg);
	if (ret != LDB_SUCCESS) {
		NTSTATUS nt = dsdb_ldb_err_to_ntstatus(ret);
		werr = ntstatus_to_werror(nt);
		goto exit;
	}

	werr = WERR_OK;
exit:
	DNS_COMMON_LOG_OPERATION(
		win_errstr(werr),
		&start,
		NULL,
		dn == NULL ? NULL : ldb_dn_get_linearized(dn),
		NULL);
	return werr;
}

bool dns_name_match(const char *zone, const char *name, size_t *host_part_len)
{
	size_t zl = strlen(zone);
	size_t nl = strlen(name);
	ssize_t zi, ni;
	static const size_t fixup = 'a' - 'A';

	if (zl > nl) {
		return false;
	}

	for (zi = zl, ni = nl; zi >= 0; zi--, ni--) {
		char zc = zone[zi];
		char nc = name[ni];

		/* convert to lower case */
		if (zc >= 'A' && zc <= 'Z') {
			zc += fixup;
		}
		if (nc >= 'A' && nc <= 'Z') {
			nc += fixup;
		}

		if (zc != nc) {
			return false;
		}
	}

	if (ni >= 0) {
		if (name[ni] != '.') {
			return false;
		}

		ni--;
	}

	*host_part_len = ni+1;

	return true;
}

WERROR dns_common_name2dn(struct ldb_context *samdb,
			  struct dns_server_zone *zones,
			  TALLOC_CTX *mem_ctx,
			  const char *name,
			  struct ldb_dn **_dn)
{
	struct ldb_dn *base;
	struct ldb_dn *dn;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;
	struct ldb_val host_part;
	WERROR werr;
	bool ok;
	const char *casefold = NULL;

	if (name == NULL) {
		return DNS_ERR(FORMAT_ERROR);
	}

	if (strcmp(name, "") == 0) {
		base = ldb_get_default_basedn(samdb);
		dn = ldb_dn_copy(mem_ctx, base);
		ok = ldb_dn_add_child_fmt(dn,
					  "DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System");
		if (ok == false) {
			TALLOC_FREE(dn);
			return WERR_NOT_ENOUGH_MEMORY;
		}

		*_dn = dn;
		return WERR_OK;
	}

	/* Check non-empty names */
	werr = dns_name_check(mem_ctx, strlen(name), name);
	if (!W_ERROR_IS_OK(werr)) {
		return werr;
	}

	for (z = zones; z != NULL; z = z->next) {
		bool match;

		match = dns_name_match(z->name, name, &host_part_len);
		if (match) {
			break;
		}
	}

	if (z == NULL) {
		return DNS_ERR(NAME_ERROR);
	}

	if (host_part_len == 0) {
		dn = ldb_dn_copy(mem_ctx, z->dn);
		ok = ldb_dn_add_child_fmt(dn, "DC=@");
		if (! ok) {
			TALLOC_FREE(dn);
			return WERR_NOT_ENOUGH_MEMORY;
		}
		*_dn = dn;
		return WERR_OK;
	}

	dn = ldb_dn_copy(mem_ctx, z->dn);
	if (dn == NULL) {
		TALLOC_FREE(dn);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	host_part = data_blob_const(name, host_part_len);

	ok = ldb_dn_add_child_val(dn, "DC", host_part);

	if (ok == false) {
		TALLOC_FREE(dn);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	/*
	 * Check the new DN here for validity, so as to catch errors
	 * early
	 */
	ok = ldb_dn_validate(dn);
	if (ok == false) {
		TALLOC_FREE(dn);
		return DNS_ERR(NAME_ERROR);
	}

	/*
	 * The value from this check is saved in the DN, and doing
	 * this here allows an easy return here.
	 */
	casefold = ldb_dn_get_casefold(dn);
	if (casefold == NULL) {
		TALLOC_FREE(dn);
		return DNS_ERR(NAME_ERROR);
	}

	*_dn = dn;
	return WERR_OK;
}

static int dns_common_sort_zones(struct ldb_message **m1, struct ldb_message **m2)
{
	const char *n1, *n2;
	size_t l1, l2;

	n1 = ldb_msg_find_attr_as_string(*m1, "name", NULL);
	n2 = ldb_msg_find_attr_as_string(*m2, "name", NULL);
	if (n1 == NULL || n2 == NULL) {
		if (n1 != NULL) {
			return -1;
		} else if (n2 != NULL) {
			return 1;
		} else {
			return 0;
		}
	}
	l1 = strlen(n1);
	l2 = strlen(n2);

	/* If the string lengths are not equal just sort by length */
	if (l1 != l2) {
		/* If m1 is the larger zone name, return it first */
		return l2 - l1;
	}

	/*TODO: We need to compare DNs here, we want the DomainDNSZones first */
	return 0;
}

NTSTATUS dns_common_zones(struct ldb_context *samdb,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *base_dn,
			  struct dns_server_zone **zones_ret)
{
	const struct timeval start = timeval_current();
	int ret;
	static const char * const attrs[] = { "name", NULL};
	struct ldb_result *res;
	int i;
	struct dns_server_zone *new_list = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS result = NT_STATUS_OK;

	if (base_dn) {
		/* This search will work against windows */
		ret = dsdb_search(samdb, frame, &res,
				  base_dn, LDB_SCOPE_SUBTREE,
				  attrs, 0, "(objectClass=dnsZone)");
	} else {
		/* TODO: this search does not work against windows */
		ret = dsdb_search(samdb, frame, &res, NULL,
				  LDB_SCOPE_SUBTREE,
				  attrs,
				  DSDB_SEARCH_SEARCH_ALL_PARTITIONS,
				  "(objectClass=dnsZone)");
	}
	if (ret != LDB_SUCCESS) {
		TALLOC_FREE(frame);
		result = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto exit;
	}

	TYPESAFE_QSORT(res->msgs, res->count, dns_common_sort_zones);

	for (i=0; i < res->count; i++) {
		struct dns_server_zone *z;

		z = talloc_zero(mem_ctx, struct dns_server_zone);
		if (z == NULL) {
			TALLOC_FREE(frame);
			result = NT_STATUS_NO_MEMORY;
			goto exit;
		}

		z->name = ldb_msg_find_attr_as_string(res->msgs[i], "name", NULL);
		talloc_steal(z, z->name);
		z->dn = talloc_move(z, &res->msgs[i]->dn);
		/*
		 * Ignore the RootDNSServers zone and zones that we don't support yet
		 * RootDNSServers should never be returned (Windows DNS server don't)
		 * ..TrustAnchors should never be returned as is, (Windows returns
		 * TrustAnchors) and for the moment we don't support DNSSEC so we'd better
		 * not return this zone.
		 */
		if ((strcmp(z->name, "RootDNSServers") == 0) ||
		    (strcmp(z->name, "..TrustAnchors") == 0))
		{
			DEBUG(10, ("Ignoring zone %s\n", z->name));
			talloc_free(z);
			continue;
		}
		DLIST_ADD_END(new_list, z);
	}

	*zones_ret = new_list;
	TALLOC_FREE(frame);
	result = NT_STATUS_OK;
exit:
	DNS_COMMON_LOG_OPERATION(
		nt_errstr(result),
		&start,
		NULL,
		base_dn == NULL ? NULL : ldb_dn_get_linearized(base_dn),
		NULL);
	return result;
}

/*
  see if two DNS names are the same
 */
bool dns_name_equal(const char *name1, const char *name2)
{
	size_t len1 = strlen(name1);
	size_t len2 = strlen(name2);

	if (len1 > 0 && name1[len1 - 1] == '.') {
		len1--;
	}
	if (len2 > 0 && name2[len2 - 1] == '.') {
		len2--;
	}
	if (len1 != len2) {
		return false;
	}
	return strncasecmp(name1, name2, len1) == 0;
}
