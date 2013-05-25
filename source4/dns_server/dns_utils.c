/*
   Unix SMB/CIFS implementation.

   DNS server utils

   Copyright (C) 2010 Kai Blin  <kai@samba.org>

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
#include "dns_server/dns_server.h"

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

/* Names are equal if they match and there's nothing left over */
bool dns_name_equal(const char *name1, const char *name2)
{
	size_t host_part_len;
	bool ret = dns_name_match(name1, name2, &host_part_len);

	return ret && (host_part_len == 0);
}

/*
  see if two dns records match
 */
bool dns_records_match(struct dnsp_DnssrvRpcRecord *rec1,
		       struct dnsp_DnssrvRpcRecord *rec2)
{
	bool status;
	int i;

	if (rec1->wType != rec2->wType) {
		return false;
	}

	/* see if the data matches */
	switch (rec1->wType) {
	case DNS_TYPE_A:
		return strcmp(rec1->data.ipv4, rec2->data.ipv4) == 0;
	case DNS_TYPE_AAAA:
		return strcmp(rec1->data.ipv6, rec2->data.ipv6) == 0;
	case DNS_TYPE_CNAME:
		return dns_name_equal(rec1->data.cname, rec2->data.cname);
	case DNS_TYPE_TXT:
		if (rec1->data.txt.count != rec2->data.txt.count) {
			return false;
		}
		status = true;
		for (i=0; i<rec1->data.txt.count; i++) {
			status = status && (strcmp(rec1->data.txt.str[i],
						rec2->data.txt.str[i]) == 0);
		}
		return status;
	case DNS_TYPE_PTR:
		return strcmp(rec1->data.ptr, rec2->data.ptr) == 0;
	case DNS_TYPE_NS:
		return dns_name_equal(rec1->data.ns, rec2->data.ns);

	case DNS_TYPE_SRV:
		return rec1->data.srv.wPriority == rec2->data.srv.wPriority &&
			rec1->data.srv.wWeight  == rec2->data.srv.wWeight &&
			rec1->data.srv.wPort    == rec2->data.srv.wPort &&
			dns_name_equal(rec1->data.srv.nameTarget, rec2->data.srv.nameTarget);

	case DNS_TYPE_MX:
		return rec1->data.mx.wPriority == rec2->data.mx.wPriority &&
			dns_name_equal(rec1->data.mx.nameTarget, rec2->data.mx.nameTarget);

	case DNS_TYPE_HINFO:
		return strcmp(rec1->data.hinfo.cpu, rec2->data.hinfo.cpu) == 0 &&
			strcmp(rec1->data.hinfo.os, rec2->data.hinfo.os) == 0;

	case DNS_TYPE_SOA:
		return dns_name_equal(rec1->data.soa.mname, rec2->data.soa.mname) &&
			dns_name_equal(rec1->data.soa.rname, rec2->data.soa.rname) &&
			rec1->data.soa.serial == rec2->data.soa.serial &&
			rec1->data.soa.refresh == rec2->data.soa.refresh &&
			rec1->data.soa.retry == rec2->data.soa.retry &&
			rec1->data.soa.expire == rec2->data.soa.expire &&
			rec1->data.soa.minimum == rec2->data.soa.minimum;
	default:
		break;
	}

	return false;
}

WERROR dns_lookup_records(struct dns_server *dns,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *rec_count)
{
	static const char * const attrs[] = { "dnsRecord", NULL};
	struct ldb_message_element *el;
	uint16_t ri;
	int ret;
	struct ldb_message *msg = NULL;
	struct dnsp_DnssrvRpcRecord *recs;

	ret = dsdb_search_one(dns->samdb, mem_ctx, &msg, dn,
			      LDB_SCOPE_BASE, attrs, 0, "%s", "(objectClass=dnsNode)");
	if (ret != LDB_SUCCESS) {
		/* TODO: we need to check if there's a glue record we need to
		 * create a referral to */
		return DNS_ERR(NAME_ERROR);
	}

	el = ldb_msg_find_element(msg, attrs[0]);
	if (el == NULL) {
		*records = NULL;
		*rec_count = 0;
		return DNS_ERR(NAME_ERROR);
	}

	recs = talloc_zero_array(mem_ctx, struct dnsp_DnssrvRpcRecord, el->num_values);
	W_ERROR_HAVE_NO_MEMORY(recs);
	for (ri = 0; ri < el->num_values; ri++) {
		struct ldb_val *v = &el->values[ri];
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_struct_blob(v, recs, &recs[ri],
				(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to grab dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}
	}
	*records = recs;
	*rec_count = el->num_values;
	return WERR_OK;
}

WERROR dns_replace_records(struct dns_server *dns,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_dn *dn,
			   bool needs_add,
			   const struct dnsp_DnssrvRpcRecord *records,
			   uint16_t rec_count)
{
	struct ldb_message_element *el;
	uint16_t i;
	int ret;
	struct ldb_message *msg = NULL;

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn = dn;

	ret = ldb_msg_add_empty(msg, "dnsRecord", LDB_FLAG_MOD_REPLACE, &el);
	if (ret != LDB_SUCCESS) {
		return DNS_ERR(SERVER_FAILURE);
	}

	el->values = talloc_zero_array(el, struct ldb_val, rec_count);
	if (rec_count > 0) {
		W_ERROR_HAVE_NO_MEMORY(el->values);
	}

	for (i = 0; i < rec_count; i++) {
		static const struct dnsp_DnssrvRpcRecord zero;
		struct ldb_val *v = &el->values[el->num_values];
		enum ndr_err_code ndr_err;

		if (memcmp(&records[i], &zero, sizeof(zero)) == 0) {
			continue;
		}
		ndr_err = ndr_push_struct_blob(v, el->values, &records[i],
				(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			DEBUG(0, ("Failed to grab dnsp_DnssrvRpcRecord\n"));
			return DNS_ERR(SERVER_FAILURE);
		}
		el->num_values++;
	}


	if (el->num_values == 0) {
		if (needs_add) {
			return WERR_OK;
		}
		/* No entries left, delete the dnsNode object */
		ret = ldb_delete(dns->samdb, msg->dn);
		if (ret != LDB_SUCCESS) {
			DEBUG(0, ("Deleting record failed; %d\n", ret));
			return DNS_ERR(SERVER_FAILURE);
		}
		return WERR_OK;
	}

	if (needs_add) {
		ret = ldb_msg_add_string(msg, "objectClass", "dnsNode");
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}

		ret = ldb_add(dns->samdb, msg);
		if (ret != LDB_SUCCESS) {
			return DNS_ERR(SERVER_FAILURE);
		}

		return WERR_OK;
	}

	ret = ldb_modify(dns->samdb, msg);
	if (ret != LDB_SUCCESS) {
		return DNS_ERR(SERVER_FAILURE);
	}

	return WERR_OK;
}

bool dns_authorative_for_zone(struct dns_server *dns,
			      const char *name)
{
	const struct dns_server_zone *z;
	size_t host_part_len = 0;

	if (name == NULL) {
		return false;
	}

	if (strcmp(name, "") == 0) {
		return true;
	}
	for (z = dns->zones; z != NULL; z = z->next) {
		bool match;

		match = dns_name_match(z->name, name, &host_part_len);
		if (match) {
			break;
		}
	}
	if (z == NULL) {
		return false;
	}

	return true;
}

WERROR dns_name2dn(struct dns_server *dns,
		   TALLOC_CTX *mem_ctx,
		   const char *name,
		   struct ldb_dn **_dn)
{
	struct ldb_dn *base;
	struct ldb_dn *dn;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;

	if (name == NULL) {
		return DNS_ERR(FORMAT_ERROR);
	}

	/*TODO: Check if 'name' is a valid DNS name */

	if (strcmp(name, "") == 0) {
		base = ldb_get_default_basedn(dns->samdb);
		dn = ldb_dn_copy(mem_ctx, base);
		ldb_dn_add_child_fmt(dn, "DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System");
		*_dn = dn;
		return WERR_OK;
	}

	for (z = dns->zones; z != NULL; z = z->next) {
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
		ldb_dn_add_child_fmt(dn, "DC=@");
		*_dn = dn;
		return WERR_OK;
	}

	dn = ldb_dn_copy(mem_ctx, z->dn);
	ldb_dn_add_child_fmt(dn, "DC=%*.*s", (int)host_part_len, (int)host_part_len, name);
	*_dn = dn;
	return WERR_OK;
}

WERROR dns_generate_options(struct dns_server *dns,
			    TALLOC_CTX *mem_ctx,
			    struct dns_res_rec **options)
{
	struct dns_res_rec *o;

	o = talloc_zero(mem_ctx, struct dns_res_rec);
	if (o == NULL) {
		return WERR_NOMEM;
	}
	o->name = '\0';
	o->rr_type = DNS_QTYPE_OPT;
	/* This is ugly, but RFC2671 wants the payload size in this field */
	o->rr_class = (enum dns_qclass) dns->max_payload;
	o->ttl = 0;
	o->length = 0;

	*options = o;
	return WERR_OK;
}
