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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

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

/*
 * Lookup a DNS record, performing an exact match.
 * i.e. DNS wild card records are not considered.
 */
WERROR dns_lookup_records(struct dns_server *dns,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *rec_count)
{
	return dns_common_lookup(dns->samdb, mem_ctx, dn,
				 records, rec_count, NULL);
}

/*
 * Lookup a DNS record, will match DNS wild card records if an exact match
 * is not found.
 */
WERROR dns_lookup_records_wildcard(struct dns_server *dns,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *rec_count)
{
	return dns_common_wildcard_lookup(dns->samdb, mem_ctx, dn,
				 records, rec_count);
}

WERROR dns_replace_records(struct dns_server *dns,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_dn *dn,
			   bool needs_add,
			   struct dnsp_DnssrvRpcRecord *records,
			   uint16_t rec_count)
{
	/* TODO: Autogenerate this somehow */
	uint32_t dwSerial = 110;
	return dns_common_replace(dns->samdb, mem_ctx, dn,
				  needs_add, dwSerial, records, rec_count);
}

bool dns_authoritative_for_zone(struct dns_server *dns,
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

const char *dns_get_authoritative_zone(struct dns_server *dns,
				       const char *name)
{
	const struct dns_server_zone *z;
	size_t host_part_len = 0;

	for (z = dns->zones; z != NULL; z = z->next) {
		bool match;
		match = dns_name_match(z->name, name, &host_part_len);
		if (match) {
			return z->name;
		}
	}
	return NULL;
}

WERROR dns_name2dn(struct dns_server *dns,
		   TALLOC_CTX *mem_ctx,
		   const char *name,
		   struct ldb_dn **dn)
{
	return dns_common_name2dn(dns->samdb, dns->zones,
				  mem_ctx, name, dn);
}

