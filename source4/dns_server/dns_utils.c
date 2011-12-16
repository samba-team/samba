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
	}
	DEBUG(5, ("No mapping exists for %%s\n"));
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
		return strcmp(rec1->data.txt, rec2->data.txt) == 0;
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
