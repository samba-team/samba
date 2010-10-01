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
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dns_server/dns_server.h"

NTSTATUS dns_err_to_ntstatus(enum dns_rcode rcode)
{
	switch (rcode) {
	case DNS_RCODE_OK: return NT_STATUS_OK;
	case DNS_RCODE_FORMERR: return NT_STATUS_INVALID_PARAMETER;
	case DNS_RCODE_SERVFAIL: return NT_STATUS_INTERNAL_ERROR;
	case DNS_RCODE_NXDOMAIN: return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	case DNS_RCODE_NOTIMP: return NT_STATUS_NOT_IMPLEMENTED;
	case DNS_RCODE_REFUSED: return NT_STATUS_ACCESS_DENIED;
	case DNS_RCODE_NOTAUTH: return NT_STATUS_FOOBAR;
	default: return NT_STATUS_NONE_MAPPED;
	}
}

uint8_t ntstatus_to_dns_err(NTSTATUS status)
{
	if (NT_STATUS_EQUAL(NT_STATUS_OK, status)) {
		return DNS_RCODE_OK;
	} else if (NT_STATUS_EQUAL(NT_STATUS_INVALID_PARAMETER, status)) {
		return DNS_RCODE_FORMERR;
	} else if (NT_STATUS_EQUAL(NT_STATUS_INTERNAL_ERROR, status)) {
		return DNS_RCODE_SERVFAIL;
	} else if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		return DNS_RCODE_NXDOMAIN;
	} else if (NT_STATUS_EQUAL(NT_STATUS_NOT_IMPLEMENTED, status)) {
		return DNS_RCODE_NOTIMP;
	} else if (NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
		return DNS_RCODE_REFUSED;
	} else if (NT_STATUS_EQUAL(NT_STATUS_FOOBAR, status)) {
		return DNS_RCODE_NOTAUTH;
	}
	DEBUG(0, ("No mapping exists for %s\n", nt_errstr(status)));
	return DNS_RCODE_NOTIMP;
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

NTSTATUS dns_name2dn(struct dns_server *dns,
		     TALLOC_CTX *mem_ctx,
		     const char *name,
		     struct ldb_dn **_dn)
{
	struct ldb_dn *base;
	struct ldb_dn *dn;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;

	if (name == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*TODO: Check if 'name' is a valid DNS name */

	if (strcmp(name, "") == 0) {
		base = ldb_get_default_basedn(dns->samdb);
		dn = ldb_dn_copy(mem_ctx, base);
		ldb_dn_add_child_fmt(dn, "DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System");
		*_dn = dn;
		return NT_STATUS_OK;
	}

	for (z = dns->zones; z != NULL; z = z->next) {
		bool match;

		match = dns_name_match(z->name, name, &host_part_len);
		if (match) {
			break;
		}
	}

	if (z == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (host_part_len == 0) {
		dn = ldb_dn_copy(mem_ctx, z->dn);
		ldb_dn_add_child_fmt(dn, "DC=@");
		*_dn = dn;
		return NT_STATUS_OK;
	}

	dn = ldb_dn_copy(mem_ctx, z->dn);
	ldb_dn_add_child_fmt(dn, "DC=%*.*s", (int)host_part_len, (int)host_part_len, name);
	*_dn = dn;
	return NT_STATUS_OK;
}
