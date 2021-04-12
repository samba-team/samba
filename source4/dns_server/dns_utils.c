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

