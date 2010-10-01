/*
   Unix SMB/CIFS implementation.

   DNS server handler for update requests

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

NTSTATUS dns_server_process_update(struct dns_server *dns,
				   TALLOC_CTX *mem_ctx,
				   struct dns_name_packet *in,
				   struct dns_res_rec **prereqs,    uint16_t *prereq_count,
				   struct dns_res_rec **updates,    uint16_t *update_count,
				   struct dns_res_rec **additional, uint16_t *arcount)
{
	struct dns_name_question *zone;
	NTSTATUS status;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;

	if (in->qdcount != 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	zone = in->questions;

	if (zone->question_type != DNS_QTYPE_SOA) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(0, ("Got a dns update request.\n"));

	for (z = dns->zones; z != NULL; z = z->next) {
		bool match;

		match = dns_name_match(z->name, zone->name, &host_part_len);
		if (match) {
			break;
		}
	}

	if (z == NULL) {
		return NT_STATUS_FOOBAR;
	}

	if (host_part_len != 0) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return NT_STATUS_NOT_IMPLEMENTED;
}
