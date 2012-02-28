/*
   Unix SMB/CIFS implementation.

   Manually parsed structures for DNSSERVER

   Copyright (C) Amitay Isaacs 2011

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
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "librpc/gen_ndr/ndr_dnsserver.h"

/*
 * parsing DNS_RPC_RECORDS_ARRAY
 */

enum ndr_err_code ndr_pull_DNS_RPC_RECORDS_ARRAY(struct ndr_pull *ndr,
		int ndr_flags, struct DNS_RPC_RECORDS_ARRAY *rec)
{
	rec->count = 0;
	rec->rec = talloc_array(ndr->current_mem_ctx, struct DNS_RPC_RECORDS, rec->count);
	if (! rec->rec) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull DNS_RPC_RECORDS_ARRAY");
	}

	while (ndr->offset < ndr->data_size) {
		rec->rec = talloc_realloc(ndr->current_mem_ctx, rec->rec, struct DNS_RPC_RECORDS, rec->count+1);
		if (! rec->rec) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull DNS_RPC_RECORDS_ARRAY");
		}
		NDR_CHECK(ndr_pull_DNS_RPC_RECORDS(ndr, ndr_flags, &rec->rec[rec->count]));
		NDR_PULL_ALIGN(ndr, 4);
		rec->count++;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_DNS_RPC_RECORDS_ARRAY(struct ndr_push *ndr,
		int ndr_flags, const struct DNS_RPC_RECORDS_ARRAY *rec)
{
	int i;

	for (i=0; i<rec->count; i++) {
		NDR_CHECK(ndr_push_DNS_RPC_RECORDS(ndr, ndr_flags, &rec->rec[i]));
		NDR_PUSH_ALIGN(ndr, 4);
	}

	return NDR_ERR_SUCCESS;
}

/*
 * Parsing of DNS_RPC_RECORD_STRING
 */

enum ndr_err_code ndr_pull_DNS_RPC_RECORD_STRING(struct ndr_pull *ndr,
		int ndr_flags, struct DNS_RPC_RECORD_STRING *rec)
{
	rec->count = 0;
	rec->str = talloc_array(ndr->current_mem_ctx, struct DNS_RPC_NAME, rec->count);
	if (! rec->str) {
		return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull DNS_RPC_RECORD_STRING");
	}

	while (ndr->offset < ndr->data_size) {
		rec->str = talloc_realloc(ndr->current_mem_ctx, rec->str, struct DNS_RPC_NAME, rec->count+1);
		if (! rec->str) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC, "Failed to pull DNS_RPC_RECORD_STRING");
		}
		NDR_CHECK(ndr_pull_DNS_RPC_NAME(ndr, ndr_flags, &rec->str[rec->count]));
		rec->count++;
	}

	return NDR_ERR_SUCCESS;
}

enum ndr_err_code ndr_push_DNS_RPC_RECORD_STRING(struct ndr_push *ndr,
		int ndr_flags, const struct DNS_RPC_RECORD_STRING *rec)
{
	int i;

	for (i=0; i<rec->count; i++) {
		NDR_CHECK(ndr_push_DNS_RPC_NAME(ndr, ndr_flags, &rec->str[i]));
	}

	return NDR_ERR_SUCCESS;
}
