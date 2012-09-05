/*
   Unix SMB/CIFS implementation.

   DNS server handler for signed packets

   Copyright (C) 2012 Kai Blin  <kai@samba.org>

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
#include "lib/crypto/hmacmd5.h"
#include "system/network.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "dns_server/dns_server.h"
#include "libcli/util/ntstatus.h"
#include "auth/auth.h"
#include "auth/gensec/gensec.h"

struct dns_server_tkey *dns_find_tkey(struct dns_server_tkey_store *store,
				      const char *name)
{
	struct dns_server_tkey *tkey = NULL;
	uint16_t i = 0;

	do {
		struct dns_server_tkey *tmp_key = store->tkeys[i];

		i++;
		i %= TKEY_BUFFER_SIZE;

		if (tmp_key == NULL) {
			continue;
		}
		if (dns_name_equal(name, tmp_key->name)) {
			tkey = tmp_key;
			break;
		}
	} while (i != 0);

	return tkey;
}

WERROR dns_sign_tsig(struct dns_server *dns,
		     TALLOC_CTX *mem_ctx,
		     struct dns_request_state *state,
		     struct dns_name_packet *packet,
		     uint16_t error)
{
	WERROR werror;
	NTSTATUS status;
	enum ndr_err_code ndr_err;
	time_t current_time = time(NULL);
	DATA_BLOB packet_blob, tsig_blob, sig;
	uint8_t *buffer = NULL;
	size_t buffer_len = 0;
	struct dns_server_tkey * tkey = NULL;
	struct dns_res_rec *tsig = talloc_zero(mem_ctx, struct dns_res_rec);

	struct dns_fake_tsig_rec *check_rec = talloc_zero(mem_ctx,
			struct dns_fake_tsig_rec);

	if (tsig == NULL) {
		return WERR_NOMEM;
	}

	if (check_rec == NULL) {
		return WERR_NOMEM;
	}

	tkey = dns_find_tkey(dns->tkeys, state->key_name);
	if (tkey == NULL) {
		/* FIXME: read up on what to do when we can't find a key */
		return WERR_OK;
	}

	/* first build and verify check packet */
	check_rec->name = talloc_strdup(check_rec, tkey->name);
	if (check_rec->name == NULL) {
		return WERR_NOMEM;
	}
	check_rec->rr_class = DNS_QCLASS_ANY;
	check_rec->ttl = 0;
	check_rec->algorithm_name = talloc_strdup(check_rec, tkey->algorithm);
	if (check_rec->algorithm_name == NULL) {
		return WERR_NOMEM;
	}
	check_rec->time_prefix = 0;
	check_rec->time = current_time;
	check_rec->fudge = 300;
	check_rec->error = state->tsig_error;
	check_rec->other_size = 0;
	check_rec->other_data = NULL;

	ndr_err = ndr_push_struct_blob(&packet_blob, mem_ctx, packet,
		(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	ndr_err = ndr_push_struct_blob(&tsig_blob, mem_ctx, check_rec,
		(ndr_push_flags_fn_t)ndr_push_dns_fake_tsig_rec);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		return DNS_ERR(SERVER_FAILURE);
	}

	buffer_len = packet_blob.length + tsig_blob.length;
	buffer = talloc_zero_array(mem_ctx, uint8_t, buffer_len);
	if (buffer == NULL) {
		return WERR_NOMEM;
	}

	memcpy(buffer, packet_blob.data, packet_blob.length);
	memcpy(buffer+packet_blob.length, tsig_blob.data, tsig_blob.length);


	status = gensec_sign_packet(tkey->gensec, mem_ctx, buffer, buffer_len,
				    buffer, buffer_len, &sig);
	if (!NT_STATUS_IS_OK(status)) {
		return ntstatus_to_werror(status);
	}

	tsig->name = talloc_strdup(tsig, check_rec->name);
	if (tsig->name == NULL) {
		return WERR_NOMEM;
	}
	tsig->rr_class = check_rec->rr_class;
	tsig->rr_type = DNS_QTYPE_TSIG;
	tsig->ttl = 0;
	tsig->length = UINT16_MAX;
	tsig->rdata.tsig_record.algorithm_name = talloc_strdup(tsig,
			check_rec->algorithm_name);
	tsig->rdata.tsig_record.time_prefix = check_rec->time_prefix;
	tsig->rdata.tsig_record.time = check_rec->time;
	tsig->rdata.tsig_record.fudge = check_rec->fudge;
	tsig->rdata.tsig_record.error = state->tsig_error;
	tsig->rdata.tsig_record.original_id = packet->id;
	tsig->rdata.tsig_record.other_size = 0;
	tsig->rdata.tsig_record.other_data = NULL;
	tsig->rdata.tsig_record.mac_size = sig.length;
	tsig->rdata.tsig_record.mac = talloc_memdup(tsig, sig.data, sig.length);


	if (packet->arcount == 0) {
		packet->additional = talloc_zero(mem_ctx, struct dns_res_rec);
		if (packet->additional == NULL) {
			return WERR_NOMEM;
		}
	}
	packet->additional = talloc_realloc(mem_ctx, packet->additional,
					    struct dns_res_rec,
					    packet->arcount + 1);
	if (packet->additional == NULL) {
		return WERR_NOMEM;
	}

	werror = dns_copy_tsig(mem_ctx, tsig,
			       &packet->additional[packet->arcount]);
	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}
	packet->arcount++;

	return WERR_OK;
}
