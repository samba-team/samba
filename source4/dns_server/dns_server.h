/*
   Unix SMB/CIFS implementation.

   DNS structures

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

#ifndef __DNS_SERVER_H__
#define __DNS_SERVER_H__

#include "librpc/gen_ndr/dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "dnsserver_common.h"

struct tsocket_address;
struct dns_server_tkey {
	const char *name;
	enum dns_tkey_mode mode;
	const char *algorithm;
	struct auth_session_info *session_info;
	struct gensec_security *gensec;
	bool complete;
};

#define TKEY_BUFFER_SIZE 128

struct dns_server_tkey_store {
	struct dns_server_tkey **tkeys;
	uint16_t next_idx;
	uint16_t size;
};

struct dns_server {
	struct task_server *task;
	struct ldb_context *samdb;
	struct dns_server_zone *zones;
	struct dns_server_tkey_store *tkeys;
	struct cli_credentials *server_credentials;
};

struct dns_request_state {
	TALLOC_CTX *mem_ctx;
	uint16_t flags;
	bool authenticated;
	bool sign;
	char *key_name;
	struct dns_res_rec *tsig;
	uint16_t tsig_error;
	const struct tsocket_address *local_address;
	const struct tsocket_address *remote_address;
};

struct tevent_req *dns_server_process_query_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns,	struct dns_request_state *req_state,
	const struct dns_name_packet *in);
WERROR dns_server_process_query_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx,
	struct dns_res_rec **answers,    uint16_t *ancount,
	struct dns_res_rec **nsrecs,     uint16_t *nscount,
	struct dns_res_rec **additional, uint16_t *arcount);

WERROR dns_server_process_update(struct dns_server *dns,
				 const struct dns_request_state *state,
				 TALLOC_CTX *mem_ctx,
				 const struct dns_name_packet *in,
				 struct dns_res_rec **prereqs,    uint16_t *prereq_count,
				 struct dns_res_rec **updates,    uint16_t *update_count,
				 struct dns_res_rec **additional, uint16_t *arcount);

bool dns_records_match(struct dnsp_DnssrvRpcRecord *rec1,
		       struct dnsp_DnssrvRpcRecord *rec2);
bool dns_authoritative_for_zone(struct dns_server *dns,
				const char *name);
const char *dns_get_authoritative_zone(struct dns_server *dns,
				       const char *name);
WERROR dns_lookup_records(struct dns_server *dns,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *rec_count);
WERROR dns_lookup_records_wildcard(struct dns_server *dns,
			  TALLOC_CTX *mem_ctx,
			  struct ldb_dn *dn,
			  struct dnsp_DnssrvRpcRecord **records,
			  uint16_t *rec_count);
WERROR dns_replace_records(struct dns_server *dns,
			   TALLOC_CTX *mem_ctx,
			   struct ldb_dn *dn,
			   bool needs_add,
			   struct dnsp_DnssrvRpcRecord *records,
			   uint16_t rec_count);
WERROR dns_name2dn(struct dns_server *dns,
		   TALLOC_CTX *mem_ctx,
		   const char *name,
		   struct ldb_dn **_dn);
struct dns_server_tkey *dns_find_tkey(struct dns_server_tkey_store *store,
				      const char *name);
WERROR dns_verify_tsig(struct dns_server *dns,
		       TALLOC_CTX *mem_ctx,
		       struct dns_request_state *state,
		       struct dns_name_packet *packet,
		       DATA_BLOB *in);
WERROR dns_sign_tsig(struct dns_server *dns,
		     TALLOC_CTX *mem_ctx,
		     struct dns_request_state *state,
		     struct dns_name_packet *packet,
		     uint16_t error);

#include "source4/dns_server/dnsserver_common.h"

#endif /* __DNS_SERVER_H__ */
