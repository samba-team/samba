/*
   Unix SMB/CIFS implementation.

   DNS server handler for queries

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
#include "smbd/service_task.h"
#include "libcli/util/werror.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include <ldb.h>
#include "param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dns_server/dns_server.h"
#include "libcli/dns/libdns.h"
#include "lib/util/util_net.h"
#include "lib/util/tevent_werror.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

static WERROR create_response_rr(const struct dns_name_question *question,
				 const struct dnsp_DnssrvRpcRecord *rec,
				 struct dns_res_rec **answers, uint16_t *ancount)
{
	struct dns_res_rec *ans = *answers;
	uint16_t ai = *ancount;
	char *tmp;
	uint32_t i;

	ZERO_STRUCT(ans[ai]);

	switch (rec->wType) {
	case DNS_QTYPE_CNAME:
		ans[ai].rdata.cname_record = talloc_strdup(ans, rec->data.cname);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.cname_record);
		break;
	case DNS_QTYPE_A:
		ans[ai].rdata.ipv4_record = talloc_strdup(ans, rec->data.ipv4);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.ipv4_record);
		break;
	case DNS_QTYPE_AAAA:
		ans[ai].rdata.ipv6_record = talloc_strdup(ans, rec->data.ipv6);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.ipv6_record);
		break;
	case DNS_TYPE_NS:
		ans[ai].rdata.ns_record = talloc_strdup(ans, rec->data.ns);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.ns_record);
		break;
	case DNS_QTYPE_SRV:
		ans[ai].rdata.srv_record.priority = rec->data.srv.wPriority;
		ans[ai].rdata.srv_record.weight   = rec->data.srv.wWeight;
		ans[ai].rdata.srv_record.port     = rec->data.srv.wPort;
		ans[ai].rdata.srv_record.target   = talloc_strdup(
			ans, rec->data.srv.nameTarget);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.srv_record.target);
		break;
	case DNS_QTYPE_SOA:
		ans[ai].rdata.soa_record.mname	 = talloc_strdup(
			ans, rec->data.soa.mname);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.soa_record.mname);
		ans[ai].rdata.soa_record.rname	 = talloc_strdup(
			ans, rec->data.soa.rname);
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.soa_record.rname);
		ans[ai].rdata.soa_record.serial	 = rec->data.soa.serial;
		ans[ai].rdata.soa_record.refresh = rec->data.soa.refresh;
		ans[ai].rdata.soa_record.retry	 = rec->data.soa.retry;
		ans[ai].rdata.soa_record.expire	 = rec->data.soa.expire;
		ans[ai].rdata.soa_record.minimum = rec->data.soa.minimum;
		break;
	case DNS_QTYPE_PTR:
		ans[ai].rdata.ptr_record = talloc_strdup(ans, rec->data.ptr);
		break;
	case DNS_QTYPE_MX:
		ans[ai].rdata.mx_record.preference = rec->data.mx.wPriority;
		ans[ai].rdata.mx_record.exchange = talloc_strdup(
			ans, rec->data.mx.nameTarget);
		if (ans[ai].rdata.mx_record.exchange == NULL) {
			return WERR_NOMEM;
		}
		break;
	case DNS_QTYPE_TXT:
		tmp = talloc_asprintf(ans, "\"%s\"", rec->data.txt.str[0]);
		W_ERROR_HAVE_NO_MEMORY(tmp);
		for (i=1; i<rec->data.txt.count; i++) {
			tmp = talloc_asprintf_append_buffer(
				tmp, " \"%s\"", rec->data.txt.str[i]);
			W_ERROR_HAVE_NO_MEMORY(tmp);
		}
		ans[ai].rdata.txt_record.txt = tmp;
		break;
	default:
		DEBUG(0, ("Got unhandled type %u query.\n", rec->wType));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	ans[ai].name = talloc_strdup(ans, question->name);
	W_ERROR_HAVE_NO_MEMORY(ans[ai].name);
	ans[ai].rr_type = rec->wType;
	ans[ai].rr_class = DNS_QCLASS_IN;
	ans[ai].ttl = rec->dwTtlSeconds;
	ans[ai].length = UINT16_MAX;
	ai++;

	*answers = ans;
	*ancount = ai;

	return WERR_OK;
}

struct ask_forwarder_state {
	struct tevent_context *ev;
	uint16_t id;
	struct dns_name_packet in_packet;
};

static void ask_forwarder_done(struct tevent_req *subreq);

static struct tevent_req *ask_forwarder_send(
	struct dns_server *dns,
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *forwarder, struct dns_name_question *question)
{
	struct tevent_req *req, *subreq;
	struct ask_forwarder_state *state;
	struct dns_res_rec *options;
	struct dns_name_packet out_packet = { 0, };
	DATA_BLOB out_blob;
	enum ndr_err_code ndr_err;
	WERROR werr;

	req = tevent_req_create(mem_ctx, &state, struct ask_forwarder_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	generate_random_buffer((uint8_t *)&state->id, sizeof(state->id));

	if (!is_ipaddress(forwarder)) {
		DEBUG(0, ("Invalid 'dns forwarder' setting '%s', needs to be "
			  "an IP address\n", forwarder));
		tevent_req_werror(req, DNS_ERR(NAME_ERROR));
		return tevent_req_post(req, ev);
	}

	out_packet.id = state->id;
	out_packet.operation |= DNS_OPCODE_QUERY | DNS_FLAG_RECURSION_DESIRED;
	out_packet.qdcount = 1;
	out_packet.questions = question;

	werr = dns_generate_options(dns, state, &options);
	if (!W_ERROR_IS_OK(werr)) {
		tevent_req_werror(req, werr);
		return tevent_req_post(req, ev);
	}

	out_packet.arcount = 1;
	out_packet.additional = options;

	ndr_err = ndr_push_struct_blob(
		&out_blob, state, &out_packet,
		(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_werror(req, DNS_ERR(SERVER_FAILURE));
		return tevent_req_post(req, ev);
	}
	subreq = dns_udp_request_send(state, ev, forwarder, out_blob.data,
				      out_blob.length);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ask_forwarder_done, req);
	return req;
}

static void ask_forwarder_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ask_forwarder_state *state = tevent_req_data(
		req, struct ask_forwarder_state);
	DATA_BLOB in_blob;
	enum ndr_err_code ndr_err;
	WERROR ret;

	ret = dns_udp_request_recv(subreq, state,
				   &in_blob.data, &in_blob.length);
	TALLOC_FREE(subreq);
	if (tevent_req_werror(req, ret)) {
		return;
	}

	ndr_err = ndr_pull_struct_blob(
		&in_blob, state, &state->in_packet,
		(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		tevent_req_werror(req, DNS_ERR(SERVER_FAILURE));
		return;
	}
	if (state->in_packet.id != state->id) {
		tevent_req_werror(req, DNS_ERR(NAME_ERROR));
		return;
	}
	tevent_req_done(req);
}

static WERROR ask_forwarder_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx,
	struct dns_res_rec **answers, uint16_t *ancount,
	struct dns_res_rec **nsrecs, uint16_t *nscount,
	struct dns_res_rec **additional, uint16_t *arcount)
{
	struct ask_forwarder_state *state = tevent_req_data(
		req, struct ask_forwarder_state);
	struct dns_name_packet *in_packet = &state->in_packet;
	WERROR err;

	if (tevent_req_is_werror(req, &err)) {
		return err;
	}

	*ancount = in_packet->ancount;
	*answers = talloc_move(mem_ctx, &in_packet->answers);

	*nscount = in_packet->nscount;
	*nsrecs = talloc_move(mem_ctx, &in_packet->nsrecs);

	*arcount = in_packet->arcount;
	*additional = talloc_move(mem_ctx, &in_packet->additional);

	return WERR_OK;
}

static WERROR handle_question(struct dns_server *dns,
			      TALLOC_CTX *mem_ctx,
			      const struct dns_name_question *question,
			      struct dns_res_rec **answers, uint16_t *ancount)
{
	struct dns_res_rec *ans = *answers;
	WERROR werror, werror_return;
	unsigned int ri;
	struct dnsp_DnssrvRpcRecord *recs;
	uint16_t rec_count, ai = *ancount;
	struct ldb_dn *dn = NULL;

	werror = dns_name2dn(dns, mem_ctx, question->name, &dn);
	W_ERROR_NOT_OK_RETURN(werror);

	werror = dns_lookup_records(dns, mem_ctx, dn, &recs, &rec_count);
	W_ERROR_NOT_OK_RETURN(werror);

	ans = talloc_realloc(mem_ctx, ans, struct dns_res_rec, rec_count + ai);
	if (ans == NULL) {
		return WERR_NOMEM;
	}

	/* Set up for an NXDOMAIN reply if no match is found */
	werror_return = DNS_ERR(NAME_ERROR);

	for (ri = 0; ri < rec_count; ri++) {
		if ((recs[ri].wType == DNS_TYPE_CNAME) &&
		    ((question->question_type == DNS_QTYPE_A) ||
		     (question->question_type == DNS_QTYPE_AAAA))) {
			struct dns_name_question *new_q =
				talloc(mem_ctx, struct dns_name_question);

			if (new_q == NULL) {
				return WERR_NOMEM;
			}

			/* We reply with one more record, so grow the array */
			ans = talloc_realloc(mem_ctx, ans, struct dns_res_rec,
					     rec_count + 1);
			if (ans == NULL) {
				TALLOC_FREE(new_q);
				return WERR_NOMEM;
			}

			/* First put in the CNAME record */
			werror = create_response_rr(question, &recs[ri], &ans, &ai);
			if (!W_ERROR_IS_OK(werror)) {
				return werror;
			}

			/* And then look up the name it points at.. */

			/* First build up the new question */
			new_q->question_type = question->question_type;
			new_q->question_class = question->question_class;
			if (new_q->question_type == DNS_QTYPE_A) {
				new_q->name = talloc_strdup(new_q, recs[ri].data.ipv4);
			} else if (new_q->question_type == DNS_QTYPE_AAAA) {
				new_q->name = talloc_strdup(new_q, recs[ri].data.ipv6);
			}
			if (new_q->name == NULL) {
				TALLOC_FREE(new_q);
				return WERR_NOMEM;
			}
			/* and then call the lookup again */
			werror = handle_question(dns, mem_ctx, new_q, &ans, &ai);
			if (!W_ERROR_IS_OK(werror)) {
				return werror;
			}
			werror_return = WERR_OK;


			continue;
		}
		if ((question->question_type != DNS_QTYPE_ALL) &&
		    (recs[ri].wType != question->question_type)) {
			werror_return = WERR_OK;
			continue;
		}
		werror = create_response_rr(question, &recs[ri], &ans, &ai);
		if (!W_ERROR_IS_OK(werror)) {
			return werror;
		}
		werror_return = WERR_OK;
	}

	*ancount = ai;
	*answers = ans;

	return werror_return;
}

static NTSTATUS create_tkey(struct dns_server *dns,
			    const char* name,
			    const char* algorithm,
			    struct dns_server_tkey **tkey)
{
	NTSTATUS status;
	struct dns_server_tkey_store *store = dns->tkeys;
	struct dns_server_tkey *k = talloc_zero(store, struct dns_server_tkey);

	if (k == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	k->name = talloc_strdup(k, name);

	if (k->name  == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	k->algorithm = talloc_strdup(k, algorithm);
	if (k->algorithm == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = samba_server_gensec_start(k,
					   dns->task->event_ctx,
					   dns->task->msg_ctx,
					   dns->task->lp_ctx,
					   dns->server_credentials,
					   "dns",
					   &k->gensec);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
		*tkey = NULL;
		return status;
	}

	gensec_want_feature(k->gensec, GENSEC_FEATURE_SIGN);

	status = gensec_start_mech_by_oid(k->gensec, GENSEC_OID_SPNEGO);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC server code: %s\n",
			  nt_errstr(status)));
		*tkey = NULL;
		return status;
	}

	if (store->tkeys[store->next_idx] != NULL) {
		TALLOC_FREE(store->tkeys[store->next_idx]);
	}

	store->tkeys[store->next_idx] = k;
	(store->next_idx)++;
	store->next_idx %= store->size;

	*tkey = k;
	return NT_STATUS_OK;
}

static NTSTATUS accept_gss_ticket(TALLOC_CTX *mem_ctx,
				  struct dns_server *dns,
				  struct dns_server_tkey *tkey,
				  const DATA_BLOB *key,
				  DATA_BLOB *reply,
				  uint16_t *dns_auth_error)
{
	NTSTATUS status;

	status = gensec_update_ev(tkey->gensec, mem_ctx, dns->task->event_ctx,
				  *key, reply);

	if (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		*dns_auth_error = DNS_RCODE_OK;
		return status;
	}

	if (NT_STATUS_IS_OK(status)) {

		status = gensec_session_info(tkey->gensec, tkey, &tkey->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			*dns_auth_error = DNS_RCODE_BADKEY;
			return status;
		}
		*dns_auth_error = DNS_RCODE_OK;
	}

	return status;
}

static WERROR handle_tkey(struct dns_server *dns,
                          TALLOC_CTX *mem_ctx,
                          const struct dns_name_packet *in,
			  struct dns_request_state *state,
                          struct dns_res_rec **answers,
                          uint16_t *ancount)
{
	struct dns_res_rec *in_tkey = NULL;
	struct dns_res_rec *ret_tkey;
	uint16_t i;

	for (i = 0; i < in->arcount; i++) {
		if (in->additional[i].rr_type == DNS_QTYPE_TKEY) {
			in_tkey = &in->additional[i];
			break;
		}
	}

	/* If this is a TKEY query, it should have a TKEY RR.
	 * Behaviour is not really specified in RFC 2930 or RFC 3645, but
	 * FORMAT_ERROR seems to be what BIND uses .*/
	if (in_tkey == NULL) {
		return DNS_ERR(FORMAT_ERROR);
	}

	ret_tkey = talloc_zero(mem_ctx, struct dns_res_rec);
	if (ret_tkey == NULL) {
		return WERR_NOMEM;
	}

	ret_tkey->name = talloc_strdup(ret_tkey, in_tkey->name);
	if (ret_tkey->name == NULL) {
		return WERR_NOMEM;
	}

	ret_tkey->rr_type = DNS_QTYPE_TKEY;
	ret_tkey->rr_class = DNS_QCLASS_ANY;
	ret_tkey->length = UINT16_MAX;

	ret_tkey->rdata.tkey_record.algorithm = talloc_strdup(ret_tkey,
			in_tkey->rdata.tkey_record.algorithm);
	if (ret_tkey->rdata.tkey_record.algorithm  == NULL) {
		return WERR_NOMEM;
	}

	ret_tkey->rdata.tkey_record.inception = in_tkey->rdata.tkey_record.inception;
	ret_tkey->rdata.tkey_record.expiration = in_tkey->rdata.tkey_record.expiration;
	ret_tkey->rdata.tkey_record.mode = in_tkey->rdata.tkey_record.mode;

	switch (in_tkey->rdata.tkey_record.mode) {
	case DNS_TKEY_MODE_DH:
		/* FIXME: According to RFC 2930, we MUST support this, but we don't.
		 * Still, claim it's a bad key instead of a bad mode */
		ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADKEY;
		break;
	case DNS_TKEY_MODE_GSSAPI: {
		NTSTATUS status;
		struct dns_server_tkey *tkey;
		DATA_BLOB key;
		DATA_BLOB reply;

		tkey = dns_find_tkey(dns->tkeys, in->questions[0].name);
		if (tkey != NULL && tkey->complete) {
			/* TODO: check if the key is still valid */
			DEBUG(1, ("Rejecting tkey negotiation for already established key\n"));
			ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADNAME;
			break;
		}

		if (tkey == NULL) {
			status  = create_tkey(dns, in->questions[0].name,
					      in_tkey->rdata.tkey_record.algorithm,
					      &tkey);
			if (!NT_STATUS_IS_OK(status)) {
				ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADKEY;
				return ntstatus_to_werror(status);
			}
		}

		key.data = in_tkey->rdata.tkey_record.key_data;
		key.length = in_tkey->rdata.tkey_record.key_size;

		status = accept_gss_ticket(ret_tkey, dns, tkey, &key, &reply,
					   &ret_tkey->rdata.tkey_record.error);
		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(1, ("More processing required\n"));
			ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADKEY;
		} else if (NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Tkey handshake completed\n"));
			ret_tkey->rdata.tkey_record.key_size = reply.length;
			ret_tkey->rdata.tkey_record.key_data = talloc_memdup(ret_tkey,
								reply.data,
								reply.length);
			state->sign = true;
			state->key_name = talloc_strdup(mem_ctx, tkey->name);
			if (state->key_name == NULL) {
				return WERR_NOMEM;
			}
		} else {
			DEBUG(1, ("GSS key negotiation returned %s\n", nt_errstr(status)));
			ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADKEY;
		}

		break;
		}
	case DNS_TKEY_MODE_DELETE:
		/* TODO: implement me */
		DEBUG(1, ("Should delete tkey here\n"));
		ret_tkey->rdata.tkey_record.error = DNS_RCODE_OK;
		break;
	case DNS_TKEY_MODE_NULL:
	case DNS_TKEY_MODE_SERVER:
	case DNS_TKEY_MODE_CLIENT:
	case DNS_TKEY_MODE_LAST:
		/* We don't have to implement these, return a mode error */
		ret_tkey->rdata.tkey_record.error = DNS_RCODE_BADMODE;
		break;
	default:
		DEBUG(1, ("Unsupported TKEY mode %d\n",
		      in_tkey->rdata.tkey_record.mode));
	}

	*answers = ret_tkey;
	*ancount = 1;

	return WERR_OK;
}

struct dns_server_process_query_state {
	struct dns_res_rec *answers;
	uint16_t ancount;
	struct dns_res_rec *nsrecs;
	uint16_t nscount;
	struct dns_res_rec *additional;
	uint16_t arcount;
};

static void dns_server_process_query_got_response(struct tevent_req *subreq);

struct tevent_req *dns_server_process_query_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns,	struct dns_request_state *req_state,
	const struct dns_name_packet *in)
{
	struct tevent_req *req, *subreq;
	struct dns_server_process_query_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct dns_server_process_query_state);
	if (req == NULL) {
		return NULL;
	}
	if (in->qdcount != 1) {
		tevent_req_werror(req, DNS_ERR(FORMAT_ERROR));
		return tevent_req_post(req, ev);
	}

	/* Windows returns NOT_IMPLEMENTED on this as well */
	if (in->questions[0].question_class == DNS_QCLASS_NONE) {
		tevent_req_werror(req, DNS_ERR(NOT_IMPLEMENTED));
		return tevent_req_post(req, ev);
	}

	if (in->questions[0].question_type == DNS_QTYPE_TKEY) {
                WERROR err;

		err = handle_tkey(dns, state, in, req_state,
				  &state->answers, &state->ancount);
		if (tevent_req_werror(req, err)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (dns_authorative_for_zone(dns, in->questions[0].name)) {
		WERROR err;

		req_state->flags |= DNS_FLAG_AUTHORITATIVE;
		err = handle_question(dns, state, &in->questions[0],
				      &state->answers, &state->ancount);
		if (tevent_req_werror(req, err)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if ((req_state->flags & DNS_FLAG_RECURSION_DESIRED) &&
	    (req_state->flags & DNS_FLAG_RECURSION_AVAIL)) {
		DEBUG(2, ("Not authoritative for '%s', forwarding\n",
			  in->questions[0].name));

		subreq = ask_forwarder_send(
			dns,
			state, ev, lpcfg_dns_forwarder(dns->task->lp_ctx),
			&in->questions[0]);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, dns_server_process_query_got_response, req);
		return req;
	}

	tevent_req_werror(req, DNS_ERR(NAME_ERROR));
	return tevent_req_post(req, ev);
}

static void dns_server_process_query_got_response(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_server_process_query_state *state = tevent_req_data(
		req, struct dns_server_process_query_state);
	WERROR err;

	err = ask_forwarder_recv(subreq, state,
				 &state->answers, &state->ancount,
				 &state->nsrecs, &state->nscount,
				 &state->additional, &state->arcount);
	TALLOC_FREE(subreq);
	if (tevent_req_werror(req, err)) {
		return;
	}
	tevent_req_done(req);
}

WERROR dns_server_process_query_recv(
	struct tevent_req *req, TALLOC_CTX *mem_ctx,
	struct dns_res_rec **answers,    uint16_t *ancount,
	struct dns_res_rec **nsrecs,     uint16_t *nscount,
	struct dns_res_rec **additional, uint16_t *arcount)
{
	struct dns_server_process_query_state *state = tevent_req_data(
		req, struct dns_server_process_query_state);
	WERROR err;

	if (tevent_req_is_werror(req, &err)) {
		return err;
	}
	*answers = talloc_move(mem_ctx, &state->answers);
	*ancount = state->ancount;
	*nsrecs = talloc_move(mem_ctx, &state->nsrecs);
	*nscount = state->nscount;
	*additional = talloc_move(mem_ctx, &state->additional);
	*arcount = state->arcount;
	return WERR_OK;
}
