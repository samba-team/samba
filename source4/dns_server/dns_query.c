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
#include "lib/util/dlinklist.h"
#include "lib/util/util_net.h"
#include "lib/util/tevent_werror.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS
#define MAX_Q_RECURSION_DEPTH 20

struct forwarder_string {
	const char *forwarder;
	struct forwarder_string *prev, *next;
};

static WERROR add_response_rr(const char *name,
			      const struct dnsp_DnssrvRpcRecord *rec,
			      struct dns_res_rec **answers)
{
	struct dns_res_rec *ans = *answers;
	uint16_t ai = talloc_array_length(ans);
	enum ndr_err_code ndr_err;

	if (ai == UINT16_MAX) {
		return WERR_BUFFER_OVERFLOW;
	}

	/*
	 * "ans" is always non-NULL and thus its own talloc context
	 */
	ans = talloc_realloc(ans, ans, struct dns_res_rec, ai+1);
	if (ans == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

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
		W_ERROR_HAVE_NO_MEMORY(ans[ai].rdata.ptr_record);
		break;
	case DNS_QTYPE_MX:
		ans[ai].rdata.mx_record.preference = rec->data.mx.wPriority;
		ans[ai].rdata.mx_record.exchange = talloc_strdup(
			ans, rec->data.mx.nameTarget);
		if (ans[ai].rdata.mx_record.exchange == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_TXT:
		ndr_err = ndr_dnsp_string_list_copy(ans,
						    &rec->data.txt,
						    &ans[ai].rdata.txt_record.txt);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	default:
		DEBUG(0, ("Got unhandled type %u query.\n", rec->wType));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	ans[ai].name = talloc_strdup(ans, name);
	W_ERROR_HAVE_NO_MEMORY(ans[ai].name);
	ans[ai].rr_type = (enum dns_qtype)rec->wType;
	ans[ai].rr_class = DNS_QCLASS_IN;
	ans[ai].ttl = rec->dwTtlSeconds;
	ans[ai].length = UINT16_MAX;

	*answers = ans;

	return WERR_OK;
}

static WERROR add_dns_res_rec(struct dns_res_rec **pdst,
			      const struct dns_res_rec *src)
{
	struct dns_res_rec *dst = *pdst;
	uint16_t di = talloc_array_length(dst);
	enum ndr_err_code ndr_err;

	if (di == UINT16_MAX) {
		return WERR_BUFFER_OVERFLOW;
	}

	dst = talloc_realloc(dst, dst, struct dns_res_rec, di+1);
	if (dst == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ZERO_STRUCT(dst[di]);

	dst[di] = (struct dns_res_rec) {
		.name = talloc_strdup(dst, src->name),
		.rr_type = src->rr_type,
		.rr_class = src->rr_class,
		.ttl = src->ttl,
		.length = src->length
	};

	if (dst[di].name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	switch (src->rr_type) {
	case DNS_QTYPE_CNAME:
		dst[di].rdata.cname_record = talloc_strdup(
			dst, src->rdata.cname_record);
		if (dst[di].rdata.cname_record == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_A:
		dst[di].rdata.ipv4_record = talloc_strdup(
			dst, src->rdata.ipv4_record);
		if (dst[di].rdata.ipv4_record == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_AAAA:
		dst[di].rdata.ipv6_record = talloc_strdup(
			dst, src->rdata.ipv6_record);
		if (dst[di].rdata.ipv6_record == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_TYPE_NS:
		dst[di].rdata.ns_record = talloc_strdup(
			dst, src->rdata.ns_record);
		if (dst[di].rdata.ns_record == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_SRV:
		dst[di].rdata.srv_record = (struct dns_srv_record) {
			.priority = src->rdata.srv_record.priority,
			.weight   = src->rdata.srv_record.weight,
			.port     = src->rdata.srv_record.port,
			.target   = talloc_strdup(
				dst, src->rdata.srv_record.target)
		};
		if (dst[di].rdata.srv_record.target == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_SOA:
		dst[di].rdata.soa_record = (struct dns_soa_record) {
			.mname	 = talloc_strdup(
				dst, src->rdata.soa_record.mname),
			.rname	 = talloc_strdup(
				dst, src->rdata.soa_record.rname),
			.serial	 = src->rdata.soa_record.serial,
			.refresh = src->rdata.soa_record.refresh,
			.retry   = src->rdata.soa_record.retry,
			.expire  = src->rdata.soa_record.expire,
			.minimum = src->rdata.soa_record.minimum
		};

		if ((dst[di].rdata.soa_record.mname == NULL) ||
		    (dst[di].rdata.soa_record.rname == NULL)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		break;
	case DNS_QTYPE_PTR:
		dst[di].rdata.ptr_record = talloc_strdup(
			dst, src->rdata.ptr_record);
		if (dst[di].rdata.ptr_record == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_MX:
		dst[di].rdata.mx_record = (struct dns_mx_record) {
			.preference = src->rdata.mx_record.preference,
			.exchange   = talloc_strdup(
				src, src->rdata.mx_record.exchange)
		};

		if (dst[di].rdata.mx_record.exchange == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	case DNS_QTYPE_TXT:
		ndr_err = ndr_dnsp_string_list_copy(dst,
						    &src->rdata.txt_record.txt,
						    &dst[di].rdata.txt_record.txt);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
		break;
	default:
		DBG_WARNING("Got unhandled type %u query.\n", src->rr_type);
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	*pdst = dst;

	return WERR_OK;
}

struct ask_forwarder_state {
	struct dns_name_packet *reply;
};

static void ask_forwarder_done(struct tevent_req *subreq);

static struct tevent_req *ask_forwarder_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *forwarder, struct dns_name_question *question)
{
	struct tevent_req *req, *subreq;
	struct ask_forwarder_state *state;

	req = tevent_req_create(mem_ctx, &state, struct ask_forwarder_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = dns_cli_request_send(state, ev, forwarder,
				      question->name, question->question_class,
				      question->question_type);
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
	int ret;

	ret = dns_cli_request_recv(subreq, state, &state->reply);
	TALLOC_FREE(subreq);

	if (ret != 0) {
		tevent_req_werror(req, unix_to_werror(ret));
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
	struct dns_name_packet *in_packet = state->reply;
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

static WERROR add_zone_authority_record(struct dns_server *dns,
					TALLOC_CTX *mem_ctx,
					const struct dns_name_question *question,
					struct dns_res_rec **nsrecs)
{
	const char *zone = NULL;
	struct dnsp_DnssrvRpcRecord *recs;
	struct dns_res_rec *ns = *nsrecs;
	uint16_t rec_count;
	struct ldb_dn *dn = NULL;
	unsigned int ri;
	WERROR werror;

	zone = dns_get_authoritative_zone(dns, question->name);
	DEBUG(10, ("Creating zone authority record for '%s'\n", zone));

	werror = dns_name2dn(dns, mem_ctx, zone, &dn);
	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}

	werror = dns_lookup_records(dns, mem_ctx, dn, &recs, &rec_count);
	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}

	for (ri = 0; ri < rec_count; ri++) {
		if (recs[ri].wType == DNS_TYPE_SOA) {
			werror = add_response_rr(zone, &recs[ri], &ns);
			if (!W_ERROR_IS_OK(werror)) {
				return werror;
			}
		}
	}

	*nsrecs = ns;

	return WERR_OK;
}

static struct tevent_req *handle_authoritative_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns, const char *forwarder,
	struct dns_name_question *question,
	struct dns_res_rec **answers, struct dns_res_rec **nsrecs,
	size_t cname_depth);
static WERROR handle_authoritative_recv(struct tevent_req *req);

struct handle_dnsrpcrec_state {
	struct dns_res_rec **answers;
	struct dns_res_rec **nsrecs;
};

static void handle_dnsrpcrec_gotauth(struct tevent_req *subreq);
static void handle_dnsrpcrec_gotforwarded(struct tevent_req *subreq);

static struct tevent_req *handle_dnsrpcrec_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns, const char *forwarder,
	const struct dns_name_question *question,
	struct dnsp_DnssrvRpcRecord *rec,
	struct dns_res_rec **answers, struct dns_res_rec **nsrecs,
	size_t cname_depth)
{
	struct tevent_req *req, *subreq;
	struct handle_dnsrpcrec_state *state;
	struct dns_name_question *new_q;
	bool resolve_cname;
	WERROR werr;

	req = tevent_req_create(mem_ctx, &state,
				struct handle_dnsrpcrec_state);
	if (req == NULL) {
		return NULL;
	}
	state->answers = answers;
	state->nsrecs = nsrecs;

	if (cname_depth >= MAX_Q_RECURSION_DEPTH) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	resolve_cname = ((rec->wType == DNS_TYPE_CNAME) &&
			 ((question->question_type == DNS_QTYPE_A) ||
			  (question->question_type == DNS_QTYPE_AAAA)));

	if (!resolve_cname) {
		if ((question->question_type != DNS_QTYPE_ALL) &&
		    (rec->wType !=
		     (enum dns_record_type) question->question_type)) {
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}

		werr = add_response_rr(question->name, rec, state->answers);
		if (tevent_req_werror(req, werr)) {
			return tevent_req_post(req, ev);
		}

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	werr = add_response_rr(question->name, rec, state->answers);
	if (tevent_req_werror(req, werr)) {
		return tevent_req_post(req, ev);
	}

	new_q = talloc(state, struct dns_name_question);
	if (tevent_req_nomem(new_q, req)) {
		return tevent_req_post(req, ev);
	}

	*new_q = (struct dns_name_question) {
		.question_type = question->question_type,
		.question_class = question->question_class,
		.name = rec->data.cname
	};

	if (dns_authoritative_for_zone(dns, new_q->name)) {
		subreq = handle_authoritative_send(
			state, ev, dns, forwarder, new_q,
			state->answers, state->nsrecs,
			cname_depth + 1);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, handle_dnsrpcrec_gotauth, req);
		return req;
	}

	subreq = ask_forwarder_send(state, ev, forwarder, new_q);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, handle_dnsrpcrec_gotforwarded, req);

	return req;
}

static void handle_dnsrpcrec_gotauth(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	WERROR werr;

	werr = handle_authoritative_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_werror(req, werr)) {
		return;
	}
	tevent_req_done(req);
}

static void handle_dnsrpcrec_gotforwarded(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct handle_dnsrpcrec_state *state = tevent_req_data(
		req, struct handle_dnsrpcrec_state);
	struct dns_res_rec *answers, *nsrecs, *additional;
	uint16_t ancount = 0;
	uint16_t nscount = 0;
	uint16_t arcount = 0;
	uint16_t i;
	WERROR werr;

	werr = ask_forwarder_recv(subreq, state, &answers, &ancount,
				  &nsrecs, &nscount, &additional, &arcount);
	if (tevent_req_werror(req, werr)) {
		return;
	}

	for (i=0; i<ancount; i++) {
		werr = add_dns_res_rec(state->answers, &answers[i]);
		if (tevent_req_werror(req, werr)) {
			return;
		}
	}

	for (i=0; i<nscount; i++) {
		werr = add_dns_res_rec(state->nsrecs, &nsrecs[i]);
		if (tevent_req_werror(req, werr)) {
			return;
		}
	}

	tevent_req_done(req);
}

static WERROR handle_dnsrpcrec_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_werror(req);
}

struct handle_authoritative_state {
	struct tevent_context *ev;
	struct dns_server *dns;
	struct dns_name_question *question;
	const char *forwarder;

	struct dnsp_DnssrvRpcRecord *recs;
	uint16_t rec_count;
	uint16_t recs_done;

	struct dns_res_rec **answers;
	struct dns_res_rec **nsrecs;

	size_t cname_depth;
};

static void handle_authoritative_done(struct tevent_req *subreq);

static struct tevent_req *handle_authoritative_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns, const char *forwarder,
	struct dns_name_question *question,
	struct dns_res_rec **answers, struct dns_res_rec **nsrecs,
	size_t cname_depth)
{
	struct tevent_req *req, *subreq;
	struct handle_authoritative_state *state;
	struct ldb_dn *dn = NULL;
	WERROR werr;

	req = tevent_req_create(mem_ctx, &state,
				struct handle_authoritative_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->dns = dns;
	state->question = question;
	state->forwarder = forwarder;
	state->answers = answers;
	state->nsrecs = nsrecs;
	state->cname_depth = cname_depth;

	werr = dns_name2dn(dns, state, question->name, &dn);
	if (tevent_req_werror(req, werr)) {
		return tevent_req_post(req, ev);
	}
	werr = dns_lookup_records_wildcard(dns, state, dn, &state->recs,
				           &state->rec_count);
	TALLOC_FREE(dn);
	if (tevent_req_werror(req, werr)) {
		return tevent_req_post(req, ev);
	}

	if (state->rec_count == 0) {
		tevent_req_werror(req, DNS_ERR(NAME_ERROR));
		return tevent_req_post(req, ev);
	}

	subreq = handle_dnsrpcrec_send(
		state, state->ev, state->dns, state->forwarder,
		state->question, &state->recs[state->recs_done],
		state->answers, state->nsrecs,
		state->cname_depth);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, handle_authoritative_done, req);
	return req;
}

static void handle_authoritative_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct handle_authoritative_state *state = tevent_req_data(
		req, struct handle_authoritative_state);
	WERROR werr;

	werr = handle_dnsrpcrec_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_werror(req, werr)) {
		return;
	}

	state->recs_done += 1;

	if (state->recs_done == state->rec_count) {
		tevent_req_done(req);
		return;
	}

	subreq = handle_dnsrpcrec_send(
		state, state->ev, state->dns, state->forwarder,
		state->question, &state->recs[state->recs_done],
		state->answers, state->nsrecs,
		state->cname_depth);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, handle_authoritative_done, req);
}

static WERROR handle_authoritative_recv(struct tevent_req *req)
{
	WERROR werr;

	if (tevent_req_is_werror(req, &werr)) {
		return werr;
	}

	return WERR_OK;
}

static NTSTATUS create_tkey(struct dns_server *dns,
			    const char* name,
			    const char* algorithm,
			    const struct tsocket_address *remote_address,
			    const struct tsocket_address *local_address,
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

	/*
	 * We only allow SPNEGO/KRB5 currently
	 * and rely on the backend to be RPC/IPC free.
	 *
	 * It allows gensec_update() not to block.
	 */
	status = samba_server_gensec_krb5_start(k,
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

	status = gensec_set_remote_address(k->gensec,
					   remote_address);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set remote address into GENSEC: %s\n",
			  nt_errstr(status)));
		*tkey = NULL;
		return status;
	}

	status = gensec_set_local_address(k->gensec,
					  local_address);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to set local address into GENSEC: %s\n",
			  nt_errstr(status)));
		*tkey = NULL;
		return status;
	}

	status = gensec_start_mech_by_oid(k->gensec, GENSEC_OID_SPNEGO);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC server code: %s\n",
			  nt_errstr(status)));
		*tkey = NULL;
		return status;
	}

	TALLOC_FREE(store->tkeys[store->next_idx]);

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

	/*
	 * We use samba_server_gensec_krb5_start(),
	 * which only allows SPNEGO/KRB5 currently
	 * and makes sure the backend to be RPC/IPC free.
	 *
	 * See gensec_gssapi_update_internal() as
	 * GENSEC_SERVER.
	 *
	 * It allows gensec_update() not to block.
	 *
	 * If that changes in future we need to use
	 * gensec_update_send/recv here!
	 */
	status = gensec_update(tkey->gensec, mem_ctx,
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
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ret_tkey->name = talloc_strdup(ret_tkey, in_tkey->name);
	if (ret_tkey->name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	ret_tkey->rr_type = DNS_QTYPE_TKEY;
	ret_tkey->rr_class = DNS_QCLASS_ANY;
	ret_tkey->length = UINT16_MAX;

	ret_tkey->rdata.tkey_record.algorithm = talloc_strdup(ret_tkey,
			in_tkey->rdata.tkey_record.algorithm);
	if (ret_tkey->rdata.tkey_record.algorithm  == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
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
					      state->remote_address,
					      state->local_address,
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
			DBG_DEBUG("Tkey handshake completed\n");
			ret_tkey->rdata.tkey_record.key_size = reply.length;
			ret_tkey->rdata.tkey_record.key_data = talloc_memdup(ret_tkey,
								reply.data,
								reply.length);
			if (ret_tkey->rdata.tkey_record.key_data == NULL) {
				return WERR_NOT_ENOUGH_MEMORY;
			}
			state->sign = true;
			state->key_name = talloc_strdup(state->mem_ctx, tkey->name);
			if (state->key_name == NULL) {
				return WERR_NOT_ENOUGH_MEMORY;
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
	struct tevent_context *ev;
	struct dns_server *dns;
	struct dns_name_question *question;

	struct dns_res_rec *answers;
	uint16_t ancount;
	struct dns_res_rec *nsrecs;
	uint16_t nscount;
	struct dns_res_rec *additional;
	uint16_t arcount;
	struct forwarder_string *forwarders;
};

static void dns_server_process_query_got_auth(struct tevent_req *subreq);
static void dns_server_process_query_got_response(struct tevent_req *subreq);

struct tevent_req *dns_server_process_query_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct dns_server *dns,	struct dns_request_state *req_state,
	const struct dns_name_packet *in)
{
	struct tevent_req *req, *subreq;
	struct dns_server_process_query_state *state;
	const char **forwarders = NULL;
	unsigned int i;

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

	state->dns = dns;
	state->ev = ev;
	state->question = &in->questions[0];

	forwarders = lpcfg_dns_forwarder(dns->task->lp_ctx);
	for (i = 0; forwarders != NULL && forwarders[i] != NULL; i++) {
		struct forwarder_string *f = talloc_zero(state,
							 struct forwarder_string);
		f->forwarder = forwarders[i];
		DLIST_ADD_END(state->forwarders, f);
	}

	if (dns_authoritative_for_zone(dns, in->questions[0].name)) {

		req_state->flags |= DNS_FLAG_AUTHORITATIVE;

		/*
		 * Initialize the response arrays, so that we can use
		 * them as their own talloc contexts when doing the
		 * realloc
		 */
		state->answers = talloc_array(state, struct dns_res_rec, 0);
		if (tevent_req_nomem(state->answers, req)) {
			return tevent_req_post(req, ev);
		}
		state->nsrecs = talloc_array(state, struct dns_res_rec, 0);
		if (tevent_req_nomem(state->nsrecs, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = handle_authoritative_send(
			state, ev, dns, (forwarders == NULL ? NULL : forwarders[0]),
			&in->questions[0], &state->answers, &state->nsrecs,
			0); /* cname_depth */
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, dns_server_process_query_got_auth, req);
		return req;
	}

	if ((req_state->flags & DNS_FLAG_RECURSION_DESIRED) &&
	    (req_state->flags & DNS_FLAG_RECURSION_AVAIL)) {
		DEBUG(5, ("Not authoritative for '%s', forwarding\n",
			  in->questions[0].name));

		subreq = ask_forwarder_send(state, ev,
					    (forwarders == NULL ? NULL : forwarders[0]),
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
	WERROR werr;

	werr = ask_forwarder_recv(subreq, state,
				  &state->answers, &state->ancount,
				  &state->nsrecs, &state->nscount,
				  &state->additional, &state->arcount);
	TALLOC_FREE(subreq);

	/* If you get an error, attempt a different forwarder */
	if (!W_ERROR_IS_OK(werr)) {
		if (state->forwarders != NULL) {
			DLIST_REMOVE(state->forwarders, state->forwarders);
		}

		/* If you have run out of forwarders, simply finish */
		if (state->forwarders == NULL) {
			tevent_req_werror(req, werr);
			return;
		}

		DEBUG(5, ("DNS query returned %s, trying another forwarder.\n",
			  win_errstr(werr)));
		subreq = ask_forwarder_send(state, state->ev,
					    state->forwarders->forwarder,
					    state->question);

		if (tevent_req_nomem(subreq, req)) {
			return;
		}

		tevent_req_set_callback(subreq,
					dns_server_process_query_got_response,
					req);
		return;
	}

	tevent_req_done(req);
}

static void dns_server_process_query_got_auth(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_server_process_query_state *state = tevent_req_data(
		req, struct dns_server_process_query_state);
	WERROR werr;
	WERROR werr2;

	werr = handle_authoritative_recv(subreq);
	TALLOC_FREE(subreq);

	/* If you get an error, attempt a different forwarder */
	if (!W_ERROR_IS_OK(werr)) {
		if (state->forwarders != NULL) {
			DLIST_REMOVE(state->forwarders, state->forwarders);
		}

		/* If you have run out of forwarders, simply finish */
		if (state->forwarders == NULL) {
			werr2 = add_zone_authority_record(state->dns,
							  state,
							  state->question,
							  &state->nsrecs);
			if (tevent_req_werror(req, werr2)) {
				DBG_WARNING("Failed to add SOA record: %s\n",
					    win_errstr(werr2));
				return;
			}

			state->ancount = talloc_array_length(state->answers);
			state->nscount = talloc_array_length(state->nsrecs);
			state->arcount = talloc_array_length(state->additional);

			tevent_req_werror(req, werr);
			return;
		}

		DEBUG(5, ("Error: %s, trying a different forwarder.\n",
			  win_errstr(werr)));
		subreq = handle_authoritative_send(state, state->ev, state->dns,
						   state->forwarders->forwarder,
						   state->question, &state->answers,
						   &state->nsrecs,
						   0); /* cname_depth */

		if (tevent_req_nomem(subreq, req)) {
			return;
		}

		tevent_req_set_callback(subreq,
					dns_server_process_query_got_auth,
					req);
		return;
	}

	werr2 = add_zone_authority_record(state->dns,
					  state,
					  state->question,
					  &state->nsrecs);
	if (tevent_req_werror(req, werr2)) {
		DBG_WARNING("Failed to add SOA record: %s\n",
				win_errstr(werr2));
		return;
	}

	state->ancount = talloc_array_length(state->answers);
	state->nscount = talloc_array_length(state->nsrecs);
	state->arcount = talloc_array_length(state->additional);

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
	WERROR err = WERR_OK;

	if (tevent_req_is_werror(req, &err)) {

		if ((!W_ERROR_EQUAL(err, DNS_ERR(NAME_ERROR))) &&
		    (!W_ERROR_EQUAL(err, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST))) {
			return err;
		}
	}
	*answers = talloc_move(mem_ctx, &state->answers);
	*ancount = state->ancount;
	*nsrecs = talloc_move(mem_ctx, &state->nsrecs);
	*nscount = state->nscount;
	*additional = talloc_move(mem_ctx, &state->additional);
	*arcount = state->arcount;
	return err;
}
