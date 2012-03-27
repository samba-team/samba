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
		break;
	case DNS_QTYPE_A:
		ans[ai].rdata.ipv4_record = talloc_strdup(ans, rec->data.ipv4);
		break;
	case DNS_QTYPE_AAAA:
		ans[ai].rdata.ipv6_record = rec->data.ipv6;
		break;
	case DNS_TYPE_NS:
		ans[ai].rdata.ns_record = rec->data.ns;
		break;
	case DNS_QTYPE_SRV:
		ans[ai].rdata.srv_record.priority = rec->data.srv.wPriority;
		ans[ai].rdata.srv_record.weight   = rec->data.srv.wWeight;
		ans[ai].rdata.srv_record.port     = rec->data.srv.wPort;
		ans[ai].rdata.srv_record.target   = rec->data.srv.nameTarget;
		break;
	case DNS_QTYPE_SOA:
		ans[ai].rdata.soa_record.mname	 = rec->data.soa.mname;
		ans[ai].rdata.soa_record.rname	 = rec->data.soa.rname;
		ans[ai].rdata.soa_record.serial	 = rec->data.soa.serial;
		ans[ai].rdata.soa_record.refresh = rec->data.soa.refresh;
		ans[ai].rdata.soa_record.retry	 = rec->data.soa.retry;
		ans[ai].rdata.soa_record.expire	 = rec->data.soa.expire;
		ans[ai].rdata.soa_record.minimum = rec->data.soa.minimum;
		break;
	case DNS_QTYPE_PTR:
		ans[ai].rdata.ptr_record = talloc_strdup(ans, rec->data.ptr);
		break;
	case DNS_QTYPE_TXT:
		tmp = talloc_asprintf(ans, "\"%s\"", rec->data.txt.str[0]);
		for (i=1; i<rec->data.txt.count; i++) {
			tmp = talloc_asprintf_append(tmp, " \"%s\"",
						     rec->data.txt.str[i]);
		}
		ans[ai].rdata.txt_record.txt = tmp;
		break;
	default:
		DEBUG(0, ("Got unhandled type %u query.\n", rec->wType));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	ans[ai].name = talloc_strdup(ans, question->name);
	ans[ai].rr_type = rec->wType;
	ans[ai].rr_class = DNS_QCLASS_IN;
	ans[ai].ttl = rec->dwTtlSeconds;
	ans[ai].length = UINT16_MAX;
	ai++;

	*answers = ans;
	*ancount = ai;

	return WERR_OK;
}

static WERROR ask_forwarder(struct dns_server *dns,
			    TALLOC_CTX *mem_ctx,
			    struct dns_name_question *question,
			    struct dns_res_rec **answers, uint16_t *ancount,
			    struct dns_res_rec **nsrecs, uint16_t *nscount,
			    struct dns_res_rec **additional, uint16_t *arcount)
{
	struct tevent_context *ev = tevent_context_init(mem_ctx);
	struct dns_name_packet *out_packet, *in_packet;
	uint16_t id = random();
	DATA_BLOB out, in;
	enum ndr_err_code ndr_err;
	WERROR werr = WERR_OK;
	struct tevent_req *req;
	const char *forwarder = lpcfg_dns_forwarder(dns->task->lp_ctx);

	if (!is_ipaddress(forwarder)) {
		DEBUG(0, ("Invalid 'dns forwarder' setting '%s', needs to be "
			  "an IP address\n", forwarder));
		return DNS_ERR(NAME_ERROR);
	}

	out_packet = talloc_zero(mem_ctx, struct dns_name_packet);
	W_ERROR_HAVE_NO_MEMORY(out_packet);

	out_packet->id = id;
	out_packet->operation |= DNS_OPCODE_QUERY | DNS_FLAG_RECURSION_DESIRED;

	out_packet->qdcount = 1;
	out_packet->questions = question;

	ndr_err = ndr_push_struct_blob(&out, mem_ctx, out_packet,
			(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return DNS_ERR(SERVER_FAILURE);
	}

	req = dns_udp_request_send(mem_ctx, ev, forwarder, out.data, out.length);
	W_ERROR_HAVE_NO_MEMORY(req);

	if(!tevent_req_poll(req, ev)) {
		return DNS_ERR(SERVER_FAILURE);
	}

	werr = dns_udp_request_recv(req, mem_ctx, &in.data, &in.length);
	W_ERROR_NOT_OK_RETURN(werr);

	in_packet = talloc_zero(mem_ctx, struct dns_name_packet);
	W_ERROR_HAVE_NO_MEMORY(in_packet);

	ndr_err = ndr_pull_struct_blob(&in, in_packet, in_packet,
			(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return DNS_ERR(SERVER_FAILURE);
	}

	if (in_packet->id != id) {
		DEBUG(0, ("DNS packet id mismatch: 0x%0x, expected 0x%0x\n",
			  in_packet->id, id));
		return DNS_ERR(NAME_ERROR);
	}

	*ancount = in_packet->ancount;
	*answers = talloc_move(mem_ctx, &in_packet->answers);

	*nscount = in_packet->nscount;
	*nsrecs = talloc_move(mem_ctx, &in_packet->nsrecs);

	*arcount = in_packet->arcount;
	*additional = talloc_move(mem_ctx, &in_packet->additional);

	return werr;
}

static WERROR handle_question(struct dns_server *dns,
			      TALLOC_CTX *mem_ctx,
			      const struct dns_name_question *question,
			      struct dns_res_rec **answers, uint16_t *ancount)
{
	struct dns_res_rec *ans;
	WERROR werror;
	unsigned int ri;
	struct dnsp_DnssrvRpcRecord *recs;
	uint16_t rec_count, ai = 0;
	struct ldb_dn *dn = NULL;

	werror = dns_name2dn(dns, mem_ctx, question->name, &dn);
	W_ERROR_NOT_OK_RETURN(werror);

	werror = dns_lookup_records(dns, mem_ctx, dn, &recs, &rec_count);
	W_ERROR_NOT_OK_RETURN(werror);

	ans = talloc_zero_array(mem_ctx, struct dns_res_rec, rec_count);
	W_ERROR_HAVE_NO_MEMORY(ans);

	for (ri = 0; ri < rec_count; ri++) {
		if ((question->question_type != DNS_QTYPE_ALL) &&
		    (recs[ri].wType != question->question_type)) {
			continue;
		}
		werror = create_response_rr(question, &recs[ri], &ans, &ai);
		W_ERROR_NOT_OK_RETURN(werror);
	}

	if (ai == 0) {
		return DNS_ERR(NAME_ERROR);
	}

	*ancount = ai;
	*answers = ans;

	return WERR_OK;

}

WERROR dns_server_process_query(struct dns_server *dns,
				struct dns_request_state *state,
				TALLOC_CTX *mem_ctx,
				struct dns_name_packet *in,
				struct dns_res_rec **answers,    uint16_t *ancount,
				struct dns_res_rec **nsrecs,     uint16_t *nscount,
				struct dns_res_rec **additional, uint16_t *arcount)
{
	uint16_t num_answers=0, num_nsrecs=0, num_additional=0;
	struct dns_res_rec *ans=NULL, *ns=NULL, *adds=NULL;
	WERROR werror;

	if (in->qdcount != 1) {
		return DNS_ERR(FORMAT_ERROR);
	}

	/* Windows returns NOT_IMPLEMENTED on this as well */
	if (in->questions[0].question_class == DNS_QCLASS_NONE) {
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	if (dns_authorative_for_zone(dns, in->questions[0].name)) {
		state->flags |= DNS_FLAG_AUTHORITATIVE;
		werror = handle_question(dns, mem_ctx, &in->questions[0],
					 &ans, &num_answers);
	} else {
		if (state->flags & DNS_FLAG_RECURSION_DESIRED &&
		    state->flags & DNS_FLAG_RECURSION_AVAIL) {
			DEBUG(2, ("Not authorative for '%s', forwarding\n",
				  in->questions[0].name));
			werror = ask_forwarder(dns, mem_ctx, &in->questions[0],
					       &ans, &num_answers,
					       &ns, &num_nsrecs,
					       &adds, &num_additional);
		} else {
			werror = DNS_ERR(NAME_ERROR);
		}
	}
	W_ERROR_NOT_OK_GOTO(werror, query_failed);

	*answers = ans;
	*ancount = num_answers;

	/*FIXME: Do something for these */
	*nsrecs  = ns;
	*nscount = num_nsrecs;

	*additional = adds;
	*arcount    = num_additional;

	return WERR_OK;

query_failed:
	/*FIXME: add our SOA record to nsrecs */
	return werror;
}
