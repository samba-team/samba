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
#include "libcli/util/werror.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dns_server/dns_server.h"

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
				TALLOC_CTX *mem_ctx,
				struct dns_name_packet *in,
				struct dns_res_rec **answers,    uint16_t *ancount,
				struct dns_res_rec **nsrecs,     uint16_t *nscount,
				struct dns_res_rec **additional, uint16_t *arcount)
{
	uint16_t num_answers=0;
	struct dns_res_rec *ans=NULL;
	WERROR werror;

	if (in->qdcount != 1) {
		return DNS_ERR(FORMAT_ERROR);
	}

	/* Windows returns NOT_IMPLEMENTED on this as well */
	if (in->questions[0].question_class == DNS_QCLASS_NONE) {
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	werror = handle_question(dns, mem_ctx, &in->questions[0], &ans, &num_answers);
	W_ERROR_NOT_OK_GOTO(werror, query_failed);

	*answers = ans;
	*ancount = num_answers;

	/*FIXME: Do something for these */
	*nsrecs  = NULL;
	*nscount = 0;

	*additional = NULL;
	*arcount    = 0;

	return WERR_OK;

query_failed:
	/*FIXME: add our SOA record to nsrecs */
	return werror;
}
