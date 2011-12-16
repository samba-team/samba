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

static WERROR dns_rr_to_dnsp(TALLOC_CTX *mem_ctx,
			     const struct dns_res_rec *rrec,
			     struct dnsp_DnssrvRpcRecord *r);

static WERROR check_one_prerequisite(struct dns_server *dns,
				     TALLOC_CTX *mem_ctx,
				     const struct dns_name_question *zone,
				     const struct dns_res_rec *pr,
				     bool *final_result)
{
	bool match;
	WERROR werror;
	struct ldb_dn *dn;
	uint16_t i;
	bool found = false;
	struct dnsp_DnssrvRpcRecord *rec = NULL;
	struct dnsp_DnssrvRpcRecord *ans;
	uint16_t acount;

	size_t host_part_len = 0;

	*final_result = true;

	if (pr->ttl != 0) {
		return DNS_ERR(FORMAT_ERROR);
	}

	match = dns_name_match(zone->name, pr->name, &host_part_len);
	if (!match) {
		return DNS_ERR(NOTZONE);
	}

	werror = dns_name2dn(dns, mem_ctx, pr->name, &dn);
	W_ERROR_NOT_OK_RETURN(werror);

	if (pr->rr_class == DNS_QCLASS_ANY) {

		if (pr->length != 0) {
			return DNS_ERR(FORMAT_ERROR);
		}


		if (pr->rr_type == DNS_QTYPE_ALL) {
			/*
			 */
			werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
			W_ERROR_NOT_OK_RETURN(werror);

			if (acount == 0) {
				return DNS_ERR(NAME_ERROR);
			}
		} else {
			/*
			 */
			werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
			if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
				return DNS_ERR(NXRRSET);
			}
			W_ERROR_NOT_OK_RETURN(werror);

			for (i = 0; i < acount; i++) {
				if (ans[i].wType == pr->rr_type) {
					found = true;
					break;
				}
			}
			if (!found) {
				return DNS_ERR(NXRRSET);
			}
		}

		/*
		 * RFC2136 3.2.5 doesn't actually mention the need to return
		 * OK here, but otherwise we'd always return a FORMAT_ERROR
		 * later on. This also matches Microsoft DNS behavior.
		 */
		return WERR_OK;
	}

	if (pr->rr_class == DNS_QCLASS_NONE) {
		if (pr->length != 0) {
			return DNS_ERR(FORMAT_ERROR);
		}

		if (pr->rr_type == DNS_QTYPE_ALL) {
			/*
			 */
			werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
			if (W_ERROR_EQUAL(werror, WERR_OK)) {
				return DNS_ERR(YXDOMAIN);
			}
		} else {
			/*
			 */
			werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
			if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
				werror = WERR_OK;
				ans = NULL;
				acount = 0;
			}

			for (i = 0; i < acount; i++) {
				if (ans[i].wType == pr->rr_type) {
					found = true;
					break;
				}
			}
			if (found) {
				return DNS_ERR(YXRRSET);
			}
		}

		/*
		 * RFC2136 3.2.5 doesn't actually mention the need to return
		 * OK here, but otherwise we'd always return a FORMAT_ERROR
		 * later on. This also matches Microsoft DNS behavior.
		 */
		return WERR_OK;
	}

	if (pr->rr_class != zone->question_class) {
		return DNS_ERR(FORMAT_ERROR);
	}

	*final_result = false;

	werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
	if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
		return DNS_ERR(NXRRSET);
	}
	W_ERROR_NOT_OK_RETURN(werror);

	rec = talloc_zero(mem_ctx, struct dnsp_DnssrvRpcRecord);
	W_ERROR_HAVE_NO_MEMORY(rec);

	werror = dns_rr_to_dnsp(rec, pr, rec);
	W_ERROR_NOT_OK_RETURN(werror);

	for (i = 0; i < acount; i++) {
		if (dns_records_match(rec, &ans[i])) {
			found = true;
			break;
		}
	}

	if (!found) {
		return DNS_ERR(NXRRSET);
	}

	return WERR_OK;
}

static WERROR check_prerequisites(struct dns_server *dns,
				  TALLOC_CTX *mem_ctx,
				  const struct dns_name_question *zone,
				  const struct dns_res_rec *prereqs, uint16_t count)
{
	uint16_t i;
	WERROR final_error = WERR_OK;

	for (i = 0; i < count; i++) {
		bool final;
		WERROR werror;

		werror = check_one_prerequisite(dns, mem_ctx, zone,
						&prereqs[i], &final);
		if (!W_ERROR_IS_OK(werror)) {
			if (final) {
				return werror;
			}
			if (W_ERROR_IS_OK(final_error)) {
				final_error = werror;
			}
		}
	}

	if (!W_ERROR_IS_OK(final_error)) {
		return final_error;
	}

	return WERR_OK;
}

static WERROR update_prescan(const struct dns_name_question *zone,
			     const struct dns_res_rec *updates, uint16_t count)
{
	const struct dns_res_rec *r;
	uint16_t i;
	size_t host_part_len;
	bool match;

	for (i = 0; i < count; i++) {
		r = &updates[i];
		match = dns_name_match(zone->name, r->name, &host_part_len);
		if (!match) {
			return DNS_ERR(NOTZONE);
		}
		if (zone->question_class == r->rr_class) {
			if (r->rr_type == DNS_QTYPE_ALL) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_AXFR) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILB) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILA) {
				return DNS_ERR(FORMAT_ERROR);
			}
		} else if (r->rr_class == DNS_QCLASS_ANY) {
			if (r->ttl != 0) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->length != 0) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_AXFR) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILB) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILA) {
				return DNS_ERR(FORMAT_ERROR);
			}
		} else if (r->rr_class == DNS_QCLASS_NONE) {
			if (r->ttl != 0) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_ALL) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_AXFR) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILB) {
				return DNS_ERR(FORMAT_ERROR);
			}
			if (r->rr_type == DNS_QTYPE_MAILA) {
				return DNS_ERR(FORMAT_ERROR);
			}
		} else {
			return DNS_ERR(FORMAT_ERROR);
		}
	}
	return WERR_OK;
}

static WERROR dns_rr_to_dnsp(TALLOC_CTX *mem_ctx,
			     const struct dns_res_rec *rrec,
			     struct dnsp_DnssrvRpcRecord *r)
{
	if (rrec->rr_type == DNS_QTYPE_ALL) {
		return DNS_ERR(FORMAT_ERROR);
	}

	ZERO_STRUCTP(r);

	r->wType = rrec->rr_type;
	r->dwTtlSeconds = rrec->ttl;
	r->rank = DNS_RANK_ZONE;
	/* TODO: Autogenerate this somehow */
	r->dwSerial = 110;

	/* If we get QCLASS_ANY, we're done here */
	if (rrec->rr_class == DNS_QCLASS_ANY) {
		goto done;
	}

	switch(rrec->rr_type) {
	case DNS_QTYPE_A:
		r->data.ipv4 = talloc_strdup(mem_ctx, rrec->rdata.ipv4_record);
		W_ERROR_HAVE_NO_MEMORY(r->data.ipv4);
		break;
	case DNS_QTYPE_AAAA:
		r->data.ipv6 = talloc_strdup(mem_ctx, rrec->rdata.ipv6_record);
		W_ERROR_HAVE_NO_MEMORY(r->data.ipv6);
		break;
	case DNS_QTYPE_NS:
		r->data.ns = talloc_strdup(mem_ctx, rrec->rdata.ns_record);
		W_ERROR_HAVE_NO_MEMORY(r->data.ns);
		break;
	case DNS_QTYPE_CNAME:
		r->data.cname = talloc_strdup(mem_ctx, rrec->rdata.cname_record);
		W_ERROR_HAVE_NO_MEMORY(r->data.cname);
		break;
	case DNS_QTYPE_SRV:
		r->data.srv.wPriority = rrec->rdata.srv_record.priority;
		r->data.srv.wWeight = rrec->rdata.srv_record.weight;
		r->data.srv.wPort = rrec->rdata.srv_record.port;
		r->data.srv.nameTarget = talloc_strdup(mem_ctx,
				rrec->rdata.srv_record.target);
		W_ERROR_HAVE_NO_MEMORY(r->data.srv.nameTarget);
		break;
	case DNS_QTYPE_MX:
		r->data.mx.wPriority = rrec->rdata.mx_record.preference;
		r->data.mx.nameTarget = talloc_strdup(mem_ctx,
				rrec->rdata.mx_record.exchange);
		W_ERROR_HAVE_NO_MEMORY(r->data.mx.nameTarget);
		break;
	case DNS_QTYPE_TXT:
		r->data.txt = talloc_strdup(mem_ctx, rrec->rdata.txt_record.txt);
		W_ERROR_HAVE_NO_MEMORY(r->data.txt);
		break;
	default:
		DEBUG(0, ("Got a qytpe of %d\n", rrec->rr_type));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

done:

	return WERR_OK;
}

WERROR dns_server_process_update(struct dns_server *dns,
				 TALLOC_CTX *mem_ctx,
				 struct dns_name_packet *in,
				 struct dns_res_rec **prereqs,    uint16_t *prereq_count,
				 struct dns_res_rec **updates,    uint16_t *update_count,
				 struct dns_res_rec **additional, uint16_t *arcount)
{
	struct dns_name_question *zone;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;
	WERROR werror = DNS_ERR(NOT_IMPLEMENTED);
	bool update_allowed = false;

	if (in->qdcount != 1) {
		return DNS_ERR(FORMAT_ERROR);
	}

	zone = &in->questions[0];

	if (zone->question_class != DNS_QCLASS_IN &&
	    zone->question_class != DNS_QCLASS_ANY) {
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	if (zone->question_type != DNS_QTYPE_SOA) {
		return DNS_ERR(FORMAT_ERROR);
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
		return DNS_ERR(NOTAUTH);
	}

	if (host_part_len != 0) {
		/* TODO: We need to delegate this one */
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	*prereq_count = in->ancount;
	*prereqs = in->answers;
	werror = check_prerequisites(dns, mem_ctx, in->questions, *prereqs,
				     *prereq_count);
	W_ERROR_NOT_OK_RETURN(werror);

	/* TODO: Check if update is allowed, we probably want "always",
	 * key-based GSSAPI, key-based bind-style TSIG and "never" as
	 * smb.conf options. */
	if (!update_allowed) {
		return DNS_ERR(REFUSED);
	}

	*update_count = in->nscount;
	*updates = in->nsrecs;
	werror = update_prescan(in->questions, *updates, *update_count);
	W_ERROR_NOT_OK_RETURN(werror);

	return werror;
}
