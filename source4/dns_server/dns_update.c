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
#include "param/param.h"
#include "param/loadparm.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "smbd/service_task.h"
#include "dns_server/dns_server.h"
#include "auth/auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

static WERROR dns_rr_to_dnsp(TALLOC_CTX *mem_ctx,
			     const struct dns_res_rec *rrec,
			     struct dnsp_DnssrvRpcRecord *r,
			     bool name_is_static);

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
			if (W_ERROR_EQUAL(werror, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
				return DNS_ERR(NAME_ERROR);
			}
			W_ERROR_NOT_OK_RETURN(werror);

			if (acount == 0) {
				return DNS_ERR(NAME_ERROR);
			}
		} else {
			/*
			 */
			werror = dns_lookup_records(dns, mem_ctx, dn, &ans, &acount);
			if (W_ERROR_EQUAL(werror, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
				return DNS_ERR(NXRRSET);
			}
			if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
				return DNS_ERR(NXRRSET);
			}
			W_ERROR_NOT_OK_RETURN(werror);

			for (i = 0; i < acount; i++) {
				if (ans[i].wType == (enum dns_record_type) pr->rr_type) {
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
			if (W_ERROR_EQUAL(werror, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
				werror = WERR_OK;
			}
			if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
				werror = WERR_OK;
			}

			for (i = 0; i < acount; i++) {
				if (ans[i].wType == (enum dns_record_type) pr->rr_type) {
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
	if (W_ERROR_EQUAL(werror, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
		return DNS_ERR(NXRRSET);
	}
	if (W_ERROR_EQUAL(werror, DNS_ERR(NAME_ERROR))) {
		return DNS_ERR(NXRRSET);
	}
	W_ERROR_NOT_OK_RETURN(werror);

	rec = talloc_zero(mem_ctx, struct dnsp_DnssrvRpcRecord);
	W_ERROR_HAVE_NO_MEMORY(rec);

	werror = dns_rr_to_dnsp(rec, pr, rec, dns_name_is_static(ans, acount));
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
			     struct dnsp_DnssrvRpcRecord *r,
			     bool name_is_static)
{
	enum ndr_err_code ndr_err;
	NTTIME t;

	if (rrec->rr_type == DNS_QTYPE_ALL) {
		return DNS_ERR(FORMAT_ERROR);
	}

	ZERO_STRUCTP(r);

	r->wType = (enum dns_record_type) rrec->rr_type;
	r->dwTtlSeconds = rrec->ttl;
	r->rank = DNS_RANK_ZONE;
	if (name_is_static) {
		r->dwTimeStamp = 0;
	} else {
		unix_to_nt_time(&t, time(NULL));
		t /= 10 * 1000 * 1000;
		t /= 3600;
		r->dwTimeStamp = t;
	}

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
	case DNS_QTYPE_PTR:
		r->data.ptr = talloc_strdup(mem_ctx, rrec->rdata.ptr_record);
		W_ERROR_HAVE_NO_MEMORY(r->data.ptr);
		break;
	case DNS_QTYPE_MX:
		r->data.mx.wPriority = rrec->rdata.mx_record.preference;
		r->data.mx.nameTarget = talloc_strdup(mem_ctx,
				rrec->rdata.mx_record.exchange);
		W_ERROR_HAVE_NO_MEMORY(r->data.mx.nameTarget);
		break;
	case DNS_QTYPE_TXT:
		ndr_err = ndr_dnsp_string_list_copy(mem_ctx,
						    &rrec->rdata.txt_record.txt,
						    &r->data.txt);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		break;
	default:
		DEBUG(0, ("Got a qytpe of %d\n", rrec->rr_type));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

done:

	return WERR_OK;
}


static WERROR handle_one_update(struct dns_server *dns,
				TALLOC_CTX *mem_ctx,
				const struct dns_name_question *zone,
				const struct dns_res_rec *update,
				const struct dns_server_tkey *tkey)
{
	struct dnsp_DnssrvRpcRecord *recs = NULL;
	uint16_t rcount = 0;
	struct ldb_dn *dn;
	uint16_t i;
	uint16_t first = 0;
	WERROR werror;
	bool tombstoned = false;
	bool needs_add = false;
	bool name_is_static;

	DEBUG(2, ("Looking at record: \n"));
	if (DEBUGLVL(2)) {
		NDR_PRINT_DEBUG(dns_res_rec, discard_const(update));
	}

	switch (update->rr_type) {
	case DNS_QTYPE_A:
	case DNS_QTYPE_NS:
	case DNS_QTYPE_CNAME:
	case DNS_QTYPE_SOA:
	case DNS_QTYPE_PTR:
	case DNS_QTYPE_MX:
	case DNS_QTYPE_AAAA:
	case DNS_QTYPE_SRV:
	case DNS_QTYPE_TXT:
		break;
	default:
		DEBUG(0, ("Can't handle updates of type %u yet\n",
			  update->rr_type));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	werror = dns_name2dn(dns, mem_ctx, update->name, &dn);
	W_ERROR_NOT_OK_RETURN(werror);

	werror = dns_common_lookup(dns->samdb, mem_ctx, dn,
				   &recs, &rcount, &tombstoned);
	if (W_ERROR_EQUAL(werror, WERR_DNS_ERROR_NAME_DOES_NOT_EXIST)) {
		needs_add = true;
		werror = WERR_OK;
	}
	W_ERROR_NOT_OK_RETURN(werror);

	if (tombstoned) {
		/*
		 * we need to keep the existing tombstone record
		 * and ignore it
		 */
		first = rcount;
	}

	name_is_static = dns_name_is_static(recs, rcount);

	if (update->rr_class == zone->question_class) {
		if (update->rr_type == DNS_QTYPE_CNAME) {
			/*
			 * If there is a record in the directory
			 * that's not a CNAME, ignore update
			 */
			for (i = first; i < rcount; i++) {
				if (recs[i].wType != DNS_TYPE_CNAME) {
					DEBUG(5, ("Skipping update\n"));
					return WERR_OK;
				}
				break;
			}

			/*
			 * There should be no entries besides one CNAME record
			 * per name, so replace everything with the new CNAME
			 */

			rcount = first;
			recs = talloc_realloc(mem_ctx, recs,
					struct dnsp_DnssrvRpcRecord, rcount + 1);
			W_ERROR_HAVE_NO_MEMORY(recs);

			werror = dns_rr_to_dnsp(
			    recs, update, &recs[rcount], name_is_static);
			W_ERROR_NOT_OK_RETURN(werror);
			rcount += 1;

			werror = dns_replace_records(dns, mem_ctx, dn,
						     needs_add, recs, rcount);
			W_ERROR_NOT_OK_RETURN(werror);

			return WERR_OK;
		} else {
			/*
			 * If there is a CNAME record for this name,
			 * ignore update
			 */
			for (i = first; i < rcount; i++) {
				if (recs[i].wType == DNS_TYPE_CNAME) {
					DEBUG(5, ("Skipping update\n"));
					return WERR_OK;
				}
			}
		}
		if (update->rr_type == DNS_QTYPE_SOA) {
			bool found = false;

			/*
			 * If the zone has no SOA record?? or update's
			 * serial number is smaller than existing SOA's,
			 * ignore update
			 */
			for (i = first; i < rcount; i++) {
				if (recs[i].wType == DNS_TYPE_SOA) {
					uint16_t n, o;

					n = update->rdata.soa_record.serial;
					o = recs[i].data.soa.serial;
					/*
					 * TODO: Implement RFC 1982 comparison
					 * logic for RFC2136
					 */
					if (n <= o) {
						DEBUG(5, ("Skipping update\n"));
						return WERR_OK;
					}
					found = true;
					break;
				}
			}
			if (!found) {
				DEBUG(5, ("Skipping update\n"));
				return WERR_OK;
			}

			werror = dns_rr_to_dnsp(
			    mem_ctx, update, &recs[i], name_is_static);
			W_ERROR_NOT_OK_RETURN(werror);

			for (i++; i < rcount; i++) {
				if (recs[i].wType != DNS_TYPE_SOA) {
					continue;
				}

				recs[i] = (struct dnsp_DnssrvRpcRecord) {
					.wType = DNS_TYPE_TOMBSTONE,
				};
			}

			werror = dns_replace_records(dns, mem_ctx, dn,
						     needs_add, recs, rcount);
			W_ERROR_NOT_OK_RETURN(werror);

			return WERR_OK;
		}

		recs = talloc_realloc(mem_ctx, recs,
				struct dnsp_DnssrvRpcRecord, rcount+1);
		W_ERROR_HAVE_NO_MEMORY(recs);

		werror =
		    dns_rr_to_dnsp(recs, update, &recs[rcount], name_is_static);
		W_ERROR_NOT_OK_RETURN(werror);

		for (i = first; i < rcount; i++) {
			if (!dns_records_match(&recs[i], &recs[rcount])) {
				continue;
			}

			recs[i].data = recs[rcount].data;
			recs[i].wType = recs[rcount].wType;
			recs[i].dwTtlSeconds = recs[rcount].dwTtlSeconds;
			recs[i].rank = recs[rcount].rank;

			werror = dns_replace_records(dns, mem_ctx, dn,
						     needs_add, recs, rcount);
			W_ERROR_NOT_OK_RETURN(werror);

			return WERR_OK;
		}

		werror = dns_replace_records(dns, mem_ctx, dn,
					     needs_add, recs, rcount+1);
		W_ERROR_NOT_OK_RETURN(werror);

		return WERR_OK;
	} else if (update->rr_class == DNS_QCLASS_ANY) {
		if (update->rr_type == DNS_QTYPE_ALL) {
			if (dns_name_equal(update->name, zone->name)) {
				for (i = first; i < rcount; i++) {

					if (recs[i].wType == DNS_TYPE_SOA) {
						continue;
					}

					if (recs[i].wType == DNS_TYPE_NS) {
						continue;
					}

					recs[i] = (struct dnsp_DnssrvRpcRecord) {
						.wType = DNS_TYPE_TOMBSTONE,
					};
				}

			} else {
				for (i = first; i < rcount; i++) {
					recs[i] = (struct dnsp_DnssrvRpcRecord) {
						.wType = DNS_TYPE_TOMBSTONE,
					};
				}
			}

		} else if (dns_name_equal(update->name, zone->name)) {

			if (update->rr_type == DNS_QTYPE_SOA) {
				return WERR_OK;
			}

			if (update->rr_type == DNS_QTYPE_NS) {
				return WERR_OK;
			}
		}
		for (i = first; i < rcount; i++) {
			if (recs[i].wType == (enum dns_record_type) update->rr_type) {
				recs[i] = (struct dnsp_DnssrvRpcRecord) {
					.wType = DNS_TYPE_TOMBSTONE,
				};
			}
		}

		werror = dns_replace_records(dns, mem_ctx, dn,
					     needs_add, recs, rcount);
		W_ERROR_NOT_OK_RETURN(werror);

		return WERR_OK;
	} else if (update->rr_class == DNS_QCLASS_NONE) {
		struct dnsp_DnssrvRpcRecord *del_rec;

		if (update->rr_type == DNS_QTYPE_SOA) {
			return WERR_OK;
		}
		if (update->rr_type == DNS_QTYPE_NS) {
			bool found = false;
			struct dnsp_DnssrvRpcRecord *ns_rec = talloc(mem_ctx,
						struct dnsp_DnssrvRpcRecord);
			W_ERROR_HAVE_NO_MEMORY(ns_rec);

			werror = dns_rr_to_dnsp(
			    ns_rec, update, ns_rec, name_is_static);
			W_ERROR_NOT_OK_RETURN(werror);

			for (i = first; i < rcount; i++) {
				if (dns_records_match(ns_rec, &recs[i])) {
					found = true;
					break;
				}
			}
			if (found) {
				return WERR_OK;
			}
		}

		del_rec = talloc(mem_ctx, struct dnsp_DnssrvRpcRecord);
		W_ERROR_HAVE_NO_MEMORY(del_rec);

		werror =
		    dns_rr_to_dnsp(del_rec, update, del_rec, name_is_static);
		W_ERROR_NOT_OK_RETURN(werror);

		for (i = first; i < rcount; i++) {
			if (dns_records_match(del_rec, &recs[i])) {
				recs[i] = (struct dnsp_DnssrvRpcRecord) {
					.wType = DNS_TYPE_TOMBSTONE,
				};
			}
		}

		werror = dns_replace_records(dns, mem_ctx, dn,
					     needs_add, recs, rcount);
		W_ERROR_NOT_OK_RETURN(werror);
	}

	return WERR_OK;
}

static WERROR handle_updates(struct dns_server *dns,
			     TALLOC_CTX *mem_ctx,
			     const struct dns_name_question *zone,
			     const struct dns_res_rec *prereqs, uint16_t pcount,
			     struct dns_res_rec *updates, uint16_t upd_count,
			     struct dns_server_tkey *tkey)
{
	struct ldb_dn *zone_dn = NULL;
	WERROR werror = WERR_OK;
	int ret;
	uint16_t ri;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	if (tkey != NULL) {
		ret = ldb_set_opaque(
			dns->samdb,
			DSDB_SESSION_INFO,
			tkey->session_info);
		if (ret != LDB_SUCCESS) {
			DEBUG(1, ("unable to set session info\n"));
			werror = DNS_ERR(SERVER_FAILURE);
			goto failed;
		}
	}

	werror = dns_name2dn(dns, tmp_ctx, zone->name, &zone_dn);
	W_ERROR_NOT_OK_GOTO(werror, failed);

	ret = ldb_transaction_start(dns->samdb);
	if (ret != LDB_SUCCESS) {
		werror = DNS_ERR(SERVER_FAILURE);
		goto failed;
	}

	werror = check_prerequisites(dns, tmp_ctx, zone, prereqs, pcount);
	W_ERROR_NOT_OK_GOTO(werror, failed);

	DBG_DEBUG("dns update count is %u\n", upd_count);

	for (ri = 0; ri < upd_count; ri++) {
		werror = handle_one_update(dns, tmp_ctx, zone,
					   &updates[ri], tkey);
		W_ERROR_NOT_OK_GOTO(werror, failed);
	}

	ldb_transaction_commit(dns->samdb);
	TALLOC_FREE(tmp_ctx);

	if (tkey != NULL) {
		ldb_set_opaque(
			dns->samdb,
			DSDB_SESSION_INFO,
			system_session(dns->task->lp_ctx));
	}

	return WERR_OK;

failed:
	ldb_transaction_cancel(dns->samdb);

	if (tkey != NULL) {
		ldb_set_opaque(
			dns->samdb,
			DSDB_SESSION_INFO,
			system_session(dns->task->lp_ctx));
	}

	TALLOC_FREE(tmp_ctx);
	return werror;

}

static WERROR dns_update_allowed(struct dns_server *dns,
				 const struct dns_request_state *state,
				 struct dns_server_tkey **tkey)
{
	if (lpcfg_allow_dns_updates(dns->task->lp_ctx) == DNS_UPDATE_ON) {
		DEBUG(2, ("All updates allowed.\n"));
		return WERR_OK;
	}

	if (lpcfg_allow_dns_updates(dns->task->lp_ctx) == DNS_UPDATE_OFF) {
		DEBUG(2, ("Updates disabled.\n"));
		return DNS_ERR(REFUSED);
	}

	if (state->authenticated == false ) {
		DEBUG(2, ("Update not allowed for unsigned packet.\n"));
		return DNS_ERR(REFUSED);
	}

        *tkey = dns_find_tkey(dns->tkeys, state->key_name);
	if (*tkey == NULL) {
		DEBUG(0, ("Authenticated, but key not found. Something is wrong.\n"));
		return DNS_ERR(REFUSED);
	}

	return WERR_OK;
}


WERROR dns_server_process_update(struct dns_server *dns,
				 const struct dns_request_state *state,
				 TALLOC_CTX *mem_ctx,
				 const struct dns_name_packet *in,
				 struct dns_res_rec **prereqs,    uint16_t *prereq_count,
				 struct dns_res_rec **updates,    uint16_t *update_count,
				 struct dns_res_rec **additional, uint16_t *arcount)
{
	struct dns_name_question *zone;
	const struct dns_server_zone *z;
	size_t host_part_len = 0;
	WERROR werror = DNS_ERR(NOT_IMPLEMENTED);
	struct dns_server_tkey *tkey = NULL;

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

	DEBUG(2, ("Got a dns update request.\n"));

	for (z = dns->zones; z != NULL; z = z->next) {
		bool match;

		match = dns_name_match(z->name, zone->name, &host_part_len);
		if (match) {
			break;
		}
	}

	if (z == NULL) {
		DEBUG(1, ("We're not authoritative for this zone\n"));
		return DNS_ERR(NOTAUTH);
	}

	if (host_part_len != 0) {
		/* TODO: We need to delegate this one */
		DEBUG(1, ("Would have to delegate zone '%s'.\n", zone->name));
		return DNS_ERR(NOT_IMPLEMENTED);
	}

	*prereq_count = in->ancount;
	*prereqs = in->answers;
	werror = check_prerequisites(dns, mem_ctx, in->questions, *prereqs,
				     *prereq_count);
	W_ERROR_NOT_OK_RETURN(werror);

	werror = dns_update_allowed(dns, state, &tkey);
	if (!W_ERROR_IS_OK(werror)) {
		return werror;
	}

	*update_count = in->nscount;
	*updates = in->nsrecs;
	werror = update_prescan(in->questions, *updates, *update_count);
	W_ERROR_NOT_OK_RETURN(werror);

	werror = handle_updates(dns, mem_ctx, in->questions, *prereqs,
			        *prereq_count, *updates, *update_count, tkey);
	W_ERROR_NOT_OK_RETURN(werror);

	return werror;
}
