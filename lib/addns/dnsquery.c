/*
   Unix SMB/CIFS implementation.
   DNS utility library
   Copyright (C) Gerald (Jerry) Carter           2006.
   Copyright (C) Jeremy Allison                  2007.

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
#include "lib/util/util_net.h"
#include "lib/util/tsort.h"
#include "librpc/gen_ndr/dns.h"
#include "libcli/dns/dns_lookup.h"
#include "lib/util/tevent_ntstatus.h"
#include "dnsquery.h"

/*********************************************************************
 Sort SRV record list based on weight and priority.  See RFC 2782.
*********************************************************************/

static int dnssrvcmp( struct dns_rr_srv *a, struct dns_rr_srv *b )
{
	if ( a->priority == b->priority ) {

		/* randomize entries with an equal weight and priority */
		if ( a->weight == b->weight )
			return 0;

		/* higher weights should be sorted lower */
		if ( a->weight > b->weight )
			return -1;
		else
			return 1;
	}

	if ( a->priority < b->priority )
		return -1;

	return 1;
}

struct ads_dns_lookup_srv_state {
	struct dns_rr_srv *srvs;
	size_t num_srvs;
};

static void ads_dns_lookup_srv_done(struct tevent_req *subreq);

struct tevent_req *ads_dns_lookup_srv_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   const char *name)
{
	struct tevent_req *req, *subreq;
	struct ads_dns_lookup_srv_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ads_dns_lookup_srv_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = dns_lookup_send(
		state,
		ev,
		NULL,
		name,
		DNS_QCLASS_IN,
		DNS_QTYPE_SRV);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ads_dns_lookup_srv_done, req);
	return req;
}

static void ads_dns_lookup_srv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_lookup_srv_state *state = tevent_req_data(
		req, struct ads_dns_lookup_srv_state);
	int ret;
	struct dns_name_packet *reply;
	uint16_t i, idx;

	ret = dns_lookup_recv(subreq, state, &reply);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(ret));
		return;
	}

	for (i=0; i<reply->ancount; i++) {
		if (reply->answers[i].rr_type == DNS_QTYPE_SRV) {
			state->num_srvs += 1;
		}
	}

	state->srvs = talloc_array(state, struct dns_rr_srv, state->num_srvs);
	if (tevent_req_nomem(state->srvs, req)) {
		return;
	}

	idx = 0;

	for (i=0; i<reply->ancount; i++) {
		struct dns_res_rec *an = &reply->answers[i];
		struct dns_rr_srv *dst = &state->srvs[idx];
		struct dns_srv_record *src;

		if (an->rr_type != DNS_QTYPE_SRV) {
			continue;
		}
		src = &an->rdata.srv_record;

		*dst = (struct dns_rr_srv) {
			.hostname = talloc_move(state->srvs, &src->target),
			.priority = src->priority,
			.weight = src->weight,
			.port = src->port,
		};
		idx += 1;
	}

	for (i=0; i<reply->arcount; i++) {
		struct dns_res_rec *ar = &reply->additional[i];
		struct sockaddr_storage addr;
		bool ok;
		size_t j;

		ok = dns_res_rec_get_sockaddr(ar, &addr);
		if (!ok) {
			continue;
		}

		for (j=0; j<state->num_srvs; j++) {
			struct dns_rr_srv *srv = &state->srvs[j];
			struct sockaddr_storage *tmp;

			if (strcmp(srv->hostname, ar->name) != 0) {
				continue;
			}

			tmp = talloc_realloc(
				state->srvs,
				srv->ss_s,
				struct sockaddr_storage,
				srv->num_ips+1);

			if (tevent_req_nomem(tmp, req)) {
				return;
			}
			srv->ss_s = tmp;

			srv->ss_s[srv->num_ips] = addr;
			srv->num_ips += 1;
		}
	}

	TYPESAFE_QSORT(state->srvs, state->num_srvs, dnssrvcmp);

	tevent_req_done(req);
}

NTSTATUS ads_dns_lookup_srv_recv(struct tevent_req *req,
				 TALLOC_CTX *mem_ctx,
				 struct dns_rr_srv **srvs,
				 size_t *num_srvs)
{
	struct ads_dns_lookup_srv_state *state = tevent_req_data(
		req, struct ads_dns_lookup_srv_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*srvs = talloc_move(mem_ctx, &state->srvs);
	*num_srvs = state->num_srvs;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*********************************************************************
 Simple wrapper for a DNS SRV query
*********************************************************************/

NTSTATUS ads_dns_lookup_srv(TALLOC_CTX *ctx,
				const char *name,
				struct dns_rr_srv **dclist,
				int *numdcs)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	size_t num_srvs = 0;

	ev = samba_tevent_context_init(ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = ads_dns_lookup_srv_send(ev, ev, name);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = ads_dns_lookup_srv_recv(req, ctx, dclist, &num_srvs);
	if (NT_STATUS_IS_OK(status)) {
		*numdcs = num_srvs;	/* size_t->int */
	}
fail:
	TALLOC_FREE(ev);
	return status;
}

struct ads_dns_lookup_ns_state {
	struct dns_rr_ns *nss;
	size_t num_nss;
};

static void ads_dns_lookup_ns_done(struct tevent_req *subreq);

struct tevent_req *ads_dns_lookup_ns_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  const char *name)
{
	struct tevent_req *req, *subreq;
	struct ads_dns_lookup_ns_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ads_dns_lookup_ns_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = dns_lookup_send(state, ev, NULL, name, DNS_QCLASS_IN,
				 DNS_QTYPE_NS);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ads_dns_lookup_ns_done, req);
	return req;
}

static void ads_dns_lookup_ns_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_lookup_ns_state *state = tevent_req_data(
		req, struct ads_dns_lookup_ns_state);
	int ret;
	struct dns_name_packet *reply;
	uint16_t i, idx;

	ret = dns_lookup_recv(subreq, state, &reply);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(ret));
		return;
	}

	for (i=0; i<reply->ancount; i++) {
		if (reply->answers[i].rr_type == DNS_QTYPE_NS) {
			state->num_nss += 1;
		}
	}

	state->nss = talloc_array(state, struct dns_rr_ns, state->num_nss);
	if (tevent_req_nomem(state->nss, req)) {
		return;
	}

	idx = 0;

	for (i=0; i<reply->ancount; i++) {
		struct dns_res_rec *an = &reply->answers[i];

		if (an->rr_type != DNS_QTYPE_NS) {
			continue;
		}

		state->nss[idx].hostname = talloc_move(state->nss,
						       &an->rdata.ns_record);
		idx += 1;
	}

	for (i=0; i<reply->arcount; i++) {
		struct dns_res_rec *ar = &reply->additional[i];
		struct sockaddr_storage addr;
		bool ok;
		size_t j;

		ok = dns_res_rec_get_sockaddr(ar, &addr);
		if (!ok) {
			continue;
		}

		for (j=0; j<state->num_nss; j++) {
			struct dns_rr_ns *ns = &state->nss[j];

			if (strcmp(ns->hostname, ar->name) == 0) {
				ns->ss = addr;
			}
		}
	}

	tevent_req_done(req);
}

NTSTATUS ads_dns_lookup_ns_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				struct dns_rr_ns **nss,
				size_t *num_nss)
{
	struct ads_dns_lookup_ns_state *state = tevent_req_data(
		req, struct ads_dns_lookup_ns_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*nss = talloc_move(mem_ctx, &state->nss);
	*num_nss = state->num_nss;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*********************************************************************
 Simple wrapper for a DNS NS query
*********************************************************************/

NTSTATUS ads_dns_lookup_ns(TALLOC_CTX *ctx,
				const char *dnsdomain,
				struct dns_rr_ns **nslist,
				int *numns)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	size_t num_ns = 0;

	ev = samba_tevent_context_init(ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = ads_dns_lookup_ns_send(ev, ev, dnsdomain);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = ads_dns_lookup_ns_recv(req, ctx, nslist, &num_ns);
	*numns = num_ns;
fail:
	TALLOC_FREE(ev);
	return status;
}


/********************************************************************
 Query with optional sitename.
********************************************************************/

static NTSTATUS ads_dns_query_internal(TALLOC_CTX *ctx,
				       const char *servicename,
				       const char *dc_pdc_gc_domains,
				       const char *realm,
				       const char *sitename,
				       struct dns_rr_srv **dclist,
				       int *numdcs )
{
	char *name;
	NTSTATUS status;
	int num_srvs = 0;

	if ((sitename != NULL) && (strlen(sitename) != 0)) {
		name = talloc_asprintf(ctx, "%s._tcp.%s._sites.%s._msdcs.%s",
				       servicename, sitename,
				       dc_pdc_gc_domains, realm);
		if (name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = ads_dns_lookup_srv(ctx, name, dclist, &num_srvs);

		TALLOC_FREE(name);

		if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_REFUSED)) {
			return status;
		}

		if (NT_STATUS_IS_OK(status) && (num_srvs != 0)) {
			goto done;
		}
	}

	name = talloc_asprintf(ctx, "%s._tcp.%s._msdcs.%s",
			       servicename, dc_pdc_gc_domains, realm);
	if (name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	status = ads_dns_lookup_srv(ctx, name, dclist, &num_srvs);

done:
	*numdcs = num_srvs; /* automatic conversion size_t->int */
	return status;
}

/********************************************************************
 Query for AD DC's.
********************************************************************/

NTSTATUS ads_dns_query_dcs(TALLOC_CTX *ctx,
			   const char *realm,
			   const char *sitename,
			   struct dns_rr_srv **dclist,
			   int *numdcs )
{
	NTSTATUS status;

	status = ads_dns_query_internal(ctx,
					"_ldap",
					"dc",
					realm,
					sitename,
					dclist,
					numdcs);
	return status;
}

/********************************************************************
 Query for AD GC's.
********************************************************************/

NTSTATUS ads_dns_query_gcs(TALLOC_CTX *ctx,
			   const char *realm,
			   const char *sitename,
			   struct dns_rr_srv **dclist,
			   int *numdcs )
{
	NTSTATUS status;

	status = ads_dns_query_internal(ctx,
					"_ldap",
					"gc",
					realm,
					sitename,
					dclist,
					numdcs);
	return status;
}

/********************************************************************
 Query for AD KDC's.
 Even if our underlying kerberos libraries are UDP only, this
 is pretty safe as it's unlikely that a KDC supports TCP and not UDP.
********************************************************************/

NTSTATUS ads_dns_query_kdcs(TALLOC_CTX *ctx,
			    const char *dns_forest_name,
			    const char *sitename,
			    struct dns_rr_srv **dclist,
			    int *numdcs )
{
	NTSTATUS status;

	status = ads_dns_query_internal(ctx,
					"_kerberos",
					"dc",
					dns_forest_name,
					sitename,
					dclist,
					numdcs);
	return status;
}

/********************************************************************
 Query for AD PDC. Sitename is obsolete here.
********************************************************************/

NTSTATUS ads_dns_query_pdc(TALLOC_CTX *ctx,
			   const char *dns_domain_name,
			   struct dns_rr_srv **dclist,
			   int *numdcs )
{
	return ads_dns_query_internal(ctx,
				      "_ldap",
				      "pdc",
				      dns_domain_name,
				      NULL,
				      dclist,
				      numdcs);
}

/********************************************************************
 Query for AD DC by guid. Sitename is obsolete here.
********************************************************************/

NTSTATUS ads_dns_query_dcs_guid(TALLOC_CTX *ctx,
				const char *dns_forest_name,
				const char *domain_guid,
				struct dns_rr_srv **dclist,
				int *numdcs )
{
	/*_ldap._tcp.DomainGuid.domains._msdcs.DnsForestName */

	const char *domains;

	/* little hack */
	domains = talloc_asprintf(ctx, "%s.domains", domain_guid);
	if (!domains) {
		return NT_STATUS_NO_MEMORY;
	}

	return ads_dns_query_internal(ctx,
				      "_ldap",
				      domains,
				      dns_forest_name,
				      NULL,
				      dclist,
				      numdcs);
}
