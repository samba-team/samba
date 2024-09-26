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
			/* uint16_t can't wrap here. */
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

			/*
			 * sometimes the name gets messed up
			 * with upper and lower case...
			 */
			if (!strequal(srv->hostname, ar->name)) {
				continue;
			}
			/* uint16_t can't wrap here. */
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
				size_t *numdcs)
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
		*numdcs = num_srvs;
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
				size_t *numns)
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

/*********************************************************************
 Async A record lookup.
*********************************************************************/

struct ads_dns_lookup_a_state {
	uint8_t rcode;
	size_t num_names;
	char **hostnames;
	struct samba_sockaddr *addrs;
};

static void ads_dns_lookup_a_done(struct tevent_req *subreq);

struct tevent_req *ads_dns_lookup_a_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 const char *name)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct ads_dns_lookup_a_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct ads_dns_lookup_a_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = dns_lookup_send(
		state,
		ev,
		NULL,
		name,
		DNS_QCLASS_IN,
		DNS_QTYPE_A);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ads_dns_lookup_a_done, req);
	return req;
}

static void ads_dns_lookup_a_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_lookup_a_state *state = tevent_req_data(
		req, struct ads_dns_lookup_a_state);
	int ret;
	struct dns_name_packet *reply = NULL;
	uint16_t i;

	ret = dns_lookup_recv(subreq, state, &reply);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(ret));
		return;
	}

	state->rcode = (reply->operation & DNS_RCODE);
	if (state->rcode != DNS_RCODE_OK) {
		/* Don't bother looking for answers. */
		tevent_req_done(req);
		return;
	}

	/*
	 * We don't care about CNAME answers here. We're
	 * just wanting an async name -> IPv4 lookup.
	 */
	for (i = 0; i < reply->ancount; i++) {
		if (reply->answers[i].rr_type == DNS_QTYPE_A) {
			state->num_names += 1;
		}
	}

	state->hostnames = talloc_zero_array(state,
					     char *,
					     state->num_names);
	if (tevent_req_nomem(state->hostnames, req)) {
		return;
	}
	state->addrs = talloc_zero_array(state,
					 struct samba_sockaddr,
					 state->num_names);
	if (tevent_req_nomem(state->addrs, req)) {
		return;
	}

	state->num_names = 0;

	for (i = 0; i < reply->ancount; i++) {
		bool ok;
		struct sockaddr_storage ss = {0};
		struct dns_res_rec *an = &reply->answers[i];

		if (an->rr_type != DNS_QTYPE_A) {
			continue;
		}
		if (an->name == NULL) {
			/* Can this happen? */
			continue;
		}
		if (an->rdata.ipv4_record == NULL) {
			/* Can this happen? */
			continue;
		}
		ok = dns_res_rec_get_sockaddr(an,
					      &ss);
		if (!ok) {
			continue;
		}
		if (is_zero_addr(&ss)) {
			continue;
		}
		state->addrs[state->num_names].u.ss = ss;
		state->addrs[state->num_names].sa_socklen =
					sizeof(struct sockaddr_in);
		state->hostnames[state->num_names] = talloc_strdup(
							state->hostnames,
							an->name);
		if (tevent_req_nomem(state->hostnames[state->num_names], req)) {
			return;
		}
		state->num_names += 1;
	}

	tevent_req_done(req);
}

NTSTATUS ads_dns_lookup_a_recv(struct tevent_req *req,
			       TALLOC_CTX *mem_ctx,
			       uint8_t *rcode_out,
			       size_t *num_names_out,
			       char ***hostnames_out,
			       struct samba_sockaddr **addrs_out)
{
	struct ads_dns_lookup_a_state *state = tevent_req_data(
		req, struct ads_dns_lookup_a_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (rcode_out != NULL) {
		/*
		 * If we got no names, an upper layer may
		 * want to print a debug message.
		 */
		*rcode_out = state->rcode;
	}
	if (hostnames_out != NULL) {
		*hostnames_out = talloc_move(mem_ctx,
					     &state->hostnames);
	}
	if (addrs_out != NULL) {
		*addrs_out = talloc_move(mem_ctx,
					 &state->addrs);
	}
	*num_names_out = state->num_names;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*********************************************************************
 Simple wrapper for a DNS A query
*********************************************************************/

NTSTATUS ads_dns_lookup_a(TALLOC_CTX *ctx,
			  const char *name_in,
			  size_t *num_names_out,
			  char ***hostnames_out,
			  struct samba_sockaddr **addrs_out)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = ads_dns_lookup_a_send(ev, ev, name_in);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	/*
	 * Synchronous doesn't need to care about the rcode or
	 * a copy of the name_in.
	 */
	status = ads_dns_lookup_a_recv(req,
				       ctx,
				       NULL,
				       num_names_out,
				       hostnames_out,
				       addrs_out);
fail:
	TALLOC_FREE(ev);
	return status;
}

#if defined(HAVE_IPV6)
/*********************************************************************
 Async AAAA record lookup.
*********************************************************************/

struct ads_dns_lookup_aaaa_state {
	uint8_t rcode;
	size_t num_names;
	char **hostnames;
	struct samba_sockaddr *addrs;
};

static void ads_dns_lookup_aaaa_done(struct tevent_req *subreq);

struct tevent_req *ads_dns_lookup_aaaa_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    const char *name)
{
	struct tevent_req *req, *subreq = NULL;
	struct ads_dns_lookup_aaaa_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct ads_dns_lookup_aaaa_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = dns_lookup_send(
		state,
		ev,
		NULL,
		name,
		DNS_QCLASS_IN,
		DNS_QTYPE_AAAA);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ads_dns_lookup_aaaa_done, req);
	return req;
}

static void ads_dns_lookup_aaaa_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_lookup_aaaa_state *state = tevent_req_data(
		req, struct ads_dns_lookup_aaaa_state);
	int ret;
	struct dns_name_packet *reply = NULL;
	uint16_t i;

	ret = dns_lookup_recv(subreq, state, &reply);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		tevent_req_nterror(req, map_nt_error_from_unix_common(ret));
		return;
	}

	state->rcode = (reply->operation & DNS_RCODE);
	if (state->rcode != DNS_RCODE_OK) {
		/* Don't bother looking for answers. */
		tevent_req_done(req);
		return;
	}

	/*
	 * We don't care about CNAME answers here. We're
	 * just wanting an async name -> IPv6 lookup.
	 */
	for (i = 0; i < reply->ancount; i++) {
		if (reply->answers[i].rr_type == DNS_QTYPE_AAAA) {
			state->num_names += 1;
		}
	}

	state->hostnames = talloc_zero_array(state,
					     char *,
					     state->num_names);
	if (tevent_req_nomem(state->hostnames, req)) {
		return;
	}
	state->addrs = talloc_zero_array(state,
					 struct samba_sockaddr,
					 state->num_names);
	if (tevent_req_nomem(state->addrs, req)) {
		return;
	}

	state->num_names = 0;

	for (i = 0; i < reply->ancount; i++) {
		bool ok;
		struct sockaddr_storage ss = {0};
		struct dns_res_rec *an = &reply->answers[i];

		if (an->rr_type != DNS_QTYPE_AAAA) {
			continue;
		}
		if (an->name == NULL) {
			/* Can this happen? */
			continue;
		}
		if (an->rdata.ipv6_record == NULL) {
			/* Can this happen? */
			continue;
		}
		ok = dns_res_rec_get_sockaddr(an,
					      &ss);
		if (!ok) {
			continue;
		}
		if (is_zero_addr(&ss)) {
			continue;
		}
		state->addrs[state->num_names].u.ss = ss;
		state->addrs[state->num_names].sa_socklen =
					sizeof(struct sockaddr_in6);

		state->hostnames[state->num_names] = talloc_strdup(
							state->hostnames,
							an->name);
		if (tevent_req_nomem(state->hostnames[state->num_names], req)) {
			return;
		}
		state->num_names += 1;
	}

	tevent_req_done(req);
}

NTSTATUS ads_dns_lookup_aaaa_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  uint8_t *rcode_out,
				  size_t *num_names_out,
				  char ***hostnames_out,
				  struct samba_sockaddr **addrs_out)
{
	struct ads_dns_lookup_aaaa_state *state = tevent_req_data(
		req, struct ads_dns_lookup_aaaa_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (rcode_out != NULL) {
		/*
		 * If we got no names, an upper layer may
		 * want to print a debug message.
		 */
		*rcode_out = state->rcode;
	}
	if (hostnames_out != NULL) {
		*hostnames_out = talloc_move(mem_ctx,
					     &state->hostnames);
	}
	if (addrs_out != NULL) {
		*addrs_out = talloc_move(mem_ctx,
					 &state->addrs);
	}
	*num_names_out = state->num_names;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

/*********************************************************************
 Simple wrapper for a DNS AAAA query
*********************************************************************/

NTSTATUS ads_dns_lookup_aaaa(TALLOC_CTX *ctx,
			     const char *name_in,
			     size_t *num_names_out,
			     char ***hostnames_out,
			     struct samba_sockaddr **addrs_out)
{
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = ads_dns_lookup_aaaa_send(ev, ev, name_in);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	/*
	 * Synchronous doesn't need to care about the rcode or
	 * a copy of the name_in.
	 */
	status = ads_dns_lookup_aaaa_recv(req,
					  ctx,
					  NULL,
					  num_names_out,
					  hostnames_out,
					  addrs_out);
fail:
	TALLOC_FREE(ev);
	return status;
}
#endif
