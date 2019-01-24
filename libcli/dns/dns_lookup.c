/*
 *  Unix SMB/CIFS implementation.
 *  Internal DNS query structures
 *  Copyright (C) Volker Lendecke 2018
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "libcli/dns/dns_lookup.h"
#include "libcli/dns/resolvconf.h"
#include "libcli/dns/libdns.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"
#include "lib/util/debug.h"

struct dns_lookup_state {
	struct tevent_context *ev;
	const char *name;
	enum dns_qclass qclass;
	enum dns_qtype qtype;

	char **nameservers;
	size_t num_nameservers;
	size_t num_sent;

	struct tevent_req **dns_subreqs;
	struct tevent_req *wait_subreq;

	struct dns_name_packet *reply;
};

static int dns_lookup_send_next(struct tevent_req *req);

static void dns_lookup_done(struct tevent_req *subreq);
static void dns_lookup_waited(struct tevent_req *subreq);

struct tevent_req *dns_lookup_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   FILE *resolv_conf_fp,
				   const char *name,
				   enum dns_qclass qclass,
				   enum dns_qtype qtype)
{
	struct tevent_req *req;
	struct dns_lookup_state *state;
	FILE *fp = resolv_conf_fp;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct dns_lookup_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->name = name;
	state->qclass = qclass;
	state->qtype = qtype;

	if (resolv_conf_fp == NULL) {
		const char *resolvconf = "/etc/resolv.conf";

#ifdef ENABLE_SELFTEST
		{
			const char *envvar = getenv("RESOLV_CONF");
			if (envvar != NULL) {
				resolvconf = envvar;
			}
		}
#endif

		fp = fopen(resolvconf, "r");
		if (fp == NULL) {
			tevent_req_error(req, errno);
			return tevent_req_post(req, ev);
		}
	}

	ret = parse_resolvconf_fp(
		fp,
		state,
		&state->nameservers,
		&state->num_nameservers);

	if (resolv_conf_fp == NULL) {
		fclose(fp);
	}

	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (state->num_nameservers == 0) {
		/*
		 * glibc's getaddrinfo returns EAI_AGAIN when no
		 * nameservers are configured. EAGAIN seems closest.
		 */
		tevent_req_error(req, EAGAIN);
		return tevent_req_post(req, ev);
	}

	state->dns_subreqs = talloc_zero_array(
		state,
		struct tevent_req *,
		state->num_nameservers);

	if (tevent_req_nomem(state->dns_subreqs, req)) {
		return tevent_req_post(req, ev);
	}

	ret = dns_lookup_send_next(req);
	if (tevent_req_error(req, ret)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static int dns_lookup_send_next(struct tevent_req *req)
{
	struct dns_lookup_state *state = tevent_req_data(
		req, struct dns_lookup_state);

	DBG_DEBUG("Sending DNS request #%zu to %s\n",
		  state->num_sent,
		  state->nameservers[state->num_sent]);

	state->dns_subreqs[state->num_sent] = dns_cli_request_send(
		state->dns_subreqs,
		state->ev,
		state->nameservers[state->num_sent],
		state->name,
		state->qclass,
		state->qtype);

	if (state->dns_subreqs[state->num_sent] == NULL) {
		return ENOMEM;
	}
	tevent_req_set_callback(state->dns_subreqs[state->num_sent],
				dns_lookup_done,
				req);
	state->num_sent += 1;

	if (state->num_sent == state->num_nameservers) {
		/*
		 * No more nameservers left
		 */
		DBG_DEBUG("cancelling wait_subreq\n");
		TALLOC_FREE(state->wait_subreq);
		return 0;
	}

	if (state->wait_subreq != NULL) {
		/*
		 * This can happen if we fire the next request upon
		 * dns_cli_request returning a network-level error
		 */
		return 0;
	}

	state->wait_subreq = tevent_wakeup_send(
		state,
		state->ev,
		tevent_timeval_current_ofs(1, 0));
	if (state->wait_subreq == NULL) {
		return ENOMEM;
	}
	tevent_req_set_callback(state->wait_subreq, dns_lookup_waited, req);

	return 0;
}

static void dns_lookup_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_lookup_state *state = tevent_req_data(
		req, struct dns_lookup_state);
	int dns_cli_request_ret;
	size_t i;

	dns_cli_request_ret = dns_cli_request_recv(
		subreq,
		state,
		&state->reply);

	for (i = 0; i < state->num_nameservers; i++) {
		if (state->dns_subreqs[i] == subreq) {
			break;
		}
	}

	TALLOC_FREE(subreq);

	if (i == state->num_nameservers) {
		/* should never happen */
		DBG_WARNING("Failed to find subreq");
		tevent_req_error(req, EINVAL);
		return;
	}
	state->dns_subreqs[i] = NULL;

	if (dns_cli_request_ret == 0) {
		/*
		 * Success, cancel everything else
		 */
		TALLOC_FREE(state->dns_subreqs);
		TALLOC_FREE(state->wait_subreq);
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("dns_cli_request[%zu] returned %s\n", i,
		  strerror(dns_cli_request_ret));

	if (state->num_sent < state->num_nameservers) {
		/*
		 * We have a nameserver left to try
		 */
		int ret;

		ret = dns_lookup_send_next(req);
		if (tevent_req_error(req, ret)) {
			return;
		}
	}

	DBG_DEBUG("looking for outstanding requests\n");

	for (i = 0; i<state->num_nameservers; i++) {
		if (state->dns_subreqs[i] != NULL) {
			break;
		}
	}

	DBG_DEBUG("i=%zu, num_nameservers=%zu\n",
		  i, state->num_nameservers);

	if (i == state->num_nameservers) {
		/*
		 * Report the lower-level error if we have nothing
		 * outstanding anymore
		 */
		tevent_req_error(req, dns_cli_request_ret);
		return;
	}

	/*
	 * Do nothing: We have other nameservers that might come back
	 * with something good.
	 */
}

static void dns_lookup_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_lookup_state *state = tevent_req_data(
		req, struct dns_lookup_state);
	int ret;
	bool ok;

	DBG_DEBUG("waited\n");

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}
	state->wait_subreq = NULL;

	ret = dns_lookup_send_next(req);
	if (tevent_req_error(req, ret)) {
		return;
	}

	/*
	 * dns_lookup_send_next() has already triggered the next wakeup
	 */
}

int dns_lookup_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		    struct dns_name_packet **reply)
{
	struct dns_lookup_state *state = tevent_req_data(
		req, struct dns_lookup_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}

	*reply = talloc_move(mem_ctx, &state->reply);

	tevent_req_received(req);
	return 0;
}

int dns_lookup(FILE *resolv_conf_fp,
	       const char *name,
	       enum dns_qclass qclass,
	       enum dns_qtype qtype,
	       TALLOC_CTX *mem_ctx,
	       struct dns_name_packet **reply)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	int ret = ENOMEM;

	ev = samba_tevent_context_init(mem_ctx);
	if (ev == NULL) {
		goto fail;
	}
	req = dns_lookup_send(ev, ev, resolv_conf_fp, name, qclass, qtype);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_unix(req, ev, &ret)) {
		goto fail;
	}
	ret = dns_lookup_recv(req, mem_ctx, reply);
fail:
	TALLOC_FREE(ev);
	return ret;
}

bool dns_res_rec_get_sockaddr(const struct dns_res_rec *rec,
			      struct sockaddr_storage *addr)
{
	sa_family_t family;
	const char *src;
	void *dst;
	int ret;

	switch (rec->rr_type) {
	    case DNS_QTYPE_A:
		    family = AF_INET;
		    src = rec->rdata.ipv4_record;
		    dst = &(((struct sockaddr_in *)addr)->sin_addr);
		    break;
#ifdef HAVE_IPV6
	    case DNS_QTYPE_AAAA:
		    family = AF_INET6;
		    src = rec->rdata.ipv6_record;
		    dst = &(((struct sockaddr_in6 *)addr)->sin6_addr);
		    break;
#endif
	    default:
		    /* We only care about IP addresses */
		    return false;
	}

	*addr = (struct sockaddr_storage) { .ss_family = family };

	ret = inet_pton(family, src, dst);
	if (ret != 1) {
		DBG_DEBUG("inet_pton(%s) failed\n", src);
		return false;
	}

	return true;
}
