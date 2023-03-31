/*
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
#include "dnsquery.h"
#include "dnsquery_srv.h"
#include "lib/util/debug.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/samba_util.h"
#include "librpc/gen_ndr/dns.h"
#include "librpc/ndr/libndr.h"

/*
 * For an array of dns_rr_srv records, issue A/AAAA queries for those
 * records where the initial reply did not return IP addresses.
 */

struct dns_rr_srv_fill_state {
	struct dns_rr_srv *srvs;
	size_t num_srvs;

	struct tevent_req **subreqs;
	size_t num_outstanding;
};

static void dns_rr_srv_fill_done_a(struct tevent_req *subreq);
#if defined(HAVE_IPV6)
static void dns_rr_srv_fill_done_aaaa(struct tevent_req *subreq);
#endif
static void dns_rr_srv_fill_timedout(struct tevent_req *subreq);

static struct tevent_req *dns_rr_srv_fill_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct dns_rr_srv *srvs,
	size_t num_srvs,
	uint32_t timeout)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct dns_rr_srv_fill_state *state = NULL;
	size_t i, num_subreqs;

	req = tevent_req_create(mem_ctx, &state, struct dns_rr_srv_fill_state);
	if (req == NULL) {
		return NULL;
	}
	state->srvs = srvs;
	state->num_srvs = num_srvs;

	/*
	 * Without IPv6 we only use half of this, but who does not
	 * have IPv6 these days?
	 */
	num_subreqs = num_srvs * 2;

	state->subreqs = talloc_zero_array(
		state, struct tevent_req *, num_subreqs);
	if (tevent_req_nomem(state->subreqs, req)) {
		return tevent_req_post(req, ev);
	}

	for (i=0; i<num_srvs; i++) {

		if (srvs[i].hostname == NULL) {
			continue;
		}
		if (srvs[i].ss_s != NULL) {
			/* IP address returned in SRV record. */
			continue;
		}

		subreq = ads_dns_lookup_a_send(
			state->subreqs, ev, srvs[i].hostname);
		if (tevent_req_nomem(subreq, req)) {
			TALLOC_FREE(state->subreqs);
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, dns_rr_srv_fill_done_a, req);

		state->subreqs[i*2] = subreq;
		state->num_outstanding += 1;

#if defined(HAVE_IPV6)
		subreq = ads_dns_lookup_aaaa_send(
			state->subreqs, ev, srvs[i].hostname);
		if (tevent_req_nomem(subreq, req)) {
			TALLOC_FREE(state->subreqs);
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, dns_rr_srv_fill_done_aaaa, req);

		state->subreqs[i*2+1] = subreq;
		state->num_outstanding += 1;
#endif
	}

	if (state->num_outstanding == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(
		state->subreqs,
		ev,
		tevent_timeval_current_ofs(timeout, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, dns_rr_srv_fill_timedout, req);

	return req;
}

static void dns_rr_srv_fill_done(
	struct tevent_req *subreq,
	NTSTATUS (*recv_fn)(
		struct tevent_req *req,
		TALLOC_CTX *mem_ctx,
		uint8_t *rcode_out,
		size_t *num_names_out,
		char ***hostnames_out,
		struct samba_sockaddr **addrs_out))
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_rr_srv_fill_state *state = tevent_req_data(
		req, struct dns_rr_srv_fill_state);
	size_t num_subreqs = talloc_array_length(state->subreqs);
	struct dns_rr_srv *srv = NULL;
	size_t num_ips;
	struct sockaddr_storage *tmp = NULL;
	uint8_t rcode = 0;
	char **hostnames_out = NULL;
	struct samba_sockaddr *addrs = NULL;
	size_t num_addrs = 0;
	NTSTATUS status;
	size_t i;
	const char *ip_dbg_str = (recv_fn == ads_dns_lookup_a_recv) ?
				 "A" : "AAAA";

	/*
	 * This loop walks all potential subreqs. Typical setups won't
	 * have more than a few DCs. If you have really many DCs
	 * (hundreds) and a DNS that doesn't return the DC IPs in the
	 * SRV reply, you have bigger problems than this loop linearly
	 * walking a pointer array. This is theoretically O(n^2), but
	 * probably the DNS roundtrip time outweighs this by a
	 * lot. And we have a global timeout on this whole
	 * dns_rr_srv_fill routine.
	 */
	for (i=0; i<num_subreqs; i++) {
		if (state->subreqs[i] == subreq) {
			state->subreqs[i] = NULL;
			break;
		}
	}
	if (i == num_subreqs) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	srv = &state->srvs[i/2]; /* 2 subreq per srv */

	status = recv_fn(
		subreq,
		state,
		&rcode,
		&num_addrs,
		&hostnames_out,
		&addrs);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_INFO("async DNS %s lookup for %s returned %s\n",
			 ip_dbg_str,
			 srv->hostname,
			 nt_errstr(status));
		num_addrs = 0;
		goto done;
	}

	if (rcode != DNS_RCODE_OK) {
		DBG_INFO("async DNS %s lookup for %s returned DNS code "
			 "%"PRIu8"\n",
			 ip_dbg_str,
			 srv->hostname,
			 rcode);
		num_addrs = 0;
		goto done;
	}

	if (num_addrs == 0) {
		DBG_INFO("async DNS %s lookup for %s returned 0 addresses.\n",
			 ip_dbg_str,
			 srv->hostname);
		goto done;
	}

	num_ips = talloc_array_length(srv->ss_s);

	if (num_ips + num_addrs < num_addrs) {
		/* overflow */
		goto done;
	}

	tmp = talloc_realloc(
		state->srvs,
		srv->ss_s,
		struct sockaddr_storage,
		num_ips + num_addrs);
	if (tmp == NULL) {
		goto done;
	}

	for (i=0; i<num_addrs; i++) {
		char addr[INET6_ADDRSTRLEN];
		DBG_INFO("async DNS %s lookup for %s [%zu] got %s -> %s\n",
			 ip_dbg_str,
			 srv->hostname,
			 i,
			 hostnames_out[i],
			 print_sockaddr(addr, sizeof(addr), &addrs[i].u.ss));
		tmp[num_ips + i] = addrs[i].u.ss;
	}
	srv->ss_s = tmp;
	srv->num_ips = num_ips + num_addrs;

done:
	state->num_outstanding -= 1;
	if (state->num_outstanding == 0) {
		tevent_req_done(req);
	}
}

static void dns_rr_srv_fill_done_a(struct tevent_req *subreq)
{
	dns_rr_srv_fill_done(subreq, ads_dns_lookup_a_recv);
}

#if defined(HAVE_IPV6)
static void dns_rr_srv_fill_done_aaaa(struct tevent_req *subreq)
{
	dns_rr_srv_fill_done(subreq, ads_dns_lookup_aaaa_recv);
}
#endif

static void dns_rr_srv_fill_timedout(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_rr_srv_fill_state *state = tevent_req_data(
		req, struct dns_rr_srv_fill_state);
	bool ok;

	if (DEBUGLEVEL >= DBGLVL_INFO) {
		size_t i, num_addrs = 0;

		for (i=0; i<state->num_srvs; i++) {
			/*
			 * Count for the debug. Code that fills this
			 * in ensures no wrap.
			 */
			num_addrs += state->srvs[i].num_ips;
		}

		DBG_INFO("async DNS lookup timed out after %zu addresses "
			 "returned (not an error)\n",
			 num_addrs);
	}

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	TALLOC_FREE(state->subreqs);
	if (!ok) {
		tevent_req_oom(subreq);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS dns_rr_srv_fill_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

/*
 * Request a SRV record and fill in the A/AAAA records if the SRV
 * record did not carry them.
 */

struct ads_dns_query_srv_state {
	struct tevent_context *ev;
	uint32_t async_dns_timeout;
	const char *query;

	struct tevent_req *fill_req;
	struct tevent_req *timeout_req;
	struct dns_rr_srv *srvs;
	size_t num_srvs;
};

static void ads_dns_query_srv_site_aware_done(struct tevent_req *subreq);
static void ads_dns_query_srv_done(struct tevent_req *subreq);
static void ads_dns_query_srv_filled(struct tevent_req *subreq);

struct tevent_req *ads_dns_query_srv_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t async_dns_timeout,
	const char *sitename,
	const char *query)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct ads_dns_query_srv_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct ads_dns_query_srv_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->async_dns_timeout = async_dns_timeout;
	state->query = query;

	if ((sitename != NULL) && (sitename[0] != '\0')) {
		char *after_tcp = NULL;
		char *site_aware = NULL;

		/*
		 * ".<SITENAME>._sites" comes after "._tcp."
		 */
		after_tcp = strstr(state->query, "._tcp.");
		if (after_tcp == NULL) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			return tevent_req_post(req, ev);
		}
		after_tcp += 6; /* strlen("._tcp.") */

		site_aware = talloc_asprintf(
			state,
			"%.*s%s._sites.%s",
			(int)(after_tcp - state->query),
			state->query,
			sitename,
			after_tcp);
		if (tevent_req_nomem(site_aware, req)) {
			return tevent_req_post(req, ev);
		}

		subreq = ads_dns_lookup_srv_send(state, ev, site_aware);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			subreq, ads_dns_query_srv_site_aware_done, req);
		return req;
	}

	subreq = ads_dns_lookup_srv_send(state, state->ev, state->query);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ads_dns_query_srv_done, req);
	return req;
}

static void ads_dns_query_srv_site_aware_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_query_srv_state *state = tevent_req_data(
		req, struct ads_dns_query_srv_state);
	NTSTATUS status;

	status = ads_dns_lookup_srv_recv(
		subreq, state, &state->srvs, &state->num_srvs);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_REFUSED)) {
		tevent_req_nterror(req, status);
		return;
	}

	if (NT_STATUS_IS_OK(status) && (state->num_srvs != 0)) {
		if (state->async_dns_timeout == 0) {
			tevent_req_done(req);
			return;
		}

		subreq = dns_rr_srv_fill_send(
			state,
			state->ev,
			state->srvs,
			state->num_srvs,
			state->async_dns_timeout);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(
			subreq, ads_dns_query_srv_filled, req);
		return;
	}

	subreq = ads_dns_lookup_srv_send(state, state->ev, state->query);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ads_dns_query_srv_done, req);
}

static void ads_dns_query_srv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ads_dns_query_srv_state *state = tevent_req_data(
		req, struct ads_dns_query_srv_state);
	NTSTATUS status;

	status = ads_dns_lookup_srv_recv(
		subreq, state, &state->srvs, &state->num_srvs);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if ((state->num_srvs == 0) || (state->async_dns_timeout == 0)) {
		tevent_req_done(req);
		return;
	}

	subreq = dns_rr_srv_fill_send(
		state,
		state->ev,
		state->srvs,
		state->num_srvs,
		state->async_dns_timeout);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, ads_dns_query_srv_filled, req);
}

static void ads_dns_query_srv_filled(struct tevent_req *subreq)
{
	NTSTATUS status = dns_rr_srv_fill_recv(subreq);
	return tevent_req_simple_finish_ntstatus(subreq, status);
}

NTSTATUS ads_dns_query_srv_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct dns_rr_srv **srvs,
	size_t *num_srvs)
{
	struct ads_dns_query_srv_state *state = tevent_req_data(
		req, struct ads_dns_query_srv_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	if (srvs != NULL) {
		*srvs = talloc_move(mem_ctx, &state->srvs);
	}
	if (num_srvs != NULL) {
		*num_srvs = state->num_srvs;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS ads_dns_query_srv(
	TALLOC_CTX *mem_ctx,
	uint32_t async_dns_timeout,
	const char *sitename,
	const char *query,
	struct dns_rr_srv **srvs,
	size_t *num_srvs)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = ads_dns_query_srv_send(
		frame, ev, async_dns_timeout, sitename, query);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = ads_dns_query_srv_recv(req, mem_ctx, srvs, num_srvs);
fail:
	TALLOC_FREE(frame);
	return status;
}

char *ads_dns_query_string_dcs(TALLOC_CTX *mem_ctx, const char *realm)
{
	char *ret = talloc_asprintf(mem_ctx, "_ldap._tcp.dc._msdcs.%s", realm);
	return ret;
}

char *ads_dns_query_string_gcs(TALLOC_CTX *mem_ctx, const char *realm)
{
	char *ret = talloc_asprintf(mem_ctx, "_ldap._tcp.gc._msdcs.%s", realm);
	return ret;
}

char *ads_dns_query_string_kdcs(TALLOC_CTX *mem_ctx, const char *realm)
{
	char *ret = talloc_asprintf(
		mem_ctx, "_kerberos._tcp.dc._msdcs.%s", realm);
	return ret;
}

char *ads_dns_query_string_pdc(TALLOC_CTX *mem_ctx, const char *realm)
{
	char *ret = talloc_asprintf(
		mem_ctx, "_ldap._tcp.pdc._msdcs.%s", realm);
	return ret;
}

char *ads_dns_query_string_dcs_guid(
	TALLOC_CTX *mem_ctx,
	const struct GUID *domain_guid,
	const char *realm)
{
	struct GUID_txt_buf buf;
	char *ret = NULL;

	talloc_asprintf(
		mem_ctx,
		"_ldap._tcp.%s.domains._msdcs.%s",
		GUID_buf_string(domain_guid, &buf),
		realm);
	return ret;
}
