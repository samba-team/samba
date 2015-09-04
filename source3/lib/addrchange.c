/*
 * Samba Unix/Linux SMB client library
 * Copyright (C) Volker Lendecke 2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "lib/addrchange.h"
#include "../lib/util/tevent_ntstatus.h"

#if HAVE_LINUX_RTNETLINK_H

#include "asm/types.h"
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "lib/tsocket/tsocket.h"

struct addrchange_context {
	struct tdgram_context *sock;
};

NTSTATUS addrchange_context_create(TALLOC_CTX *mem_ctx,
				   struct addrchange_context **pctx)
{
	struct addrchange_context *ctx;
	struct sockaddr_nl addr;
	NTSTATUS status;
	int sock = -1;
	int res;
	bool ok;

	ctx = talloc(mem_ctx, struct addrchange_context);
	if (ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	ok = smb_set_close_on_exec(sock);
	if (!ok) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	res = set_blocking(sock, false);
	if (res == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	/*
	 * We're interested in address changes
	 */
	ZERO_STRUCT(addr);
	addr.nl_family = AF_NETLINK;
	addr.nl_groups = RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_IFADDR;

	res = bind(sock, (struct sockaddr *)(void *)&addr, sizeof(addr));
	if (res == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	res = tdgram_bsd_existing_socket(ctx, sock, &ctx->sock);
	if (res == -1) {
		status = map_nt_error_from_unix(errno);
		goto fail;
	}

	*pctx = ctx;
	return NT_STATUS_OK;
fail:
	if (sock != -1) {
		close(sock);
	}
	TALLOC_FREE(ctx);
	return status;
}

struct addrchange_state {
	struct tevent_context *ev;
	struct addrchange_context *ctx;
	uint8_t *buf;
	struct tsocket_address *fromaddr;

	enum addrchange_type type;
	struct sockaddr_storage addr;
};

static void addrchange_done(struct tevent_req *subreq);

struct tevent_req *addrchange_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct addrchange_context *ctx)
{
	struct tevent_req *req, *subreq;
	struct addrchange_state *state;

	req = tevent_req_create(mem_ctx, &state, struct addrchange_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->ctx = ctx;

	subreq = tdgram_recvfrom_send(state, state->ev, state->ctx->sock);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, state->ev);
	}
	tevent_req_set_callback(subreq, addrchange_done, req);
	return req;
}

static void addrchange_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct addrchange_state *state = tevent_req_data(
		req, struct addrchange_state);
	union {
		struct sockaddr sa;
		struct sockaddr_nl nl;
		struct sockaddr_storage ss;
	} fromaddr;
	struct nlmsghdr *h;
	struct ifaddrmsg *ifa;
	struct rtattr *rta;
	ssize_t received;
	int len;
	int err;
	bool found;

	received = tdgram_recvfrom_recv(subreq, &err, state,
					&state->buf,
					&state->fromaddr);
	TALLOC_FREE(subreq);
	if (received == -1) {
		DEBUG(10, ("tdgram_recvfrom_recv returned %s\n", strerror(err)));
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	len = tsocket_address_bsd_sockaddr(state->fromaddr,
					   &fromaddr.sa,
					   sizeof(fromaddr));

	if ((len != sizeof(fromaddr.nl) ||
	    fromaddr.sa.sa_family != AF_NETLINK))
	{
		DEBUG(10, ("Got message from wrong addr\n"));
		goto retry;
	}

	if (fromaddr.nl.nl_pid != 0) {
		DEBUG(10, ("Got msg from pid %d, not from the kernel\n",
			   (int)fromaddr.nl.nl_pid));
		goto retry;
	}

	if (received < sizeof(struct nlmsghdr)) {
		DEBUG(10, ("received %d, expected at least %d\n",
			   (int)received, (int)sizeof(struct nlmsghdr)));
		goto retry;
	}

	h = (struct nlmsghdr *)state->buf;
	if (h->nlmsg_len < sizeof(struct nlmsghdr)) {
		DEBUG(10, ("nlmsg_len=%d, expected at least %d\n",
			   (int)h->nlmsg_len, (int)sizeof(struct nlmsghdr)));
		goto retry;
	}
	if (h->nlmsg_len > received) {
		DEBUG(10, ("nlmsg_len=%d, expected at most %d\n",
			   (int)h->nlmsg_len, (int)received));
		goto retry;
	}
	switch (h->nlmsg_type) {
	case RTM_NEWADDR:
		state->type = ADDRCHANGE_ADD;
		break;
	case RTM_DELADDR:
		state->type = ADDRCHANGE_DEL;
		break;
	default:
		DEBUG(10, ("Got unexpected type %d - ignoring\n", h->nlmsg_type));
		goto retry;
	}

	if (h->nlmsg_len < sizeof(struct nlmsghdr)+sizeof(struct ifaddrmsg)) {
		DEBUG(10, ("nlmsg_len=%d, expected at least %d\n",
			   (int)h->nlmsg_len,
			   (int)(sizeof(struct nlmsghdr)
				 +sizeof(struct ifaddrmsg))));
		tevent_req_nterror(req, NT_STATUS_UNEXPECTED_IO_ERROR);
		return;
	}

	ifa = (struct ifaddrmsg *)NLMSG_DATA(h);

	state->addr.ss_family = ifa->ifa_family;

	rta = IFA_RTA(ifa);
	len = h->nlmsg_len - sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg);

	found = false;

	for (rta = IFA_RTA(ifa); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {

		if ((rta->rta_type != IFA_LOCAL)
		    && (rta->rta_type != IFA_ADDRESS)) {
			continue;
		}

		switch (ifa->ifa_family) {
		case AF_INET: {
			struct sockaddr_in *v4_addr;
			v4_addr = (struct sockaddr_in *)(void *)&state->addr;

			if (RTA_PAYLOAD(rta) != sizeof(uint32_t)) {
				continue;
			}
			v4_addr->sin_addr.s_addr = *(uint32_t *)RTA_DATA(rta);
			found = true;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *v6_addr;
			v6_addr = (struct sockaddr_in6 *)(void *)&state->addr;

			if (RTA_PAYLOAD(rta) !=
			    sizeof(v6_addr->sin6_addr.s6_addr)) {
				continue;
			}
			memcpy(v6_addr->sin6_addr.s6_addr, RTA_DATA(rta),
			       sizeof(v6_addr->sin6_addr.s6_addr));
			found = true;
			break;
		}
		}
	}

	if (!found) {
		tevent_req_nterror(req, NT_STATUS_INVALID_ADDRESS);
		return;
	}

	tevent_req_done(req);
	return;

retry:
	TALLOC_FREE(state->buf);
	TALLOC_FREE(state->fromaddr);

	subreq = tdgram_recvfrom_send(state, state->ev, state->ctx->sock);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, addrchange_done, req);
}

NTSTATUS addrchange_recv(struct tevent_req *req, enum addrchange_type *type,
			 struct sockaddr_storage *addr)
{
	struct addrchange_state *state = tevent_req_data(
		req, struct addrchange_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*type = state->type;
	*addr = state->addr;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

#else

NTSTATUS addrchange_context_create(TALLOC_CTX *mem_ctx,
				   struct addrchange_context **pctx)
{
	return NT_STATUS_NOT_SUPPORTED;
}

struct tevent_req *addrchange_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct addrchange_context *ctx)
{
	return NULL;
}

NTSTATUS addrchange_recv(struct tevent_req *req, enum addrchange_type *type,
			 struct sockaddr_storage *addr)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

#endif
