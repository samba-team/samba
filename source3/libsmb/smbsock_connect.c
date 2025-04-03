/*
   Unix SMB/CIFS implementation.
   Connect to 445 and 139/nbsesssetup
   Copyright (C) Volker Lendecke 2010

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
#include "../lib/param/param.h"
#include "../lib/async_req/async_sock.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"
#include "client.h"
#include "../libcli/smb/smbXcli_base.h"
#include "async_smb.h"
#include "../libcli/smb/read_smb.h"
#include "libsmb/nmblib.h"
#include "libsmb/smbsock_connect.h"
#include "../source4/lib/tls/tls.h"

#ifdef HAVE_LIBQUIC
#include <netinet/quic.h>
#endif

struct cli_session_request_state {
	struct tevent_context *ev;
	int sock;
	uint32_t len_hdr;
	struct iovec iov[3];
	uint8_t nb_session_response;
};

static void cli_session_request_sent(struct tevent_req *subreq);
static void cli_session_request_recvd(struct tevent_req *subreq);

static struct tevent_req *cli_session_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					int sock,
					const struct nmb_name *called,
					const struct nmb_name *calling)
{
	struct tevent_req *req, *subreq;
	struct cli_session_request_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct cli_session_request_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->sock = sock;

	state->iov[1].iov_base = name_mangle(
		state, called->name, called->name_type);
	if (tevent_req_nomem(state->iov[1].iov_base, req)) {
		return tevent_req_post(req, ev);
	}
	state->iov[1].iov_len = name_len(
		(unsigned char *)state->iov[1].iov_base,
		talloc_get_size(state->iov[1].iov_base));

	state->iov[2].iov_base = name_mangle(
		state, calling->name, calling->name_type);
	if (tevent_req_nomem(state->iov[2].iov_base, req)) {
		return tevent_req_post(req, ev);
	}
	state->iov[2].iov_len = name_len(
		(unsigned char *)state->iov[2].iov_base,
		talloc_get_size(state->iov[2].iov_base));

	_smb_setlen(((char *)&state->len_hdr),
		    state->iov[1].iov_len + state->iov[2].iov_len);
	SCVAL((char *)&state->len_hdr, 0, 0x81);

	state->iov[0].iov_base = &state->len_hdr;
	state->iov[0].iov_len = sizeof(state->len_hdr);

	subreq = writev_send(state, ev, NULL, sock, true, state->iov, 3);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, cli_session_request_sent, req);
	return req;
}

static void cli_session_request_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_request_state *state = tevent_req_data(
		req, struct cli_session_request_state);
	ssize_t ret;
	int err;

	ret = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	subreq = read_smb_send(state, state->ev, state->sock);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, cli_session_request_recvd, req);
}

static void cli_session_request_recvd(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct cli_session_request_state *state = tevent_req_data(
		req, struct cli_session_request_state);
	uint8_t *buf;
	ssize_t ret;
	int err;

	ret = read_smb_recv(subreq, talloc_tos(), &buf, &err);
	TALLOC_FREE(subreq);

	if (ret < 4) {
		ret = -1;
		err = EIO;
	}
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	/*
	 * In case of an error there is more information in the data
	 * portion according to RFC1002. We're not subtle enough to
	 * respond to the different error conditions, so drop the
	 * error info here.
	 */
	state->nb_session_response = CVAL(buf, 0);
	tevent_req_done(req);
}

static bool cli_session_request_recv(struct tevent_req *req, int *err, uint8_t *resp)
{
	struct cli_session_request_state *state = tevent_req_data(
		req, struct cli_session_request_state);

	if (tevent_req_is_unix_error(req, err)) {
		return false;
	}
	*resp = state->nb_session_response;
	return true;
}

struct nb_connect_state {
	struct tevent_context *ev;
	const struct sockaddr_storage *addr;
	const char *called_name;
	int sock;
	struct tevent_req *session_subreq;
	struct nmb_name called;
	struct nmb_name calling;
};

static void nb_connect_cleanup(struct tevent_req *req,
			       enum tevent_req_state req_state);
static void nb_connect_connected(struct tevent_req *subreq);
static void nb_connect_done(struct tevent_req *subreq);

static struct tevent_req *nb_connect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  const struct sockaddr_storage *addr,
					  const char *called_name,
					  int called_type,
					  const char *calling_name,
					  int calling_type,
					  uint16_t port)
{
	struct tevent_req *req, *subreq;
	struct nb_connect_state *state;

	req = tevent_req_create(mem_ctx, &state, struct nb_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->called_name = called_name;
	state->addr = addr;

	state->sock = -1;
	make_nmb_name(&state->called, called_name, called_type);
	make_nmb_name(&state->calling, calling_name, calling_type);

	tevent_req_set_cleanup_fn(req, nb_connect_cleanup);

	subreq = open_socket_out_send(state,
				      ev,
				      IPPROTO_TCP,
				      addr,
				      port,
				      5000);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, nb_connect_connected, req);
	return req;
}

static void nb_connect_cleanup(struct tevent_req *req,
			       enum tevent_req_state req_state)
{
	struct nb_connect_state *state = tevent_req_data(
		req, struct nb_connect_state);

	/*
	 * we need to free a pending request before closing the
	 * socket, see bug #11141
	 */
	TALLOC_FREE(state->session_subreq);

	if (req_state == TEVENT_REQ_DONE) {
		/*
		 * we keep the socket open for the caller to use
		 */
		return;
	}

	if (state->sock != -1) {
		close(state->sock);
		state->sock = -1;
	}

	return;
}

static void nb_connect_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_connect_state *state = tevent_req_data(
		req, struct nb_connect_state);
	NTSTATUS status;

	status = open_socket_out_recv(subreq, &state->sock);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	subreq = cli_session_request_send(state, state->ev, state->sock,
					  &state->called, &state->calling);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, nb_connect_done, req);
	state->session_subreq = subreq;
}

static void nb_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_connect_state *state = tevent_req_data(
		req, struct nb_connect_state);
	bool ret;
	int err;
	uint8_t resp;

	state->session_subreq = NULL;

	ret = cli_session_request_recv(subreq, &err, &resp);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}

	/*
	 * RFC1002: 0x82 - POSITIVE SESSION RESPONSE
	 */

	if (resp != 0x82) {
		/*
		 * The server did not like our session request
		 */
		close(state->sock);
		state->sock = -1;

		if (strequal(state->called_name, "*SMBSERVER")) {
			/*
			 * Here we could try a name status request and
			 * use the first 0x20 type name.
			 */
			tevent_req_nterror(
				req, NT_STATUS_RESOURCE_NAME_NOT_FOUND);
			return;
		}

		/*
		 * We could be subtle and distinguish between
		 * different failure modes, but what we do here
		 * instead is just retry with *SMBSERVER type 0x20.
		 */
		state->called_name = "*SMBSERVER";
		make_nmb_name(&state->called, state->called_name, 0x20);

		subreq = open_socket_out_send(state,
					      state->ev,
					      IPPROTO_TCP,
					      state->addr,
					      NBT_SMB_PORT,
					      5000);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, nb_connect_connected, req);
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS nb_connect_recv(struct tevent_req *req, int *sock)
{
	struct nb_connect_state *state = tevent_req_data(
		req, struct nb_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	*sock = state->sock;
	state->sock = -1;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct smb_transports smbsock_transports_from_port(uint16_t port)
{
	struct smb_transports ts = { .num_transports = 0, };

	if (port == 0) {
		ts = smb_transports_parse("client smb transports",
					  lp_client_smb_transports());
	} else if (port == NBT_SMB_PORT) {
		struct smb_transport *t = &ts.transports[0];

		*t = (struct smb_transport) {
			.type = SMB_TRANSPORT_TYPE_NBT,
			.port = NBT_SMB_PORT,
		};
		ts.num_transports = 1;
	} else {
		struct smb_transport *t = &ts.transports[0];

		*t = (struct smb_transport) {
			.type = SMB_TRANSPORT_TYPE_TCP,
			.port = port,
		};
		ts.num_transports = 1;
	}

	return ts;
}

struct smbsock_connect_substate {
	struct tevent_req *req;
	size_t idx;
	struct smb_transport transport;
	struct tevent_req *subreq;
	int sockfd;
};

struct smbsock_connect_state {
	struct tevent_context *ev;
	const struct sockaddr_storage *addr;
	const char *target_name;
	const char *called_name;
	uint8_t called_type;
	const char *calling_name;
	uint8_t calling_type;
	struct tstream_tls_params *quic_tlsp;
	struct tevent_req *wake_subreq;
	uint8_t num_substates;
	uint8_t submit_idx;
	uint8_t num_pending;
	struct smbsock_connect_substate substates[SMB_TRANSPORTS_MAX_TRANSPORTS];
	struct smbXcli_transport *transport;
	struct smbXcli_transport *(*create_bsd_transport)(
						TALLOC_CTX *mem_ctx,
						int *fd,
						const struct smb_transport *tp);
};

static void smbsock_connect_cleanup(struct tevent_req *req,
				    enum tevent_req_state req_state);
static bool smbsock_connect_submit_next(struct tevent_req *req);
static void smbsock_connect_waited(struct tevent_req *subreq);
static void smbsock_connect_nbt_connected(struct tevent_req *subreq);
static void smbsock_connect_tcp_connected(struct tevent_req *subreq);
#ifdef HAVE_LIBQUIC
static void smbsock_connect_quic_connected(struct tevent_req *subreq);
static void smbsock_connect_quic_ready(struct tevent_req *subreq);
#endif /* HAVE_LIBQUIC */

struct tevent_req *smbsock_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct loadparm_context *lp_ctx,
					const struct sockaddr_storage *addr,
					const struct smb_transports *transports,
					const char *called_name,
					int called_type,
					const char *calling_name,
					int calling_type)
{
	struct tevent_req *req;
	struct smbsock_connect_state *state;
	bool force_bsd_tstream = false;
	uint8_t num_unsupported = 0;
	struct smb_transports ts = *transports;
	uint8_t ti;
	bool ok;
	bool request_quic = false;
	bool try_quic = false;

	req = tevent_req_create(mem_ctx, &state, struct smbsock_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->addr = addr;
	state->target_name = called_name;
	state->called_name =
		(called_name != NULL) ? called_name : "*SMBSERVER";
	state->called_type =
		(called_type != -1) ? called_type : 0x20;
	state->calling_name =
		(calling_name != NULL) ? calling_name : lp_netbios_name();
	state->calling_type =
		(calling_type != -1) ? calling_type : 0x00;

	force_bsd_tstream = lpcfg_parm_bool(lp_ctx,
					    NULL,
					    "client smb transport",
					    "force_bsd_tstream",
					    false);
	if (force_bsd_tstream) {
		state->create_bsd_transport = smbXcli_transport_bsd_tstream;
	} else {
		state->create_bsd_transport = smbXcli_transport_bsd;
	}

	tevent_req_set_cleanup_fn(req, smbsock_connect_cleanup);

	SMB_ASSERT(ts.num_transports <= ARRAY_SIZE(state->substates));

	for (ti = 0; ti < ts.num_transports; ti++) {
		const struct smb_transport *t = &ts.transports[ti];

		if (t->type != SMB_TRANSPORT_TYPE_QUIC) {
			continue;
		}

		if (state->target_name != NULL) {
			request_quic = true;
			break;
		}
	}

	if (request_quic) {
		NTSTATUS status;

		status = tstream_tls_params_client_lpcfg(state,
							 lp_ctx,
							 state->target_name,
							 &state->quic_tlsp);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		status = tstream_tls_params_quic_prepare(state->quic_tlsp);
		if (tevent_req_nterror(req, status)) {
			return tevent_req_post(req, ev);
		}

		try_quic = tstream_tls_params_quic_enabled(state->quic_tlsp);
	}

	for (ti = 0; ti < ts.num_transports; ti++) {
		const struct smb_transport *t = &ts.transports[ti];
		struct smbsock_connect_substate *s =
			&state->substates[state->num_substates];

		switch (t->type) {
		case SMB_TRANSPORT_TYPE_UNKNOWN:
			/*
			 * Should never happen
			 */
			smb_panic(__location__);
			continue;
		case SMB_TRANSPORT_TYPE_NBT:
			if (lp_disable_netbios()) {
				num_unsupported += 1;
				continue;
			}
			break;
		case SMB_TRANSPORT_TYPE_TCP:
			break;
		case SMB_TRANSPORT_TYPE_QUIC:
			if (try_quic) {
				break;
			}

			/*
			 * Not supported yet or no
			 * called_name as peer name
			 * available.
			 */
			continue;
		}

		s->req = req;
		s->idx = state->num_substates;
		s->transport = *t;
		s->sockfd = -1;

		state->num_substates += 1;
	}

	if (state->num_substates == 0 && num_unsupported != 0) {
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	if (state->num_substates == 0) {
		tevent_req_nterror(req, NT_STATUS_PORT_NOT_SET);
		return tevent_req_post(req, ev);
	}

	ok = smbsock_connect_submit_next(req);
	if (!ok) {
		return tevent_req_post(req, ev);
	}

	if (state->submit_idx == state->num_substates) {
		/* only one transport */
		return req;
	}

	/*
	 * After 5 msecs, fire all remaining requests
	 */
	state->wake_subreq = tevent_wakeup_send(state,
						ev,
						timeval_current_ofs(0, 5000));
	if (tevent_req_nomem(state->wake_subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->wake_subreq,
				smbsock_connect_waited,
				req);

	return req;
}

static void smbsock_connect_cleanup(struct tevent_req *req,
				    enum tevent_req_state req_state)
{
	struct smbsock_connect_state *state = tevent_req_data(
		req, struct smbsock_connect_state);
	uint8_t si;

	/*
	 * we need to free a pending request before closing the
	 * socket, see bug #11141
	 */
	TALLOC_FREE(state->wake_subreq);
	for (si = 0; si < state->num_substates; si++) {
		struct smbsock_connect_substate *s =
			&state->substates[si];

		TALLOC_FREE(s->subreq);
		if (s->sockfd != -1) {
			close(s->sockfd);
			s->sockfd = -1;
		}
	}

	if (req_state == TEVENT_REQ_DONE) {
		/*
		 * we keep the socket open for the caller to use
		 */
		return;
	}

	TALLOC_FREE(state->transport);

	return;
}

static bool smbsock_connect_submit_next(struct tevent_req *req)
{
	struct smbsock_connect_state *state =
		tevent_req_data(req,
		struct smbsock_connect_state);
	struct smbsock_connect_substate *s =
		&state->substates[state->submit_idx];

	SMB_ASSERT(state->submit_idx < state->num_substates);

	switch (s->transport.type) {
	case SMB_TRANSPORT_TYPE_UNKNOWN:
		break;

	case SMB_TRANSPORT_TYPE_NBT:
		s->subreq = nb_connect_send(state,
					    state->ev,
					    state->addr,
					    state->called_name,
					    state->called_type,
					    state->calling_name,
					    state->calling_type,
					    s->transport.port);
		if (tevent_req_nomem(s->subreq, req)) {
			return false;
		}
		tevent_req_set_callback(s->subreq,
					smbsock_connect_nbt_connected,
					s);
		break;

	case SMB_TRANSPORT_TYPE_TCP:
		s->subreq = open_socket_out_send(state,
						 state->ev,
						 IPPROTO_TCP,
						 state->addr,
						 s->transport.port,
						 5000);
		if (tevent_req_nomem(s->subreq, req)) {
			return false;
		}
		tevent_req_set_callback(s->subreq,
					smbsock_connect_tcp_connected,
					s);
		break;

	case SMB_TRANSPORT_TYPE_QUIC:
#ifdef HAVE_LIBQUIC
		s->subreq = open_socket_out_send(state,
						 state->ev,
						 IPPROTO_QUIC,
						 state->addr,
						 s->transport.port,
						 5000);
		if (tevent_req_nomem(s->subreq, req)) {
			return false;
		}
		tevent_req_set_callback(s->subreq,
					smbsock_connect_quic_connected,
					s);
		break;
#else /* ! HAVE_LIBQUIC */
		/*
		 * Not supported yet, should already be
		 * checked above.
		 */
		smb_panic(__location__);
		break;
#endif /* ! HAVE_LIBQUIC */
	}

	if (s->subreq == NULL) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return false;
	}

	state->num_pending += 1;
	state->submit_idx += 1;
	if (state->submit_idx == state->num_substates) {
		TALLOC_FREE(state->wake_subreq);
	}

	return true;
}

static void smbsock_connect_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbsock_connect_state *state = tevent_req_data(
		req, struct smbsock_connect_state);
	bool ok;

	SMB_ASSERT(state->wake_subreq == subreq);
	state->wake_subreq = NULL;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	SMB_ASSERT(state->submit_idx < state->num_substates);

	while (state->submit_idx < state->num_substates) {
		ok = smbsock_connect_submit_next(req);
		if (!ok) {
			return;
		}
	}
}

static void smbsock_connect_nbt_connected(struct tevent_req *subreq)
{
	struct smbsock_connect_substate *s =
		(struct smbsock_connect_substate *)
		tevent_req_callback_data_void(subreq);
	struct tevent_req *req = s->req;
	struct smbsock_connect_state *state =
		tevent_req_data(req,
		struct smbsock_connect_state);
	NTSTATUS status;

	SMB_ASSERT(s->subreq == subreq);
	s->subreq = NULL;
	SMB_ASSERT(state->num_pending > 0);
	state->num_pending -= 1;

	status = nb_connect_recv(subreq, &s->sockfd);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		set_socket_options(s->sockfd, lp_socket_options());
		state->transport = state->create_bsd_transport(state,
							       &s->sockfd,
							       &s->transport);
		if (tevent_req_nomem(state->transport, req)) {
			return;
		}
		tevent_req_done(req);
		return;
	}

	/*
	 * Do nothing, wait for the remaining
	 * requests to come here.
	 *
	 * Submit the next requests if there
	 * are unsubmitted requests remaining.
	 */
	if (state->submit_idx < state->num_substates) {
		bool ok;

		ok = smbsock_connect_submit_next(req);
		if (!ok) {
			return;
		}
	}

	if (state->num_pending == 0) {
		/*
		 * All requests failed
		 *
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		tevent_req_nterror(req, status);
		return;
	}
}

static void smbsock_connect_tcp_connected(struct tevent_req *subreq)
{
	struct smbsock_connect_substate *s =
		(struct smbsock_connect_substate *)
		tevent_req_callback_data_void(subreq);
	struct tevent_req *req = s->req;
	struct smbsock_connect_state *state =
		tevent_req_data(req,
		struct smbsock_connect_state);
	NTSTATUS status;

	SMB_ASSERT(s->subreq == subreq);
	s->subreq = NULL;
	SMB_ASSERT(state->num_pending > 0);
	state->num_pending -= 1;

	status = open_socket_out_recv(subreq, &s->sockfd);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		set_socket_options(s->sockfd, lp_socket_options());
		state->transport = state->create_bsd_transport(state,
							       &s->sockfd,
							       &s->transport);
		if (tevent_req_nomem(state->transport, req)) {
			return;
		}
		tevent_req_done(req);
		return;
	}

	/*
	 * Do nothing, wait for the remaining
	 * requests to come here.
	 *
	 * Submit the next requests if there
	 * are unsubmitted requests remaining.
	 */
	if (state->submit_idx < state->num_substates) {
		bool ok;

		ok = smbsock_connect_submit_next(req);
		if (!ok) {
			return;
		}
	}

	if (state->num_pending == 0) {
		/*
		 * All requests failed
		 *
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		tevent_req_nterror(req, status);
		return;
	}
}

#ifdef HAVE_LIBQUIC
static void smbsock_connect_quic_connected(struct tevent_req *subreq)
{
	struct smbsock_connect_substate *s =
		(struct smbsock_connect_substate *)
		tevent_req_callback_data_void(subreq);
	struct tevent_req *req = s->req;
	struct smbsock_connect_state *state =
		tevent_req_data(req,
		struct smbsock_connect_state);
	NTSTATUS status;

	SMB_ASSERT(s->subreq == subreq);
	s->subreq = NULL;
	SMB_ASSERT(state->num_pending > 0);
	state->num_pending -= 1;

	status = open_socket_out_recv(subreq, &s->sockfd);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		s->subreq = tstream_tls_quic_handshake_send(state,
							    state->ev,
							    state->quic_tlsp,
							    false, /* is_server */
							    5000,
							    "smb",
							    s->sockfd);
		if (s->subreq == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		tevent_req_set_callback(s->subreq,
					smbsock_connect_quic_ready,
					s);
		state->num_pending += 1;
		return;
	}

fail:
	/*
	 * Do nothing, wait for the remaining
	 * requests to come here.
	 *
	 * Submit the next requests if there
	 * are unsubmitted requests remaining.
	 */
	if (state->submit_idx < state->num_substates) {
		bool ok;

		ok = smbsock_connect_submit_next(req);
		if (!ok) {
			return;
		}
	}

	if (state->num_pending == 0) {
		/*
		 * All requests failed
		 *
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		tevent_req_nterror(req, status);
		return;
	}
}

static void smbsock_connect_quic_ready(struct tevent_req *subreq)
{
	struct smbsock_connect_substate *s =
		(struct smbsock_connect_substate *)
		tevent_req_callback_data_void(subreq);
	struct tevent_req *req = s->req;
	struct smbsock_connect_state *state =
		tevent_req_data(req,
		struct smbsock_connect_state);
	NTSTATUS status;

	SMB_ASSERT(s->subreq == subreq);
	s->subreq = NULL;
	SMB_ASSERT(state->num_pending > 0);
	state->num_pending -= 1;

	status = tstream_tls_quic_handshake_recv(subreq);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		state->transport = state->create_bsd_transport(state,
							       &s->sockfd,
							       &s->transport);
		if (tevent_req_nomem(state->transport, req)) {
			return;
		}
		tevent_req_done(req);
		return;
	}

	/*
	 * Do nothing, wait for the remaining
	 * requests to come here.
	 *
	 * Submit the next requests if there
	 * are unsubmitted requests remaining.
	 */
	if (state->submit_idx < state->num_substates) {
		bool ok;

		ok = smbsock_connect_submit_next(req);
		if (!ok) {
			return;
		}
	}

	if (state->num_pending == 0) {
		/*
		 * All requests failed
		 *
		 * smbsock_connect_cleanup()
		 * will free all other subreqs
		 */
		tevent_req_nterror(req, status);
		return;
	}
}
#endif /* HAVE_LIBQUIC */

NTSTATUS smbsock_connect_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      struct smbXcli_transport **ptransport)
{
	struct smbsock_connect_state *state = tevent_req_data(
		req, struct smbsock_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	*ptransport = talloc_move(mem_ctx, &state->transport);
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS smbsock_connect(const struct sockaddr_storage *addr,
			 struct loadparm_context *lp_ctx,
			 const struct smb_transports *transports,
			 const char *called_name, int called_type,
			 const char *calling_name, int calling_type,
			 int sec_timeout,
			 TALLOC_CTX *mem_ctx,
			 struct smbXcli_transport **ptransport)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smbsock_connect_send(frame, ev, lp_ctx, addr, transports,
				   called_name, called_type,
				   calling_name, calling_type);
	if (req == NULL) {
		goto fail;
	}
	if ((sec_timeout != 0) &&
	    !tevent_req_set_endtime(
		    req, ev, timeval_current_ofs(sec_timeout, 0))) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smbsock_connect_recv(req, mem_ctx, ptransport);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct smbsock_any_connect_state {
	struct tevent_context *ev;
	struct loadparm_context *lp_ctx;
	const struct sockaddr_storage *addrs;
	const char **called_names;
	int *called_types;
	const char **calling_names;
	int *calling_types;
	size_t num_addrs;
	struct smb_transports transports;

	struct tevent_req **requests;
	size_t num_sent;
	size_t num_received;

	struct smbXcli_transport *transport;
	size_t chosen_index;
};

static void smbsock_any_connect_cleanup(struct tevent_req *req,
					enum tevent_req_state req_state);
static bool smbsock_any_connect_send_next(
	struct tevent_req *req,	struct smbsock_any_connect_state *state);
static void smbsock_any_connect_trynext(struct tevent_req *subreq);
static void smbsock_any_connect_connected(struct tevent_req *subreq);

struct tevent_req *smbsock_any_connect_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct loadparm_context *lp_ctx,
					    const struct sockaddr_storage *addrs,
					    const char **called_names,
					    int *called_types,
					    const char **calling_names,
					    int *calling_types,
					    size_t num_addrs,
					    const struct smb_transports *transports)
{
	struct tevent_req *req, *subreq;
	struct smbsock_any_connect_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smbsock_any_connect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->lp_ctx = lp_ctx;
	state->addrs = addrs;
	state->num_addrs = num_addrs;
	state->called_names = called_names;
	state->called_types = called_types;
	state->calling_names = calling_names;
	state->calling_types = calling_types;
	state->transports = *transports;

	tevent_req_set_cleanup_fn(req, smbsock_any_connect_cleanup);

	if (num_addrs == 0) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->requests = talloc_zero_array(state, struct tevent_req *,
					    num_addrs);
	if (tevent_req_nomem(state->requests, req)) {
		return tevent_req_post(req, ev);
	}
	if (!smbsock_any_connect_send_next(req, state)) {
		return tevent_req_post(req, ev);
	}
	if (state->num_sent >= state->num_addrs) {
		return req;
	}
	subreq = tevent_wakeup_send(state, ev, timeval_current_ofs(0, 10000));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbsock_any_connect_trynext, req);
	return req;
}

static void smbsock_any_connect_cleanup(struct tevent_req *req,
					enum tevent_req_state req_state)
{
	struct smbsock_any_connect_state *state = tevent_req_data(
		req, struct smbsock_any_connect_state);

	TALLOC_FREE(state->requests);

	if (req_state == TEVENT_REQ_DONE) {
		/*
		 * Keep the socket open for the caller.
		 */
		return;
	}

	TALLOC_FREE(state->transport);
}

static void smbsock_any_connect_trynext(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbsock_any_connect_state *state = tevent_req_data(
		req, struct smbsock_any_connect_state);
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	if (!smbsock_any_connect_send_next(req, state)) {
		return;
	}
	if (state->num_sent >= state->num_addrs) {
		return;
	}
	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_set(0, 10000));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, smbsock_any_connect_trynext, req);
}

static bool smbsock_any_connect_send_next(
	struct tevent_req *req, struct smbsock_any_connect_state *state)
{
	struct tevent_req *subreq;

	if (state->num_sent >= state->num_addrs) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return false;
	}
	subreq = smbsock_connect_send(
		state->requests,
		state->ev,
		state->lp_ctx,
		&state->addrs[state->num_sent],
		&state->transports,
		(state->called_names != NULL)
		? state->called_names[state->num_sent] : NULL,
		(state->called_types != NULL)
		? state->called_types[state->num_sent] : -1,
		(state->calling_names != NULL)
		? state->calling_names[state->num_sent] : NULL,
		(state->calling_types != NULL)
		? state->calling_types[state->num_sent] : -1);
	if (tevent_req_nomem(subreq, req)) {
		return false;
	}
	tevent_req_set_callback(subreq, smbsock_any_connect_connected, req);

	state->requests[state->num_sent] = subreq;
	state->num_sent += 1;

	return true;
}

static void smbsock_any_connect_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbsock_any_connect_state *state = tevent_req_data(
		req, struct smbsock_any_connect_state);
	NTSTATUS status;
	size_t i;
	size_t chosen_index = 0;

	for (i=0; i<state->num_sent; i++) {
		if (state->requests[i] == subreq) {
			chosen_index = i;
			break;
		}
	}
	if (i == state->num_sent) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	status = smbsock_connect_recv(subreq, state, &state->transport);

	TALLOC_FREE(subreq);
	state->requests[chosen_index] = NULL;

	if (NT_STATUS_IS_OK(status)) {
		state->chosen_index = chosen_index;
		tevent_req_done(req);
		return;
	}

	state->num_received += 1;
	if (state->num_received < state->num_addrs) {
		/*
		 * More addrs pending, wait for the others
		 */
		return;
	}

	/*
	 * This is the last response, none succeeded.
	 */
	tevent_req_nterror(req, status);
	return;
}

NTSTATUS smbsock_any_connect_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct smbXcli_transport **ptransport,
				  size_t *chosen_index)
{
	struct smbsock_any_connect_state *state = tevent_req_data(
		req, struct smbsock_any_connect_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	*ptransport = talloc_move(mem_ctx, &state->transport);
	if (chosen_index != NULL) {
		*chosen_index = state->chosen_index;
	}
	tevent_req_received(req);
	return NT_STATUS_OK;
}

NTSTATUS smbsock_any_connect(const struct sockaddr_storage *addrs,
			     const char **called_names,
			     int *called_types,
			     const char **calling_names,
			     int *calling_types,
			     size_t num_addrs,
			     struct loadparm_context *lp_ctx,
			     const struct smb_transports *transports,
			     int sec_timeout,
			     TALLOC_CTX *mem_ctx,
			     struct smbXcli_transport **ptransport,
			     size_t *chosen_index)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smbsock_any_connect_send(frame, ev, lp_ctx, addrs,
				       called_names, called_types,
				       calling_names, calling_types,
				       num_addrs, transports);
	if (req == NULL) {
		goto fail;
	}
	if ((sec_timeout != 0) &&
	    !tevent_req_set_endtime(
		    req, ev, timeval_current_ofs(sec_timeout, 0))) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = smbsock_any_connect_recv(req, mem_ctx, ptransport, chosen_index);
 fail:
	TALLOC_FREE(frame);
	return status;
}
