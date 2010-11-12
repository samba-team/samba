/*
   Unix SMB/CIFS implementation.

   KDC Server request proxying

   Copyright (C) Andrew Tridgell	2010
   Copyright (C) Andrew Bartlett        2010

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
#include "smbd/process_model.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/util/tstream.h"
#include "system/network.h"
#include "param/param.h"
#include "lib/stream/packet.h"
#include "kdc/kdc-glue.h"
#include "ldb.h"
#include "librpc/gen_ndr/drsblobs.h"
#include "dsdb/schema/schema.h"
#include "dsdb/common/proto.h"
#include "libcli/composite/composite.h"
#include "libcli/resolve/resolve.h"


/*
  get a list of our replication partners from repsFrom, returning it in *proxy_list
 */
static WERROR kdc_proxy_get_writeable_dcs(struct kdc_server *kdc, TALLOC_CTX *mem_ctx, char ***proxy_list)
{
	WERROR werr;
	uint32_t count, i;
	struct repsFromToBlob *reps;

	werr = dsdb_loadreps(kdc->samdb, mem_ctx, ldb_get_default_basedn(kdc->samdb), "repsFrom", &reps, &count);
	W_ERROR_NOT_OK_RETURN(werr);

	if (count == 0) {
		/* we don't have any DCs to replicate with. Very
		   strange for a RODC */
		DEBUG(1,(__location__ ": No replication sources for RODC in KDC proxy\n"));
		talloc_free(reps);
		return WERR_DS_DRA_NO_REPLICA;
	}

	(*proxy_list) = talloc_array(mem_ctx, char *, count+1);
	W_ERROR_HAVE_NO_MEMORY_AND_FREE(*proxy_list, reps);

	talloc_steal(*proxy_list, reps);

	for (i=0; i<count; i++) {
		const char *dns_name = NULL;
		if (reps->version == 1) {
			dns_name = reps->ctr.ctr1.other_info->dns_name;
		} else if (reps->version == 2) {
			dns_name = reps->ctr.ctr2.other_info->dns_name1;
		}
		(*proxy_list)[i] = talloc_strdup(*proxy_list, dns_name);
		W_ERROR_HAVE_NO_MEMORY_AND_FREE((*proxy_list)[i], *proxy_list);
	}
	(*proxy_list)[i] = NULL;

	talloc_free(reps);

	return WERR_OK;
}


struct kdc_udp_proxy_state {
	struct kdc_udp_call *call;
	struct kdc_udp_socket *sock;
	struct kdc_server *kdc;
	char **proxy_list;
	uint32_t next_proxy;
	const char *proxy_ip;
	uint16_t port;
};


static void kdc_udp_next_proxy(struct kdc_udp_proxy_state *state);

/*
  called when the send of the call to the proxy is complete
  this is used to get an errors from the sendto()
 */
static void kdc_udp_proxy_sendto_done(struct tevent_req *req)
{
	struct kdc_udp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_udp_proxy_state);
	ssize_t ret;
	int sys_errno;

	ret = tdgram_sendto_queue_recv(req, &sys_errno);
	talloc_free(req);

	if (ret == -1) {
		DEBUG(4,("kdc_udp_proxy: sendto for %s gave %d : %s\n",
			 state->proxy_ip, sys_errno, strerror(sys_errno)));
		kdc_udp_next_proxy(state);
	}
}

/*
  called when the send of the reply to the client is complete
  this is used to get an errors from the sendto()
 */
static void kdc_udp_proxy_reply_done(struct tevent_req *req)
{
	struct kdc_udp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_udp_proxy_state);
	ssize_t ret;
	int sys_errno;

	ret = tdgram_sendto_queue_recv(req, &sys_errno);
	if (ret == -1) {
		DEBUG(3,("kdc_udp_proxy: reply sendto gave %d : %s\n",
			 sys_errno, strerror(sys_errno)));
	}

	/* all done - we can destroy the proxy state */
	talloc_free(req);
	talloc_free(state);
}


/*
  called when the proxy replies
 */
static void kdc_udp_proxy_reply(struct tevent_req *req)
{
	struct kdc_udp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_udp_proxy_state);
	int sys_errno;
	uint8_t *buf;
	struct tsocket_address *src;
	ssize_t len;

	len = tdgram_recvfrom_recv(req, &sys_errno,
				   state, &buf, &src);
	talloc_free(req);
	if (len == -1) {
		DEBUG(4,("kdc_udp_proxy: reply from %s gave %d : %s\n",
			 state->proxy_ip, sys_errno, strerror(sys_errno)));
		kdc_udp_next_proxy(state);
		return;
	}

	state->call->out.length = len;
	state->call->out.data = buf;

	/* TODO: check the reply came from the right IP? */

	req = tdgram_sendto_queue_send(state,
				       state->kdc->task->event_ctx,
				       state->sock->dgram,
				       state->sock->send_queue,
				       state->call->out.data,
				       state->call->out.length,
				       state->call->src);
	if (req == NULL) {
		kdc_udp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_udp_proxy_reply_done, state);
}


/*
  called when we've resolved the name of a proxy
 */
static void kdc_udp_proxy_resolve_done(struct composite_context *c)
{
	struct kdc_udp_proxy_state *state;
	NTSTATUS status;
	struct tevent_req *req;
	struct tsocket_address *local_addr, *proxy_addr;
	int ret;
	struct tdgram_context *dgram;
	struct tevent_queue *send_queue;

	state = talloc_get_type(c->async.private_data, struct kdc_udp_proxy_state);

	status = resolve_name_recv(c, state, &state->proxy_ip);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to resolve proxy\n"));
		kdc_udp_next_proxy(state);
		return;
	}

	/* get an address for us to use locally */
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0, &local_addr);
	if (ret != 0) {
		kdc_udp_next_proxy(state);
		return;
	}

	ret = tsocket_address_inet_from_strings(state, "ip",
						state->proxy_ip, state->port, &proxy_addr);
	if (ret != 0) {
		kdc_udp_next_proxy(state);
		return;
	}

	/* create a socket for us to work on */
	ret = tdgram_inet_udp_socket(local_addr, proxy_addr, state, &dgram);
	if (ret != 0) {
		kdc_udp_next_proxy(state);
		return;
	}

	send_queue = tevent_queue_create(state, "kdc_udp_proxy");
	if (send_queue == NULL) {
		kdc_udp_next_proxy(state);
		return;
	}

	req = tdgram_sendto_queue_send(state,
				       state->kdc->task->event_ctx,
				       dgram,
				       send_queue,
				       state->call->in.data,
				       state->call->in.length,
				       proxy_addr);
	if (req == NULL) {
		kdc_udp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_udp_proxy_sendto_done, state);

	/* setup to receive the reply from the proxy */
	req = tdgram_recvfrom_send(state, state->kdc->task->event_ctx, dgram);
	if (req == NULL) {
		kdc_udp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_udp_proxy_reply, state);

	tevent_req_set_endtime(req, state->kdc->task->event_ctx,
			       timeval_current_ofs(state->kdc->proxy_timeout, 0));

	DEBUG(4,("kdc_udp_proxy: proxying request to %s\n", state->proxy_ip));
}


/*
  called when our proxies are not available
 */
static void kdc_udp_proxy_unavailable(struct kdc_udp_proxy_state *state)
{
	int kret;
	krb5_data k5_error_blob;
	struct tevent_req *req;

	kret = krb5_mk_error(state->kdc->smb_krb5_context->krb5_context,
			     KRB5KDC_ERR_SVC_UNAVAILABLE, NULL, NULL,
			     NULL, NULL, NULL, NULL, &k5_error_blob);
	if (kret != 0) {
		DEBUG(2,(__location__ ": Unable to form krb5 error reply\n"));
		talloc_free(state);
		return;
	}

	state->call->out = data_blob_talloc(state, k5_error_blob.data, k5_error_blob.length);
	krb5_data_free(&k5_error_blob);
	if (!state->call->out.data) {
		talloc_free(state);
		return;
	}

	req = tdgram_sendto_queue_send(state,
				       state->kdc->task->event_ctx,
				       state->sock->dgram,
				       state->sock->send_queue,
				       state->call->out.data,
				       state->call->out.length,
				       state->call->src);
	if (!req) {
		talloc_free(state);
		return;
	}

	tevent_req_set_callback(req, kdc_udp_proxy_reply_done, state);
}

/*
  try the next proxy in the list
 */
static void kdc_udp_next_proxy(struct kdc_udp_proxy_state *state)
{
	const char *proxy_dnsname = state->proxy_list[state->next_proxy];
	struct nbt_name name;
	struct composite_context *c;

	if (proxy_dnsname == NULL) {
		kdc_udp_proxy_unavailable(state);
		return;
	}

	state->next_proxy++;

	make_nbt_name(&name, proxy_dnsname, 0);

	c = resolve_name_ex_send(lpcfg_resolve_context(state->kdc->task->lp_ctx),
				 state,
				 RESOLVE_NAME_FLAG_FORCE_DNS,
				 0,
				 &name,
				 state->kdc->task->event_ctx);
	if (c == NULL) {
		kdc_udp_next_proxy(state);
		return;
	}
	c->async.fn = kdc_udp_proxy_resolve_done;
	c->async.private_data = state;
}


/*
  proxy a UDP kdc request to a writeable DC
 */
void kdc_udp_proxy(struct kdc_server *kdc, struct kdc_udp_socket *sock,
		   struct kdc_udp_call *call, uint16_t port)
{
	struct kdc_udp_proxy_state *state;
	WERROR werr;

	state = talloc_zero(kdc, struct kdc_udp_proxy_state);
	if (state == NULL) {
		talloc_free(call);
		return;
	}

	state->call = talloc_steal(state, call);
	state->sock = sock;
	state->kdc  = kdc;
	state->port = port;

	werr = kdc_proxy_get_writeable_dcs(kdc, state, &state->proxy_list);
	if (!W_ERROR_IS_OK(werr)) {
		kdc_udp_proxy_unavailable(state);
		return;
	}

	kdc_udp_next_proxy(state);
}


struct kdc_tcp_proxy_state {
	struct kdc_tcp_call *call;
	struct kdc_tcp_connection *kdc_conn;
	struct kdc_server *kdc;
	uint16_t port;
	uint32_t next_proxy;
	char **proxy_list;
	const char *proxy_ip;
};

static void kdc_tcp_next_proxy(struct kdc_tcp_proxy_state *state);

/*
  called when the send of the proxied reply to the client is done
 */
static void kdc_tcp_proxy_reply_done(struct tevent_req *req)
{
	struct kdc_tcp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_tcp_proxy_state);
	int ret, sys_errno;

	ret = tstream_writev_queue_recv(req, &sys_errno);
	if (ret == -1) {
		DEBUG(4,("kdc_tcp_proxy: writev of reply gave %d : %s\n",
			 sys_errno, strerror(sys_errno)));
	}
	talloc_free(req);
	talloc_free(state);
}

/*
  called when the recv of the proxied reply is done
 */
static void kdc_tcp_proxy_recv_done(struct tevent_req *req)
{
	struct kdc_tcp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_tcp_proxy_state);
	NTSTATUS status;

	status = tstream_read_pdu_blob_recv(req,
					    state,
					    &state->call->out);
	talloc_free(req);

	if (!NT_STATUS_IS_OK(status)) {
		kdc_tcp_next_proxy(state);
		return;
	}


	/* send the reply to the original caller */

	state->call->out_iov[0].iov_base = (char *)state->call->out.data;
	state->call->out_iov[0].iov_len = state->call->out.length;

	req = tstream_writev_queue_send(state,
					state->kdc_conn->conn->event.ctx,
					state->kdc_conn->tstream,
					state->kdc_conn->send_queue,
					state->call->out_iov, 1);
	if (req == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_tcp_proxy_reply_done, state);
}

/*
  called when the send of the proxied packet is done
 */
static void kdc_tcp_proxy_send_done(struct tevent_req *req)
{
	struct kdc_tcp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_tcp_proxy_state);
	int ret, sys_errno;

	ret = tstream_writev_queue_recv(req, &sys_errno);
	talloc_free(req);
	if (ret == -1) {
		kdc_tcp_next_proxy(state);
	}
}

/*
  called when we've connected to the proxy
 */
static void kdc_tcp_proxy_connect_done(struct tevent_req *req)
{
	struct kdc_tcp_proxy_state *state = tevent_req_callback_data(req,
								     struct kdc_tcp_proxy_state);
	int ret, sys_errno;
	struct tstream_context *stream;
	struct tevent_queue *send_queue;


	ret = tstream_inet_tcp_connect_recv(req, &sys_errno, state, &stream, NULL);
	talloc_free(req);

	if (ret != 0) {
		kdc_tcp_next_proxy(state);
		return;
	}

	RSIVAL(state->call->out_hdr, 0, state->call->in.length);
	state->call->out_iov[0].iov_base = (char *)state->call->out_hdr;
	state->call->out_iov[0].iov_len = 4;
	state->call->out_iov[1].iov_base = (char *) state->call->in.data;
	state->call->out_iov[1].iov_len = state->call->in.length;

	send_queue = tevent_queue_create(state, "kdc_tcp_proxy");
	if (send_queue == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}

	req = tstream_writev_queue_send(state,
					state->kdc_conn->conn->event.ctx,
					stream,
					send_queue,
					state->call->out_iov, 2);
	if (req == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_tcp_proxy_send_done, state);

	req = tstream_read_pdu_blob_send(state,
					 state->kdc_conn->conn->event.ctx,
					 stream,
					 4, /* initial_read_size */
					 packet_full_request_u32,
					 state);
	if (req == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_tcp_proxy_recv_done, state);
	tevent_req_set_endtime(req, state->kdc->task->event_ctx,
			       timeval_current_ofs(state->kdc->proxy_timeout, 0));

}


/*
  called when name resolution for a proxy is done
 */
static void kdc_tcp_proxy_resolve_done(struct composite_context *c)
{
	struct kdc_tcp_proxy_state *state;
	NTSTATUS status;
	struct tevent_req *req;
	struct tsocket_address *local_addr, *proxy_addr;
	int ret;

	state = talloc_get_type(c->async.private_data, struct kdc_tcp_proxy_state);

	status = resolve_name_recv(c, state, &state->proxy_ip);
	if (!NT_STATUS_IS_OK(status)) {
		kdc_tcp_next_proxy(state);
		return;
	}

	/* get an address for us to use locally */
	ret = tsocket_address_inet_from_strings(state, "ip", NULL, 0, &local_addr);
	if (ret != 0) {
		kdc_tcp_next_proxy(state);
		return;
	}

	ret = tsocket_address_inet_from_strings(state, "ip",
						state->proxy_ip, state->port, &proxy_addr);
	if (ret != 0) {
		kdc_tcp_next_proxy(state);
		return;
	}

	/* connect to the proxy */
	req = tstream_inet_tcp_connect_send(state, state->kdc->task->event_ctx, local_addr, proxy_addr);
	if (req == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}

	tevent_req_set_callback(req, kdc_tcp_proxy_connect_done, state);

	tevent_req_set_endtime(req, state->kdc->task->event_ctx,
			       timeval_current_ofs(state->kdc->proxy_timeout, 0));

	DEBUG(4,("kdc_tcp_proxy: proxying request to %s\n", state->proxy_ip));
}


/*
  called when our proxies are not available
 */
static void kdc_tcp_proxy_unavailable(struct kdc_tcp_proxy_state *state)
{
	int kret;
	krb5_data k5_error_blob;
	struct tevent_req *req;

	kret = krb5_mk_error(state->kdc->smb_krb5_context->krb5_context,
			     KRB5KDC_ERR_SVC_UNAVAILABLE, NULL, NULL,
			     NULL, NULL, NULL, NULL, &k5_error_blob);
	if (kret != 0) {
		DEBUG(2,(__location__ ": Unable to form krb5 error reply\n"));
		talloc_free(state);
		return;
	}


	state->call->out = data_blob_talloc(state, k5_error_blob.data, k5_error_blob.length);
	krb5_data_free(&k5_error_blob);
	if (!state->call->out.data) {
		talloc_free(state);
		return;
	}

	state->call->out_iov[0].iov_base = (char *)state->call->out.data;
	state->call->out_iov[0].iov_len = state->call->out.length;

	req = tstream_writev_queue_send(state,
					state->kdc_conn->conn->event.ctx,
					state->kdc_conn->tstream,
					state->kdc_conn->send_queue,
					state->call->out_iov, 1);
	if (!req) {
		talloc_free(state);
		return;
	}

	tevent_req_set_callback(req, kdc_tcp_proxy_reply_done, state);
}

/*
  try the next proxy in the list
 */
static void kdc_tcp_next_proxy(struct kdc_tcp_proxy_state *state)
{
	const char *proxy_dnsname = state->proxy_list[state->next_proxy];
	struct nbt_name name;
	struct composite_context *c;

	if (proxy_dnsname == NULL) {
		kdc_tcp_proxy_unavailable(state);
		return;
	}

	state->next_proxy++;

	make_nbt_name(&name, proxy_dnsname, 0);

	c = resolve_name_ex_send(lpcfg_resolve_context(state->kdc->task->lp_ctx),
				 state,
				 RESOLVE_NAME_FLAG_FORCE_DNS,
				 0,
				 &name,
				 state->kdc->task->event_ctx);
	if (c == NULL) {
		kdc_tcp_next_proxy(state);
		return;
	}
	c->async.fn = kdc_tcp_proxy_resolve_done;
	c->async.private_data = state;
}


/*
  proxy a TCP kdc request to a writeable DC
 */
void kdc_tcp_proxy(struct kdc_server *kdc, struct kdc_tcp_connection *kdc_conn,
		   struct kdc_tcp_call *call, uint16_t port)
{
	struct kdc_tcp_proxy_state *state;
	WERROR werr;

	state = talloc_zero(kdc_conn, struct kdc_tcp_proxy_state);

	state->call = talloc_steal(state, call);
	state->kdc_conn = kdc_conn;
	state->kdc  = kdc;
	state->port = port;

	werr = kdc_proxy_get_writeable_dcs(kdc, state, &state->proxy_list);
	if (!W_ERROR_IS_OK(werr)) {
		kdc_tcp_proxy_unavailable(state);
		return;
	}

	kdc_tcp_next_proxy(state);
}
