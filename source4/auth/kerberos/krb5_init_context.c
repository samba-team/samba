/*
   Unix SMB/CIFS implementation.
   Wrapper for krb5_init_context

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2004

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
#include "system/kerberos.h"
#include <tevent.h>
#include "auth/kerberos/kerberos.h"
#include "lib/socket/socket.h"
#include "lib/stream/packet.h"
#include "system/network.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"
#include "../lib/tsocket/tsocket.h"
#include "krb5_init_context.h"
#ifdef SAMBA4_USES_HEIMDAL
#include "../lib/dbwrap/dbwrap.h"
#include "../lib/dbwrap/dbwrap_rbt.h"
#include "../lib/util/util_tdb.h"
#include <krb5/send_to_kdc_plugin.h>
#endif
#ifdef USING_EMBEDDED_HEIMDAL
#include <krb5_locl.h>
#endif

/*
  context structure for operations on cldap packets
*/
struct smb_krb5_socket {
	struct socket_context *sock;

	/* the fd event */
	struct tevent_fd *fde;

	NTSTATUS status;
	DATA_BLOB request, reply;

	struct packet_context *packet;

	size_t partial_read;
#ifdef SAMBA4_USES_HEIMDAL
	krb5_krbhst_info *hi;
#endif
};

static krb5_error_code smb_krb5_context_destroy(struct smb_krb5_context *ctx)
{
#ifdef SAMBA4_USES_HEIMDAL
	if (ctx->pvt_log_data) {
		/* Otherwise krb5_free_context will try and close what we
		 * have already free()ed */
		krb5_set_warn_dest(ctx->krb5_context, NULL);
		krb5_closelog(ctx->krb5_context,
				(krb5_log_facility *)ctx->pvt_log_data);
	}
#endif
	krb5_free_context(ctx->krb5_context);
	return 0;
}

#ifdef SAMBA4_USES_HEIMDAL
/* We never close down the DEBUG system, and no need to unreference the use */
static void smb_krb5_debug_close(void *private_data) {
	return;
}
#endif

#ifdef SAMBA4_USES_HEIMDAL
static void smb_krb5_debug_wrapper(
#ifdef HAVE_KRB5_ADDLOG_FUNC_NEED_CONTEXT
		krb5_context ctx,
#endif /* HAVE_KRB5_ADDLOG_FUNC_NEED_CONTEXT */
		const char *timestr, const char *msg, void *private_data)
{
	DEBUGC(DBGC_KERBEROS, 3, ("Kerberos: %s\n", msg));
}
#endif

#ifdef SAMBA4_USES_HEIMDAL
/*
  handle recv events on a smb_krb5 socket
*/
static void smb_krb5_socket_recv(struct smb_krb5_socket *smb_krb5)
{
	TALLOC_CTX *tmp_ctx = talloc_new(smb_krb5);
	DATA_BLOB blob;
	size_t nread, dsize;

	smb_krb5->status = socket_pending(smb_krb5->sock, &dsize);
	if (!NT_STATUS_IS_OK(smb_krb5->status)) {
		talloc_free(tmp_ctx);
		return;
	}

	blob = data_blob_talloc(tmp_ctx, NULL, dsize);
	if (blob.data == NULL && dsize != 0) {
		smb_krb5->status = NT_STATUS_NO_MEMORY;
		talloc_free(tmp_ctx);
		return;
	}

	smb_krb5->status = socket_recv(smb_krb5->sock, blob.data, blob.length, &nread);
	if (!NT_STATUS_IS_OK(smb_krb5->status)) {
		talloc_free(tmp_ctx);
		return;
	}
	blob.length = nread;

	if (nread == 0) {
		smb_krb5->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		talloc_free(tmp_ctx);
		return;
	}

	DEBUG(4,("Received smb_krb5 packet of length %d\n",
		 (int)blob.length));

	talloc_steal(smb_krb5, blob.data);
	smb_krb5->reply = blob;
	talloc_free(tmp_ctx);
}

static NTSTATUS smb_krb5_full_packet(void *private_data, DATA_BLOB data)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private_data, struct smb_krb5_socket);
	talloc_steal(smb_krb5, data.data);
	smb_krb5->reply = data;
	smb_krb5->reply.length -= 4;
	smb_krb5->reply.data += 4;
	return NT_STATUS_OK;
}

/*
  handle request timeouts
*/
static void smb_krb5_request_timeout(struct tevent_context *event_ctx,
				  struct tevent_timer *te, struct timeval t,
				  void *private_data)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private_data, struct smb_krb5_socket);
	DEBUG(5,("Timed out smb_krb5 packet\n"));
	smb_krb5->status = NT_STATUS_IO_TIMEOUT;
}

static void smb_krb5_error_handler(void *private_data, NTSTATUS status)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private_data, struct smb_krb5_socket);
	smb_krb5->status = status;
}

/*
  handle send events on a smb_krb5 socket
*/
static void smb_krb5_socket_send(struct smb_krb5_socket *smb_krb5)
{
	NTSTATUS status;

	size_t len;

	len = smb_krb5->request.length;
	status = socket_send(smb_krb5->sock, &smb_krb5->request, &len);

	if (!NT_STATUS_IS_OK(status)) return;

	TEVENT_FD_READABLE(smb_krb5->fde);

	TEVENT_FD_NOT_WRITEABLE(smb_krb5->fde);
	return;
}


/*
  handle fd events on a smb_krb5_socket
*/
static void smb_krb5_socket_handler(struct tevent_context *ev, struct tevent_fd *fde,
				 uint16_t flags, void *private_data)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private_data, struct smb_krb5_socket);
	switch (smb_krb5->hi->proto) {
	case KRB5_KRBHST_UDP:
		if (flags & TEVENT_FD_READ) {
			smb_krb5_socket_recv(smb_krb5);
			return;
		}
		if (flags & TEVENT_FD_WRITE) {
			smb_krb5_socket_send(smb_krb5);
			return;
		}
		/* not reached */
		return;
	case KRB5_KRBHST_TCP:
		if (flags & TEVENT_FD_READ) {
			packet_recv(smb_krb5->packet);
			return;
		}
		if (flags & TEVENT_FD_WRITE) {
			packet_queue_run(smb_krb5->packet);
			return;
		}
		/* not reached */
		return;
	case KRB5_KRBHST_HTTP:
		/* can't happen */
		break;
	}
}

static krb5_error_code smb_krb5_send_and_recv_func_int(struct smb_krb5_context *smb_krb5_context,
						       struct tevent_context *ev,
						       krb5_krbhst_info *hi,
						       struct addrinfo *ai,
						       smb_krb5_send_to_kdc_func func,
						       void *data,
						       time_t timeout,
						       const krb5_data *send_buf,
						       krb5_data *recv_buf)
{
	krb5_error_code ret;
	NTSTATUS status;
	const char *name;
	struct addrinfo *a;
	struct smb_krb5_socket *smb_krb5;

	DATA_BLOB send_blob;

	TALLOC_CTX *frame = talloc_stackframe();
	if (frame == NULL) {
		return ENOMEM;
	}

	send_blob = data_blob_const(send_buf->data, send_buf->length);

	for (a = ai; a; a = a->ai_next) {
		struct socket_address *remote_addr;
		smb_krb5 = talloc(frame, struct smb_krb5_socket);
		if (!smb_krb5) {
			TALLOC_FREE(frame);
			return ENOMEM;
		}
		smb_krb5->hi = hi;

		switch (a->ai_family) {
		case PF_INET:
			name = "ipv4";
			break;
#ifdef HAVE_IPV6
		case PF_INET6:
			name = "ipv6";
			break;
#endif
		default:
			TALLOC_FREE(frame);
			return EINVAL;
		}

		status = NT_STATUS_INVALID_PARAMETER;
		switch (hi->proto) {
		case KRB5_KRBHST_UDP:
			status = socket_create(smb_krb5, name,
					       SOCKET_TYPE_DGRAM,
					       &smb_krb5->sock, 0);
			break;
		case KRB5_KRBHST_TCP:
			status = socket_create(smb_krb5, name,
					       SOCKET_TYPE_STREAM,
					       &smb_krb5->sock, 0);
			break;
		case KRB5_KRBHST_HTTP:
			TALLOC_FREE(frame);
			return EINVAL;
		}
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(smb_krb5);
			continue;
		}

		remote_addr = socket_address_from_sockaddr(smb_krb5, a->ai_addr, a->ai_addrlen);
		if (!remote_addr) {
			talloc_free(smb_krb5);
			continue;
		}

		status = socket_connect_ev(smb_krb5->sock, NULL, remote_addr, 0, ev);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(smb_krb5);
			continue;
		}

		/* Setup the FDE, start listening for read events
		 * from the start (otherwise we may miss a socket
		 * drop) and mark as AUTOCLOSE along with the fde */

		/* This is equivalent to EVENT_FD_READABLE(smb_krb5->fde) */
		smb_krb5->fde = tevent_add_fd(ev, smb_krb5->sock,
					      socket_get_fd(smb_krb5->sock),
					      TEVENT_FD_READ,
					      smb_krb5_socket_handler, smb_krb5);
		/* its now the job of the event layer to close the socket */
		tevent_fd_set_close_fn(smb_krb5->fde, socket_tevent_fd_close_fn);
		socket_set_flags(smb_krb5->sock, SOCKET_FLAG_NOCLOSE);

		tevent_add_timer(ev, smb_krb5,
				 timeval_current_ofs(timeout, 0),
				 smb_krb5_request_timeout, smb_krb5);

		smb_krb5->status = NT_STATUS_OK;
		smb_krb5->reply = data_blob(NULL, 0);

		switch (hi->proto) {
		case KRB5_KRBHST_UDP:
			TEVENT_FD_WRITEABLE(smb_krb5->fde);
			smb_krb5->request = send_blob;
			break;
		case KRB5_KRBHST_TCP:

			smb_krb5->packet = packet_init(smb_krb5);
			if (smb_krb5->packet == NULL) {
				talloc_free(smb_krb5);
				return ENOMEM;
			}
			packet_set_private(smb_krb5->packet, smb_krb5);
			packet_set_socket(smb_krb5->packet, smb_krb5->sock);
			packet_set_callback(smb_krb5->packet, smb_krb5_full_packet);
			packet_set_full_request(smb_krb5->packet, packet_full_request_u32);
			packet_set_error_handler(smb_krb5->packet, smb_krb5_error_handler);
			packet_set_event_context(smb_krb5->packet, ev);
			packet_set_fde(smb_krb5->packet, smb_krb5->fde);

			smb_krb5->request = data_blob_talloc(smb_krb5, NULL, send_blob.length + 4);
			RSIVAL(smb_krb5->request.data, 0, send_blob.length);
			memcpy(smb_krb5->request.data+4, send_blob.data, send_blob.length);
			packet_send(smb_krb5->packet, smb_krb5->request);
			break;
		case KRB5_KRBHST_HTTP:
			TALLOC_FREE(frame);
			return EINVAL;
		}
		while ((NT_STATUS_IS_OK(smb_krb5->status)) && !smb_krb5->reply.length) {
			if (tevent_loop_once(ev) != 0) {
				TALLOC_FREE(frame);
				return EINVAL;
			}

                        if (func) {
				/* After each and every event loop, reset the
				 * send_to_kdc pointers to what they were when
				 * we entered this loop.  That way, if a
				 * nested event has invalidated them, we put
				 * it back before we return to the heimdal
				 * code */
				ret = smb_krb5_set_send_to_kdc_func(smb_krb5_context,
								    NULL, /* send_to_realm */
								    func,
								    data);
				if (ret != 0) {
					TALLOC_FREE(frame);
					return ret;
				}
			}
		}
		if (NT_STATUS_EQUAL(smb_krb5->status, NT_STATUS_IO_TIMEOUT)) {
			talloc_free(smb_krb5);
			continue;
		}

		if (!NT_STATUS_IS_OK(smb_krb5->status)) {
			struct tsocket_address *addr = socket_address_to_tsocket_address(smb_krb5, remote_addr);
			const char *addr_string = NULL;
			if (addr) {
				addr_string = tsocket_address_inet_addr_string(addr, smb_krb5);
			} else {
				addr_string = NULL;
			}
			DEBUG(2,("Error reading smb_krb5 reply packet: %s from %s\n", nt_errstr(smb_krb5->status),
				 addr_string));
			talloc_free(smb_krb5);
			continue;
		}

		ret = krb5_data_copy(recv_buf, smb_krb5->reply.data, smb_krb5->reply.length);
		if (ret) {
			TALLOC_FREE(frame);
			return ret;
		}
		talloc_free(smb_krb5);

		break;
	}
	TALLOC_FREE(frame);
	if (a) {
		return 0;
	}
	return KRB5_KDC_UNREACH;
}

krb5_error_code smb_krb5_send_and_recv_func(struct smb_krb5_context *smb_krb5_context,
					    void *data,
					    krb5_krbhst_info *hi,
					    time_t timeout,
					    const krb5_data *send_buf,
					    krb5_data *recv_buf)
{
	krb5_error_code ret;
	struct addrinfo *ai;

	struct tevent_context *ev;
	TALLOC_CTX *frame = talloc_stackframe();
	if (frame == NULL) {
		return ENOMEM;
	}

	if (data == NULL) {
		/* If no event context was available, then create one for this loop */
		ev = samba_tevent_context_init(frame);
		if (ev == NULL) {
			TALLOC_FREE(frame);
			return ENOMEM;
		}
	} else {
		ev = talloc_get_type_abort(data, struct tevent_context);
	}

	ret = krb5_krbhst_get_addrinfo(smb_krb5_context->krb5_context, hi, &ai);
	if (ret) {
		TALLOC_FREE(frame);
		return ret;
	}

	ret = smb_krb5_send_and_recv_func_int(smb_krb5_context,
					      ev, hi, ai,
					      smb_krb5_send_and_recv_func,
					      data, timeout, send_buf, recv_buf);
	TALLOC_FREE(frame);
	return ret;
}

krb5_error_code smb_krb5_send_and_recv_func_forced_tcp(struct smb_krb5_context *smb_krb5_context,
						       struct addrinfo *ai,
						       time_t timeout,
						       const krb5_data *send_buf,
						       krb5_data *recv_buf)
{
	krb5_error_code k5ret;
	krb5_krbhst_info hi = {
		.proto = KRB5_KRBHST_TCP,
	};
	struct tevent_context *ev;
	TALLOC_CTX *frame = talloc_stackframe();
	if (frame == NULL) {
		return ENOMEM;
	}

	/* no event context is passed in, create one for this loop */
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		TALLOC_FREE(frame);
		return ENOMEM;
	}

	/* No need to pass in send_and_recv functions, we won't nest on this private event loop */
	k5ret = smb_krb5_send_and_recv_func_int(smb_krb5_context, ev, &hi, ai, NULL, NULL,
						timeout, send_buf, recv_buf);
	TALLOC_FREE(frame);
	return k5ret;
}

static struct db_context *smb_krb5_plugin_db;

struct smb_krb5_send_to_kdc_state {
	intptr_t key_ptr;
	struct smb_krb5_context *smb_krb5_context;
	smb_krb5_send_to_realm_func send_to_realm;
	smb_krb5_send_to_kdc_func send_to_kdc;
	void *private_data;
};

static int smb_krb5_send_to_kdc_state_destructor(struct smb_krb5_send_to_kdc_state *state)
{
	TDB_DATA key = make_tdb_data((uint8_t *)&state->key_ptr, sizeof(state->key_ptr));
	NTSTATUS status;

	status = dbwrap_delete(smb_krb5_plugin_db, key);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}

	state->smb_krb5_context = NULL;
	return 0;
}

krb5_error_code smb_krb5_set_send_to_kdc_func(struct smb_krb5_context *smb_krb5_context,
					      smb_krb5_send_to_realm_func send_to_realm,
					      smb_krb5_send_to_kdc_func send_to_kdc,
					      void *private_data)
{
	intptr_t key_ptr = (intptr_t)smb_krb5_context->krb5_context;
	TDB_DATA key = make_tdb_data((uint8_t *)&key_ptr, sizeof(key_ptr));
	intptr_t value_ptr = (intptr_t)NULL;
	TDB_DATA value = make_tdb_data(NULL, 0);
	struct db_record *rec = NULL;
	struct smb_krb5_send_to_kdc_state *state = NULL;
	NTSTATUS status;

	rec = dbwrap_fetch_locked(smb_krb5_plugin_db, smb_krb5_context, key);
	if (rec == NULL) {
		return ENOMEM;
	}

	value = dbwrap_record_get_value(rec);
	if (value.dsize != 0) {
		SMB_ASSERT(value.dsize == sizeof(value_ptr));
		memcpy(&value_ptr, value.dptr, sizeof(value_ptr));
		state = talloc_get_type_abort((const void *)value_ptr,
					      struct smb_krb5_send_to_kdc_state);
		if (send_to_realm == NULL && send_to_kdc == NULL) {
			status = dbwrap_record_delete(rec);
			TALLOC_FREE(rec);
			if (!NT_STATUS_IS_OK(status)) {
				return EINVAL;
			}
			return 0;
		}
		state->send_to_realm = send_to_realm;
		state->send_to_kdc = send_to_kdc;
		state->private_data = private_data;
		TALLOC_FREE(rec);
		return 0;
	}

	if (send_to_kdc == NULL && send_to_realm == NULL) {
		TALLOC_FREE(rec);
		return 0;
	}

	state = talloc_zero(smb_krb5_context,
			    struct smb_krb5_send_to_kdc_state);
	if (state == NULL) {
		TALLOC_FREE(rec);
		return ENOMEM;
	}
	state->key_ptr = key_ptr;
	state->smb_krb5_context = smb_krb5_context;
	state->send_to_realm = send_to_realm;
	state->send_to_kdc = send_to_kdc;
	state->private_data = private_data;

	value_ptr = (intptr_t)state;
	value = make_tdb_data((uint8_t *)&value_ptr, sizeof(value_ptr));

	status = dbwrap_record_store(rec, value, TDB_INSERT);
	TALLOC_FREE(rec);
	if (!NT_STATUS_IS_OK(status)) {
		return EINVAL;
	}
	talloc_set_destructor(state, smb_krb5_send_to_kdc_state_destructor);

	return 0;
}

static krb5_error_code smb_krb5_plugin_init(krb5_context context, void **pctx)
{
	*pctx = NULL;
	return 0;
}

static void smb_krb5_plugin_fini(void *ctx)
{
}

static void smb_krb5_send_to_kdc_state_parser(TDB_DATA key, TDB_DATA value,
					      void *private_data)
{
	struct smb_krb5_send_to_kdc_state **state =
		(struct smb_krb5_send_to_kdc_state **)private_data;
	intptr_t value_ptr;

	SMB_ASSERT(value.dsize == sizeof(value_ptr));
	memcpy(&value_ptr, value.dptr, sizeof(value_ptr));
	*state = talloc_get_type_abort((const void *)value_ptr,
				       struct smb_krb5_send_to_kdc_state);
}

static struct smb_krb5_send_to_kdc_state *
smb_krb5_send_to_kdc_get_state(krb5_context context)
{
	intptr_t key_ptr = (intptr_t)context;
	TDB_DATA key = make_tdb_data((uint8_t *)&key_ptr, sizeof(key_ptr));
	struct smb_krb5_send_to_kdc_state *state = NULL;
	NTSTATUS status;

	status = dbwrap_parse_record(smb_krb5_plugin_db, key,
				     smb_krb5_send_to_kdc_state_parser,
				     &state);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	return state;
}

static krb5_error_code smb_krb5_plugin_send_to_kdc(krb5_context context,
						   void *ctx,
						   krb5_krbhst_info *ho,
						   time_t timeout,
						   const krb5_data *in,
						   krb5_data *out)
{
	struct smb_krb5_send_to_kdc_state *state = NULL;

	state = smb_krb5_send_to_kdc_get_state(context);
	if (state == NULL) {
		return KRB5_PLUGIN_NO_HANDLE;
	}

	if (state->send_to_kdc == NULL) {
		return KRB5_PLUGIN_NO_HANDLE;
	}

	return state->send_to_kdc(state->smb_krb5_context,
				  state->private_data,
				  ho, timeout, in, out);
}

static krb5_error_code smb_krb5_plugin_send_to_realm(krb5_context context,
						     void *ctx,
						     krb5_const_realm realm,
						     time_t timeout,
						     const krb5_data *in,
						     krb5_data *out)
{
	struct smb_krb5_send_to_kdc_state *state = NULL;

	state = smb_krb5_send_to_kdc_get_state(context);
	if (state == NULL) {
		return KRB5_PLUGIN_NO_HANDLE;
	}

	if (state->send_to_realm == NULL) {
		return KRB5_PLUGIN_NO_HANDLE;
	}

	return state->send_to_realm(state->smb_krb5_context,
				    state->private_data,
				    realm, timeout, in, out);
}

static krb5plugin_send_to_kdc_ftable smb_krb5_plugin_ftable = {
	KRB5_PLUGIN_SEND_TO_KDC_VERSION_2,
	smb_krb5_plugin_init,
	smb_krb5_plugin_fini,
	smb_krb5_plugin_send_to_kdc,
	smb_krb5_plugin_send_to_realm
};
#endif

krb5_error_code
smb_krb5_init_context_basic(TALLOC_CTX *tmp_ctx,
			    struct loadparm_context *lp_ctx,
			    krb5_context *_krb5_context)
{
	krb5_error_code ret;
#ifdef SAMBA4_USES_HEIMDAL
	char **config_files;
	const char *config_file, *realm;
#endif
	krb5_context krb5_ctx;

	ret = smb_krb5_init_context_common(&krb5_ctx);
	if (ret) {
		return ret;
	}

	/* The MIT Kerberos build relies on using the system krb5.conf file.
	 * If you really want to use another file please set KRB5_CONFIG
	 * accordingly. */
#ifdef SAMBA4_USES_HEIMDAL
	config_file = lpcfg_config_path(tmp_ctx, lp_ctx, "krb5.conf");
	if (!config_file) {
		krb5_free_context(krb5_ctx);
		return ENOMEM;
	}

	/* Use our local krb5.conf file by default */
	ret = krb5_prepend_config_files_default(config_file, &config_files);
	if (ret) {
		DEBUG(1,("krb5_prepend_config_files_default failed (%s)\n",
			 smb_get_krb5_error_message(krb5_ctx, ret, tmp_ctx)));
		krb5_free_context(krb5_ctx);
		return ret;
	}

	ret = krb5_set_config_files(krb5_ctx, config_files);
	krb5_free_config_files(config_files);
	if (ret) {
		DEBUG(1,("krb5_set_config_files failed (%s)\n",
			 smb_get_krb5_error_message(krb5_ctx, ret, tmp_ctx)));
		krb5_free_context(krb5_ctx);
		return ret;
	}

	/*
	 * This is already called in smb_krb5_init_context_common(),
	 * but krb5_set_config_files() may resets it.
	 */
	krb5_set_dns_canonicalize_hostname(krb5_ctx, false);

	realm = lpcfg_realm(lp_ctx);
	if (realm != NULL) {
		ret = krb5_set_default_realm(krb5_ctx, realm);
		if (ret) {
			DEBUG(1,("krb5_set_default_realm failed (%s)\n",
				 smb_get_krb5_error_message(krb5_ctx, ret, tmp_ctx)));
			krb5_free_context(krb5_ctx);
			return ret;
		}
	}

	if (smb_krb5_plugin_db == NULL) {
		/*
		 * while krb5_plugin_register() takes a krb5_context,
		 * plugins are registered into a global list, so
		 * we only do that once
		 *
		 * We maintain a separate dispatch table for per
		 * krb5_context state.
		 */
		ret = krb5_plugin_register(krb5_ctx, PLUGIN_TYPE_DATA,
				     KRB5_PLUGIN_SEND_TO_KDC,
				     &smb_krb5_plugin_ftable);
		if (ret) {
			DEBUG(1,("krb5_plugin_register(KRB5_PLUGIN_SEND_TO_KDC) failed (%s)\n",
				 smb_get_krb5_error_message(krb5_ctx, ret, tmp_ctx)));
			krb5_free_context(krb5_ctx);
			return ret;
		}
		smb_krb5_plugin_db = db_open_rbt(NULL);
		if (smb_krb5_plugin_db == NULL) {
			DEBUG(1,("db_open_rbt() failed\n"));
			krb5_free_context(krb5_ctx);
			return ENOMEM;
		}
	}
#endif
	*_krb5_context = krb5_ctx;
	return 0;
}

krb5_error_code smb_krb5_init_context(void *parent_ctx,
				      struct loadparm_context *lp_ctx,
				      struct smb_krb5_context **smb_krb5_context)
{
	krb5_error_code ret;
	TALLOC_CTX *tmp_ctx;
	krb5_context kctx;
#ifdef SAMBA4_USES_HEIMDAL
	krb5_log_facility *logf;
#endif

	tmp_ctx = talloc_new(parent_ctx);
	*smb_krb5_context = talloc_zero(tmp_ctx, struct smb_krb5_context);

	if (!*smb_krb5_context || !tmp_ctx) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	ret = smb_krb5_init_context_basic(tmp_ctx, lp_ctx, &kctx);
	if (ret) {
		DEBUG(1,("smb_krb5_context_init_basic failed (%s)\n",
			 error_message(ret)));
		talloc_free(tmp_ctx);
		return ret;
	}
	(*smb_krb5_context)->krb5_context = kctx;

	talloc_set_destructor(*smb_krb5_context, smb_krb5_context_destroy);

#ifdef SAMBA4_USES_HEIMDAL
	/* TODO: Should we have a different name here? */
	ret = krb5_initlog(kctx, "Samba", &logf);

	if (ret) {
		DEBUG(1,("krb5_initlog failed (%s)\n",
			 smb_get_krb5_error_message(kctx, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
	(*smb_krb5_context)->pvt_log_data = logf;

	ret = krb5_addlog_func(kctx, logf, 0 /* min */, -1 /* max */,
			       smb_krb5_debug_wrapper,
				smb_krb5_debug_close, NULL);
	if (ret) {
		DEBUG(1,("krb5_addlog_func failed (%s)\n",
			 smb_get_krb5_error_message(kctx, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
	krb5_set_warn_dest(kctx, logf);
#endif
#ifdef USING_EMBEDDED_HEIMDAL
	/*
	 * The KRB5_CTX_F_ALWAYS_INCLUDE_PAC flag is a Samba extension to
	 * Heimdal and is only available in the embedded heimdal
	 */
	if (lpcfg_kdc_always_include_pac(lp_ctx)) {
		kctx->flags |= KRB5_CTX_F_ALWAYS_INCLUDE_PAC;
	}
#endif

	talloc_steal(parent_ctx, *smb_krb5_context);
	talloc_free(tmp_ctx);

	return 0;
}

#ifdef SAMBA4_USES_HEIMDAL
krb5_error_code smb_krb5_context_set_event_ctx(struct smb_krb5_context *smb_krb5_context,
					       struct tevent_context *ev,
					       struct tevent_context **previous_ev)
{
	int ret;
	if (!ev) {
		return EINVAL;
	}

	*previous_ev = smb_krb5_context->current_ev;

	smb_krb5_context->current_ev = talloc_reference(smb_krb5_context, ev);
	if (!smb_krb5_context->current_ev) {
		return ENOMEM;
	}

	/* Set use of our socket lib */
	ret = smb_krb5_set_send_to_kdc_func(smb_krb5_context,
					    NULL, /* send_to_realm */
					    smb_krb5_send_and_recv_func,
					    ev);
	if (ret) {
		TALLOC_CTX *tmp_ctx = talloc_new(NULL);
		DEBUG(1,("smb_krb5_set_send_recv_func failed (%s)\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		talloc_unlink(smb_krb5_context, smb_krb5_context->current_ev);
		smb_krb5_context->current_ev = NULL;
		return ret;
	}
	return 0;
}

krb5_error_code smb_krb5_context_remove_event_ctx(struct smb_krb5_context *smb_krb5_context,
						  struct tevent_context *previous_ev,
						  struct tevent_context *ev)
{
	int ret;
	talloc_unlink(smb_krb5_context, ev);
	/* If there was a mismatch with things happening on a stack, then don't wipe things */
	smb_krb5_context->current_ev = previous_ev;
	/* Set use of our socket lib */
	ret = smb_krb5_set_send_to_kdc_func(smb_krb5_context,
					    NULL, /* send_to_realm */
					    smb_krb5_send_and_recv_func,
					    previous_ev);
	if (ret) {
		TALLOC_CTX *tmp_ctx = talloc_new(NULL);
		DEBUG(1,("smb_krb5_set_send_recv_func failed (%s)\n",
			 smb_get_krb5_error_message(smb_krb5_context->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
	return 0;
}
#endif
