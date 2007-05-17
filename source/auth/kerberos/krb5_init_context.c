/* 
   Unix SMB/CIFS implementation.
   Wrapper for krb5_init_context

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/kerberos.h"
#include "heimdal/lib/krb5/krb5_locl.h"
#include "auth/kerberos/kerberos.h"
#include "lib/socket/socket.h"
#include "system/network.h"
#include "lib/events/events.h"
#include "roken.h"

/*
  context structure for operations on cldap packets
*/
struct smb_krb5_socket {
	struct socket_context *sock;

	/* the fd event */
	struct fd_event *fde;

	BOOL timeout;
	NTSTATUS status;
	DATA_BLOB request, reply, partial;

	size_t partial_read;

	krb5_krbhst_info *hi;
};

static int smb_krb5_context_destroy_1(struct smb_krb5_context *ctx)
{
	krb5_free_context(ctx->krb5_context); 
	return 0;
}

static int smb_krb5_context_destroy_2(struct smb_krb5_context *ctx)
{
	/* Otherwise krb5_free_context will try and close what we have already free()ed */
	krb5_set_warn_dest(ctx->krb5_context, NULL);
	krb5_closelog(ctx->krb5_context, ctx->logf);
	smb_krb5_context_destroy_1(ctx);
	return 0;
}

/* We never close down the DEBUG system, and no need to unreference the use */
static void smb_krb5_debug_close(void *private) {
	return;
}

static void smb_krb5_debug_wrapper(const char *timestr, const char *msg, void *private) 
{
	DEBUG(2, ("Kerberos: %s\n", msg));
}

/*
  handle recv events on a smb_krb5 socket
*/
static void smb_krb5_socket_recv(struct smb_krb5_socket *smb_krb5)
{
	TALLOC_CTX *tmp_ctx = talloc_new(smb_krb5);
	DATA_BLOB blob;
	size_t nread, dsize;

	switch (smb_krb5->hi->proto) {
	case KRB5_KRBHST_UDP:
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
		
		DEBUG(2,("Received smb_krb5 packet of length %d\n", 
			 (int)blob.length));
		
		talloc_steal(smb_krb5, blob.data);
		smb_krb5->reply = blob;
		talloc_free(tmp_ctx);
		break;
	case KRB5_KRBHST_TCP:
		if (smb_krb5->partial.length == 0) {
			smb_krb5->partial = data_blob_talloc(smb_krb5, NULL, 4);
			if (!smb_krb5->partial.data) {
				smb_krb5->status = NT_STATUS_NO_MEMORY;
				return;
			}
			
			smb_krb5->partial_read = 0;
		}
		
		/* read in the packet length */
		if (smb_krb5->partial_read < 4) {
			uint32_t packet_length;
			
			smb_krb5->status = socket_recv(smb_krb5->sock, 
					     smb_krb5->partial.data + smb_krb5->partial_read,
					     4 - smb_krb5->partial_read,
					     &nread);
			/* todo: this should be converted to the packet_*() routines */
			if (!NT_STATUS_IS_OK(smb_krb5->status)) {
				return;
			}
			
			smb_krb5->partial_read += nread;
			if (smb_krb5->partial_read != 4) {
				return;
			}
			
			packet_length = RIVAL(smb_krb5->partial.data, 0);
			
			smb_krb5->partial.data = talloc_realloc(smb_krb5, smb_krb5->partial.data, 
								uint8_t, packet_length + 4);
			if (!smb_krb5->partial.data)  {
				smb_krb5->status = NT_STATUS_NO_MEMORY;
				return;
			}
			
			smb_krb5->partial.length = packet_length + 4;
		}
		
		/* read in the body */
		smb_krb5->status = socket_recv(smb_krb5->sock, 
				     smb_krb5->partial.data + smb_krb5->partial_read,
				     smb_krb5->partial.length - smb_krb5->partial_read,
				     &nread);
		if (!NT_STATUS_IS_OK(smb_krb5->status)) return;
		
		smb_krb5->partial_read += nread;

		if (smb_krb5->partial_read != smb_krb5->partial.length) return;

		smb_krb5->reply = data_blob_talloc(smb_krb5, smb_krb5->partial.data + 4, smb_krb5->partial.length - 4);
		break;
	case KRB5_KRBHST_HTTP:
		return;
	}
}

/*
  handle request timeouts
*/
static void smb_krb5_request_timeout(struct event_context *event_ctx, 
				  struct timed_event *te, struct timeval t,
				  void *private)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private, struct smb_krb5_socket);
	DEBUG(5,("Timed out smb_krb5 packet\n"));
	smb_krb5->timeout = True;
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
	
	EVENT_FD_READABLE(smb_krb5->fde);

	EVENT_FD_NOT_WRITEABLE(smb_krb5->fde);
	return;
}


/*
  handle fd events on a smb_krb5_socket
*/
static void smb_krb5_socket_handler(struct event_context *ev, struct fd_event *fde,
				 uint16_t flags, void *private)
{
	struct smb_krb5_socket *smb_krb5 = talloc_get_type(private, struct smb_krb5_socket);
	if (flags & EVENT_FD_WRITE) {
		smb_krb5_socket_send(smb_krb5);
	} 
	if (flags & EVENT_FD_READ) {
		smb_krb5_socket_recv(smb_krb5);
	}
}


krb5_error_code smb_krb5_send_and_recv_func(krb5_context context,
					    void *data,
					    krb5_krbhst_info *hi,
					    const krb5_data *send_buf,
					    krb5_data *recv_buf)
{
	krb5_error_code ret;
	NTSTATUS status;
	struct socket_address *remote_addr;
	const char *name;
	struct addrinfo *ai, *a;
	struct smb_krb5_socket *smb_krb5;

	struct event_context *ev = talloc_get_type(data, struct event_context);

	DATA_BLOB send_blob = data_blob_const(send_buf->data, send_buf->length);

	ret = krb5_krbhst_get_addrinfo(context, hi, &ai);
	if (ret) {
		return ret;
	}

	for (a = ai; a; a = ai->ai_next) {
		smb_krb5 = talloc(NULL, struct smb_krb5_socket);
		if (!smb_krb5) {
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
			talloc_free(smb_krb5);
			return EINVAL;
		}
		
		status = NT_STATUS_INVALID_PARAMETER;
		switch (hi->proto) {
		case KRB5_KRBHST_UDP:
			if (lp_parm_bool(-1, "krb5", "udp", True)) {
				status = socket_create(name, SOCKET_TYPE_DGRAM, &smb_krb5->sock, 0);
			}
			break;
		case KRB5_KRBHST_TCP:
			if (lp_parm_bool(-1, "krb5", "tcp", True)) {
				status = socket_create(name, SOCKET_TYPE_STREAM, &smb_krb5->sock, 0);
			}
			break;
		case KRB5_KRBHST_HTTP:
			talloc_free(smb_krb5);
			return EINVAL;
		}
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(smb_krb5);
			continue;
		}

		talloc_steal(smb_krb5, smb_krb5->sock);
		
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
		talloc_free(remote_addr);

		smb_krb5->fde = event_add_fd(ev, smb_krb5, 
					     socket_get_fd(smb_krb5->sock), 
					     EVENT_FD_AUTOCLOSE,
					     smb_krb5_socket_handler, smb_krb5);
		/* its now the job of the event layer to close the socket */
		socket_set_flags(smb_krb5->sock, SOCKET_FLAG_NOCLOSE);

		event_add_timed(ev, smb_krb5, 
				timeval_current_ofs(context->kdc_timeout, 0),
				smb_krb5_request_timeout, smb_krb5);

		EVENT_FD_WRITEABLE(smb_krb5->fde);
		
		switch (hi->proto) {
		case KRB5_KRBHST_UDP:
			smb_krb5->request = send_blob;
			break;
		case KRB5_KRBHST_TCP:
			smb_krb5->request = data_blob_talloc(smb_krb5, NULL, send_blob.length + 4);
			RSIVAL(smb_krb5->request.data, 0, send_blob.length);
			memcpy(smb_krb5->request.data+4, send_blob.data, send_blob.length);
			break;
		case KRB5_KRBHST_HTTP:
			talloc_free(smb_krb5);
			return EINVAL;
		}
		smb_krb5->timeout = False;
		smb_krb5->status = NT_STATUS_OK;
		smb_krb5->reply = data_blob(NULL, 0);
		smb_krb5->partial = data_blob(NULL, 0);

		while (!smb_krb5->timeout && (NT_STATUS_IS_OK(smb_krb5->status)) && !smb_krb5->reply.length) {
			if (event_loop_once(ev) != 0) {
				talloc_free(smb_krb5);
				return EINVAL;
			}
		}
		if (!NT_STATUS_IS_OK(smb_krb5->status)) {
			DEBUG(2,("Error reading smb_krb5 reply packet: %s\n", nt_errstr(smb_krb5->status)));
			talloc_free(smb_krb5);
			continue;
		}

		if (smb_krb5->timeout) {
			talloc_free(smb_krb5);
			continue;
		}

		ret = krb5_data_copy(recv_buf, smb_krb5->reply.data, smb_krb5->reply.length);
		if (ret) {
			talloc_free(smb_krb5);
			return ret;
		}
		talloc_free(smb_krb5);
		
		break;
	}
	if (a) {
		return 0;
	}
	return KRB5_KDC_UNREACH;
}

krb5_error_code smb_krb5_init_context(void *parent_ctx, 
				       struct smb_krb5_context **smb_krb5_context) 
{
	krb5_error_code ret;
	TALLOC_CTX *tmp_ctx;
	struct event_context *ev;
	char **config_files;
	const char *config_file;
	
	initialize_krb5_error_table();
	
	tmp_ctx = talloc_new(parent_ctx);
	*smb_krb5_context = talloc(tmp_ctx, struct smb_krb5_context);

	if (!*smb_krb5_context || !tmp_ctx) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}

	ret = krb5_init_context(&(*smb_krb5_context)->krb5_context);
	if (ret) {
		DEBUG(1,("krb5_init_context failed (%s)\n", 
			 error_message(ret)));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_set_destructor(*smb_krb5_context, smb_krb5_context_destroy_1);

	config_file = config_path(tmp_ctx, "krb5.conf");
	if (!config_file) {
		talloc_free(tmp_ctx);
		return ENOMEM;
	}
		
	/* Use our local krb5.conf file by default */
	ret = krb5_prepend_config_files_default(config_file, &config_files);
	if (ret) {
		DEBUG(1,("krb5_prepend_config_files_default failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = krb5_set_config_files((*smb_krb5_context)->krb5_context, 
				    config_files);
	krb5_free_config_files(config_files);
	if (ret) {
		DEBUG(1,("krb5_set_config_files failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
						
	if (lp_realm() && *lp_realm()) {
		char *upper_realm = strupper_talloc(tmp_ctx, lp_realm());
		if (!upper_realm) {
			DEBUG(1,("gensec_krb5_start: could not uppercase realm: %s\n", lp_realm()));
			talloc_free(tmp_ctx);
			return ENOMEM;
		}
		ret = krb5_set_default_realm((*smb_krb5_context)->krb5_context, upper_realm);
		if (ret) {
			DEBUG(1,("krb5_set_default_realm failed (%s)\n", 
				 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
			talloc_free(tmp_ctx);
			return ret;
		}
	}

	/* TODO: Should we have a different name here? */
	ret = krb5_initlog((*smb_krb5_context)->krb5_context, "Samba", &(*smb_krb5_context)->logf);
	
	if (ret) {
		DEBUG(1,("krb5_initlog failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_set_destructor(*smb_krb5_context, smb_krb5_context_destroy_2);

	ret = krb5_addlog_func((*smb_krb5_context)->krb5_context, (*smb_krb5_context)->logf, 0 /* min */, -1 /* max */, 
			       smb_krb5_debug_wrapper, smb_krb5_debug_close, NULL);
	if (ret) {
		DEBUG(1,("krb5_addlog_func failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}
	krb5_set_warn_dest((*smb_krb5_context)->krb5_context, (*smb_krb5_context)->logf);

	ev = event_context_find(*smb_krb5_context);
	/* Set use of our socket lib */
	ret = krb5_set_send_to_kdc_func((*smb_krb5_context)->krb5_context, 
					smb_krb5_send_and_recv_func, 
					ev);
	if (ret) {
		DEBUG(1,("krb5_set_send_recv_func failed (%s)\n", 
			 smb_get_krb5_error_message((*smb_krb5_context)->krb5_context, ret, tmp_ctx)));
		talloc_free(tmp_ctx);
		return ret;
	}

	talloc_steal(parent_ctx, *smb_krb5_context);
	talloc_free(tmp_ctx);

	/* Set options in kerberos */

	krb5_set_dns_canonicalize_hostname((*smb_krb5_context)->krb5_context,
					   lp_parm_bool(-1, "krb5", "set_dns_canonicalize", false));

	return 0;
}

