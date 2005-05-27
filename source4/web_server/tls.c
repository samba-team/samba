/* 
   Unix SMB/CIFS implementation.

   transport layer security handling code

   Copyright (C) Andrew Tridgell 2005
   
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
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "web_server/web_server.h"
#include "lib/events/events.h"
#include "system/network.h"

#if HAVE_LIBGNUTLS
#include "gnutls/gnutls.h"

#define DH_BITS 1024

/* hold per connection tls data */
struct tls_session {
	gnutls_session session;
	BOOL done_handshake;
};

/* hold persistent tls data */
struct tls_data {
	gnutls_certificate_credentials x509_cred;
	gnutls_dh_params dh_params;
};

/*
  initialise global tls state
*/
void tls_initialise(struct task_server *task)
{
	struct esp_data *edata = talloc_get_type(task->private, struct esp_data);
	struct tls_data *tls;
	int ret;
	const char *keyfile = lp_web_keyfile();
	const char *certfile = lp_web_certfile();
	const char *cafile = lp_web_cafile();
	const char *crlfile = lp_web_crlfile();

	if (!lp_web_tls() || keyfile == NULL || *keyfile == 0) {
		return;
	}

	tls = talloc_zero(edata, struct tls_data);
	edata->tls_data = tls;

	ret = gnutls_global_init();
	if (ret < 0) goto init_failed;

	gnutls_certificate_allocate_credentials(&tls->x509_cred);
	if (ret < 0) goto init_failed;

	ret = gnutls_certificate_set_x509_trust_file(tls->x509_cred, cafile, 
						     GNUTLS_X509_FMT_PEM);	
	if (ret < 0) {
		DEBUG(0,("TLS failed to initialise cafile %s\n", cafile));
		goto init_failed;
	}

	if (crlfile && *crlfile) {
		ret = gnutls_certificate_set_x509_crl_file(tls->x509_cred, 
							   crlfile, 
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DEBUG(0,("TLS failed to initialise crlfile %s\n", cafile));
			goto init_failed;
		}
	}
	
	ret = gnutls_certificate_set_x509_key_file(tls->x509_cred, 
						   certfile, keyfile,
						   GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		DEBUG(0,("TLS failed to initialise certfile %s and keyfile %s\n", 
			 lp_web_certfile(), lp_web_keyfile()));
		goto init_failed;
	}
	
	ret = gnutls_dh_params_init(&tls->dh_params);
	if (ret < 0) goto init_failed;

	ret = gnutls_dh_params_generate2(tls->dh_params, DH_BITS);
	if (ret < 0) goto init_failed;

	gnutls_certificate_set_dh_params(tls->x509_cred, tls->dh_params);
	return;

init_failed:
	DEBUG(0,("GNUTLS failed to initialise with code %d - disabling\n", ret));
	talloc_free(tls);
	edata->tls_data = NULL;
}


/*
  callback for reading from a socket
*/
static ssize_t tls_pull(gnutls_transport_ptr ptr, void *buf, size_t size)
{
	struct websrv_context *web = talloc_get_type(ptr, struct websrv_context);
	NTSTATUS status;
	size_t nread;
	
	if (web->input.tls_first_char) {
		*(uint8_t *)buf = web->input.first_byte;
		web->input.tls_first_char = False;
		return 1;
	}

	status = socket_recv(web->conn->socket, buf, size, &nread, 0);
	if (!NT_STATUS_IS_OK(status)) {
		EVENT_FD_READABLE(web->conn->event.fde);
		EVENT_FD_NOT_WRITEABLE(web->conn->event.fde);
		return -1;
	}
	if (web->output.output_pending) {
		EVENT_FD_WRITEABLE(web->conn->event.fde);
	}
	if (size != nread) {
		EVENT_FD_READABLE(web->conn->event.fde);
	}
	return nread;
}

/*
  callback for writing to a socket
*/
static ssize_t tls_push(gnutls_transport_ptr ptr, const void *buf, size_t size)
{
	struct websrv_context *web = talloc_get_type(ptr, struct websrv_context);
	NTSTATUS status;
	size_t nwritten;
	DATA_BLOB b;

	if (web->tls_session == NULL) {
		return size;
	}

	b.data = discard_const(buf);
	b.length = size;

	status = socket_send(web->conn->socket, &b, &nwritten, 0);
	if (!NT_STATUS_IS_OK(status)) {
		EVENT_FD_WRITEABLE(web->conn->event.fde);
		return -1;
	}
	if (size != nwritten) {
		EVENT_FD_WRITEABLE(web->conn->event.fde);
	}
	return nwritten;
}

/*
  destroy a tls session
 */
static int tls_destructor(void *ptr)
{
	struct tls_session *tls_session = talloc_get_type(ptr, struct tls_session);
	gnutls_bye(tls_session->session, GNUTLS_SHUT_WR);
	return 0;
}


/*
  setup for a new connection
*/
NTSTATUS tls_init_connection(struct websrv_context *web)
{
	struct esp_data *edata = talloc_get_type(web->task->private, struct esp_data);
	struct tls_data *tls_data = talloc_get_type(edata->tls_data, struct tls_data);
	struct tls_session *tls_session;
	int ret;

	if (edata->tls_data == NULL) {
		web->tls_session = NULL;
		return NT_STATUS_OK;
	}

#define TLSCHECK(call) do { \
	ret = call; \
	if (ret < 0) { \
		DEBUG(0,("TLS failed with code %d - %s\n", ret, #call)); \
		goto failed; \
	} \
} while (0)

	tls_session = talloc_zero(web, struct tls_session);
	web->tls_session = tls_session;

	TLSCHECK(gnutls_init(&tls_session->session, GNUTLS_SERVER));

	talloc_set_destructor(tls_session, tls_destructor);

	TLSCHECK(gnutls_set_default_priority(tls_session->session));
	TLSCHECK(gnutls_credentials_set(tls_session->session, GNUTLS_CRD_CERTIFICATE, tls_data->x509_cred));
	gnutls_certificate_server_set_request(tls_session->session, GNUTLS_CERT_REQUEST);
	gnutls_dh_set_prime_bits(tls_session->session, DH_BITS);
	gnutls_transport_set_ptr(tls_session->session, (gnutls_transport_ptr)web);
	gnutls_transport_set_pull_function(tls_session->session, (gnutls_pull_func)tls_pull);
	gnutls_transport_set_push_function(tls_session->session, (gnutls_push_func)tls_push);
	gnutls_transport_set_lowat(tls_session->session, 0);

	web->input.tls_detect = True;
	
	return NT_STATUS_OK;

failed:
	web->tls_session = NULL;
	talloc_free(tls_session);
	return NT_STATUS_OK;
}

/*
  possibly continue the handshake process
*/
static NTSTATUS tls_handshake(struct tls_session *tls_session)
{
	int ret;

	if (tls_session->done_handshake) {
		return NT_STATUS_OK;
	}
	
	ret = gnutls_handshake(tls_session->session);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return STATUS_MORE_ENTRIES;
	}
	if (ret < 0) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	tls_session->done_handshake = True;
	return NT_STATUS_OK;
}


/*
  receive data either by tls or normal socket_recv
*/
NTSTATUS tls_socket_recv(struct websrv_context *web, void *buf, size_t wantlen, 
			 size_t *nread)
{
	int ret;
	NTSTATUS status;
	struct tls_session *tls_session = talloc_get_type(web->tls_session, 
							  struct tls_session);

	if (web->tls_session != NULL && web->input.tls_detect) {
		status = socket_recv(web->conn->socket, &web->input.first_byte, 
				     1, nread, 0);
		NT_STATUS_NOT_OK_RETURN(status);
		if (*nread == 0) return NT_STATUS_OK;
		web->input.tls_detect = False;
		/* look for the first byte of a valid HTTP operation */
		if (strchr("GPHO", web->input.first_byte)) {
			/* not a tls link */
			web->tls_session = NULL;
			talloc_free(tls_session);
			*(uint8_t *)buf = web->input.first_byte;
			return NT_STATUS_OK;
		}
		web->input.tls_first_char = True;
	}

	if (web->tls_session == NULL) {
		return socket_recv(web->conn->socket, buf, wantlen, nread, 0);
	}

	status = tls_handshake(tls_session);
	NT_STATUS_NOT_OK_RETURN(status);

	ret = gnutls_record_recv(tls_session->session, buf, wantlen);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return STATUS_MORE_ENTRIES;
	}
	if (ret < 0) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	*nread = ret;
	return NT_STATUS_OK;
}


/*
  send data either by tls or normal socket_recv
*/
NTSTATUS tls_socket_send(struct websrv_context *web, const DATA_BLOB *blob, 
			 size_t *sendlen)
{
	NTSTATUS status;
	int ret;
	struct tls_session *tls_session = talloc_get_type(web->tls_session, 
							  struct tls_session);

	if (web->tls_session == NULL) {
		return socket_send(web->conn->socket, blob, sendlen, 0);
	}

	status = tls_handshake(tls_session);
	NT_STATUS_NOT_OK_RETURN(status);

	ret = gnutls_record_send(tls_session->session, blob->data, blob->length);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return STATUS_MORE_ENTRIES;
	}
	if (ret < 0) {
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	*sendlen = ret;
	return NT_STATUS_OK;
}
#else

/* for systems without tls */
NTSTATUS tls_socket_recv(struct websrv_context *web, void *buf, size_t wantlen, 
			 size_t *nread)
{
	return socket_recv(web->conn->socket, buf, wantlen, nread, 0);
}

NTSTATUS tls_socket_send(struct websrv_context *web, const DATA_BLOB *blob, 
			 size_t *sendlen)
{
	return socket_send(web->conn->socket, blob, sendlen, 0);
}

NTSTATUS tls_init_connection(struct websrv_context *web)
{
	web->tls_session = NULL;
	return NT_STATUS_OK;
}

void tls_initialise(struct task_server *task)
{
	struct esp_data *edata = talloc_get_type(task->private, struct esp_data);
	edata->tls_data = NULL;
}

#endif
