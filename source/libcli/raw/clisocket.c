/* 
   Unix SMB/CIFS implementation.
   SMB client socket context management functions

   Copyright (C) Andrew Tridgell 1994-2005
   Copyright (C) James Myers 2003 <myersjj@samba.org>
   
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
#include "events.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

/*
  this private structure is used during async connection handling
*/
struct clisocket_connect {
	int *iports;
	struct smbcli_socket *sock;
	const char *dest_host;
};

/*
  create a smbcli_socket context
*/
struct smbcli_socket *smbcli_sock_init(TALLOC_CTX *mem_ctx)
{
	struct smbcli_socket *sock;

	sock = talloc_zero(mem_ctx, struct smbcli_socket);
	if (!sock) {
		return NULL;
	}

	sock->event.ctx = event_context_init(sock);
	if (sock->event.ctx == NULL) {
		talloc_free(sock);
		return NULL;
	}

	return sock;
}

static NTSTATUS smbcli_sock_connect_one(struct smbcli_socket *sock, 
					const char *hostaddr, int port);

/*
  handle socket write events during an async connect. These happen when the OS
  has either completed the connect() or has returned an error
*/
static void smbcli_sock_connect_handler(struct event_context *ev, struct fd_event *fde, 
					struct timeval t, uint16_t flags)
{
	struct smbcli_composite *c = fde->private;
	struct clisocket_connect *conn = c->private;
	int i;
	
	c->status = socket_connect_complete(conn->sock->sock, 0);
	if (NT_STATUS_IS_OK(c->status)) {
		socket_set_option(conn->sock->sock, lp_socket_options(), NULL);
		c->state = SMBCLI_REQUEST_DONE;
		if (c->async.fn) {
			c->async.fn(c);
		}
		return;
	}

	/* that port failed - try the next port */
	for (i=c->stage+1;conn->iports[i];i++) {
		c->stage = i;
		c->status = smbcli_sock_connect_one(conn->sock, 
						    conn->dest_host, 
						    conn->iports[i]);
		if (NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			conn->sock->event.fde->private = c;
			return;
		}
		if (NT_STATUS_IS_OK(c->status)) {
			c->state = SMBCLI_REQUEST_DONE;
			if (c->async.fn) {
				c->async.fn(c);
			}
			return;
		}
	}

	c->state = SMBCLI_REQUEST_ERROR;
	if (c->async.fn) {
		c->async.fn(c);
	}
}


/*
  try to connect to the given address/port
*/
static NTSTATUS smbcli_sock_connect_one(struct smbcli_socket *sock, 
					const char *hostaddr, int port)
{
	struct fd_event fde;
	NTSTATUS status;

	if (sock->sock) {
		talloc_free(sock->sock);
		sock->sock = NULL;
	}

	if (sock->event.fde) {
		event_remove_fd(sock->event.ctx, sock->event.fde);
		sock->event.fde = NULL;
	}

	status = socket_create("ip", SOCKET_TYPE_STREAM, &sock->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	talloc_steal(sock, sock->sock);

	/* we initially look for write - see the man page on
	   non-blocking connect */
	fde.fd = socket_get_fd(sock->sock);
	fde.flags = EVENT_FD_WRITE;
	fde.handler = smbcli_sock_connect_handler;
	fde.private = sock;

	sock->event.fde = event_add_fd(sock->event.ctx, &fde);
	sock->port = port;
	set_blocking(fde.fd, False);

	return socket_connect(sock->sock, NULL, 0, hostaddr, port, 0);
}
					

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose 445 then 139

  this is the async send side of the interface
*/
struct smbcli_composite *smbcli_sock_connect_send(struct smbcli_socket *sock, 
						  struct ipv4_addr *ip, int port)
{
	struct smbcli_composite *c;
	struct clisocket_connect *conn;
	int i;

	c = talloc_zero(sock, struct smbcli_composite);
	if (c == NULL) return NULL;

	c->event_ctx = sock->event.ctx;

	conn = talloc(c, struct clisocket_connect);
	if (conn == NULL) goto failed;

	conn->sock = sock;

	/* work out what ports we will try */
	if (port == 0) {
		const char **ports = lp_smb_ports();
		for (i=0;ports[i];i++) /* noop */ ;
		conn->iports = talloc_array(c, int, i+1);
		if (conn->iports == NULL) goto failed;
		for (i=0;ports[i];i++) {
			conn->iports[i] = atoi(ports[i]);
		}
		conn->iports[i] = 0;
	} else {
		conn->iports = talloc_array(c, int, 2);
		if (conn->iports == NULL) goto failed;
		conn->iports[0] = port;
		conn->iports[1] = 0;
	}

	conn->dest_host = talloc_strdup(c, sys_inet_ntoa(*ip));
	if (conn->dest_host == NULL) goto failed;

	c->private = conn;
	c->state = SMBCLI_REQUEST_SEND;

	/* startup the connect process for each port in turn until one
	   succeeds or tells us that it is pending */
	for (i=0;conn->iports[i];i++) {
		c->stage = i;
		conn->sock->port = conn->iports[i];
		c->status = smbcli_sock_connect_one(sock, 
						    conn->dest_host, 
						    conn->iports[i]);
		if (NT_STATUS_EQUAL(c->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			sock->event.fde->private = c;
			return c;
		}
		if (NT_STATUS_IS_OK(c->status)) {
			c->state = SMBCLI_REQUEST_DONE;
			return c;
		}
	}

	c->state = SMBCLI_REQUEST_ERROR;
	return c;
	
failed:
	talloc_free(c);
	return NULL;
}

/*
  finish a smbcli_sock_connect_send() operation
*/
NTSTATUS smbcli_sock_connect_recv(struct smbcli_composite *c)
{
	NTSTATUS status;
	status = smb_composite_wait(c);
	talloc_free(c);
	return status;
}

/*
  connect a smbcli_socket context to an IP/port pair
  if port is 0 then choose the ports listed in smb.conf (normally 445 then 139)

  sync version of the function
*/
NTSTATUS smbcli_sock_connect(struct smbcli_socket *sock, struct ipv4_addr *ip, int port)
{
	struct smbcli_composite *c;

	c = smbcli_sock_connect_send(sock, ip, port);
	if (c == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return smbcli_sock_connect_recv(c);
}


/****************************************************************************
 mark the socket as dead
****************************************************************************/
void smbcli_sock_dead(struct smbcli_socket *sock)
{
	if (sock->sock != NULL) {
		talloc_free(sock->sock);
		sock->sock = NULL;
	}
}

/****************************************************************************
 Set socket options on a open connection.
****************************************************************************/
void smbcli_sock_set_options(struct smbcli_socket *sock, const char *options)
{
	socket_set_option(sock->sock, options, NULL);
}

/****************************************************************************
 Write to socket. Return amount written.
****************************************************************************/
ssize_t smbcli_sock_write(struct smbcli_socket *sock, const uint8_t *data, size_t len)
{
	NTSTATUS status;
	DATA_BLOB blob;
	size_t nsent;

	if (sock->sock == NULL) {
		errno = EIO;
		return -1;
	}

	blob.data = discard_const(data);
	blob.length = len;

	status = socket_send(sock->sock, &blob, &nsent, 0);
	if (NT_STATUS_IS_ERR(status)) {
		return -1;
	}

	return nsent;
}


/****************************************************************************
 Read from socket. return amount read
****************************************************************************/
ssize_t smbcli_sock_read(struct smbcli_socket *sock, uint8_t *data, size_t len)
{
	NTSTATUS status;
	size_t nread;

	if (sock->sock == NULL) {
		errno = EIO;
		return -1;
	}

	status = socket_recv(sock->sock, data, len, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		return -1;
	}

	return nread;
}


/****************************************************************************
resolve a hostname and connect 
****************************************************************************/
BOOL smbcli_sock_connect_byname(struct smbcli_socket *sock, const char *host, int port)
{
	int name_type = 0x20;
	struct ipv4_addr ip;
	char *name, *p;
	NTSTATUS status;

	name = talloc_strdup(sock, host);

	/* allow hostnames of the form NAME#xx and do a netbios lookup */
	if ((p = strchr(name, '#'))) {
		name_type = strtol(p+1, NULL, 16);
		*p = 0;
	}

	if (!resolve_name(name, name, &ip, name_type)) {
		return False;
	}

	sock->hostname = name;

	status = smbcli_sock_connect(sock, &ip, port);

	return NT_STATUS_IS_OK(status);
}
