/* 
   Unix SMB/CIFS implementation.

   unix domain socket functions

   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Andrew Tridgell 2004
   
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
#include "system/network.h"



/*
  approximate errno mapping
*/
static NTSTATUS unixdom_error(int ernum)
{
	return map_nt_error_from_unix(ernum);
}

static NTSTATUS unixdom_init(struct socket_context *sock)
{
	sock->fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock->fd == -1) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}
	sock->private_data = NULL;

	return NT_STATUS_OK;
}

static void unixdom_close(struct socket_context *sock)
{
	close(sock->fd);
}

static NTSTATUS unixdom_connect(struct socket_context *sock,
				const char *my_address, int my_port,
				const char *srv_address, int srv_port,
				uint32_t flags)
{
	struct sockaddr_un srv_addr;
	int ret;

	if (strlen(srv_address)+1 > sizeof(srv_addr.sun_path)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ZERO_STRUCT(srv_addr);
	srv_addr.sun_family = AF_UNIX;
	strncpy(srv_addr.sun_path, srv_address, sizeof(srv_addr.sun_path));

	if (!(flags & SOCKET_FLAG_BLOCK)) {
		ret = set_blocking(sock->fd, False);
		if (ret == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
	}

	ret = connect(sock->fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		return unixdom_error(errno);
	}

	sock->state = SOCKET_STATE_CLIENT_CONNECTED;

	return NT_STATUS_OK;
}

static NTSTATUS unixdom_listen(struct socket_context *sock,
			       const char *my_address, int port,
			       int queue_size, uint32_t flags)
{
	struct sockaddr_un my_addr;
	int ret;

	if (strlen(my_address)+1 > sizeof(my_addr.sun_path)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* delete if it already exists */
	unlink(my_address);

	ZERO_STRUCT(my_addr);
	my_addr.sun_family = AF_UNIX;
	strncpy(my_addr.sun_path, my_address, sizeof(my_addr.sun_path));

	ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if (ret == -1) {
		return unixdom_error(errno);
	}

	ret = listen(sock->fd, queue_size);
	if (ret == -1) {
		return unixdom_error(errno);
	}

	if (!(flags & SOCKET_FLAG_BLOCK)) {
		ret = set_blocking(sock->fd, False);
		if (ret == -1) {
			return unixdom_error(errno);
		}
	}

	sock->state = SOCKET_STATE_SERVER_LISTEN;
	sock->private_data = (void *)talloc_strdup(sock, my_address);

	return NT_STATUS_OK;
}

static NTSTATUS unixdom_accept(struct socket_context *sock, 
			       struct socket_context **new_sock)
{
	struct sockaddr_un cli_addr;
	socklen_t cli_addr_len = sizeof(cli_addr);
	int new_fd;

	new_fd = accept(sock->fd, (struct sockaddr *)&cli_addr, &cli_addr_len);
	if (new_fd == -1) {
		return unixdom_error(errno);
	}

	if (!(sock->flags & SOCKET_FLAG_BLOCK)) {
		int ret = set_blocking(new_fd, False);
		if (ret == -1) {
			close(new_fd);
			return map_nt_error_from_unix(errno);
		}
	}

	(*new_sock) = talloc_p(NULL, struct socket_context);
	if (!(*new_sock)) {
		close(new_fd);
		return NT_STATUS_NO_MEMORY;
	}

	/* copy the socket_context */
	(*new_sock)->type		= sock->type;
	(*new_sock)->state		= SOCKET_STATE_SERVER_CONNECTED;
	(*new_sock)->flags		= sock->flags;

	(*new_sock)->fd			= new_fd;

	(*new_sock)->private_data	= NULL;
	(*new_sock)->ops		= sock->ops;

	return NT_STATUS_OK;
}

static NTSTATUS unixdom_recv(struct socket_context *sock, void *buf, 
			     size_t wantlen, size_t *nread, uint32_t flags)
{
	ssize_t gotlen;
	int flgs = 0;

	/* TODO: we need to map all flags here */
	if (flags & SOCKET_FLAG_PEEK) {
		flgs |= MSG_PEEK;
	}

	if (flags & SOCKET_FLAG_BLOCK) {
		flgs |= MSG_WAITALL;
	}

	*nread = 0;

	gotlen = recv(sock->fd, buf, wantlen, flgs);
	if (gotlen == 0) {
		return NT_STATUS_END_OF_FILE;
	} else if (gotlen == -1) {
		return unixdom_error(errno);
	}

	*nread = gotlen;

	return NT_STATUS_OK;
}

static NTSTATUS unixdom_send(struct socket_context *sock,
			     const DATA_BLOB *blob, size_t *sendlen, uint32_t flags)
{
	ssize_t len;
	int flgs = 0;

	*sendlen = 0;

	len = send(sock->fd, blob->data, blob->length, flgs);
	if (len == -1) {
		return unixdom_error(errno);
	}	

	*sendlen = len;

	return NT_STATUS_OK;
}

static NTSTATUS unixdom_set_option(struct socket_context *sock, 
				   const char *option, const char *val)
{
	return NT_STATUS_OK;
}

static char *unixdom_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	return talloc_strdup(mem_ctx, "LOCAL/unixdom");
}

static char *unixdom_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	return talloc_strdup(mem_ctx, "LOCAL/unixdom");
}

static int unixdom_get_peer_port(struct socket_context *sock)
{
	return 0;
}

static char *unixdom_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	return talloc_strdup(mem_ctx, "LOCAL/unixdom");
}

static int unixdom_get_my_port(struct socket_context *sock)
{
	return 0;
}

static int unixdom_get_fd(struct socket_context *sock)
{
	return sock->fd;
}

static const struct socket_ops unixdom_ops = {
	.name			= "unix",
	.type			= SOCKET_TYPE_STREAM,

	.fn_init		= unixdom_init,
	.fn_connect		= unixdom_connect,
	.fn_listen		= unixdom_listen,
	.fn_accept		= unixdom_accept,
	.fn_recv		= unixdom_recv,
	.fn_send		= unixdom_send,
	.fn_close		= unixdom_close,

	.fn_set_option		= unixdom_set_option,

	.fn_get_peer_name	= unixdom_get_peer_name,
	.fn_get_peer_addr	= unixdom_get_peer_addr,
	.fn_get_peer_port	= unixdom_get_peer_port,
	.fn_get_my_addr		= unixdom_get_my_addr,
	.fn_get_my_port		= unixdom_get_my_port,

	.fn_get_fd		= unixdom_get_fd
};

const struct socket_ops *socket_unixdom_ops(void)
{
	return &unixdom_ops;
}
