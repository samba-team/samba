/* 
   Unix SMB/CIFS implementation.
   Socket functions
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

/*
  auto-close sockets on free
*/
static int socket_destructor(void *ptr)
{
	struct socket_context *sock = ptr;
	if (sock->ops->close) {
		sock->ops->close(sock);
	}
	return 0;
}

NTSTATUS socket_create(const char *name, enum socket_type type, struct socket_context **new_sock, uint32_t flags)
{
	NTSTATUS status;

	(*new_sock) = talloc_p(NULL, struct socket_context);
	if (!(*new_sock)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*new_sock)->type = type;
	(*new_sock)->state = SOCKET_STATE_UNDEFINED;
	(*new_sock)->flags = flags;

	(*new_sock)->fd = -1;

	(*new_sock)->private_data = NULL;
	(*new_sock)->ops = socket_getops_byname(name, type);
	if (!(*new_sock)->ops) {
		talloc_free(*new_sock);
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = (*new_sock)->ops->init((*new_sock));
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(*new_sock);
		return status;
	}

	talloc_set_destructor(*new_sock, socket_destructor);

	return NT_STATUS_OK;
}

void socket_destroy(struct socket_context *sock)
{
	/* the close is handled by the destructor */
	talloc_free(sock);
}

NTSTATUS socket_connect(struct socket_context *sock,
			const char *my_address, int my_port,
			const char *server_address, int server_port,
			uint32_t flags)
{
	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sock->state != SOCKET_STATE_UNDEFINED) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sock->ops->connect) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return sock->ops->connect(sock, my_address, my_port, server_address, server_port, flags);
}

NTSTATUS socket_listen(struct socket_context *sock, const char *my_address, int port, int queue_size, uint32_t flags)
{
	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sock->state != SOCKET_STATE_UNDEFINED) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sock->ops->listen) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return sock->ops->listen(sock, my_address, port, queue_size, flags);
}

NTSTATUS socket_accept(struct socket_context *sock, struct socket_context **new_sock, uint32_t flags)
{
	NTSTATUS status;

	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sock->state != SOCKET_STATE_SERVER_LISTEN) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sock->ops->accept) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	status = sock->ops->accept(sock, new_sock, flags);

	if (NT_STATUS_IS_OK(status)) {
		talloc_set_destructor(*new_sock, socket_destructor);
	}

	return status;
}

NTSTATUS socket_recv(struct socket_context *sock, TALLOC_CTX *mem_ctx,
		     DATA_BLOB *blob, size_t wantlen, uint32_t flags)
{
	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sock->state != SOCKET_STATE_CLIENT_CONNECTED &&
	    sock->state != SOCKET_STATE_SERVER_CONNECTED) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sock->ops->recv) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return sock->ops->recv(sock, mem_ctx, blob, wantlen, flags);
}

NTSTATUS socket_send(struct socket_context *sock, TALLOC_CTX *mem_ctx,
			const DATA_BLOB *blob, size_t *sendlen, uint32_t flags)
{
	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (sock->state != SOCKET_STATE_CLIENT_CONNECTED &&
	    sock->state != SOCKET_STATE_SERVER_CONNECTED) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!sock->ops->send) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return sock->ops->send(sock, mem_ctx, blob, sendlen, flags);
}

NTSTATUS socket_set_option(struct socket_context *sock, const char *option, const char *val)
{
	if (!sock->ops->set_option) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	return sock->ops->set_option(sock, option, val);
}

char *socket_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	if (!sock->ops->get_peer_name) {
		return NULL;
	}

	return sock->ops->get_peer_name(sock, mem_ctx);
}

char *socket_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	if (!sock->ops->get_peer_addr) {
		return NULL;
	}

	return sock->ops->get_peer_addr(sock, mem_ctx);
}

int socket_get_peer_port(struct socket_context *sock)
{
	if (!sock->ops->get_peer_port) {
		return -1;
	}

	return sock->ops->get_peer_port(sock);
}

char *socket_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	if (!sock->ops->get_my_addr) {
		return NULL;
	}

	return sock->ops->get_my_addr(sock, mem_ctx);
}

int socket_get_my_port(struct socket_context *sock)
{
	if (!sock->ops->get_my_port) {
		return -1;
	}

	return sock->ops->get_my_port(sock);
}

int socket_get_fd(struct socket_context *sock)
{
	if (!sock->ops->get_fd) {
		return -1;
	}

	return sock->ops->get_fd(sock);
}

const struct socket_ops *socket_getops_byname(const char *name, enum socket_type type)
{
	if (strcmp("ip", name) == 0 || 
	    strcmp("ipv4", name) == 0) {
		return socket_ipv4_ops();
	}

	if (strcmp("unix", name) == 0) {
		return socket_unixdom_ops();
	}

	return NULL;
}
