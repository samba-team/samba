/* 
   Unix SMB/CIFS implementation.
   Socket IPv4 functions
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

static NTSTATUS ipv4_tcp_init(struct socket_context *sock)
{
	sock->fd = socket(PF_INET, SOCK_STREAM, 0);
	if (sock->fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	return NT_STATUS_OK;
}

static void ipv4_tcp_close(struct socket_context *sock)
{
	close(sock->fd);
}

static NTSTATUS ipv4_tcp_connect(struct socket_context *sock,
				 const char *my_address, int my_port,
				 const char *srv_address, int srv_port,
				 uint32_t flags)
{
	struct sockaddr_in srv_addr;
	struct in_addr my_ip;
	struct in_addr srv_ip;
	int ret;

	my_ip = interpret_addr2(my_address);

	if (my_ip.s_addr != 0 || my_port != 0) {
		struct sockaddr_in my_addr;
		ZERO_STRUCT(my_addr);
#ifdef HAVE_SOCK_SIN_LEN
		my_addr.sin_len		= sizeof(my_addr);
#endif
		my_addr.sin_addr	= my_ip;
		my_addr.sin_port	= htons(my_port);
		my_addr.sin_family	= PF_INET;
		
		ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	srv_ip = interpret_addr2(srv_address);

	ZERO_STRUCT(srv_addr);
#ifdef HAVE_SOCK_SIN_LEN
	srv_addr.sin_len	= sizeof(srv_addr);
#endif
	srv_addr.sin_addr	= srv_ip;
	srv_addr.sin_port	= htons(srv_port);
	srv_addr.sin_family	= PF_INET;

	ret = connect(sock->fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr));
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (!(flags & SOCKET_FLAG_BLOCK)) {
		ret = set_blocking(sock->fd, False);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	sock->state = SOCKET_STATE_CLIENT_CONNECTED;

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_tcp_listen(struct socket_context *sock,
					const char *my_address, int port,
					int queue_size, uint32_t flags)
{
	struct sockaddr_in my_addr;
	struct in_addr ip_addr;
	int ret;

	ip_addr = interpret_addr2(my_address);

	ZERO_STRUCT(my_addr);
#ifdef HAVE_SOCK_SIN_LEN
	my_addr.sin_len		= sizeof(my_addr);
#endif
	my_addr.sin_addr	= ip_addr;
	my_addr.sin_port	= htons(port);
	my_addr.sin_family	= PF_INET;

	ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	ret = listen(sock->fd, queue_size);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (!(flags & SOCKET_FLAG_BLOCK)) {
		ret = set_blocking(sock->fd, False);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	sock->state= SOCKET_STATE_SERVER_LISTEN;

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_tcp_accept(struct socket_context *sock, struct socket_context **new_sock, uint32_t flags)
{
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len = sizeof(cli_addr);
	int new_fd;

	new_fd = accept(sock->fd, (struct sockaddr *)&cli_addr, &cli_addr_len);
	if (new_fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	/* TODO: we could add a 'accept_check' hook here
	 *	 which get the black/white lists via socket_set_accept_filter()
	 *	 or something like that
	 *	 --metze
	 */

	(*new_sock) = talloc_p(NULL, struct socket_context);
	if (!(*new_sock)) {
		close(new_fd);
		return NT_STATUS_NO_MEMORY;
	}

	/* copy the socket_context */
	(*new_sock)->type		= sock->type;
	(*new_sock)->state		= SOCKET_STATE_SERVER_CONNECTED;
	(*new_sock)->flags		= flags;

	(*new_sock)->fd			= new_fd;

	(*new_sock)->private_data	= NULL;
	(*new_sock)->ops		= sock->ops;

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_tcp_recv(struct socket_context *sock, TALLOC_CTX *mem_ctx,
			      DATA_BLOB *blob, size_t wantlen, uint32_t flags)
{
	ssize_t gotlen;
	void *buf;
	int flgs = 0;

	buf = talloc(mem_ctx, wantlen);
	if (!buf) {
		return NT_STATUS_NO_MEMORY;
	}

	/* TODO: we need to map all flags here */
	if (flags & SOCKET_FLAG_PEEK) {
		flgs |= MSG_PEEK;
	}

	if (!(flags & SOCKET_FLAG_BLOCK)) {
		flgs |= MSG_DONTWAIT;
	}

	if (flags & SOCKET_FLAG_BLOCK) {
		flgs |= MSG_WAITALL;
	}

	gotlen = recv(sock->fd, buf, wantlen, flgs);
	if (gotlen == 0) {
		talloc_free(buf);
		return NT_STATUS_END_OF_FILE;
	} else if (gotlen == -1) {
		NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
		switch (errno) {
			case EBADF:
			case ENOTCONN:
			case ENOTSOCK:
			case EFAULT:
			case EINVAL:
				status = NT_STATUS_INVALID_PARAMETER;
				break;
			case EAGAIN:
			case EINTR:
				status = STATUS_MORE_ENTRIES;
				break;
			case ECONNREFUSED:
				status = NT_STATUS_CONNECTION_REFUSED;
				break;
		}
		talloc_free(buf);
		return status;
	}

	blob->length = gotlen;
	blob->data = talloc_realloc(mem_ctx, buf, gotlen);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_tcp_send(struct socket_context *sock, TALLOC_CTX *mem_ctx,
					const DATA_BLOB *blob, size_t *sendlen, uint32_t flags)
{
	ssize_t len;
	int flgs = 0;

	/* TODO: we need to map all flags here */
	if (!(flags & SOCKET_FLAG_BLOCK)) {
		flgs |= MSG_DONTWAIT;
	}

	len = send(sock->fd, blob->data, blob->length, flgs);
	if (len == -1) {
		return map_nt_error_from_unix(errno);
	}	

	*sendlen = len;

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_tcp_set_option(struct socket_context *sock, const char *option, const char *val)
{
	set_socket_options(sock->fd, option);
	return NT_STATUS_OK;
}

static char *ipv4_tcp_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in peer_addr;
	socklen_t len = sizeof(peer_addr);
	struct hostent *he;
	int ret;

	ret = getpeername(sock->fd, (struct sockaddr *)&peer_addr, &len);
	if (ret == -1) {
		return NULL;
	}

	he = gethostbyaddr((char *)&peer_addr.sin_addr, sizeof(peer_addr.sin_addr), AF_INET);
	if (he == NULL) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, he->h_name);
}

static char *ipv4_tcp_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in peer_addr;
	socklen_t len = sizeof(peer_addr);
	int ret;

	ret = getpeername(sock->fd, (struct sockaddr *)&peer_addr, &len);
	if (ret == -1) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, inet_ntoa(peer_addr.sin_addr));
}

static int ipv4_tcp_get_peer_port(struct socket_context *sock)
{
	struct sockaddr_in peer_addr;
	socklen_t len = sizeof(peer_addr);
	int ret;

	ret = getpeername(sock->fd, (struct sockaddr *)&peer_addr, &len);
	if (ret == -1) {
		return -1;
	}

	return ntohs(peer_addr.sin_port);
}

static char *ipv4_tcp_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in my_addr;
	socklen_t len = sizeof(my_addr);
	int ret;

	ret = getsockname(sock->fd, (struct sockaddr *)&my_addr, &len);
	if (ret == -1) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, inet_ntoa(my_addr.sin_addr));
}

static int ipv4_tcp_get_my_port(struct socket_context *sock)
{
	struct sockaddr_in my_addr;
	socklen_t len = sizeof(my_addr);
	int ret;

	ret = getsockname(sock->fd, (struct sockaddr *)&my_addr, &len);
	if (ret == -1) {
		return -1;
	}

	return ntohs(my_addr.sin_port);
}

static int ipv4_tcp_get_fd(struct socket_context *sock)
{
	return sock->fd;
}

static const struct socket_ops ipv4_tcp_ops = {
	.name		= "ipv4",
	.type		= SOCKET_TYPE_STREAM,

	.init		= ipv4_tcp_init,
	.connect	= ipv4_tcp_connect,
	.listen		= ipv4_tcp_listen,
	.accept		= ipv4_tcp_accept,
	.recv		= ipv4_tcp_recv,
	.send		= ipv4_tcp_send,
	.close		= ipv4_tcp_close,

	.set_option	= ipv4_tcp_set_option,

	.get_peer_name	= ipv4_tcp_get_peer_name,
	.get_peer_addr	= ipv4_tcp_get_peer_addr,
	.get_peer_port	= ipv4_tcp_get_peer_port,
	.get_my_addr	= ipv4_tcp_get_my_addr,
	.get_my_port	= ipv4_tcp_get_my_port,

	.get_fd		= ipv4_tcp_get_fd
};

const struct socket_ops *socket_ipv4_ops(void)
{
	return &ipv4_tcp_ops;
}

NTSTATUS socket_ipv4_init(void)
{
	return NT_STATUS_OK;
}
