/* 
   Unix SMB/CIFS implementation.
   Socket IPv6 functions
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Jelmer Vernooij 2004
   
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
#include "lib/socket/socket.h"
#include "system/filesys.h" /* needed for close() */
#include "system/network.h"

static struct in6_addr interpret_addr6(const char *name)
{
	struct hostent *he;
	
	if (name == NULL) return in6addr_any;

	if (strcasecmp(name, "localhost") == 0) {
		name = "::1";
	}

	he = gethostbyname2(name, PF_INET6);

	if (he == NULL) return in6addr_any;

	return *((struct in6_addr *)he->h_addr);
}

static NTSTATUS ipv6_tcp_init(struct socket_context *sock)
{
	sock->fd = socket(PF_INET6, SOCK_STREAM, 0);
	if (sock->fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	sock->backend_name = "ipv6";

	return NT_STATUS_OK;
}

static void ipv6_tcp_close(struct socket_context *sock)
{
	close(sock->fd);
}

static NTSTATUS ipv6_tcp_connect_complete(struct socket_context *sock, uint32_t flags)
{
	int error=0, ret;
	socklen_t len = sizeof(error);

	/* check for any errors that may have occurred - this is needed
	   for non-blocking connect */
	ret = getsockopt(sock->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}
	if (error != 0) {
		return map_nt_error_from_unix(error);
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

static NTSTATUS ipv6_tcp_connect(struct socket_context *sock,
				 const struct socket_address *my_address,
				 const struct socket_address *srv_address,
				 uint32_t flags)
{
	int ret;

	if (my_address && my_address->sockaddr) {
		ret = bind(sock->fd, my_address->sockaddr, my_address->sockaddrlen);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else if (my_address) {
		struct in6_addr my_ip;
		my_ip = interpret_addr6(my_address->addr);

		if (memcmp(&my_ip, &in6addr_any, sizeof(my_ip)) || my_address->port != 0) {
			struct sockaddr_in6 my_addr;
			ZERO_STRUCT(my_addr);
			my_addr.sin6_addr	= my_ip;
			my_addr.sin6_port	= htons(my_address->port);
			my_addr.sin6_family	= PF_INET6;
			
			ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
			if (ret == -1) {
				return map_nt_error_from_unix(errno);
			}
		}
	}

	if (srv_address->sockaddr) {
		ret = connect(sock->fd, srv_address->sockaddr, srv_address->sockaddrlen);
	} else {
		struct in6_addr srv_ip;
		struct sockaddr_in6 srv_addr;
		srv_ip = interpret_addr6(srv_address->addr);
		if (memcmp(&srv_ip, &in6addr_any, sizeof(srv_ip)) == 0) {
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		
		ZERO_STRUCT(srv_addr);
		srv_addr.sin6_addr	= srv_ip;
		srv_addr.sin6_port	= htons(srv_address->port);
		srv_addr.sin6_family	= PF_INET6;
		
		ret = connect(sock->fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr));
	}
	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	return ipv6_tcp_connect_complete(sock, flags);
}

static NTSTATUS ipv6_tcp_listen(struct socket_context *sock,
				const struct socket_address *my_address,
				int queue_size, uint32_t flags)
{
	struct sockaddr_in6 my_addr;
	struct in6_addr ip_addr;
	int ret;

	socket_set_option(sock, "SO_REUSEADDR=1", NULL);

	if (my_address->sockaddr) {
		ret = bind(sock->fd, my_address->sockaddr, my_address->sockaddrlen);
	} else {
		ip_addr = interpret_addr6(my_address->addr);
		
		ZERO_STRUCT(my_addr);
		my_addr.sin6_addr	= ip_addr;
		my_addr.sin6_port	= htons(my_address->port);
		my_addr.sin6_family	= PF_INET6;
		
		ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
	}

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

static NTSTATUS ipv6_tcp_accept(struct socket_context *sock, struct socket_context **new_sock)
{
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len = sizeof(cli_addr);
	int new_fd;

	new_fd = accept(sock->fd, (struct sockaddr *)&cli_addr, &cli_addr_len);
	if (new_fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (!(sock->flags & SOCKET_FLAG_BLOCK)) {
		int ret = set_blocking(new_fd, False);
		if (ret == -1) {
			close(new_fd);
			return map_nt_error_from_unix(errno);
		}
	}

	/* TODO: we could add a 'accept_check' hook here
	 *	 which get the black/white lists via socket_set_accept_filter()
	 *	 or something like that
	 *	 --metze
	 */

	(*new_sock) = talloc(NULL, struct socket_context);
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
	(*new_sock)->backend_name	= sock->backend_name;

	return NT_STATUS_OK;
}

static NTSTATUS ipv6_tcp_recv(struct socket_context *sock, void *buf, 
			      size_t wantlen, size_t *nread)
{
	ssize_t gotlen;

	*nread = 0;

	gotlen = recv(sock->fd, buf, wantlen, 0);
	if (gotlen == 0) {
		return NT_STATUS_END_OF_FILE;
	} else if (gotlen == -1) {
		return map_nt_error_from_unix(errno);
	}

	*nread = gotlen;

	return NT_STATUS_OK;
}

static NTSTATUS ipv6_tcp_send(struct socket_context *sock, 
			      const DATA_BLOB *blob, size_t *sendlen)
{
	ssize_t len;

	*sendlen = 0;

	len = send(sock->fd, blob->data, blob->length, 0);
	if (len == -1) {
		return map_nt_error_from_unix(errno);
	}	

	*sendlen = len;

	return NT_STATUS_OK;
}

static NTSTATUS ipv6_tcp_set_option(struct socket_context *sock, const char *option, const char *val)
{
	set_socket_options(sock->fd, option);
	return NT_STATUS_OK;
}

static char *ipv6_tcp_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in6 peer_addr;
	socklen_t len = sizeof(peer_addr);
	struct hostent *he;
	int ret;

	ret = getpeername(sock->fd, (struct sockaddr *)&peer_addr, &len);
	if (ret == -1) {
		return NULL;
	}

	he = gethostbyaddr((char *)&peer_addr.sin6_addr, sizeof(peer_addr.sin6_addr), AF_INET6);
	if (he == NULL) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, he->h_name);
}

static struct socket_address *ipv6_tcp_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in6 *peer_addr;
	socklen_t len = sizeof(*peer_addr);
	struct socket_address *peer;
	int ret;
	char addr[128];
	const char *addr_ret;
	
	peer = talloc(mem_ctx, struct socket_address);
	if (!peer) {
		return NULL;
	}
	
	peer->family = sock->backend_name;
	peer_addr = talloc(peer, struct sockaddr_in6);
	if (!peer_addr) {
		talloc_free(peer);
		return NULL;
	}

	peer->sockaddr = (struct sockaddr *)peer_addr;

	ret = getpeername(sock->fd, peer->sockaddr, &len);
	if (ret == -1) {
		talloc_free(peer);
		return NULL;
	}

	peer->sockaddrlen = len;

	addr_ret = inet_ntop(AF_INET6, &peer_addr->sin6_addr, addr, sizeof(addr));
	if (addr_ret == NULL) {
		talloc_free(peer);
		return NULL;
	}

	peer->addr = talloc_strdup(peer, addr_ret);
	if (peer->addr == NULL) {
		talloc_free(peer);
		return NULL;
	}

	peer->port = ntohs(peer_addr->sin6_port);

	return peer;
}

static struct socket_address *ipv6_tcp_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in6 *local_addr;
	socklen_t len = sizeof(*local_addr);
	struct socket_address *local;
	int ret;
	struct hostent *he;
	
	local = talloc(mem_ctx, struct socket_address);
	if (!local) {
		return NULL;
	}
	
	local->family = sock->backend_name;
	local_addr = talloc(local, struct sockaddr_in6);
	if (!local_addr) {
		talloc_free(local);
		return NULL;
	}

	local->sockaddr = (struct sockaddr *)local_addr;

	ret = getsockname(sock->fd, local->sockaddr, &len);
	if (ret == -1) {
		talloc_free(local);
		return NULL;
	}

	local->sockaddrlen = len;

	he = gethostbyaddr((char *)&local_addr->sin6_addr, len, AF_INET6);

	if (!he || !he->h_name) {
		talloc_free(local);
		return NULL;
	}
	
	local->addr = talloc_strdup(mem_ctx, he->h_name);
	if (!local->addr) {
		talloc_free(local);
		return NULL;
	}
	local->port = ntohs(local_addr->sin6_port);

	return local;
}

static int ipv6_tcp_get_fd(struct socket_context *sock)
{
	return sock->fd;
}

static const struct socket_ops ipv6_tcp_ops = {
	.name			= "ipv6",
	.fn_init		= ipv6_tcp_init,
	.fn_connect		= ipv6_tcp_connect,
	.fn_connect_complete	= ipv6_tcp_connect_complete,
	.fn_listen		= ipv6_tcp_listen,
	.fn_accept		= ipv6_tcp_accept,
	.fn_recv		= ipv6_tcp_recv,
	.fn_send		= ipv6_tcp_send,
	.fn_close		= ipv6_tcp_close,

	.fn_set_option		= ipv6_tcp_set_option,

	.fn_get_peer_name	= ipv6_tcp_get_peer_name,
	.fn_get_peer_addr	= ipv6_tcp_get_peer_addr,
	.fn_get_my_addr		= ipv6_tcp_get_my_addr,

	.fn_get_fd		= ipv6_tcp_get_fd
};

const struct socket_ops *socket_ipv6_ops(enum socket_type type)
{
	if (type != SOCKET_TYPE_STREAM) {
		return NULL;
	}
	return &ipv6_tcp_ops;
}
