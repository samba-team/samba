/* 
   Unix SMB/CIFS implementation.

   Socket IPv4 functions

   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Andrew Tridgell 2004-2005
   
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
#include "system/filesys.h"
#include "lib/socket/socket.h"
#include "system/network.h"

static NTSTATUS ipv4_init(struct socket_context *sock)
{
	int type;

	switch (sock->type) {
	case SOCKET_TYPE_STREAM:
		type = SOCK_STREAM;
		break;
	case SOCKET_TYPE_DGRAM:
		type = SOCK_DGRAM;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	sock->fd = socket(PF_INET, type, 0);
	if (sock->fd == -1) {
		return map_nt_error_from_unix(errno);
	}

	sock->backend_name = "ipv4";

	return NT_STATUS_OK;
}

static void ipv4_close(struct socket_context *sock)
{
	close(sock->fd);
}

static NTSTATUS ipv4_connect_complete(struct socket_context *sock, uint32_t flags)
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


static NTSTATUS ipv4_connect(struct socket_context *sock,
			     const struct socket_address *my_address, 
			     const struct socket_address *srv_address,
			     uint32_t flags)
{
	struct sockaddr_in srv_addr;
	struct ipv4_addr my_ip;
	struct ipv4_addr srv_ip;
	int ret;

	if (my_address && my_address->sockaddr) {
		ret = bind(sock->fd, my_address->sockaddr, my_address->sockaddrlen);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else if (my_address) {
		my_ip = interpret_addr2(my_address->addr);
		
		if (my_ip.addr != 0 || my_address->port != 0) {
			struct sockaddr_in my_addr;
			ZERO_STRUCT(my_addr);
#ifdef HAVE_SOCK_SIN_LEN
			my_addr.sin_len		= sizeof(my_addr);
#endif
			my_addr.sin_addr.s_addr	= my_ip.addr;
			my_addr.sin_port	= htons(my_address->port);
			my_addr.sin_family	= PF_INET;
			
			ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
			if (ret == -1) {
				return map_nt_error_from_unix(errno);
			}
		}
	}

	if (srv_address->sockaddr) {
		ret = connect(sock->fd, srv_address->sockaddr, srv_address->sockaddrlen);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		srv_ip = interpret_addr2(srv_address->addr);
		if (!srv_ip.addr) {
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		
		ZERO_STRUCT(srv_addr);
#ifdef HAVE_SOCK_SIN_LEN
		srv_addr.sin_len	= sizeof(srv_addr);
#endif
		srv_addr.sin_addr.s_addr= srv_ip.addr;
		srv_addr.sin_port	= htons(srv_address->port);
		srv_addr.sin_family	= PF_INET;

		ret = connect(sock->fd, (const struct sockaddr *)&srv_addr, sizeof(srv_addr));
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	return ipv4_connect_complete(sock, flags);
}


/*
  note that for simplicity of the API, socket_listen() is also
  use for DGRAM sockets, but in reality only a bind() is done
*/
static NTSTATUS ipv4_listen(struct socket_context *sock,
			    const struct socket_address *my_address, 
			    int queue_size, uint32_t flags)
{
	struct sockaddr_in my_addr;
	struct ipv4_addr ip_addr;
	int ret;

	socket_set_option(sock, "SO_REUSEADDR=1", NULL);

	if (my_address->sockaddr) {
		ret = bind(sock->fd, my_address->sockaddr, my_address->sockaddrlen);
	} else {
		ip_addr = interpret_addr2(my_address->addr);
		
		ZERO_STRUCT(my_addr);
#ifdef HAVE_SOCK_SIN_LEN
		my_addr.sin_len		= sizeof(my_addr);
#endif
		my_addr.sin_addr.s_addr	= ip_addr.addr;
		my_addr.sin_port	= htons(my_address->port);
		my_addr.sin_family	= PF_INET;
		
		ret = bind(sock->fd, (struct sockaddr *)&my_addr, sizeof(my_addr));
	}

	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (sock->type == SOCKET_TYPE_STREAM) {
		ret = listen(sock->fd, queue_size);
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
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

static NTSTATUS ipv4_accept(struct socket_context *sock, struct socket_context **new_sock)
{
	struct sockaddr_in cli_addr;
	socklen_t cli_addr_len = sizeof(cli_addr);
	int new_fd;

	if (sock->type != SOCKET_TYPE_STREAM) {
		return NT_STATUS_INVALID_PARAMETER;
	}

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

static NTSTATUS ipv4_recv(struct socket_context *sock, void *buf, 
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


static NTSTATUS ipv4_recvfrom(struct socket_context *sock, void *buf, 
			      size_t wantlen, size_t *nread, 
			      TALLOC_CTX *addr_ctx, struct socket_address **_src)
{
	ssize_t gotlen;
	struct sockaddr_in *from_addr;
	socklen_t from_len = sizeof(*from_addr);
	struct socket_address *src;
	const char *addr;
	
	src = talloc(addr_ctx, struct socket_address);
	if (!src) {
		return NT_STATUS_NO_MEMORY;
	}
	
	src->family = sock->backend_name;

	from_addr = talloc(src, struct sockaddr_in);
	if (!from_addr) {
		talloc_free(src);
		return NT_STATUS_NO_MEMORY;
	}

	src->sockaddr = (struct sockaddr *)from_addr;

	*nread = 0;

	gotlen = recvfrom(sock->fd, buf, wantlen, 0, 
			  src->sockaddr, &from_len);
	if (gotlen == 0) {
		talloc_free(src);
		return NT_STATUS_END_OF_FILE;
	} else if (gotlen == -1) {
		talloc_free(src);
		return map_nt_error_from_unix(errno);
	}

	src->sockaddrlen = from_len;

	addr = inet_ntoa(from_addr->sin_addr);
	if (addr == NULL) {
		talloc_free(src);
		return NT_STATUS_INTERNAL_ERROR;
	}
	src->addr = talloc_strdup(src, addr);
	if (src->addr == NULL) {
		talloc_free(src);
		return NT_STATUS_NO_MEMORY;
	}
	src->port = ntohs(from_addr->sin_port);

	*nread	= gotlen;
	*_src	= src;
	return NT_STATUS_OK;
}

static NTSTATUS ipv4_send(struct socket_context *sock, 
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

static NTSTATUS ipv4_sendto(struct socket_context *sock, 
			    const DATA_BLOB *blob, size_t *sendlen, 
			    const struct socket_address *dest_addr)
{
	ssize_t len;

	if (dest_addr->sockaddr) {
		len = sendto(sock->fd, blob->data, blob->length, 0, 
			     dest_addr->sockaddr, dest_addr->sockaddrlen);
	} else {
		struct sockaddr_in srv_addr;
		struct ipv4_addr addr;
		
		ZERO_STRUCT(srv_addr);
#ifdef HAVE_SOCK_SIN_LEN
		srv_addr.sin_len         = sizeof(srv_addr);
#endif
		addr                     = interpret_addr2(dest_addr->addr);
		srv_addr.sin_addr.s_addr = addr.addr;
		srv_addr.sin_port        = htons(dest_addr->port);
		srv_addr.sin_family      = PF_INET;
		
		*sendlen = 0;
		
		len = sendto(sock->fd, blob->data, blob->length, 0, 
			     (struct sockaddr *)&srv_addr, sizeof(srv_addr));
	}
	if (len == -1) {
		return map_nt_error_from_unix(errno);
	}	

	*sendlen = len;

	return NT_STATUS_OK;
}

static NTSTATUS ipv4_set_option(struct socket_context *sock, const char *option, const char *val)
{
	set_socket_options(sock->fd, option);
	return NT_STATUS_OK;
}

static char *ipv4_get_peer_name(struct socket_context *sock, TALLOC_CTX *mem_ctx)
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

static struct socket_address *ipv4_get_peer_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in *peer_addr;
	socklen_t len = sizeof(*peer_addr);
	const char *addr;
	struct socket_address *peer;
	int ret;
	
	peer = talloc(mem_ctx, struct socket_address);
	if (!peer) {
		return NULL;
	}
	
	peer->family = sock->backend_name;
	peer_addr = talloc(peer, struct sockaddr_in);
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

	addr = inet_ntoa(peer_addr->sin_addr);
	if (addr == NULL) {
		talloc_free(peer);
		return NULL;
	}
	peer->addr = talloc_strdup(peer, addr);
	if (!peer->addr) {
		talloc_free(peer);
		return NULL;
	}
	peer->port = ntohs(peer_addr->sin_port);

	return peer;
}

static struct socket_address *ipv4_get_my_addr(struct socket_context *sock, TALLOC_CTX *mem_ctx)
{
	struct sockaddr_in *local_addr;
	socklen_t len = sizeof(*local_addr);
	const char *addr;
	struct socket_address *local;
	int ret;
	
	local = talloc(mem_ctx, struct socket_address);
	if (!local) {
		return NULL;
	}
	
	local->family = sock->backend_name;
	local_addr = talloc(local, struct sockaddr_in);
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

	addr = inet_ntoa(local_addr->sin_addr);
	if (addr == NULL) {
		talloc_free(local);
		return NULL;
	}
	local->addr = talloc_strdup(local, addr);
	if (!local->addr) {
		talloc_free(local);
		return NULL;
	}
	local->port = ntohs(local_addr->sin_port);

	return local;
}
static int ipv4_get_fd(struct socket_context *sock)
{
	return sock->fd;
}

static NTSTATUS ipv4_pending(struct socket_context *sock, size_t *npending)
{
	int value = 0;
	if (ioctl(sock->fd, FIONREAD, &value) == 0) {
		*npending = value;
		return NT_STATUS_OK;
	}
	return map_nt_error_from_unix(errno);
}

static const struct socket_ops ipv4_ops = {
	.name			= "ipv4",
	.fn_init		= ipv4_init,
	.fn_connect		= ipv4_connect,
	.fn_connect_complete	= ipv4_connect_complete,
	.fn_listen		= ipv4_listen,
	.fn_accept		= ipv4_accept,
	.fn_recv		= ipv4_recv,
	.fn_recvfrom		= ipv4_recvfrom,
	.fn_send		= ipv4_send,
	.fn_sendto		= ipv4_sendto,
	.fn_pending		= ipv4_pending,
	.fn_close		= ipv4_close,

	.fn_set_option		= ipv4_set_option,

	.fn_get_peer_name	= ipv4_get_peer_name,
	.fn_get_peer_addr	= ipv4_get_peer_addr,
	.fn_get_my_addr		= ipv4_get_my_addr,
	.fn_get_fd		= ipv4_get_fd
};

const struct socket_ops *socket_ipv4_ops(enum socket_type type)
{
	return &ipv4_ops;
}
