/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "tsocket.h"
#include "tsocket_internal.h"

static const struct tsocket_context_ops tsocket_context_bsd_ops;
static const struct tsocket_address_ops tsocket_address_bsd_ops;

static int tsocket_context_bsd_set_option(const struct tsocket_context *sock,
					  const char *option,
					  bool force,
					  const char *value);

struct tsocket_context_bsd {
	bool close_on_disconnect;
	int fd;
	struct tevent_fd *fde;
};

struct tsocket_address_bsd {
	bool broadcast;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
#ifdef HAVE_IPV6
		struct sockaddr_in6 sin6;
#endif
		struct sockaddr_un sun;
		struct sockaddr_storage ss;
	} u;
};

static int _tsocket_address_bsd_from_sockaddr(TALLOC_CTX *mem_ctx,
					      struct sockaddr *sa,
					      socklen_t sa_len,
					      struct tsocket_address **_addr,
					      const char *location)
{
	struct tsocket_address *addr;
	struct tsocket_address_bsd *bsda;

	switch (sa->sa_family) {
	case AF_UNIX:
		if (sa_len < sizeof(struct sockaddr_un)) {
			errno = EINVAL;
			return -1;
		}
		break;
	case AF_INET:
		if (sa_len < sizeof(struct sockaddr_in)) {
			errno = EINVAL;
			return -1;
		}
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (sa_len < sizeof(struct sockaddr_in6)) {
			errno = EINVAL;
			return -1;
		}
		break;
#endif
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	if (sa_len > sizeof(struct sockaddr_storage)) {
		errno = EINVAL;
		return -1;
	}

	addr = tsocket_address_create(mem_ctx,
				      &tsocket_address_bsd_ops,
				      &bsda,
				      struct tsocket_address_bsd,
				      location);
	if (!addr) {
		errno = ENOMEM;
		return -1;
	}

	ZERO_STRUCTP(bsda);

	memcpy(&bsda->u.ss, sa, sa_len);

	*_addr = addr;
	return 0;
}

int _tsocket_address_inet_from_strings(TALLOC_CTX *mem_ctx,
				       const char *fam,
				       const char *addr,
				       uint16_t port,
				       struct tsocket_address **_addr,
				       const char *location)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	char port_str[6];
	int ret;

	ZERO_STRUCT(hints);
	/*
	 * we use SOCKET_STREAM here to get just one result
	 * back from getaddrinfo().
	 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

	if (strcasecmp(fam, "ip") == 0) {
		hints.ai_family = AF_UNSPEC;
		if (!addr) {
#ifdef HAVE_IPV6
			addr = "::";
#else
			addr = "0.0.0.0";
#endif
		}
	} else if (strcasecmp(fam, "ipv4") == 0) {
		hints.ai_family = AF_INET;
		if (!addr) {
			addr = "0.0.0.0";
		}
#ifdef HAVE_IPV6
	} else if (strcasecmp(fam, "ipv6") == 0) {
		hints.ai_family = AF_INET6;
		if (!addr) {
			addr = "::";
		}
#endif
	} else {
		errno = EAFNOSUPPORT;
		return -1;
	}

	snprintf(port_str, sizeof(port_str) - 1, "%u", port);

	ret = getaddrinfo(addr, port_str, &hints, &result);
	if (ret != 0) {
		switch (ret) {
		case EAI_FAIL:
			errno = EINVAL;
			break;
		}
		ret = -1;
		goto done;
	}

	if (result->ai_socktype != SOCK_STREAM) {
		errno = EINVAL;
		ret = -1;
		goto done;
	}

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						  result->ai_addr,
						  result->ai_addrlen,
						  _addr,
						  location);

done:
	if (result) {
		freeaddrinfo(result);
	}
	return ret;
}

char *tsocket_address_inet_addr_string(const struct tsocket_address *addr,
				       TALLOC_CTX *mem_ctx)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	char addr_str[INET6_ADDRSTRLEN+1];
	const char *str;

	if (!bsda) {
		errno = EINVAL;
		return NULL;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		str = inet_ntop(bsda->u.sin.sin_family,
				&bsda->u.sin.sin_addr,
				addr_str, sizeof(addr_str));
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		str = inet_ntop(bsda->u.sin6.sin6_family,
				&bsda->u.sin6.sin6_addr,
				addr_str, sizeof(addr_str));
		break;
#endif
	default:
		errno = EINVAL;
		return NULL;
	}

	if (!str) {
		return NULL;
	}

	return talloc_strdup(mem_ctx, str);
}

uint16_t tsocket_address_inet_port(const struct tsocket_address *addr)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	uint16_t port = 0;

	if (!bsda) {
		errno = EINVAL;
		return 0;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		port = ntohs(bsda->u.sin.sin_port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		port = ntohs(bsda->u.sin6.sin6_port);
		break;
#endif
	default:
		errno = EINVAL;
		return 0;
	}

	return port;
}

int tsocket_address_inet_set_port(struct tsocket_address *addr,
				  uint16_t port)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);

	if (!bsda) {
		errno = EINVAL;
		return -1;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_INET:
		bsda->u.sin.sin_port = htons(port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		bsda->u.sin6.sin6_port = htons(port);
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

void tsocket_address_inet_set_broadcast(struct tsocket_address *addr,
					bool broadcast)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);

	if (!bsda) {
		return;
	}

	bsda->broadcast = broadcast;
}

int _tsocket_address_unix_from_path(TALLOC_CTX *mem_ctx,
				    const char *path,
				    struct tsocket_address **_addr,
				    const char *location)
{
	struct sockaddr_un sun;
	void *p = &sun;
	int ret;

	if (!path) {
		path = "";
	}

	ZERO_STRUCT(sun);
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, path, sizeof(sun.sun_path));

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						 (struct sockaddr *)p,
						 sizeof(sun),
						 _addr,
						 location);

	return ret;
}

char *tsocket_address_unix_path(const struct tsocket_address *addr,
				TALLOC_CTX *mem_ctx)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	const char *str;

	if (!bsda) {
		errno = EINVAL;
		return NULL;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		str = bsda->u.sun.sun_path;
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	return talloc_strdup(mem_ctx, str);
}

static char *tsocket_address_bsd_string(const struct tsocket_address *addr,
					TALLOC_CTX *mem_ctx)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	char *str;
	char *addr_str;
	const char *prefix = NULL;
	uint16_t port;

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		return talloc_asprintf(mem_ctx, "unix:%s",
				       bsda->u.sun.sun_path);
	case AF_INET:
		prefix = "ipv4";
		break;
	case AF_INET6:
		prefix = "ipv6";
		break;
	default:
		errno = EINVAL;
		return NULL;
	}

	addr_str = tsocket_address_inet_addr_string(addr, mem_ctx);
	if (!addr_str) {
		return NULL;
	}

	port = tsocket_address_inet_port(addr);

	str = talloc_asprintf(mem_ctx, "%s:%s:%u",
			      prefix, addr_str, port);
	talloc_free(addr_str);

	return str;
}

static struct tsocket_address *tsocket_address_bsd_copy(const struct tsocket_address *addr,
							 TALLOC_CTX *mem_ctx,
							 const char *location)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	struct tsocket_address *copy;
	int ret;

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						 &bsda->u.sa,
						 sizeof(bsda->u.ss),
						 &copy,
						 location);
	if (ret != 0) {
		return NULL;
	}

	tsocket_address_inet_set_broadcast(copy, bsda->broadcast);
	return copy;
}

int _tsocket_context_bsd_wrap_existing(TALLOC_CTX *mem_ctx,
				       int fd, bool close_on_disconnect,
				       struct tsocket_context **_sock,
				       const char *location)
{
	struct tsocket_context *sock;
	struct tsocket_context_bsd *bsds;

	sock = tsocket_context_create(mem_ctx,
				      &tsocket_context_bsd_ops,
				      &bsds,
				      struct tsocket_context_bsd,
				      location);
	if (!sock) {
		return -1;
	}

	bsds->close_on_disconnect	= close_on_disconnect;
	bsds->fd			= fd;
	bsds->fde			= NULL;

	*_sock = sock;
	return 0;
}

static int tsocket_address_bsd_create_socket(const struct tsocket_address *addr,
					     enum tsocket_type type,
					     TALLOC_CTX *mem_ctx,
					     struct tsocket_context **_sock,
					     const char *location)
{
	struct tsocket_address_bsd *bsda = talloc_get_type(addr->private_data,
					   struct tsocket_address_bsd);
	struct tsocket_context *sock;
	int bsd_type;
	int fd;
	int ret;
	bool do_bind = false;
	bool do_reuseaddr = false;

	switch (type) {
	case TSOCKET_TYPE_STREAM:
		if (bsda->broadcast) {
			errno = EINVAL;
			return -1;
		}
		bsd_type = SOCK_STREAM;
		break;
	case TSOCKET_TYPE_DGRAM:
		bsd_type = SOCK_DGRAM;
		break;
	default:
		errno = EPROTONOSUPPORT;
		return -1;
	}

	switch (bsda->u.sa.sa_family) {
	case AF_UNIX:
		if (bsda->broadcast) {
			errno = EINVAL;
			return -1;
		}
		if (bsda->u.sun.sun_path[0] != 0) {
			do_bind = true;
		}
		break;
	case AF_INET:
		if (bsda->u.sin.sin_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (bsda->u.sin.sin_addr.s_addr == INADDR_ANY) {
			do_bind = true;
		}
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (bsda->u.sin6.sin6_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (memcmp(&in6addr_any,
			   &bsda->u.sin6.sin6_addr,
			   sizeof(in6addr_any)) != 0) {
			do_bind = true;
		}
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	fd = socket(bsda->u.sa.sa_family, bsd_type, 0);
	if (fd < 0) {
		return fd;
	}

	fd = tsocket_common_prepare_fd(fd, true);
	if (fd < 0) {
		return fd;
	}

	ret = _tsocket_context_bsd_wrap_existing(mem_ctx, fd, true,
						 &sock, location);
	if (ret != 0) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return ret;
	}

	if (bsda->broadcast) {
		ret = tsocket_context_bsd_set_option(sock, "SO_BROADCAST", true, "1");
		if (ret != 0) {
			int saved_errno = errno;
			talloc_free(sock);
			errno = saved_errno;
			return ret;
		}
	}

	if (do_reuseaddr) {
		ret = tsocket_context_bsd_set_option(sock, "SO_REUSEADDR", true, "1");
		if (ret != 0) {
			int saved_errno = errno;
			talloc_free(sock);
			errno = saved_errno;
			return ret;
		}
	}

	if (do_bind) {
		ret = bind(fd, &bsda->u.sa, sizeof(bsda->u.ss));
		if (ret != 0) {
			int saved_errno = errno;
			talloc_free(sock);
			errno = saved_errno;
			return ret;
		}
	}

	*_sock = sock;
	return 0;
}

static const struct tsocket_address_ops tsocket_address_bsd_ops = {
	.name		= "bsd",
	.string		= tsocket_address_bsd_string,
	.copy		= tsocket_address_bsd_copy,
	.create_socket	= tsocket_address_bsd_create_socket
};

static void tsocket_context_bsd_fde_handler(struct tevent_context *ev,
					    struct tevent_fd *fde,
					    uint16_t flags,
					    void *private_data)
{
	struct tsocket_context *sock = talloc_get_type(private_data,
				       struct tsocket_context);

	if (flags & TEVENT_FD_WRITE) {
		sock->event.write_handler(sock, sock->event.write_private);
		return;
	}
	if (flags & TEVENT_FD_READ) {
		sock->event.read_handler(sock, sock->event.read_private);
		return;
	}
}

static int tsocket_context_bsd_set_event_context(struct tsocket_context *sock,
						 struct tevent_context *ev)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);

	talloc_free(bsds->fde);
	bsds->fde = NULL;
	ZERO_STRUCT(sock->event);

	if (!ev) {
		return 0;
	}

	bsds->fde = tevent_add_fd(ev, bsds,
				  bsds->fd,
				  0,
				  tsocket_context_bsd_fde_handler,
				  sock);
	if (!bsds->fde) {
		if (errno == 0) {
			errno = ENOMEM;
		}
		return -1;
	}

	sock->event.ctx = ev;

	return 0;
}

static int tsocket_context_bsd_set_read_handler(struct tsocket_context *sock,
						tsocket_event_handler_t handler,
						void *private_data)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);

	if (sock->event.read_handler && !handler) {
		TEVENT_FD_NOT_READABLE(bsds->fde);
	} else if (!sock->event.read_handler && handler) {
		TEVENT_FD_READABLE(bsds->fde);
	}

	sock->event.read_handler = handler;
	sock->event.read_private = private_data;

	return 0;
}

static int tsocket_context_bsd_set_write_handler(struct tsocket_context *sock,
						 tsocket_event_handler_t handler,
						 void *private_data)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);

	if (sock->event.write_handler && !handler) {
		TEVENT_FD_NOT_WRITEABLE(bsds->fde);
	} else if (!sock->event.write_handler && handler) {
		TEVENT_FD_WRITEABLE(bsds->fde);
	}

	sock->event.write_handler = handler;
	sock->event.write_private = private_data;

	return 0;
}

static int tsocket_context_bsd_connect_to(struct tsocket_context *sock,
					  const struct tsocket_address *remote)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	struct tsocket_address_bsd *bsda = talloc_get_type(remote->private_data,
					   struct tsocket_address_bsd);
	int ret;

	ret = connect(bsds->fd, &bsda->u.sa,
		      sizeof(bsda->u.ss));

	return ret;
}

static int tsocket_context_bsd_listen_on(struct tsocket_context *sock,
					  int queue_size)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int ret;

	ret = listen(bsds->fd, queue_size);

	return ret;
}

static int tsocket_context_bsd_accept_new(struct tsocket_context *sock,
					   TALLOC_CTX *mem_ctx,
					   struct tsocket_context **_new_sock,
					   const char *location)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int new_fd;
	struct tsocket_context *new_sock;
	struct tsocket_context_bsd *new_bsds;
	struct sockaddr_storage ss;
	void *p = &ss;
	socklen_t ss_len = sizeof(ss);

	new_fd = accept(bsds->fd, (struct sockaddr *)p, &ss_len);
	if (new_fd < 0) {
		return new_fd;
	}

	new_fd = tsocket_common_prepare_fd(new_fd, true);
	if (new_fd < 0) {
		return new_fd;
	}

	new_sock = tsocket_context_create(mem_ctx,
					  &tsocket_context_bsd_ops,
					  &new_bsds,
					  struct tsocket_context_bsd,
					  location);
	if (!new_sock) {
		int saved_errno = errno;
		close(new_fd);
		errno = saved_errno;
		return -1;
	}

	new_bsds->close_on_disconnect	= true;
	new_bsds->fd			= new_fd;
	new_bsds->fde			= NULL;

	*_new_sock = new_sock;
	return 0;
}

static ssize_t tsocket_context_bsd_pending_data(struct tsocket_context *sock)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int ret;
	int value = 0;

	ret = ioctl(bsds->fd, FIONREAD, &value);
	if (ret == -1) {
		return ret;
	}

	if (ret == 0) {
		if (value == 0) {
			int error=0;
			socklen_t len = sizeof(error);
			/*
			 * if no data is available check if the socket
			 * is in error state. For dgram sockets
			 * it's the way to return ICMP error messages
			 * of connected sockets to the caller.
			 */
			ret = getsockopt(bsds->fd, SOL_SOCKET, SO_ERROR,
					 &error, &len);
			if (ret == -1) {
				return ret;
			}
			if (error != 0) {
				errno = error;
				return -1;
			}
		}
		return value;
	}

	/* this should not be reached */
	errno = EIO;
	return -1;
}

static int tsocket_context_bsd_readv_data(struct tsocket_context *sock,
					  const struct iovec *vector,
					  size_t count)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int ret;

	ret = readv(bsds->fd, vector, count);

	return ret;
}

static int tsocket_context_bsd_writev_data(struct tsocket_context *sock,
					   const struct iovec *vector,
					   size_t count)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int ret;

	ret = writev(bsds->fd, vector, count);

	return ret;
}

static ssize_t tsocket_context_bsd_recvfrom_data(struct tsocket_context *sock,
						  uint8_t *data, size_t len,
						  TALLOC_CTX *addr_ctx,
						  struct tsocket_address **remote)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	struct tsocket_address *addr = NULL;
	struct tsocket_address_bsd *bsda;
	ssize_t ret;
	struct sockaddr *sa = NULL;
	socklen_t sa_len = 0;

	if (remote) {
		addr = tsocket_address_create(addr_ctx,
					      &tsocket_address_bsd_ops,
					      &bsda,
					      struct tsocket_address_bsd,
					      __location__ "recvfrom");
		if (!addr) {
			return -1;
		}

		ZERO_STRUCTP(bsda);

		sa = &bsda->u.sa;
		sa_len = sizeof(bsda->u.ss);
	}

	ret = recvfrom(bsds->fd, data, len, 0, sa, &sa_len);
	if (ret < 0) {
		int saved_errno = errno;
		talloc_free(addr);
		errno = saved_errno;
		return ret;
	}

	if (remote) {
		*remote = addr;
	}
	return ret;
}

static ssize_t tsocket_context_bsd_sendto_data(struct tsocket_context *sock,
						const uint8_t *data, size_t len,
						const struct tsocket_address *remote)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	struct sockaddr *sa = NULL;
	socklen_t sa_len = 0;
	ssize_t ret;

	if (remote) {
		struct tsocket_address_bsd *bsda =
			talloc_get_type(remote->private_data,
			struct tsocket_address_bsd);

		sa = &bsda->u.sa;
		sa_len = sizeof(bsda->u.ss);
	}

	ret = sendto(bsds->fd, data, len, 0, sa, sa_len);

	return ret;
}

static int tsocket_context_bsd_get_status(const struct tsocket_context *sock)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	int ret;
	int error=0;
	socklen_t len = sizeof(error);

	if (bsds->fd == -1) {
		errno = EPIPE;
		return -1;
	}

	ret = getsockopt(bsds->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (ret == -1) {
		return ret;
	}
	if (error != 0) {
		errno = error;
		return -1;
	}

	return 0;
}

static int tsocket_context_bsd_get_local_address(const struct tsocket_context *sock,
						  TALLOC_CTX *mem_ctx,
						  struct tsocket_address **_addr,
						  const char *location)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	struct tsocket_address *addr;
	struct tsocket_address_bsd *bsda;
	ssize_t ret;
	socklen_t sa_len;

	addr = tsocket_address_create(mem_ctx,
				      &tsocket_address_bsd_ops,
				      &bsda,
				      struct tsocket_address_bsd,
				      location);
	if (!addr) {
		return -1;
	}

	ZERO_STRUCTP(bsda);

	sa_len = sizeof(bsda->u.ss);
	ret = getsockname(bsds->fd, &bsda->u.sa, &sa_len);
	if (ret < 0) {
		int saved_errno = errno;
		talloc_free(addr);
		errno = saved_errno;
		return ret;
	}

	*_addr = addr;
	return 0;
}

static int tsocket_context_bsd_get_remote_address(const struct tsocket_context *sock,
						   TALLOC_CTX *mem_ctx,
						   struct tsocket_address **_addr,
						   const char *location)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	struct tsocket_address *addr;
	struct tsocket_address_bsd *bsda;
	ssize_t ret;
	socklen_t sa_len;

	addr = tsocket_address_create(mem_ctx,
				      &tsocket_address_bsd_ops,
				      &bsda,
				      struct tsocket_address_bsd,
				      location);
	if (!addr) {
		return -1;
	}

	ZERO_STRUCTP(bsda);

	sa_len = sizeof(bsda->u.ss);
	ret = getpeername(bsds->fd, &bsda->u.sa, &sa_len);
	if (ret < 0) {
		int saved_errno = errno;
		talloc_free(addr);
		errno = saved_errno;
		return ret;
	}

	*_addr = addr;
	return 0;
}

static const struct tsocket_context_bsd_option {
	const char *name;
	int level;
	int optnum;
	int optval;
} tsocket_context_bsd_options[] = {
#define TSOCKET_OPTION(_level, _optnum, _optval) { \
	.name = #_optnum, \
	.level = _level, \
	.optnum = _optnum, \
	.optval = _optval \
}
	TSOCKET_OPTION(SOL_SOCKET, SO_REUSEADDR, 0),
	TSOCKET_OPTION(SOL_SOCKET, SO_BROADCAST, 0)
};

static int tsocket_context_bsd_get_option(const struct tsocket_context *sock,
					  const char *option,
					  TALLOC_CTX *mem_ctx,
					  char **_value)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	const struct tsocket_context_bsd_option *opt = NULL;
	uint32_t i;
	int optval;
	socklen_t optval_len = sizeof(optval);
	char *value;
	int ret;

	for (i=0; i < ARRAY_SIZE(tsocket_context_bsd_options); i++) {
		if (strcmp(option, tsocket_context_bsd_options[i].name) != 0) {
			continue;
		}

		opt = &tsocket_context_bsd_options[i];
		break;
	}

	if (!opt) {
		goto nosys;
	}

	ret = getsockopt(bsds->fd, opt->level, opt->optnum,
			 (void *)&optval, &optval_len);
	if (ret != 0) {
		return ret;
	}

	if (optval_len != sizeof(optval)) {
		value = NULL;
	} if (opt->optval != 0) {
		if (optval == opt->optval) {
			value = talloc_strdup(mem_ctx, "1");
		} else {
			value = talloc_strdup(mem_ctx, "0");
		}
		if (!value) {
			goto nomem;
		}
	} else {
		value = talloc_asprintf(mem_ctx, "%d", optval);
		if (!value) {
			goto nomem;
		}
	}

	*_value = value;
	return 0;

 nomem:
	errno = ENOMEM;
	return -1;
 nosys:
	errno = ENOSYS;
	return -1;
}

static int tsocket_context_bsd_set_option(const struct tsocket_context *sock,
					  const char *option,
					  bool force,
					  const char *value)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);
	const struct tsocket_context_bsd_option *opt = NULL;
	uint32_t i;
	int optval;
	int ret;

	for (i=0; i < ARRAY_SIZE(tsocket_context_bsd_options); i++) {
		if (strcmp(option, tsocket_context_bsd_options[i].name) != 0) {
			continue;
		}

		opt = &tsocket_context_bsd_options[i];
		break;
	}

	if (!opt) {
		goto nosys;
	}

	if (value) {
		if (opt->optval != 0) {
			errno = EINVAL;
			return -1;
		}

		optval = atoi(value);
	} else {
		optval = opt->optval;
	}

	ret = setsockopt(bsds->fd, opt->level, opt->optnum,
			 (const void *)&optval, sizeof(optval));
	if (ret != 0) {
		if (!force) {
			errno = 0;
			return 0;
		}
		return ret;
	}

	return 0;

 nosys:
	if (!force) {
		return 0;
	}

	errno = ENOSYS;
	return -1;
}

static void tsocket_context_bsd_disconnect(struct tsocket_context *sock)
{
	struct tsocket_context_bsd *bsds = talloc_get_type(sock->private_data,
					   struct tsocket_context_bsd);

	tsocket_context_bsd_set_event_context(sock, NULL);

	if (bsds->fd != -1) {
		if (bsds->close_on_disconnect) {
			close(bsds->fd);
		}
		bsds->fd = -1;
	}
}

static const struct tsocket_context_ops tsocket_context_bsd_ops = {
	.name			= "bsd",

	.set_event_context	= tsocket_context_bsd_set_event_context,
	.set_read_handler	= tsocket_context_bsd_set_read_handler,
	.set_write_handler	= tsocket_context_bsd_set_write_handler,

	.connect_to		= tsocket_context_bsd_connect_to,
	.listen_on		= tsocket_context_bsd_listen_on,
	.accept_new		= tsocket_context_bsd_accept_new,

	.pending_data		= tsocket_context_bsd_pending_data,
	.readv_data		= tsocket_context_bsd_readv_data,
	.writev_data		= tsocket_context_bsd_writev_data,
	.recvfrom_data		= tsocket_context_bsd_recvfrom_data,
	.sendto_data		= tsocket_context_bsd_sendto_data,

	.get_status		= tsocket_context_bsd_get_status,
	.get_local_address	= tsocket_context_bsd_get_local_address,
	.get_remote_address	= tsocket_context_bsd_get_remote_address,

	.get_option		= tsocket_context_bsd_get_option,
	.set_option		= tsocket_context_bsd_set_option,

	.disconnect		= tsocket_context_bsd_disconnect
};
