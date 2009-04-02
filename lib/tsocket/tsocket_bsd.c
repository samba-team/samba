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
#include "system/filesys.h"
#include "system/network.h"
#include "system/filesys.h"
#include "tsocket.h"
#include "tsocket_internal.h"

static int tsocket_bsd_error_from_errno(int ret,
					int sys_errno,
					bool *retry)
{
	*retry = false;

	if (ret >= 0) {
		return 0;
	}

	if (ret != -1) {
		return EIO;
	}

	if (sys_errno == 0) {
		return EIO;
	}

	if (sys_errno == EINTR) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EINPROGRESS) {
		*retry = true;
		return sys_errno;
	}

	if (sys_errno == EAGAIN) {
		*retry = true;
		return sys_errno;
	}

#ifdef EWOULDBLOCK
	if (sys_errno == EWOULDBLOCK) {
		*retry = true;
		return sys_errno;
	}
#endif

	return sys_errno;
}

static int tsocket_bsd_common_prepare_fd(int fd, bool high_fd)
{
	int i;
	int sys_errno = 0;
	int fds[3];
	int num_fds = 0;

	int result, flags;

	if (fd == -1) {
		return -1;
	}

	/* first make a fd >= 3 */
	if (high_fd) {
		while (fd < 3) {
			fds[num_fds++] = fd;
			fd = dup(fd);
			if (fd == -1) {
				sys_errno = errno;
				break;
			}
		}
		for (i=0; i<num_fds; i++) {
			close(fds[i]);
		}
		if (fd == -1) {
			errno = sys_errno;
			return fd;
		}
	}

	/* fd should be nonblocking. */

#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	if ((flags = fcntl(fd, F_GETFL)) == -1) {
		goto fail;
	}

	flags |= FLAG_TO_SET;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		goto fail;
	}

#undef FLAG_TO_SET

	/* fd should be closed on exec() */
#ifdef FD_CLOEXEC
	result = flags = fcntl(fd, F_GETFD, 0);
	if (flags >= 0) {
		flags |= FD_CLOEXEC;
		result = fcntl(fd, F_SETFD, flags);
	}
	if (result < 0) {
		goto fail;
	}
#endif
	return fd;

 fail:
	if (fd != -1) {
		sys_errno = errno;
		close(fd);
		errno = sys_errno;
	}
	return -1;
}

static ssize_t tsocket_bsd_pending(int fd)
{
	int ret;
	int value = 0;

	ret = ioctl(fd, FIONREAD, &value);
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
			ret = getsockopt(fd, SOL_SOCKET, SO_ERROR,
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
		struct sockaddr_in in;
#ifdef HAVE_IPV6
		struct sockaddr_in6 in6;
#endif
		struct sockaddr_un un;
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
		str = inet_ntop(bsda->u.in.sin_family,
				&bsda->u.in.sin_addr,
				addr_str, sizeof(addr_str));
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		str = inet_ntop(bsda->u.in6.sin6_family,
				&bsda->u.in6.sin6_addr,
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
		port = ntohs(bsda->u.in.sin_port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		port = ntohs(bsda->u.in6.sin6_port);
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
		bsda->u.in.sin_port = htons(port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		bsda->u.in6.sin6_port = htons(port);
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
	struct sockaddr_un un;
	void *p = &un;
	int ret;

	if (!path) {
		path = "";
	}

	ZERO_STRUCT(un);
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, path, sizeof(un.sun_path));

	ret = _tsocket_address_bsd_from_sockaddr(mem_ctx,
						 (struct sockaddr *)p,
						 sizeof(un),
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
		str = bsda->u.un.sun_path;
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
				       bsda->u.un.sun_path);
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
		if (bsda->u.un.sun_path[0] != 0) {
			do_bind = true;
		}
		break;
	case AF_INET:
		if (bsda->u.in.sin_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (bsda->u.in.sin_addr.s_addr == INADDR_ANY) {
			do_bind = true;
		}
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (bsda->u.in6.sin6_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (memcmp(&in6addr_any,
			   &bsda->u.in6.sin6_addr,
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

struct tdgram_bsd {
	int fd;

	void *event_ptr;
	struct tevent_fd *fde;

	void *readable_private;
	void (*readable_handler)(void *private_data);
	void *writeable_private;
	void (*writeable_handler)(void *private_data);

	struct tevent_req *read_req;
	struct tevent_req *write_req;
};

static void tdgram_bsd_fde_handler(struct tevent_context *ev,
				   struct tevent_fd *fde,
				   uint16_t flags,
				   void *private_data)
{
	struct tdgram_bsd *bsds = talloc_get_type_abort(private_data,
				  struct tdgram_bsd);

	if (flags & TEVENT_FD_WRITE) {
		bsds->writeable_handler(bsds->writeable_private);
		return;
	}
	if (flags & TEVENT_FD_READ) {
		if (!bsds->readable_handler) {
			TEVENT_FD_NOT_READABLE(bsds->fde);
			return;
		}
		bsds->readable_handler(bsds->readable_private);
		return;
	}
}

static int tdgram_bsd_set_readable_handler(struct tdgram_bsd *bsds,
					   struct tevent_context *ev,
					   void (*handler)(void *private_data),
					   void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->readable_handler) {
			return 0;
		}
		bsds->readable_handler = NULL;
		bsds->readable_private = NULL;

		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
	}

	if (bsds->fde == NULL) {
		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd, TEVENT_FD_READ,
					  tdgram_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->readable_handler) {
		TEVENT_FD_READABLE(bsds->fde);
	}

	bsds->readable_handler = handler;
	bsds->readable_private = private_data;

	return 0;
}

static int tdgram_bsd_set_writeable_handler(struct tdgram_bsd *bsds,
					    struct tevent_context *ev,
					    void (*handler)(void *private_data),
					    void *private_data)
{
	if (ev == NULL) {
		if (handler) {
			errno = EINVAL;
			return -1;
		}
		if (!bsds->writeable_handler) {
			return 0;
		}
		bsds->writeable_handler = NULL;
		bsds->writeable_private = NULL;
		TEVENT_FD_NOT_WRITEABLE(bsds->fde);

		return 0;
	}

	/* read and write must use the same tevent_context */
	if (bsds->event_ptr != ev) {
		if (bsds->readable_handler || bsds->writeable_handler) {
			errno = EINVAL;
			return -1;
		}
		bsds->event_ptr = NULL;
		TALLOC_FREE(bsds->fde);
	}

	if (bsds->fde == NULL) {
		bsds->fde = tevent_add_fd(ev, bsds,
					  bsds->fd, TEVENT_FD_WRITE,
					  tdgram_bsd_fde_handler,
					  bsds);
		if (!bsds->fde) {
			return -1;
		}

		/* cache the event context we're running on */
		bsds->event_ptr = ev;
	} else if (!bsds->writeable_handler) {
		TEVENT_FD_WRITEABLE(bsds->fde);
	}

	bsds->writeable_handler = handler;
	bsds->writeable_private = private_data;

	return 0;
}

struct tdgram_bsd_recvfrom_state {
	struct tdgram_context *dgram;

	uint8_t *buf;
	size_t len;
	struct tsocket_address *src;
};

static int tdgram_bsd_recvfrom_destructor(struct tdgram_bsd_recvfrom_state *state)
{
	struct tdgram_bsd *bsds = tdgram_context_data(state->dgram,
				  struct tdgram_bsd);

	bsds->read_req = NULL;
	tdgram_bsd_set_readable_handler(bsds, NULL, NULL, NULL);

	return 0;
}

static void tdgram_bsd_recvfrom_handler(void *private_data);

static struct tevent_req *tdgram_bsd_recvfrom_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tdgram_context *dgram)
{
	struct tevent_req *req;
	struct tdgram_bsd_recvfrom_state *state;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_recvfrom_state);
	if (!req) {
		return NULL;
	}

	state->dgram	= dgram;
	state->buf	= NULL;
	state->len	= 0;
	state->src	= NULL;

	if (bsds->read_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	bsds->read_req = req;

	talloc_set_destructor(state, tdgram_bsd_recvfrom_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit readable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	tdgram_bsd_recvfrom_handler(req);
	if (!tevent_req_is_in_progress(req)) {
		goto post;
	}

	ret = tdgram_bsd_set_readable_handler(bsds, ev,
					      tdgram_bsd_recvfrom_handler,
					      req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_bsd_recvfrom_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tdgram_bsd_recvfrom_state *state = tevent_req_data(req,
					struct tdgram_bsd_recvfrom_state);
	struct tdgram_context *dgram = state->dgram;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct tsocket_address_bsd *bsda;
	ssize_t ret;
	struct sockaddr *sa = NULL;
	socklen_t sa_len = 0;
	int err;
	bool retry;

	ret = tsocket_bsd_pending(bsds->fd);
	if (ret == 0) {
		/* retry later */
		return;
	}
	err = tsocket_bsd_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->buf = talloc_array(state, uint8_t, ret);
	if (tevent_req_nomem(state->buf, req)) {
		return;
	}
	state->len = ret;

	state->src = tsocket_address_create(state,
					    &tsocket_address_bsd_ops,
					    &bsda,
					    struct tsocket_address_bsd,
					    __location__ "bsd_recvfrom");
	if (tevent_req_nomem(state->src, req)) {
		return;
	}

	ZERO_STRUCTP(bsda);

	sa = &bsda->u.sa;
	sa_len = sizeof(bsda->u.ss);

	ret = recvfrom(bsds->fd, state->buf, state->len, 0, sa, &sa_len);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	if (ret != state->len) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

static ssize_t tdgram_bsd_recvfrom_recv(struct tevent_req *req,
					int *perrno,
					TALLOC_CTX *mem_ctx,
					uint8_t **buf,
					struct tsocket_address **src)
{
	struct tdgram_bsd_recvfrom_state *state = tevent_req_data(req,
					struct tdgram_bsd_recvfrom_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		*buf = talloc_move(mem_ctx, &state->buf);
		ret = state->len;
		if (src) {
			*src = talloc_move(mem_ctx, &state->src);
		}
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_bsd_sendto_state {
	struct tdgram_context *dgram;

	const uint8_t *buf;
	size_t len;
	const struct tsocket_address *dst;

	ssize_t ret;
};

static int tdgram_bsd_sendto_destructor(struct tdgram_bsd_sendto_state *state)
{
	struct tdgram_bsd *bsds = tdgram_context_data(state->dgram,
				  struct tdgram_bsd);

	bsds->write_req = NULL;
	tdgram_bsd_set_writeable_handler(bsds, NULL, NULL, NULL);
	return 0;
}

static void tdgram_bsd_sendto_handler(void *private_data);

static struct tevent_req *tdgram_bsd_sendto_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 struct tdgram_context *dgram,
						 const uint8_t *buf,
						 size_t len,
						 const struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tdgram_bsd_sendto_state *state;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_sendto_state);
	if (!req) {
		return NULL;
	}

	state->dgram	= dgram;
	state->buf	= buf;
	state->len	= len;
	state->dst	= dst;
	state->ret	= -1;

	if (bsds->write_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	bsds->write_req = req;

	talloc_set_destructor(state, tdgram_bsd_sendto_destructor);

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	/*
	 * this is a fast path, not waiting for the
	 * socket to become explicit writeable gains
	 * about 10%-20% performance in benchmark tests.
	 */
	tdgram_bsd_sendto_handler(req);
	if (!tevent_req_is_in_progress(req)) {
		goto post;
	}

	ret = tdgram_bsd_set_writeable_handler(bsds, ev,
					       tdgram_bsd_sendto_handler,
					       req);
	if (ret == -1) {
		tevent_req_error(req, errno);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_bsd_sendto_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(private_data,
				 struct tevent_req);
	struct tdgram_bsd_sendto_state *state = tevent_req_data(req,
					struct tdgram_bsd_sendto_state);
	struct tdgram_context *dgram = state->dgram;
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct sockaddr *sa = NULL;
	socklen_t sa_len = 0;
	ssize_t ret;
	int err;
	bool retry;

	if (state->dst) {
		struct tsocket_address_bsd *bsda =
			talloc_get_type(state->dst->private_data,
			struct tsocket_address_bsd);

		sa = &bsda->u.sa;
		sa_len = sizeof(bsda->u.ss);
	}

	ret = sendto(bsds->fd, state->buf, state->len, 0, sa, sa_len);
	err = tsocket_error_from_errno(ret, errno, &retry);
	if (retry) {
		/* retry later */
		return;
	}
	if (tevent_req_error(req, err)) {
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

static ssize_t tdgram_bsd_sendto_recv(struct tevent_req *req, int *perrno)
{
	struct tdgram_bsd_sendto_state *state = tevent_req_data(req,
					struct tdgram_bsd_sendto_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_bsd_disconnect_state {
	int ret;
};

static struct tevent_req *tdgram_bsd_disconnect_send(TALLOC_CTX *mem_ctx,
						     struct tevent_context *ev,
						     struct tdgram_context *dgram)
{
	struct tdgram_bsd *bsds = tdgram_context_data(dgram, struct tdgram_bsd);
	struct tevent_req *req;
	struct tdgram_bsd_disconnect_state *state;
	int ret;
	int err;
	bool dummy;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_bsd_disconnect_state);
	if (req == NULL) {
		return NULL;
	}
	state->ret = -1;

	if (bsds->read_req || bsds->write_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}

	if (bsds->fd == -1) {
		tevent_req_error(req, ENOTCONN);
		goto post;
	}

	state->ret = close(bsds->fd);
	bsds->fd = -1;
	err = tsocket_error_from_errno(ret, errno, &dummy);
	if (tevent_req_error(req, err)) {
		goto post;
	}

	tevent_req_done(req);
post:
	tevent_req_post(req, ev);
	return req;
}

static int tdgram_bsd_disconnect_recv(struct tevent_req *req,
				      int *perrno)
{
	struct tdgram_bsd_disconnect_state *state = tevent_req_data(req,
					struct tdgram_bsd_disconnect_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

static const struct tdgram_context_ops tdgram_bsd_ops = {
	.name			= "bsd",

	.recvfrom_send		= tdgram_bsd_recvfrom_send,
	.recvfrom_recv		= tdgram_bsd_recvfrom_recv,

	.sendto_send		= tdgram_bsd_sendto_send,
	.sendto_recv		= tdgram_bsd_sendto_recv,

	.disconnect_send	= tdgram_bsd_disconnect_send,
	.disconnect_recv	= tdgram_bsd_disconnect_recv,
};

static int tdgram_bsd_destructor(struct tdgram_bsd *bsds)
{
	TALLOC_FREE(bsds->fde);
	if (bsds->fd != -1) {
		close(bsds->fd);
		bsds->fd = -1;
	}
	return 0;
}

static int tdgram_bsd_dgram_socket(const struct tsocket_address *local,
				   const struct tsocket_address *remote,
				   TALLOC_CTX *mem_ctx,
				   struct tdgram_context **_dgram,
				   const char *location)
{
	struct tsocket_address_bsd *lbsda =
		talloc_get_type_abort(local->private_data,
		struct tsocket_address_bsd);
	struct tsocket_address_bsd *rbsda = NULL;
	struct tdgram_context *dgram;
	struct tdgram_bsd *bsds;
	int fd;
	int ret;
	bool do_bind = false;
	bool do_reuseaddr = false;

	if (remote) {
		rbsda = talloc_get_type_abort(remote->private_data,
			struct tsocket_address_bsd);
	}

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		if (lbsda->u.un.sun_path[0] != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		break;
	case AF_INET:
		if (lbsda->u.in.sin_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (lbsda->u.in.sin_addr.s_addr == INADDR_ANY) {
			do_bind = true;
		}
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (lbsda->u.in6.sin6_port != 0) {
			do_reuseaddr = true;
			do_bind = true;
		}
		if (memcmp(&in6addr_any,
			   &lbsda->u.in6.sin6_addr,
			   sizeof(in6addr_any)) != 0) {
			do_bind = true;
		}
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	fd = socket(lbsda->u.sa.sa_family, SOCK_DGRAM, 0);
	if (fd < 0) {
		return fd;
	}

	fd = tsocket_bsd_common_prepare_fd(fd, true);
	if (fd < 0) {
		return fd;
	}

	dgram = tdgram_context_create(mem_ctx,
				      &tdgram_bsd_ops,
				      &bsds,
				      struct tdgram_bsd,
				      location);
	if (!dgram) {
		int saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	ZERO_STRUCTP(bsds);
	bsds->fd = fd;
	talloc_set_destructor(bsds, tdgram_bsd_destructor);

	if (lbsda->broadcast) {
		int val = 1;

		ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return ret;
		}
	}

	if (do_reuseaddr) {
		int val = 1;

		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
				 (const void *)&val, sizeof(val));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return ret;
		}
	}

	if (do_bind) {
		ret = bind(fd, &lbsda->u.sa, sizeof(lbsda->u.ss));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return ret;
		}
	}

	if (rbsda) {
		ret = connect(fd, &rbsda->u.sa, sizeof(rbsda->u.ss));
		if (ret == -1) {
			int saved_errno = errno;
			talloc_free(dgram);
			errno = saved_errno;
			return ret;
		}
	}

	*_dgram = dgram;
	return 0;
}

int _tdgram_inet_udp_socket(const struct tsocket_address *local,
			    const struct tsocket_address *remote,
			    TALLOC_CTX *mem_ctx,
			    struct tdgram_context **dgram,
			    const char *location)
{
	struct tsocket_address_bsd *lbsda =
		talloc_get_type_abort(local->private_data,
		struct tsocket_address_bsd);
	int ret;

	switch (lbsda->u.sa.sa_family) {
	case AF_INET:
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		break;
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	ret = tdgram_bsd_dgram_socket(local, remote, mem_ctx, dgram, location);

	return ret;
}

int _tdgram_unix_dgram_socket(const struct tsocket_address *local,
			      const struct tsocket_address *remote,
			      TALLOC_CTX *mem_ctx,
			      struct tdgram_context **dgram,
			      const char *location)
{
	struct tsocket_address_bsd *lbsda =
		talloc_get_type_abort(local->private_data,
		struct tsocket_address_bsd);
	int ret;

	switch (lbsda->u.sa.sa_family) {
	case AF_UNIX:
		break;
	default:
		errno = EINVAL;
		return -1;
	}

	ret = tdgram_bsd_dgram_socket(local, remote, mem_ctx, dgram, location);

	return ret;
}

