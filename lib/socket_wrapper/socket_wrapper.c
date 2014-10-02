/*
 * Copyright (c) 2005-2008 Jelmer Vernooij <jelmer@samba.org>
 * Copyright (C) 2006-2014 Stefan Metzmacher <metze@samba.org>
 * Copyright (C) 2013-2014 Andreas Schneider <asn@samba.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
   Socket wrapper library. Passes all socket communication over
   unix domain sockets if the environment variable SOCKET_WRAPPER_DIR
   is set.
*/

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_SIGNALFD_H
#include <sys/signalfd.h>
#endif
#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif
#ifdef HAVE_SYS_TIMERFD_H
#include <sys/timerfd.h>
#endif
#include <sys/uio.h>
#include <errno.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#ifdef HAVE_GNU_LIB_NAMES_H
#include <gnu/lib-names.h>
#endif
#ifdef HAVE_RPC_RPC_H
#include <rpc/rpc.h>
#endif

enum swrap_dbglvl_e {
	SWRAP_LOG_ERROR = 0,
	SWRAP_LOG_WARN,
	SWRAP_LOG_DEBUG,
	SWRAP_LOG_TRACE
};

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define SWRAP_THREAD __thread
#else
# define SWRAP_THREAD
#endif

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

#ifndef ZERO_STRUCTP
#define ZERO_STRUCTP(x) do { \
		if ((x) != NULL) \
			memset((char *)(x), 0, sizeof(*(x))); \
	} while(0)
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#ifdef IPV6_PKTINFO
# ifndef IPV6_RECVPKTINFO
#  define IPV6_RECVPKTINFO IPV6_PKTINFO
# endif /* IPV6_RECVPKTINFO */
#endif /* IPV6_PKTINFO */

/*
 * On BSD IP_PKTINFO has a different name because during
 * the time when they implemented it, there was no RFC.
 * The name for IPv6 is the same as on Linux.
 */
#ifndef IP_PKTINFO
# ifdef IP_RECVDSTADDR
#  define IP_PKTINFO IP_RECVDSTADDR
# endif
#endif


#define SWRAP_DLIST_ADD(list,item) do { \
	if (!(list)) { \
		(item)->prev	= NULL; \
		(item)->next	= NULL; \
		(list)		= (item); \
	} else { \
		(item)->prev	= NULL; \
		(item)->next	= (list); \
		(list)->prev	= (item); \
		(list)		= (item); \
	} \
} while (0)

#define SWRAP_DLIST_REMOVE(list,item) do { \
	if ((list) == (item)) { \
		(list)		= (item)->next; \
		if (list) { \
			(list)->prev	= NULL; \
		} \
	} else { \
		if ((item)->prev) { \
			(item)->prev->next	= (item)->next; \
		} \
		if ((item)->next) { \
			(item)->next->prev	= (item)->prev; \
		} \
	} \
	(item)->prev	= NULL; \
	(item)->next	= NULL; \
} while (0)

#if defined(HAVE_GETTIMEOFDAY_TZ) || defined(HAVE_GETTIMEOFDAY_TZ_VOID)
#define swrapGetTimeOfDay(tval) gettimeofday(tval,NULL)
#else
#define swrapGetTimeOfDay(tval)	gettimeofday(tval)
#endif

/* we need to use a very terse format here as IRIX 6.4 silently
   truncates names to 16 chars, so if we use a longer name then we
   can't tell which port a packet came from with recvfrom()

   with this format we have 8 chars left for the directory name
*/
#define SOCKET_FORMAT "%c%02X%04X"
#define SOCKET_TYPE_CHAR_TCP		'T'
#define SOCKET_TYPE_CHAR_UDP		'U'
#define SOCKET_TYPE_CHAR_TCP_V6		'X'
#define SOCKET_TYPE_CHAR_UDP_V6		'Y'

/*
 * Cut down to 1500 byte packets for stream sockets,
 * which makes it easier to format PCAP capture files
 * (as the caller will simply continue from here)
 */
#define SOCKET_MAX_PACKET 1500

#define SOCKET_MAX_SOCKETS 1024

/* This limit is to avoid broadcast sendto() needing to stat too many
 * files.  It may be raised (with a performance cost) to up to 254
 * without changing the format above */
#define MAX_WRAPPED_INTERFACES 40

struct swrap_address {
	socklen_t sa_socklen;
	union {
		struct sockaddr s;
		struct sockaddr_in in;
#ifdef HAVE_IPV6
		struct sockaddr_in6 in6;
#endif
		struct sockaddr_un un;
		struct sockaddr_storage ss;
	} sa;
};

struct socket_info_fd {
	struct socket_info_fd *prev, *next;
	int fd;
};

struct socket_info
{
	struct socket_info_fd *fds;

	int family;
	int type;
	int protocol;
	int bound;
	int bcast;
	int is_server;
	int connected;
	int defer_connect;
	int pktinfo;

	/* The unix path so we can unlink it on close() */
	struct sockaddr_un un_addr;

	struct swrap_address bindname;
	struct swrap_address myname;
	struct swrap_address peername;

	struct {
		unsigned long pck_snd;
		unsigned long pck_rcv;
	} io;

	struct socket_info *prev, *next;
};

/*
 * File descriptors are shared between threads so we should share socket
 * information too.
 */
struct socket_info *sockets;

/* Function prototypes */

bool socket_wrapper_enabled(void);
void swrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

#ifdef NDEBUG
# define SWRAP_LOG(...)
#else

static void swrap_log(enum swrap_dbglvl_e dbglvl, const char *func, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define SWRAP_LOG(dbglvl, ...) swrap_log((dbglvl), __func__, __VA_ARGS__)

static void swrap_log(enum swrap_dbglvl_e dbglvl,
		      const char *func,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;

	d = getenv("SOCKET_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		switch (dbglvl) {
			case SWRAP_LOG_ERROR:
				fprintf(stderr,
					"SWRAP_ERROR(%d) - %s: %s\n",
					(int)getpid(), func, buffer);
				break;
			case SWRAP_LOG_WARN:
				fprintf(stderr,
					"SWRAP_WARN(%d) - %s: %s\n",
					(int)getpid(), func, buffer);
				break;
			case SWRAP_LOG_DEBUG:
				fprintf(stderr,
					"SWRAP_DEBUG(%d) - %s: %s\n",
					(int)getpid(), func, buffer);
				break;
			case SWRAP_LOG_TRACE:
				fprintf(stderr,
					"SWRAP_TRACE(%d) - %s: %s\n",
					(int)getpid(), func, buffer);
				break;
		}
	}
}
#endif

/*********************************************************
 * SWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

struct swrap_libc_fns {
	int (*libc_accept)(int sockfd,
			   struct sockaddr *addr,
			   socklen_t *addrlen);
	int (*libc_bind)(int sockfd,
			 const struct sockaddr *addr,
			 socklen_t addrlen);
	int (*libc_close)(int fd);
	int (*libc_connect)(int sockfd,
			    const struct sockaddr *addr,
			    socklen_t addrlen);
	int (*libc_dup)(int fd);
	int (*libc_dup2)(int oldfd, int newfd);
	int (*libc_fcntl)(int fd, int cmd, ...);
	FILE *(*libc_fopen)(const char *name, const char *mode);
#ifdef HAVE_EVENTFD
	int (*libc_eventfd)(int count, int flags);
#endif
	int (*libc_getpeername)(int sockfd,
				struct sockaddr *addr,
				socklen_t *addrlen);
	int (*libc_getsockname)(int sockfd,
				struct sockaddr *addr,
				socklen_t *addrlen);
	int (*libc_getsockopt)(int sockfd,
			       int level,
			       int optname,
			       void *optval,
			       socklen_t *optlen);
	int (*libc_ioctl)(int d, unsigned long int request, ...);
	int (*libc_listen)(int sockfd, int backlog);
	int (*libc_open)(const char *pathname, int flags, mode_t mode);
	int (*libc_pipe)(int pipefd[2]);
	int (*libc_read)(int fd, void *buf, size_t count);
	ssize_t (*libc_readv)(int fd, const struct iovec *iov, int iovcnt);
	int (*libc_recv)(int sockfd, void *buf, size_t len, int flags);
	int (*libc_recvfrom)(int sockfd,
			     void *buf,
			     size_t len,
			     int flags,
			     struct sockaddr *src_addr,
			     socklen_t *addrlen);
	int (*libc_recvmsg)(int sockfd, const struct msghdr *msg, int flags);
	int (*libc_send)(int sockfd, const void *buf, size_t len, int flags);
	int (*libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
	int (*libc_sendto)(int sockfd,
			   const void *buf,
			   size_t len,
			   int flags,
			   const  struct sockaddr *dst_addr,
			   socklen_t addrlen);
	int (*libc_setsockopt)(int sockfd,
			       int level,
			       int optname,
			       const void *optval,
			       socklen_t optlen);
#ifdef HAVE_SIGNALFD
	int (*libc_signalfd)(int fd, const sigset_t *mask, int flags);
#endif
	int (*libc_socket)(int domain, int type, int protocol);
	int (*libc_socketpair)(int domain, int type, int protocol, int sv[2]);
#ifdef HAVE_TIMERFD_CREATE
	int (*libc_timerfd_create)(int clockid, int flags);
#endif
	ssize_t (*libc_writev)(int fd, const struct iovec *iov, int iovcnt);
};

struct swrap {
	void *libc_handle;
	void *libsocket_handle;

	bool initialised;
	bool enabled;

	char *socket_dir;

	struct swrap_libc_fns fns;
};

static struct swrap swrap;

/* prototypes */
static const char *socket_wrapper_dir(void);

#define LIBC_NAME "libc.so"

enum swrap_lib {
    SWRAP_LIBC,
    SWRAP_LIBNSL,
    SWRAP_LIBSOCKET,
};

#ifndef NDEBUG
static const char *swrap_str_lib(enum swrap_lib lib)
{
	switch (lib) {
	case SWRAP_LIBC:
		return "libc";
	case SWRAP_LIBNSL:
		return "libnsl";
	case SWRAP_LIBSOCKET:
		return "libsocket";
	}

	/* Compiler would warn us about unhandled enum value if we get here */
	return "unknown";
}
#endif

static void *swrap_load_lib_handle(enum swrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case SWRAP_LIBNSL:
		/* FALL TROUGH */
	case SWRAP_LIBSOCKET:
#ifdef HAVE_LIBSOCKET
		handle = swrap.libsocket_handle;
		if (handle == NULL) {
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libsocket.so.%d", i);
				handle = dlopen(soname, flags);
			}

			swrap.libsocket_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case SWRAP_LIBC:
		handle = swrap.libc_handle;
#ifdef LIBC_SO
		if (handle == NULL) {
			handle = dlopen(LIBC_SO, flags);

			swrap.libc_handle = handle;
		}
#endif
		if (handle == NULL) {
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
			}

			swrap.libc_handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = swrap.libc_handle = swrap.libsocket_handle = RTLD_NEXT;
#else
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_swrap_load_lib_function(enum swrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = swrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
				"Failed to find %s: %s\n",
				fn_name, dlerror());
		exit(-1);
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
			"Loaded %s from %s",
			fn_name, swrap_str_lib(lib));
	return func;
}

#define swrap_load_lib_function(lib, fn_name) \
	if (swrap.fns.libc_##fn_name == NULL) { \
		void *swrap_cast_ptr = _swrap_load_lib_function(lib, #fn_name); \
		*(void **) (&swrap.fns.libc_##fn_name) = \
			swrap_cast_ptr; \
	}


/*
 * IMPORTANT
 *
 * Functions especially from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
static int libc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, accept);

	return swrap.fns.libc_accept(sockfd, addr, addrlen);
}

static int libc_bind(int sockfd,
		     const struct sockaddr *addr,
		     socklen_t addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, bind);

	return swrap.fns.libc_bind(sockfd, addr, addrlen);
}

static int libc_close(int fd)
{
	swrap_load_lib_function(SWRAP_LIBC, close);

	return swrap.fns.libc_close(fd);
}

static int libc_connect(int sockfd,
			const struct sockaddr *addr,
			socklen_t addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, connect);

	return swrap.fns.libc_connect(sockfd, addr, addrlen);
}

static int libc_dup(int fd)
{
	swrap_load_lib_function(SWRAP_LIBC, dup);

	return swrap.fns.libc_dup(fd);
}

static int libc_dup2(int oldfd, int newfd)
{
	swrap_load_lib_function(SWRAP_LIBC, dup2);

	return swrap.fns.libc_dup2(oldfd, newfd);
}

#ifdef HAVE_EVENTFD
static int libc_eventfd(int count, int flags)
{
	swrap_load_lib_function(SWRAP_LIBC, eventfd);

	return swrap.fns.libc_eventfd(count, flags);
}
#endif

static int libc_vfcntl(int fd, int cmd, va_list ap)
{
	long int args[4];
	int rc;
	int i;

	swrap_load_lib_function(SWRAP_LIBC, fcntl);

	for (i = 0; i < 4; i++) {
		args[i] = va_arg(ap, long int);
	}

	rc = swrap.fns.libc_fcntl(fd,
				  cmd,
				  args[0],
				  args[1],
				  args[2],
				  args[3]);

	return rc;
}

static int libc_getpeername(int sockfd,
			    struct sockaddr *addr,
			    socklen_t *addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, getpeername);

	return swrap.fns.libc_getpeername(sockfd, addr, addrlen);
}

static int libc_getsockname(int sockfd,
			    struct sockaddr *addr,
			    socklen_t *addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, getsockname);

	return swrap.fns.libc_getsockname(sockfd, addr, addrlen);
}

static int libc_getsockopt(int sockfd,
			   int level,
			   int optname,
			   void *optval,
			   socklen_t *optlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, getsockopt);

	return swrap.fns.libc_getsockopt(sockfd, level, optname, optval, optlen);
}

static int libc_vioctl(int d, unsigned long int request, va_list ap)
{
	long int args[4];
	int rc;
	int i;

	swrap_load_lib_function(SWRAP_LIBC, ioctl);

	for (i = 0; i < 4; i++) {
		args[i] = va_arg(ap, long int);
	}

	rc = swrap.fns.libc_ioctl(d,
				  request,
				  args[0],
				  args[1],
				  args[2],
				  args[3]);

	return rc;
}

static int libc_listen(int sockfd, int backlog)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, listen);

	return swrap.fns.libc_listen(sockfd, backlog);
}

static FILE *libc_fopen(const char *name, const char *mode)
{
	swrap_load_lib_function(SWRAP_LIBC, fopen);

	return swrap.fns.libc_fopen(name, mode);
}

static int libc_vopen(const char *pathname, int flags, va_list ap)
{
	long int mode = 0;
	int fd;

	swrap_load_lib_function(SWRAP_LIBC, open);

	mode = va_arg(ap, long int);

	fd = swrap.fns.libc_open(pathname, flags, (mode_t)mode);

	return fd;
}

static int libc_open(const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = libc_vopen(pathname, flags, ap);
	va_end(ap);

	return fd;
}

static int libc_pipe(int pipefd[2])
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, pipe);

	return swrap.fns.libc_pipe(pipefd);
}

static int libc_read(int fd, void *buf, size_t count)
{
	swrap_load_lib_function(SWRAP_LIBC, read);

	return swrap.fns.libc_read(fd, buf, count);
}

static ssize_t libc_readv(int fd, const struct iovec *iov, int iovcnt)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, readv);

	return swrap.fns.libc_readv(fd, iov, iovcnt);
}

static int libc_recv(int sockfd, void *buf, size_t len, int flags)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, recv);

	return swrap.fns.libc_recv(sockfd, buf, len, flags);
}

static int libc_recvfrom(int sockfd,
			 void *buf,
			 size_t len,
			 int flags,
			 struct sockaddr *src_addr,
			 socklen_t *addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, recvfrom);

	return swrap.fns.libc_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

static int libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, recvmsg);

	return swrap.fns.libc_recvmsg(sockfd, msg, flags);
}

static int libc_send(int sockfd, const void *buf, size_t len, int flags)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, send);

	return swrap.fns.libc_send(sockfd, buf, len, flags);
}

static int libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, sendmsg);

	return swrap.fns.libc_sendmsg(sockfd, msg, flags);
}

static int libc_sendto(int sockfd,
		       const void *buf,
		       size_t len,
		       int flags,
		       const  struct sockaddr *dst_addr,
		       socklen_t addrlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, sendto);

	return swrap.fns.libc_sendto(sockfd, buf, len, flags, dst_addr, addrlen);
}

static int libc_setsockopt(int sockfd,
			   int level,
			   int optname,
			   const void *optval,
			   socklen_t optlen)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, setsockopt);

	return swrap.fns.libc_setsockopt(sockfd, level, optname, optval, optlen);
}

#ifdef HAVE_SIGNALFD
static int libc_signalfd(int fd, const sigset_t *mask, int flags)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, signalfd);

	return swrap.fns.libc_signalfd(fd, mask, flags);
}
#endif

static int libc_socket(int domain, int type, int protocol)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, socket);

	return swrap.fns.libc_socket(domain, type, protocol);
}

static int libc_socketpair(int domain, int type, int protocol, int sv[2])
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, socketpair);

	return swrap.fns.libc_socketpair(domain, type, protocol, sv);
}

#ifdef HAVE_TIMERFD_CREATE
static int libc_timerfd_create(int clockid, int flags)
{
	swrap_load_lib_function(SWRAP_LIBC, timerfd_create);

	return swrap.fns.libc_timerfd_create(clockid, flags);
}
#endif

static ssize_t libc_writev(int fd, const struct iovec *iov, int iovcnt)
{
	swrap_load_lib_function(SWRAP_LIBSOCKET, writev);

	return swrap.fns.libc_writev(fd, iov, iovcnt);
}

/*********************************************************
 * SWRAP HELPER FUNCTIONS
 *********************************************************/

#ifdef HAVE_IPV6
/*
 * FD00::5357:5FXX
 */
static const struct in6_addr *swrap_ipv6(void)
{
	static struct in6_addr v;
	static int initialized;
	int ret;

	if (initialized) {
		return &v;
	}
	initialized = 1;

	ret = inet_pton(AF_INET6, "FD00::5357:5F00", &v);
	if (ret <= 0) {
		abort();
	}

	return &v;
}
#endif

static void set_port(int family, int prt, struct swrap_address *addr)
{
	switch (family) {
	case AF_INET:
		addr->sa.in.sin_port = htons(prt);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		addr->sa.in6.sin6_port = htons(prt);
		break;
#endif
	}
}

static size_t socket_length(int family)
{
	switch (family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
#ifdef HAVE_IPV6
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
#endif
	}
	return 0;
}

static const char *socket_wrapper_dir(void)
{
	const char *s = getenv("SOCKET_WRAPPER_DIR");
	if (s == NULL) {
		return NULL;
	}
	/* TODO use realpath(3) here, when we add support for threads */
	if (strncmp(s, "./", 2) == 0) {
		s += 2;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE, "socket_wrapper_dir: %s", s);
	return s;
}

bool socket_wrapper_enabled(void)
{
	const char *s = socket_wrapper_dir();

	return s != NULL ? true : false;
}

static unsigned int socket_wrapper_default_iface(void)
{
	const char *s = getenv("SOCKET_WRAPPER_DEFAULT_IFACE");
	if (s) {
		unsigned int iface;
		if (sscanf(s, "%u", &iface) == 1) {
			if (iface >= 1 && iface <= MAX_WRAPPED_INTERFACES) {
				return iface;
			}
		}
	}

	return 1;/* 127.0.0.1 */
}

static int convert_un_in(const struct sockaddr_un *un, struct sockaddr *in, socklen_t *len)
{
	unsigned int iface;
	unsigned int prt;
	const char *p;
	char type;

	p = strrchr(un->sun_path, '/');
	if (p) p++; else p = un->sun_path;

	if (sscanf(p, SOCKET_FORMAT, &type, &iface, &prt) != 3) {
		errno = EINVAL;
		return -1;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE, "type %c iface %u port %u",
			type, iface, prt);

	if (iface == 0 || iface > MAX_WRAPPED_INTERFACES) {
		errno = EINVAL;
		return -1;
	}

	if (prt > 0xFFFF) {
		errno = EINVAL;
		return -1;
	}

	switch(type) {
	case SOCKET_TYPE_CHAR_TCP:
	case SOCKET_TYPE_CHAR_UDP: {
		struct sockaddr_in *in2 = (struct sockaddr_in *)(void *)in;

		if ((*len) < sizeof(*in2)) {
		    errno = EINVAL;
		    return -1;
		}

		memset(in2, 0, sizeof(*in2));
		in2->sin_family = AF_INET;
		in2->sin_addr.s_addr = htonl((127<<24) | iface);
		in2->sin_port = htons(prt);

		*len = sizeof(*in2);
		break;
	}
#ifdef HAVE_IPV6
	case SOCKET_TYPE_CHAR_TCP_V6:
	case SOCKET_TYPE_CHAR_UDP_V6: {
		struct sockaddr_in6 *in2 = (struct sockaddr_in6 *)(void *)in;

		if ((*len) < sizeof(*in2)) {
			errno = EINVAL;
			return -1;
		}

		memset(in2, 0, sizeof(*in2));
		in2->sin6_family = AF_INET6;
		in2->sin6_addr = *swrap_ipv6();
		in2->sin6_addr.s6_addr[15] = iface;
		in2->sin6_port = htons(prt);

		*len = sizeof(*in2);
		break;
	}
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static int convert_in_un_remote(struct socket_info *si, const struct sockaddr *inaddr, struct sockaddr_un *un,
				int *bcast)
{
	char type = '\0';
	unsigned int prt;
	unsigned int iface;
	int is_bcast = 0;

	if (bcast) *bcast = 0;

	switch (inaddr->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *in =
		    (const struct sockaddr_in *)(const void *)inaddr;
		unsigned int addr = ntohl(in->sin_addr.s_addr);
		char u_type = '\0';
		char b_type = '\0';
		char a_type = '\0';

		switch (si->type) {
		case SOCK_STREAM:
			u_type = SOCKET_TYPE_CHAR_TCP;
			break;
		case SOCK_DGRAM:
			u_type = SOCKET_TYPE_CHAR_UDP;
			a_type = SOCKET_TYPE_CHAR_UDP;
			b_type = SOCKET_TYPE_CHAR_UDP;
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		prt = ntohs(in->sin_port);
		if (a_type && addr == 0xFFFFFFFF) {
			/* 255.255.255.255 only udp */
			is_bcast = 2;
			type = a_type;
			iface = socket_wrapper_default_iface();
		} else if (b_type && addr == 0x7FFFFFFF) {
			/* 127.255.255.255 only udp */
			is_bcast = 1;
			type = b_type;
			iface = socket_wrapper_default_iface();
		} else if ((addr & 0xFFFFFF00) == 0x7F000000) {
			/* 127.0.0.X */
			is_bcast = 0;
			type = u_type;
			iface = (addr & 0x000000FF);
		} else {
			errno = ENETUNREACH;
			return -1;
		}
		if (bcast) *bcast = is_bcast;
		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		const struct sockaddr_in6 *in =
		    (const struct sockaddr_in6 *)(const void *)inaddr;
		struct in6_addr cmp1, cmp2;

		switch (si->type) {
		case SOCK_STREAM:
			type = SOCKET_TYPE_CHAR_TCP_V6;
			break;
		case SOCK_DGRAM:
			type = SOCKET_TYPE_CHAR_UDP_V6;
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		/* XXX no multicast/broadcast */

		prt = ntohs(in->sin6_port);

		cmp1 = *swrap_ipv6();
		cmp2 = in->sin6_addr;
		cmp2.s6_addr[15] = 0;
		if (IN6_ARE_ADDR_EQUAL(&cmp1, &cmp2)) {
			iface = in->sin6_addr.s6_addr[15];
		} else {
			errno = ENETUNREACH;
			return -1;
		}

		break;
	}
#endif
	default:
		SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family!\n");
		errno = ENETUNREACH;
		return -1;
	}

	if (prt == 0) {
		SWRAP_LOG(SWRAP_LOG_WARN, "Port not set\n");
		errno = EINVAL;
		return -1;
	}

	if (is_bcast) {
		snprintf(un->sun_path, sizeof(un->sun_path), "%s/EINVAL",
			 socket_wrapper_dir());
		SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);
		/* the caller need to do more processing */
		return 0;
	}

	snprintf(un->sun_path, sizeof(un->sun_path), "%s/"SOCKET_FORMAT,
		 socket_wrapper_dir(), type, iface, prt);
	SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);

	return 0;
}

static int convert_in_un_alloc(struct socket_info *si, const struct sockaddr *inaddr, struct sockaddr_un *un,
			       int *bcast)
{
	char type = '\0';
	unsigned int prt;
	unsigned int iface;
	struct stat st;
	int is_bcast = 0;

	if (bcast) *bcast = 0;

	switch (si->family) {
	case AF_INET: {
		const struct sockaddr_in *in =
		    (const struct sockaddr_in *)(const void *)inaddr;
		unsigned int addr = ntohl(in->sin_addr.s_addr);
		char u_type = '\0';
		char d_type = '\0';
		char b_type = '\0';
		char a_type = '\0';

		prt = ntohs(in->sin_port);

		switch (si->type) {
		case SOCK_STREAM:
			u_type = SOCKET_TYPE_CHAR_TCP;
			d_type = SOCKET_TYPE_CHAR_TCP;
			break;
		case SOCK_DGRAM:
			u_type = SOCKET_TYPE_CHAR_UDP;
			d_type = SOCKET_TYPE_CHAR_UDP;
			a_type = SOCKET_TYPE_CHAR_UDP;
			b_type = SOCKET_TYPE_CHAR_UDP;
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		if (addr == 0) {
			/* 0.0.0.0 */
		 	is_bcast = 0;
			type = d_type;
			iface = socket_wrapper_default_iface();
		} else if (a_type && addr == 0xFFFFFFFF) {
			/* 255.255.255.255 only udp */
			is_bcast = 2;
			type = a_type;
			iface = socket_wrapper_default_iface();
		} else if (b_type && addr == 0x7FFFFFFF) {
			/* 127.255.255.255 only udp */
			is_bcast = 1;
			type = b_type;
			iface = socket_wrapper_default_iface();
		} else if ((addr & 0xFFFFFF00) == 0x7F000000) {
			/* 127.0.0.X */
			is_bcast = 0;
			type = u_type;
			iface = (addr & 0x000000FF);
		} else {
			errno = EADDRNOTAVAIL;
			return -1;
		}

		/* Store the bind address for connect() */
		if (si->bindname.sa_socklen == 0) {
			struct sockaddr_in bind_in;
			socklen_t blen = sizeof(struct sockaddr_in);

			ZERO_STRUCT(bind_in);
			bind_in.sin_family = in->sin_family;
			bind_in.sin_port = in->sin_port;
			bind_in.sin_addr.s_addr = htonl(0x7F000000 | iface);

			si->bindname.sa_socklen = blen;
			memcpy(&si->bindname.sa.in, &bind_in, blen);
		}

		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		const struct sockaddr_in6 *in =
		    (const struct sockaddr_in6 *)(const void *)inaddr;
		struct in6_addr cmp1, cmp2;

		switch (si->type) {
		case SOCK_STREAM:
			type = SOCKET_TYPE_CHAR_TCP_V6;
			break;
		case SOCK_DGRAM:
			type = SOCKET_TYPE_CHAR_UDP_V6;
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		/* XXX no multicast/broadcast */

		prt = ntohs(in->sin6_port);

		cmp1 = *swrap_ipv6();
		cmp2 = in->sin6_addr;
		cmp2.s6_addr[15] = 0;
		if (IN6_IS_ADDR_UNSPECIFIED(&in->sin6_addr)) {
			iface = socket_wrapper_default_iface();
		} else if (IN6_ARE_ADDR_EQUAL(&cmp1, &cmp2)) {
			iface = in->sin6_addr.s6_addr[15];
		} else {
			errno = EADDRNOTAVAIL;
			return -1;
		}

		/* Store the bind address for connect() */
		if (si->bindname.sa_socklen == 0) {
			struct sockaddr_in6 bind_in;
			socklen_t blen = sizeof(struct sockaddr_in6);

			ZERO_STRUCT(bind_in);
			bind_in.sin6_family = in->sin6_family;
			bind_in.sin6_port = in->sin6_port;

			bind_in.sin6_addr = *swrap_ipv6();
			bind_in.sin6_addr.s6_addr[15] = iface;

			memcpy(&si->bindname.sa.in6, &bind_in, blen);
			si->bindname.sa_socklen = blen;
		}

		break;
	}
#endif
	default:
		SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family\n");
		errno = EADDRNOTAVAIL;
		return -1;
	}


	if (bcast) *bcast = is_bcast;

	if (iface == 0 || iface > MAX_WRAPPED_INTERFACES) {
		errno = EINVAL;
		return -1;
	}

	if (prt == 0) {
		/* handle auto-allocation of ephemeral ports */
		for (prt = 5001; prt < 10000; prt++) {
			snprintf(un->sun_path, sizeof(un->sun_path), "%s/"SOCKET_FORMAT,
				 socket_wrapper_dir(), type, iface, prt);
			if (stat(un->sun_path, &st) == 0) continue;

			set_port(si->family, prt, &si->myname);
			set_port(si->family, prt, &si->bindname);

			break;
		}
		if (prt == 10000) {
			errno = ENFILE;
			return -1;
		}
	}

	snprintf(un->sun_path, sizeof(un->sun_path), "%s/"SOCKET_FORMAT,
		 socket_wrapper_dir(), type, iface, prt);
	SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);
	return 0;
}

static struct socket_info *find_socket_info(int fd)
{
	struct socket_info *i;

	for (i = sockets; i; i = i->next) {
		struct socket_info_fd *f;
		for (f = i->fds; f; f = f->next) {
			if (f->fd == fd) {
				return i;
			}
		}
	}

	return NULL;
}

#if 0 /* FIXME */
static bool check_addr_port_in_use(const struct sockaddr *sa, socklen_t len)
{
	struct socket_info *s;

	/* first catch invalid input */
	switch (sa->sa_family) {
	case AF_INET:
		if (len < sizeof(struct sockaddr_in)) {
			return false;
		}
		break;
#if HAVE_IPV6
	case AF_INET6:
		if (len < sizeof(struct sockaddr_in6)) {
			return false;
		}
		break;
#endif
	default:
		return false;
		break;
	}

	for (s = sockets; s != NULL; s = s->next) {
		if (s->myname == NULL) {
			continue;
		}
		if (s->myname->sa_family != sa->sa_family) {
			continue;
		}
		switch (s->myname->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin1, *sin2;

			sin1 = (struct sockaddr_in *)s->myname;
			sin2 = (struct sockaddr_in *)sa;

			if (sin1->sin_addr.s_addr == htonl(INADDR_ANY)) {
				continue;
			}
			if (sin1->sin_port != sin2->sin_port) {
				continue;
			}
			if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr) {
				continue;
			}

			/* found */
			return true;
			break;
		}
#if HAVE_IPV6
		case AF_INET6: {
			struct sockaddr_in6 *sin1, *sin2;

			sin1 = (struct sockaddr_in6 *)s->myname;
			sin2 = (struct sockaddr_in6 *)sa;

			if (sin1->sin6_port != sin2->sin6_port) {
				continue;
			}
			if (!IN6_ARE_ADDR_EQUAL(&sin1->sin6_addr,
						&sin2->sin6_addr))
			{
				continue;
			}

			/* found */
			return true;
			break;
		}
#endif
		default:
			continue;
			break;

		}
	}

	return false;
}
#endif

static void swrap_remove_stale(int fd)
{
	struct socket_info *si = find_socket_info(fd);
	struct socket_info_fd *fi;

	if (si != NULL) {
		for (fi = si->fds; fi; fi = fi->next) {
			if (fi->fd == fd) {
				SWRAP_LOG(SWRAP_LOG_TRACE, "remove stale wrapper for %d", fd);
				SWRAP_DLIST_REMOVE(si->fds, fi);
				free(fi);
				break;
			}
		}

		if (si->fds == NULL) {
			SWRAP_DLIST_REMOVE(sockets, si);
		}
	}
}

static int sockaddr_convert_to_un(struct socket_info *si,
				  const struct sockaddr *in_addr,
				  socklen_t in_len,
				  struct sockaddr_un *out_addr,
				  int alloc_sock,
				  int *bcast)
{
	struct sockaddr *out = (struct sockaddr *)(void *)out_addr;

	(void) in_len; /* unused */

	if (out_addr == NULL) {
		return 0;
	}

	out->sa_family = AF_UNIX;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	out->sa_len = sizeof(*out_addr);
#endif

	switch (in_addr->sa_family) {
	case AF_UNSPEC: {
		const struct sockaddr_in *sin;
		if (si->family != AF_INET) {
			break;
		}
		if (in_len < sizeof(struct sockaddr_in)) {
			break;
		}
		sin = (const struct sockaddr_in *)(const void *)in_addr;
		if(sin->sin_addr.s_addr != htonl(INADDR_ANY)) {
			break;
		}

		/*
		 * Note: in the special case of AF_UNSPEC and INADDR_ANY,
		 * AF_UNSPEC is mapped to AF_INET and must be treated here.
		 */

		/* FALL THROUGH */
	}
	case AF_INET:
#ifdef HAVE_IPV6
	case AF_INET6:
#endif
		switch (si->type) {
		case SOCK_STREAM:
		case SOCK_DGRAM:
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}
		if (alloc_sock) {
			return convert_in_un_alloc(si, in_addr, out_addr, bcast);
		} else {
			return convert_in_un_remote(si, in_addr, out_addr, bcast);
		}
	default:
		break;
	}

	errno = EAFNOSUPPORT;
	SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family\n");
	return -1;
}

static int sockaddr_convert_from_un(const struct socket_info *si,
				    const struct sockaddr_un *in_addr,
				    socklen_t un_addrlen,
				    int family,
				    struct sockaddr *out_addr,
				    socklen_t *out_addrlen)
{
	int ret;

	if (out_addr == NULL || out_addrlen == NULL)
		return 0;

	if (un_addrlen == 0) {
		*out_addrlen = 0;
		return 0;
	}

	switch (family) {
	case AF_INET:
#ifdef HAVE_IPV6
	case AF_INET6:
#endif
		switch (si->type) {
		case SOCK_STREAM:
		case SOCK_DGRAM:
			break;
		default:
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!\n");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}
		ret = convert_un_in(in_addr, out_addr, out_addrlen);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		out_addr->sa_len = *out_addrlen;
#endif
		return ret;
	default:
		break;
	}

	SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family\n");
	errno = EAFNOSUPPORT;
	return -1;
}

enum swrap_packet_type {
	SWRAP_CONNECT_SEND,
	SWRAP_CONNECT_UNREACH,
	SWRAP_CONNECT_RECV,
	SWRAP_CONNECT_ACK,
	SWRAP_ACCEPT_SEND,
	SWRAP_ACCEPT_RECV,
	SWRAP_ACCEPT_ACK,
	SWRAP_RECVFROM,
	SWRAP_SENDTO,
	SWRAP_SENDTO_UNREACH,
	SWRAP_PENDING_RST,
	SWRAP_RECV,
	SWRAP_RECV_RST,
	SWRAP_SEND,
	SWRAP_SEND_RST,
	SWRAP_CLOSE_SEND,
	SWRAP_CLOSE_RECV,
	SWRAP_CLOSE_ACK,
};

struct swrap_file_hdr {
	uint32_t	magic;
	uint16_t	version_major;
	uint16_t	version_minor;
	int32_t		timezone;
	uint32_t	sigfigs;
	uint32_t	frame_max_len;
#define SWRAP_FRAME_LENGTH_MAX 0xFFFF
	uint32_t	link_type;
};
#define SWRAP_FILE_HDR_SIZE 24

struct swrap_packet_frame {
	uint32_t seconds;
	uint32_t micro_seconds;
	uint32_t recorded_length;
	uint32_t full_length;
};
#define SWRAP_PACKET_FRAME_SIZE 16

union swrap_packet_ip {
	struct {
		uint8_t		ver_hdrlen;
		uint8_t		tos;
		uint16_t	packet_length;
		uint16_t	identification;
		uint8_t		flags;
		uint8_t		fragment;
		uint8_t		ttl;
		uint8_t		protocol;
		uint16_t	hdr_checksum;
		uint32_t	src_addr;
		uint32_t	dest_addr;
	} v4;
#define SWRAP_PACKET_IP_V4_SIZE 20
	struct {
		uint8_t		ver_prio;
		uint8_t		flow_label_high;
		uint16_t	flow_label_low;
		uint16_t	payload_length;
		uint8_t		next_header;
		uint8_t		hop_limit;
		uint8_t		src_addr[16];
		uint8_t		dest_addr[16];
	} v6;
#define SWRAP_PACKET_IP_V6_SIZE 40
};
#define SWRAP_PACKET_IP_SIZE 40

union swrap_packet_payload {
	struct {
		uint16_t	source_port;
		uint16_t	dest_port;
		uint32_t	seq_num;
		uint32_t	ack_num;
		uint8_t		hdr_length;
		uint8_t		control;
		uint16_t	window;
		uint16_t	checksum;
		uint16_t	urg;
	} tcp;
#define SWRAP_PACKET_PAYLOAD_TCP_SIZE 20
	struct {
		uint16_t	source_port;
		uint16_t	dest_port;
		uint16_t	length;
		uint16_t	checksum;
	} udp;
#define SWRAP_PACKET_PAYLOAD_UDP_SIZE 8
	struct {
		uint8_t		type;
		uint8_t		code;
		uint16_t	checksum;
		uint32_t	unused;
	} icmp4;
#define SWRAP_PACKET_PAYLOAD_ICMP4_SIZE 8
	struct {
		uint8_t		type;
		uint8_t		code;
		uint16_t	checksum;
		uint32_t	unused;
	} icmp6;
#define SWRAP_PACKET_PAYLOAD_ICMP6_SIZE 8
};
#define SWRAP_PACKET_PAYLOAD_SIZE 20

#define SWRAP_PACKET_MIN_ALLOC \
	(SWRAP_PACKET_FRAME_SIZE + \
	 SWRAP_PACKET_IP_SIZE + \
	 SWRAP_PACKET_PAYLOAD_SIZE)

static const char *swrap_pcap_init_file(void)
{
	static int initialized = 0;
	static const char *s = NULL;
	static const struct swrap_file_hdr h;
	static const struct swrap_packet_frame f;
	static const union swrap_packet_ip i;
	static const union swrap_packet_payload p;

	if (initialized == 1) {
		return s;
	}
	initialized = 1;

	/*
	 * TODO: don't use the structs use plain buffer offsets
	 *       and PUSH_U8(), PUSH_U16() and PUSH_U32()
	 *
	 * for now make sure we disable PCAP support
	 * if the struct has alignment!
	 */
	if (sizeof(h) != SWRAP_FILE_HDR_SIZE) {
		return NULL;
	}
	if (sizeof(f) != SWRAP_PACKET_FRAME_SIZE) {
		return NULL;
	}
	if (sizeof(i) != SWRAP_PACKET_IP_SIZE) {
		return NULL;
	}
	if (sizeof(i.v4) != SWRAP_PACKET_IP_V4_SIZE) {
		return NULL;
	}
	if (sizeof(i.v6) != SWRAP_PACKET_IP_V6_SIZE) {
		return NULL;
	}
	if (sizeof(p) != SWRAP_PACKET_PAYLOAD_SIZE) {
		return NULL;
	}
	if (sizeof(p.tcp) != SWRAP_PACKET_PAYLOAD_TCP_SIZE) {
		return NULL;
	}
	if (sizeof(p.udp) != SWRAP_PACKET_PAYLOAD_UDP_SIZE) {
		return NULL;
	}
	if (sizeof(p.icmp4) != SWRAP_PACKET_PAYLOAD_ICMP4_SIZE) {
		return NULL;
	}
	if (sizeof(p.icmp6) != SWRAP_PACKET_PAYLOAD_ICMP6_SIZE) {
		return NULL;
	}

	s = getenv("SOCKET_WRAPPER_PCAP_FILE");
	if (s == NULL) {
		return NULL;
	}
	if (strncmp(s, "./", 2) == 0) {
		s += 2;
	}
	return s;
}

static uint8_t *swrap_pcap_packet_init(struct timeval *tval,
				       const struct sockaddr *src,
				       const struct sockaddr *dest,
				       int socket_type,
				       const uint8_t *payload,
				       size_t payload_len,
				       unsigned long tcp_seqno,
				       unsigned long tcp_ack,
				       unsigned char tcp_ctl,
				       int unreachable,
				       size_t *_packet_len)
{
	uint8_t *base;
	uint8_t *buf;
	struct swrap_packet_frame *frame;
	union swrap_packet_ip *ip;
	union swrap_packet_payload *pay;
	size_t packet_len;
	size_t alloc_len;
	size_t nonwire_len = sizeof(*frame);
	size_t wire_hdr_len = 0;
	size_t wire_len = 0;
	size_t ip_hdr_len = 0;
	size_t icmp_hdr_len = 0;
	size_t icmp_truncate_len = 0;
	uint8_t protocol = 0, icmp_protocol = 0;
	const struct sockaddr_in *src_in = NULL;
	const struct sockaddr_in *dest_in = NULL;
#ifdef HAVE_IPV6
	const struct sockaddr_in6 *src_in6 = NULL;
	const struct sockaddr_in6 *dest_in6 = NULL;
#endif
	uint16_t src_port;
	uint16_t dest_port;

	switch (src->sa_family) {
	case AF_INET:
		src_in = (const struct sockaddr_in *)(const void *)src;
		dest_in = (const struct sockaddr_in *)(const void *)dest;
		src_port = src_in->sin_port;
		dest_port = dest_in->sin_port;
		ip_hdr_len = sizeof(ip->v4);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		src_in6 = (const struct sockaddr_in6 *)(const void *)src;
		dest_in6 = (const struct sockaddr_in6 *)(const void *)dest;
		src_port = src_in6->sin6_port;
		dest_port = dest_in6->sin6_port;
		ip_hdr_len = sizeof(ip->v6);
		break;
#endif
	default:
		return NULL;
	}

	switch (socket_type) {
	case SOCK_STREAM:
		protocol = 0x06; /* TCP */
		wire_hdr_len = ip_hdr_len + sizeof(pay->tcp);
		wire_len = wire_hdr_len + payload_len;
		break;

	case SOCK_DGRAM:
		protocol = 0x11; /* UDP */
		wire_hdr_len = ip_hdr_len + sizeof(pay->udp);
		wire_len = wire_hdr_len + payload_len;
		break;

	default:
		return NULL;
	}

	if (unreachable) {
		icmp_protocol = protocol;
		switch (src->sa_family) {
		case AF_INET:
			protocol = 0x01; /* ICMPv4 */
			icmp_hdr_len = ip_hdr_len + sizeof(pay->icmp4);
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			protocol = 0x3A; /* ICMPv6 */
			icmp_hdr_len = ip_hdr_len + sizeof(pay->icmp6);
			break;
#endif
		}
		if (wire_len > 64 ) {
			icmp_truncate_len = wire_len - 64;
		}
		wire_hdr_len += icmp_hdr_len;
		wire_len += icmp_hdr_len;
	}

	packet_len = nonwire_len + wire_len;
	alloc_len = packet_len;
	if (alloc_len < SWRAP_PACKET_MIN_ALLOC) {
		alloc_len = SWRAP_PACKET_MIN_ALLOC;
	}

	base = (uint8_t *)malloc(alloc_len);
	if (base == NULL) {
		return NULL;
	}
	memset(base, 0x0, alloc_len);

	buf = base;

	frame = (struct swrap_packet_frame *)(void *)buf;
	frame->seconds		= tval->tv_sec;
	frame->micro_seconds	= tval->tv_usec;
	frame->recorded_length	= wire_len - icmp_truncate_len;
	frame->full_length	= wire_len - icmp_truncate_len;
	buf += SWRAP_PACKET_FRAME_SIZE;

	ip = (union swrap_packet_ip *)(void *)buf;
	switch (src->sa_family) {
	case AF_INET:
		ip->v4.ver_hdrlen	= 0x45; /* version 4 and 5 * 32 bit words */
		ip->v4.tos		= 0x00;
		ip->v4.packet_length	= htons(wire_len - icmp_truncate_len);
		ip->v4.identification	= htons(0xFFFF);
		ip->v4.flags		= 0x40; /* BIT 1 set - means don't fragment */
		ip->v4.fragment		= htons(0x0000);
		ip->v4.ttl		= 0xFF;
		ip->v4.protocol		= protocol;
		ip->v4.hdr_checksum	= htons(0x0000);
		ip->v4.src_addr		= src_in->sin_addr.s_addr;
		ip->v4.dest_addr	= dest_in->sin_addr.s_addr;
		buf += SWRAP_PACKET_IP_V4_SIZE;
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		ip->v6.ver_prio		= 0x60; /* version 4 and 5 * 32 bit words */
		ip->v6.flow_label_high	= 0x00;
		ip->v6.flow_label_low	= 0x0000;
		ip->v6.payload_length	= htons(wire_len - icmp_truncate_len); /* TODO */
		ip->v6.next_header	= protocol;
		memcpy(ip->v6.src_addr, src_in6->sin6_addr.s6_addr, 16);
		memcpy(ip->v6.dest_addr, dest_in6->sin6_addr.s6_addr, 16);
		buf += SWRAP_PACKET_IP_V6_SIZE;
		break;
#endif
	}

	if (unreachable) {
		pay = (union swrap_packet_payload *)(void *)buf;
		switch (src->sa_family) {
		case AF_INET:
			pay->icmp4.type		= 0x03; /* destination unreachable */
			pay->icmp4.code		= 0x01; /* host unreachable */
			pay->icmp4.checksum	= htons(0x0000);
			pay->icmp4.unused	= htonl(0x00000000);
			buf += SWRAP_PACKET_PAYLOAD_ICMP4_SIZE;

			/* set the ip header in the ICMP payload */
			ip = (union swrap_packet_ip *)(void *)buf;
			ip->v4.ver_hdrlen	= 0x45; /* version 4 and 5 * 32 bit words */
			ip->v4.tos		= 0x00;
			ip->v4.packet_length	= htons(wire_len - icmp_hdr_len);
			ip->v4.identification	= htons(0xFFFF);
			ip->v4.flags		= 0x40; /* BIT 1 set - means don't fragment */
			ip->v4.fragment		= htons(0x0000);
			ip->v4.ttl		= 0xFF;
			ip->v4.protocol		= icmp_protocol;
			ip->v4.hdr_checksum	= htons(0x0000);
			ip->v4.src_addr		= dest_in->sin_addr.s_addr;
			ip->v4.dest_addr	= src_in->sin_addr.s_addr;
			buf += SWRAP_PACKET_IP_V4_SIZE;

			src_port = dest_in->sin_port;
			dest_port = src_in->sin_port;
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			pay->icmp6.type		= 0x01; /* destination unreachable */
			pay->icmp6.code		= 0x03; /* address unreachable */
			pay->icmp6.checksum	= htons(0x0000);
			pay->icmp6.unused	= htonl(0x00000000);
			buf += SWRAP_PACKET_PAYLOAD_ICMP6_SIZE;

			/* set the ip header in the ICMP payload */
			ip = (union swrap_packet_ip *)(void *)buf;
			ip->v6.ver_prio		= 0x60; /* version 4 and 5 * 32 bit words */
			ip->v6.flow_label_high	= 0x00;
			ip->v6.flow_label_low	= 0x0000;
			ip->v6.payload_length	= htons(wire_len - icmp_truncate_len); /* TODO */
			ip->v6.next_header	= protocol;
			memcpy(ip->v6.src_addr, dest_in6->sin6_addr.s6_addr, 16);
			memcpy(ip->v6.dest_addr, src_in6->sin6_addr.s6_addr, 16);
			buf += SWRAP_PACKET_IP_V6_SIZE;

			src_port = dest_in6->sin6_port;
			dest_port = src_in6->sin6_port;
			break;
#endif
		}
	}

	pay = (union swrap_packet_payload *)(void *)buf;

	switch (socket_type) {
	case SOCK_STREAM:
		pay->tcp.source_port	= src_port;
		pay->tcp.dest_port	= dest_port;
		pay->tcp.seq_num	= htonl(tcp_seqno);
		pay->tcp.ack_num	= htonl(tcp_ack);
		pay->tcp.hdr_length	= 0x50; /* 5 * 32 bit words */
		pay->tcp.control	= tcp_ctl;
		pay->tcp.window		= htons(0x7FFF);
		pay->tcp.checksum	= htons(0x0000);
		pay->tcp.urg		= htons(0x0000);
		buf += SWRAP_PACKET_PAYLOAD_TCP_SIZE;

		break;

	case SOCK_DGRAM:
		pay->udp.source_port	= src_port;
		pay->udp.dest_port	= dest_port;
		pay->udp.length		= htons(8 + payload_len);
		pay->udp.checksum	= htons(0x0000);
		buf += SWRAP_PACKET_PAYLOAD_UDP_SIZE;

		break;
	}

	if (payload && payload_len > 0) {
		memcpy(buf, payload, payload_len);
	}

	*_packet_len = packet_len - icmp_truncate_len;
	return base;
}

static int swrap_pcap_get_fd(const char *fname)
{
	static int fd = -1;

	if (fd != -1) return fd;

	fd = libc_open(fname, O_WRONLY|O_CREAT|O_EXCL|O_APPEND, 0644);
	if (fd != -1) {
		struct swrap_file_hdr file_hdr;
		file_hdr.magic		= 0xA1B2C3D4;
		file_hdr.version_major	= 0x0002;	
		file_hdr.version_minor	= 0x0004;
		file_hdr.timezone	= 0x00000000;
		file_hdr.sigfigs	= 0x00000000;
		file_hdr.frame_max_len	= SWRAP_FRAME_LENGTH_MAX;
		file_hdr.link_type	= 0x0065; /* 101 RAW IP */

		if (write(fd, &file_hdr, sizeof(file_hdr)) != sizeof(file_hdr)) {
			close(fd);
			fd = -1;
		}
		return fd;
	}

	fd = libc_open(fname, O_WRONLY|O_APPEND, 0644);

	return fd;
}

static uint8_t *swrap_pcap_marshall_packet(struct socket_info *si,
					   const struct sockaddr *addr,
					   enum swrap_packet_type type,
					   const void *buf, size_t len,
					   size_t *packet_len)
{
	const struct sockaddr *src_addr;
	const struct sockaddr *dest_addr;
	unsigned long tcp_seqno = 0;
	unsigned long tcp_ack = 0;
	unsigned char tcp_ctl = 0;
	int unreachable = 0;

	struct timeval tv;

	switch (si->family) {
	case AF_INET:
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		break;
#endif
	default:
		return NULL;
	}

	switch (type) {
	case SWRAP_CONNECT_SEND:
		if (si->type != SOCK_STREAM) return NULL;

		src_addr  = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x02; /* SYN */

		si->io.pck_snd += 1;

		break;

	case SWRAP_CONNECT_RECV:
		if (si->type != SOCK_STREAM) return NULL;

		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x12; /** SYN,ACK */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_CONNECT_UNREACH:
		if (si->type != SOCK_STREAM) return NULL;

		dest_addr = &si->myname.sa.s;
		src_addr  = addr;

		/* Unreachable: resend the data of SWRAP_CONNECT_SEND */
		tcp_seqno = si->io.pck_snd - 1;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x02; /* SYN */
		unreachable = 1;

		break;

	case SWRAP_CONNECT_ACK:
		if (si->type != SOCK_STREAM) return NULL;

		src_addr  = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x10; /* ACK */

		break;

	case SWRAP_ACCEPT_SEND:
		if (si->type != SOCK_STREAM) return NULL;

		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x02; /* SYN */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_ACCEPT_RECV:
		if (si->type != SOCK_STREAM) return NULL;

		src_addr = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x12; /* SYN,ACK */

		si->io.pck_snd += 1;

		break;

	case SWRAP_ACCEPT_ACK:
		if (si->type != SOCK_STREAM) return NULL;

		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x10; /* ACK */

		break;

	case SWRAP_SEND:
		src_addr  = &si->myname.sa.s;
		dest_addr = &si->peername.sa.s;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x18; /* PSH,ACK */

		si->io.pck_snd += len;

		break;

	case SWRAP_SEND_RST:
		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		if (si->type == SOCK_DGRAM) {
			return swrap_pcap_marshall_packet(si,
							  &si->peername.sa.s,
							  SWRAP_SENDTO_UNREACH,
							  buf,
							  len,
							  packet_len);
		}

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x14; /** RST,ACK */

		break;

	case SWRAP_PENDING_RST:
		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		if (si->type == SOCK_DGRAM) {
			return NULL;
		}

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x14; /* RST,ACK */

		break;

	case SWRAP_RECV:
		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x18; /* PSH,ACK */

		si->io.pck_rcv += len;

		break;

	case SWRAP_RECV_RST:
		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		if (si->type == SOCK_DGRAM) {
			return NULL;
		}

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x14; /* RST,ACK */

		break;

	case SWRAP_SENDTO:
		src_addr = &si->myname.sa.s;
		dest_addr = addr;

		si->io.pck_snd += len;

		break;

	case SWRAP_SENDTO_UNREACH:
		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		unreachable = 1;

		break;

	case SWRAP_RECVFROM:
		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		si->io.pck_rcv += len;

		break;

	case SWRAP_CLOSE_SEND:
		if (si->type != SOCK_STREAM) return NULL;

		src_addr  = &si->myname.sa.s;
		dest_addr = &si->peername.sa.s;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x11; /* FIN, ACK */

		si->io.pck_snd += 1;

		break;

	case SWRAP_CLOSE_RECV:
		if (si->type != SOCK_STREAM) return NULL;

		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x11; /* FIN,ACK */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_CLOSE_ACK:
		if (si->type != SOCK_STREAM) return NULL;

		src_addr  = &si->myname.sa.s;
		dest_addr = &si->peername.sa.s;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x10; /* ACK */

		break;
	default:
		return NULL;
	}

	swrapGetTimeOfDay(&tv);

	return swrap_pcap_packet_init(&tv,
				      src_addr,
				      dest_addr,
				      si->type,
				      (const uint8_t *)buf,
				      len,
				      tcp_seqno,
				      tcp_ack,
				      tcp_ctl,
				      unreachable,
				      packet_len);
}

static void swrap_pcap_dump_packet(struct socket_info *si,
				   const struct sockaddr *addr,
				   enum swrap_packet_type type,
				   const void *buf, size_t len)
{
	const char *file_name;
	uint8_t *packet;
	size_t packet_len = 0;
	int fd;

	file_name = swrap_pcap_init_file();
	if (!file_name) {
		return;
	}

	packet = swrap_pcap_marshall_packet(si,
					    addr,
					    type,
					    buf,
					    len,
					    &packet_len);
	if (packet == NULL) {
		return;
	}

	fd = swrap_pcap_get_fd(file_name);
	if (fd != -1) {
		if (write(fd, packet, packet_len) != (ssize_t)packet_len) {
			free(packet);
			return;
		}
	}

	free(packet);
}

/****************************************************************************
 *   SIGNALFD
 ***************************************************************************/

#ifdef HAVE_SIGNALFD
static int swrap_signalfd(int fd, const sigset_t *mask, int flags)
{
	int rc;

	rc = libc_signalfd(fd, mask, flags);
	if (rc != -1) {
		swrap_remove_stale(fd);
	}

	return rc;
}

int signalfd(int fd, const sigset_t *mask, int flags)
{
	return swrap_signalfd(fd, mask, flags);
}
#endif

/****************************************************************************
 *   SOCKET
 ***************************************************************************/

static int swrap_socket(int family, int type, int protocol)
{
	struct socket_info *si;
	struct socket_info_fd *fi;
	int fd;
	int real_type = type;

	/*
	 * Remove possible addition flags passed to socket() so
	 * do not fail checking the type.
	 * See https://lwn.net/Articles/281965/
	 */
#ifdef SOCK_CLOEXEC
	real_type &= ~SOCK_CLOEXEC;
#endif
#ifdef SOCK_NONBLOCK
	real_type &= ~SOCK_NONBLOCK;
#endif

	if (!socket_wrapper_enabled()) {
		return libc_socket(family, type, protocol);
	}

	switch (family) {
	case AF_INET:
#ifdef HAVE_IPV6
	case AF_INET6:
#endif
		break;
	case AF_UNIX:
		return libc_socket(family, type, protocol);
	default:
		errno = EAFNOSUPPORT;
		return -1;
	}

	switch (real_type) {
	case SOCK_STREAM:
		break;
	case SOCK_DGRAM:
		break;
	default:
		errno = EPROTONOSUPPORT;
		return -1;
	}

	switch (protocol) {
	case 0:
		break;
	case 6:
		if (real_type == SOCK_STREAM) {
			break;
		}
		/*fall through*/
	case 17:
		if (real_type == SOCK_DGRAM) {
			break;
		}
		/*fall through*/
	default:
		errno = EPROTONOSUPPORT;
		return -1;
	}

	/*
	 * We must call libc_socket with type, from the caller, not the version
	 * we removed SOCK_CLOEXEC and SOCK_NONBLOCK from
	 */
	fd = libc_socket(AF_UNIX, type, 0);

	if (fd == -1) {
		return -1;
	}

	/* Check if we have a stale fd and remove it */
	si = find_socket_info(fd);
	if (si != NULL) {
		swrap_remove_stale(fd);
	}

	si = (struct socket_info *)malloc(sizeof(struct socket_info));
	memset(si, 0, sizeof(struct socket_info));
	if (si == NULL) {
		errno = ENOMEM;
		return -1;
	}

	si->family = family;

	/* however, the rest of the socket_wrapper code expects just
	 * the type, not the flags */
	si->type = real_type;
	si->protocol = protocol;

	/*
	 * Setup myname so getsockname() can succeed to find out the socket
	 * type.
	 */
	switch(si->family) {
	case AF_INET: {
		struct sockaddr_in sin = {
			.sin_family = AF_INET,
		};

		si->myname.sa_socklen = sizeof(struct sockaddr_in);
		memcpy(&si->myname.sa.in, &sin, si->myname.sa_socklen);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
		};

		si->myname.sa_socklen = sizeof(struct sockaddr_in6);
		memcpy(&si->myname.sa.in6, &sin6, si->myname.sa_socklen);
		break;
	}
	default:
		free(si);
		errno = EINVAL;
		return -1;
	}

	fi = (struct socket_info_fd *)calloc(1, sizeof(struct socket_info_fd));
	if (fi == NULL) {
		free(si);
		errno = ENOMEM;
		return -1;
	}

	fi->fd = fd;

	SWRAP_DLIST_ADD(si->fds, fi);
	SWRAP_DLIST_ADD(sockets, si);

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "Created %s socket for protocol %s",
		  si->family == AF_INET ? "IPv4" : "IPv6",
		  si->type == SOCK_DGRAM ? "UDP" : "TCP");

	return fd;
}

int socket(int family, int type, int protocol)
{
	return swrap_socket(family, type, protocol);
}

/****************************************************************************
 *   SOCKETPAIR
 ***************************************************************************/

static int swrap_socketpair(int family, int type, int protocol, int sv[2])
{
	int rc;

	rc = libc_socketpair(family, type, protocol, sv);
	if (rc != -1) {
		swrap_remove_stale(sv[0]);
		swrap_remove_stale(sv[1]);
	}

	return rc;
}

int socketpair(int family, int type, int protocol, int sv[2])
{
	return swrap_socketpair(family, type, protocol, sv);
}

/****************************************************************************
 *   SOCKETPAIR
 ***************************************************************************/

#ifdef HAVE_TIMERFD_CREATE
static int swrap_timerfd_create(int clockid, int flags)
{
	int fd;

	fd = libc_timerfd_create(clockid, flags);
	if (fd != -1) {
		swrap_remove_stale(fd);
	}

	return fd;
}

int timerfd_create(int clockid, int flags)
{
	return swrap_timerfd_create(clockid, flags);
}
#endif

/****************************************************************************
 *   PIPE
 ***************************************************************************/

static int swrap_pipe(int pipefd[2])
{
	int rc;

	rc = libc_pipe(pipefd);
	if (rc != -1) {
		swrap_remove_stale(pipefd[0]);
		swrap_remove_stale(pipefd[1]);
	}

	return rc;
}

int pipe(int pipefd[2])
{
	return swrap_pipe(pipefd);
}

/****************************************************************************
 *   ACCEPT
 ***************************************************************************/

static int swrap_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	struct socket_info *parent_si, *child_si;
	struct socket_info_fd *child_fi;
	int fd;
	struct swrap_address un_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct swrap_address un_my_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct swrap_address in_addr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	struct swrap_address in_my_addr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	int ret;

	parent_si = find_socket_info(s);
	if (!parent_si) {
		return libc_accept(s, addr, addrlen);
	}

	/*
	 * assume out sockaddr have the same size as the in parent
	 * socket family
	 */
	in_addr.sa_socklen = socket_length(parent_si->family);
	if (in_addr.sa_socklen <= 0) {
		errno = EINVAL;
		return -1;
	}

	ret = libc_accept(s, &un_addr.sa.s, &un_addr.sa_socklen);
	if (ret == -1) {
		if (errno == ENOTSOCK) {
			/* Remove stale fds */
			swrap_remove_stale(s);
		}
		return ret;
	}

	fd = ret;

	ret = sockaddr_convert_from_un(parent_si,
				       &un_addr.sa.un,
				       un_addr.sa_socklen,
				       parent_si->family,
				       &in_addr.sa.s,
				       &in_addr.sa_socklen);
	if (ret == -1) {
		close(fd);
		return ret;
	}

	child_si = (struct socket_info *)malloc(sizeof(struct socket_info));
	memset(child_si, 0, sizeof(struct socket_info));

	child_fi = (struct socket_info_fd *)calloc(1, sizeof(struct socket_info_fd));
	if (child_fi == NULL) {
		free(child_si);
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	child_fi->fd = fd;

	SWRAP_DLIST_ADD(child_si->fds, child_fi);

	child_si->family = parent_si->family;
	child_si->type = parent_si->type;
	child_si->protocol = parent_si->protocol;
	child_si->bound = 1;
	child_si->is_server = 1;
	child_si->connected = 1;

	child_si->peername = (struct swrap_address) {
		.sa_socklen = in_addr.sa_socklen,
	};
	memcpy(&child_si->peername.sa.ss, &in_addr.sa.ss, in_addr.sa_socklen);

	if (addr != NULL && addrlen != NULL) {
		size_t copy_len = MIN(*addrlen, in_addr.sa_socklen);
		if (copy_len > 0) {
			memcpy(addr, &in_addr.sa.ss, copy_len);
		}
		*addrlen = in_addr.sa_socklen;
	}

	ret = libc_getsockname(fd,
			       &un_my_addr.sa.s,
			       &un_my_addr.sa_socklen);
	if (ret == -1) {
		free(child_fi);
		free(child_si);
		close(fd);
		return ret;
	}

	ret = sockaddr_convert_from_un(child_si,
				       &un_my_addr.sa.un,
				       un_my_addr.sa_socklen,
				       child_si->family,
				       &in_my_addr.sa.s,
				       &in_my_addr.sa_socklen);
	if (ret == -1) {
		free(child_fi);
		free(child_si);
		close(fd);
		return ret;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "accept() path=%s, fd=%d",
		  un_my_addr.sa.un.sun_path, s);

	child_si->myname = (struct swrap_address) {
		.sa_socklen = in_my_addr.sa_socklen,
	};
	memcpy(&child_si->myname.sa.ss, &in_my_addr.sa.ss, in_my_addr.sa_socklen);

	SWRAP_DLIST_ADD(sockets, child_si);

	if (addr != NULL) {
		swrap_pcap_dump_packet(child_si, addr, SWRAP_ACCEPT_SEND, NULL, 0);
		swrap_pcap_dump_packet(child_si, addr, SWRAP_ACCEPT_RECV, NULL, 0);
		swrap_pcap_dump_packet(child_si, addr, SWRAP_ACCEPT_ACK, NULL, 0);
	}

	return fd;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int accept(int s, struct sockaddr *addr, Psocklen_t addrlen)
#else
int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
#endif
{
	return swrap_accept(s, addr, (socklen_t *)addrlen);
}

static int autobind_start_init;
static int autobind_start;

/* using sendto() or connect() on an unbound socket would give the
   recipient no way to reply, as unlike UDP and TCP, a unix domain
   socket can't auto-assign ephemeral port numbers, so we need to
   assign it here.
   Note: this might change the family from ipv6 to ipv4
*/
static int swrap_auto_bind(int fd, struct socket_info *si, int family)
{
	struct swrap_address un_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	int i;
	char type;
	int ret;
	int port;
	struct stat st;

	if (autobind_start_init != 1) {
		autobind_start_init = 1;
		autobind_start = getpid();
		autobind_start %= 50000;
		autobind_start += 10000;
	}

	un_addr.sa.un.sun_family = AF_UNIX;

	switch (family) {
	case AF_INET: {
		struct sockaddr_in in;

		switch (si->type) {
		case SOCK_STREAM:
			type = SOCKET_TYPE_CHAR_TCP;
			break;
		case SOCK_DGRAM:
			type = SOCKET_TYPE_CHAR_UDP;
			break;
		default:
		    errno = ESOCKTNOSUPPORT;
		    return -1;
		}

		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		in.sin_addr.s_addr = htonl(127<<24 |
					   socket_wrapper_default_iface());

		si->myname = (struct swrap_address) {
			.sa_socklen = sizeof(in),
		};
		memcpy(&si->myname.sa.in, &in, si->myname.sa_socklen);
		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		struct sockaddr_in6 in6;

		if (si->family != family) {
			errno = ENETUNREACH;
			return -1;
		}

		switch (si->type) {
		case SOCK_STREAM:
			type = SOCKET_TYPE_CHAR_TCP_V6;
			break;
		case SOCK_DGRAM:
			type = SOCKET_TYPE_CHAR_UDP_V6;
			break;
		default:
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		memset(&in6, 0, sizeof(in6));
		in6.sin6_family = AF_INET6;
		in6.sin6_addr = *swrap_ipv6();
		in6.sin6_addr.s6_addr[15] = socket_wrapper_default_iface();

		si->myname = (struct swrap_address) {
			.sa_socklen = sizeof(in6),
		};
		memcpy(&si->myname.sa.in6, &in6, si->myname.sa_socklen);
		break;
	}
#endif
	default:
		errno = ESOCKTNOSUPPORT;
		return -1;
	}

	if (autobind_start > 60000) {
		autobind_start = 10000;
	}

	for (i = 0; i < SOCKET_MAX_SOCKETS; i++) {
		port = autobind_start + i;
		snprintf(un_addr.sa.un.sun_path, sizeof(un_addr.sa.un.sun_path),
			 "%s/"SOCKET_FORMAT, socket_wrapper_dir(),
			 type, socket_wrapper_default_iface(), port);
		if (stat(un_addr.sa.un.sun_path, &st) == 0) continue;

		ret = libc_bind(fd, &un_addr.sa.s, un_addr.sa_socklen);
		if (ret == -1) return ret;

		si->un_addr = un_addr.sa.un;

		si->bound = 1;
		autobind_start = port + 1;
		break;
	}
	if (i == SOCKET_MAX_SOCKETS) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "Too many open unix sockets (%u) for "
					   "interface "SOCKET_FORMAT,
					   SOCKET_MAX_SOCKETS,
					   type,
					   socket_wrapper_default_iface(),
					   0);
		errno = ENFILE;
		return -1;
	}

	si->family = family;
	set_port(si->family, port, &si->myname);

	return 0;
}

/****************************************************************************
 *   CONNECT
 ***************************************************************************/

static int swrap_connect(int s, const struct sockaddr *serv_addr,
			 socklen_t addrlen)
{
	int ret;
	struct swrap_address un_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct socket_info *si = find_socket_info(s);
	int bcast = 0;

	if (!si) {
		return libc_connect(s, serv_addr, addrlen);
	}

	if (si->bound == 0) {
		ret = swrap_auto_bind(s, si, serv_addr->sa_family);
		if (ret == -1) return -1;
	}

	if (si->family != serv_addr->sa_family) {
		errno = EINVAL;
		return -1;
	}

	ret = sockaddr_convert_to_un(si, serv_addr,
				     addrlen, &un_addr.sa.un, 0, &bcast);
	if (ret == -1) return -1;

	if (bcast) {
		errno = ENETUNREACH;
		return -1;
	}

	if (si->type == SOCK_DGRAM) {
		si->defer_connect = 1;
		ret = 0;
	} else {
		swrap_pcap_dump_packet(si, serv_addr, SWRAP_CONNECT_SEND, NULL, 0);

		ret = libc_connect(s,
				   &un_addr.sa.s,
				   un_addr.sa_socklen);
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "connect() path=%s, fd=%d",
		  un_addr.sa.un.sun_path, s);


	/* to give better errors */
	if (ret == -1 && errno == ENOENT) {
		errno = EHOSTUNREACH;
	}

	if (ret == 0) {
		si->peername = (struct swrap_address) {
			.sa_socklen = addrlen,
		};

		memcpy(&si->peername.sa.ss, serv_addr, addrlen);
		si->connected = 1;

		/*
		 * When we connect() on a socket than we have to bind the
		 * outgoing connection on the interface we use for the
		 * transport. We already bound it on the right interface
		 * but here we have to update the name so getsockname()
		 * returns correct information.
		 */
		if (si->bindname.sa_socklen > 0) {
			si->myname = (struct swrap_address) {
				.sa_socklen = si->bindname.sa_socklen,
			};

			memcpy(&si->myname.sa.ss,
			       &si->bindname.sa.ss,
			       si->bindname.sa_socklen);

			/* Cleanup bindname */
			si->bindname = (struct swrap_address) {
				.sa_socklen = 0,
			};
		}

		swrap_pcap_dump_packet(si, serv_addr, SWRAP_CONNECT_RECV, NULL, 0);
		swrap_pcap_dump_packet(si, serv_addr, SWRAP_CONNECT_ACK, NULL, 0);
	} else {
		swrap_pcap_dump_packet(si, serv_addr, SWRAP_CONNECT_UNREACH, NULL, 0);
	}

	return ret;
}

int connect(int s, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	return swrap_connect(s, serv_addr, addrlen);
}

/****************************************************************************
 *   BIND
 ***************************************************************************/

static int swrap_bind(int s, const struct sockaddr *myaddr, socklen_t addrlen)
{
	int ret;
	struct swrap_address un_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct socket_info *si = find_socket_info(s);
	int bind_error = 0;
#if 0 /* FIXME */
	bool in_use;
#endif

	if (!si) {
		return libc_bind(s, myaddr, addrlen);
	}

	switch (si->family) {
	case AF_INET: {
		const struct sockaddr_in *sin;
		if (addrlen < sizeof(struct sockaddr_in)) {
			bind_error = EINVAL;
			break;
		}

		sin = (const struct sockaddr_in *)(const void *)myaddr;

		if (sin->sin_family != AF_INET) {
			bind_error = EAFNOSUPPORT;
		}

		/* special case for AF_UNSPEC */
		if (sin->sin_family == AF_UNSPEC &&
		    (sin->sin_addr.s_addr == htonl(INADDR_ANY)))
		{
			bind_error = 0;
		}

		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		const struct sockaddr_in6 *sin6;
		if (addrlen < sizeof(struct sockaddr_in6)) {
			bind_error = EINVAL;
			break;
		}

		sin6 = (const struct sockaddr_in6 *)(const void *)myaddr;

		if (sin6->sin6_family != AF_INET6) {
			bind_error = EAFNOSUPPORT;
		}

		break;
	}
#endif
	default:
		bind_error = EINVAL;
		break;
	}

	if (bind_error != 0) {
		errno = bind_error;
		return -1;
	}

#if 0 /* FIXME */
	in_use = check_addr_port_in_use(myaddr, addrlen);
	if (in_use) {
		errno = EADDRINUSE;
		return -1;
	}
#endif

	si->myname.sa_socklen = addrlen;
	memcpy(&si->myname.sa.ss, myaddr, addrlen);

	ret = sockaddr_convert_to_un(si,
				     myaddr,
				     addrlen,
				     &un_addr.sa.un,
				     1,
				     &si->bcast);
	if (ret == -1) return -1;

	unlink(un_addr.sa.un.sun_path);

	ret = libc_bind(s, &un_addr.sa.s, un_addr.sa_socklen);

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "bind() path=%s, fd=%d",
		  un_addr.sa.un.sun_path, s);

	if (ret == 0) {
		si->bound = 1;
	}

	return ret;
}

int bind(int s, const struct sockaddr *myaddr, socklen_t addrlen)
{
	return swrap_bind(s, myaddr, addrlen);
}

/****************************************************************************
 *   BINDRESVPORT
 ***************************************************************************/

#ifdef HAVE_BINDRESVPORT
static int swrap_getsockname(int s, struct sockaddr *name, socklen_t *addrlen);

static int swrap_bindresvport_sa(int sd, struct sockaddr *sa)
{
	struct swrap_address myaddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	socklen_t salen;
	static uint16_t port;
	uint16_t i;
	int rc = -1;
	int af;

#define SWRAP_STARTPORT 600
#define SWRAP_ENDPORT (IPPORT_RESERVED - 1)
#define SWRAP_NPORTS (SWRAP_ENDPORT - SWRAP_STARTPORT + 1)

	if (port == 0) {
		port = (getpid() % SWRAP_NPORTS) + SWRAP_STARTPORT;
	}

	if (sa == NULL) {
		salen = myaddr.sa_socklen;
		sa = &myaddr.sa.s;

		rc = swrap_getsockname(sd, &myaddr.sa.s, &salen);
		if (rc < 0) {
			return -1;
		}

		af = sa->sa_family;
		memset(&myaddr.sa.ss, 0, salen);
	} else {
		af = sa->sa_family;
	}

	for (i = 0; i < SWRAP_NPORTS; i++, port++) {
		switch(af) {
		case AF_INET: {
			struct sockaddr_in *sinp = (struct sockaddr_in *)(void *)sa;

			salen = sizeof(struct sockaddr_in);
			sinp->sin_port = htons(port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *)(void *)sa;

			salen = sizeof(struct sockaddr_in6);
			sin6p->sin6_port = htons(port);
			break;
		}
		default:
			errno = EAFNOSUPPORT;
			return -1;
		}
		sa->sa_family = af;

		if (port > SWRAP_ENDPORT) {
			port = SWRAP_STARTPORT;
		}

		rc = swrap_bind(sd, (struct sockaddr *)sa, salen);
		if (rc == 0 || errno != EADDRINUSE) {
			break;
		}
	}

	return rc;
}

int bindresvport(int sockfd, struct sockaddr_in *sinp)
{
	return swrap_bindresvport_sa(sockfd, (struct sockaddr *)sinp);
}
#endif

/****************************************************************************
 *   LISTEN
 ***************************************************************************/

static int swrap_listen(int s, int backlog)
{
	int ret;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return libc_listen(s, backlog);
	}

	ret = libc_listen(s, backlog);

	return ret;
}

int listen(int s, int backlog)
{
	return swrap_listen(s, backlog);
}

/****************************************************************************
 *   FOPEN
 ***************************************************************************/

static FILE *swrap_fopen(const char *name, const char *mode)
{
	FILE *fp;

	fp = libc_fopen(name, mode);
	if (fp != NULL) {
		int fd = fileno(fp);

		swrap_remove_stale(fd);
	}

	return fp;
}

FILE *fopen(const char *name, const char *mode)
{
	return swrap_fopen(name, mode);
}

/****************************************************************************
 *   OPEN
 ***************************************************************************/

static int swrap_vopen(const char *pathname, int flags, va_list ap)
{
	int ret;

	ret = libc_vopen(pathname, flags, ap);
	if (ret != -1) {
		/*
		 * There are methods for closing descriptors (libc-internal code
		 * paths, direct syscalls) which close descriptors in ways that
		 * we can't intercept, so try to recover when we notice that
		 * that's happened
		 */
		swrap_remove_stale(ret);
	}
	return ret;
}

int open(const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = swrap_vopen(pathname, flags, ap);
	va_end(ap);

	return fd;
}

/****************************************************************************
 *   GETPEERNAME
 ***************************************************************************/

static int swrap_getpeername(int s, struct sockaddr *name, socklen_t *addrlen)
{
	struct socket_info *si = find_socket_info(s);
	socklen_t len;

	if (!si) {
		return libc_getpeername(s, name, addrlen);
	}

	if (si->peername.sa_socklen == 0)
	{
		errno = ENOTCONN;
		return -1;
	}

	len = MIN(*addrlen, si->peername.sa_socklen);
	if (len == 0) {
		return 0;
	}

	memcpy(name, &si->peername.sa.ss, len);
	*addrlen = si->peername.sa_socklen;

	return 0;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int getpeername(int s, struct sockaddr *name, Psocklen_t addrlen)
#else
int getpeername(int s, struct sockaddr *name, socklen_t *addrlen)
#endif
{
	return swrap_getpeername(s, name, (socklen_t *)addrlen);
}

/****************************************************************************
 *   GETSOCKNAME
 ***************************************************************************/

static int swrap_getsockname(int s, struct sockaddr *name, socklen_t *addrlen)
{
	struct socket_info *si = find_socket_info(s);
	socklen_t len;

	if (!si) {
		return libc_getsockname(s, name, addrlen);
	}

	len = MIN(*addrlen, si->myname.sa_socklen);
	if (len == 0) {
		return 0;
	}

	memcpy(name, &si->myname.sa.ss, len);
	*addrlen = si->myname.sa_socklen;

	return 0;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int getsockname(int s, struct sockaddr *name, Psocklen_t addrlen)
#else
int getsockname(int s, struct sockaddr *name, socklen_t *addrlen)
#endif
{
	return swrap_getsockname(s, name, (socklen_t *)addrlen);
}

/****************************************************************************
 *   GETSOCKOPT
 ***************************************************************************/

#ifndef SO_PROTOCOL
# ifdef SO_PROTOTYPE /* The Solaris name */
#  define SO_PROTOCOL SO_PROTOTYPE
# endif /* SO_PROTOTYPE */
#endif /* SO_PROTOCOL */

static int swrap_getsockopt(int s, int level, int optname,
			    void *optval, socklen_t *optlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return libc_getsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	if (level == SOL_SOCKET) {
		switch (optname) {
#ifdef SO_DOMAIN
		case SO_DOMAIN:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				return -1;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->family;
			return 0;
#endif /* SO_DOMAIN */

#ifdef SO_PROTOCOL
		case SO_PROTOCOL:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				return -1;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->protocol;
			return 0;
#endif /* SO_PROTOCOL */
		case SO_TYPE:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				return -1;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->type;
			return 0;
		default:
			return libc_getsockopt(s,
					       level,
					       optname,
					       optval,
					       optlen);
		}
	}

	errno = ENOPROTOOPT;
	return -1;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int getsockopt(int s, int level, int optname, void *optval, Psocklen_t optlen)
#else
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
#endif
{
	return swrap_getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

/****************************************************************************
 *   SETSOCKOPT
 ***************************************************************************/

static int swrap_setsockopt(int s, int level, int optname,
			    const void *optval, socklen_t optlen)
{
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return libc_setsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	if (level == SOL_SOCKET) {
		return libc_setsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	switch (si->family) {
	case AF_INET:
		if (level == IPPROTO_IP) {
#ifdef IP_PKTINFO
			if (optname == IP_PKTINFO) {
				si->pktinfo = AF_INET;
			}
#endif /* IP_PKTINFO */
		}
		return 0;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (level == IPPROTO_IPV6) {
#ifdef IPV6_RECVPKTINFO
			if (optname == IPV6_RECVPKTINFO) {
				si->pktinfo = AF_INET6;
			}
#endif /* IPV6_PKTINFO */
		}
		return 0;
#endif
	default:
		errno = ENOPROTOOPT;
		return -1;
	}
}

int setsockopt(int s, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	return swrap_setsockopt(s, level, optname, optval, optlen);
}

/****************************************************************************
 *   IOCTL
 ***************************************************************************/

static int swrap_vioctl(int s, unsigned long int r, va_list va)
{
	struct socket_info *si = find_socket_info(s);
	va_list ap;
	int value;
	int rc;

	if (!si) {
		return libc_vioctl(s, r, va);
	}

	va_copy(ap, va);

	rc = libc_vioctl(s, r, va);

	switch (r) {
	case FIONREAD:
		value = *((int *)va_arg(ap, int *));

		if (rc == -1 && errno != EAGAIN && errno != ENOBUFS) {
			swrap_pcap_dump_packet(si, NULL, SWRAP_PENDING_RST, NULL, 0);
		} else if (value == 0) { /* END OF FILE */
			swrap_pcap_dump_packet(si, NULL, SWRAP_PENDING_RST, NULL, 0);
		}
		break;
	}

	va_end(ap);

	return rc;
}

#ifdef HAVE_IOCTL_INT
int ioctl(int s, int r, ...)
#else
int ioctl(int s, unsigned long int r, ...)
#endif
{
	va_list va;
	int rc;

	va_start(va, r);

	rc = swrap_vioctl(s, (unsigned long int) r, va);

	va_end(va);

	return rc;
}

/*****************
 * CMSG
 *****************/

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL

#ifndef CMSG_ALIGN
# ifdef _ALIGN /* BSD */
#define CMSG_ALIGN _ALIGN
# else
#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
# endif /* _ALIGN */
#endif /* CMSG_ALIGN */

/**
 * @brief Add a cmsghdr to a msghdr.
 *
 * This is an function to add any type of cmsghdr. It will operate on the
 * msg->msg_control and msg->msg_controllen you pass in by adapting them to
 * the buffer position after the added cmsg element. Hence, this function is
 * intended to be used with an intermediate msghdr and not on the original
 * one handed in by the client.
 *
 * @param[in]  msg      The msghdr to which to add the cmsg.
 *
 * @param[in]  level    The cmsg level to set.
 *
 * @param[in]  type     The cmsg type to set.
 *
 * @param[in]  data     The cmsg data to set.
 *
 * @param[in]  len      the length of the data to set.
 */
static void swrap_msghdr_add_cmsghdr(struct msghdr *msg,
				     int level,
				     int type,
				     const void *data,
				     size_t len)
{
	size_t cmlen = CMSG_LEN(len);
	size_t cmspace = CMSG_SPACE(len);
	uint8_t cmbuf[cmspace];
	void *cast_ptr = (void *)cmbuf;
	struct cmsghdr *cm = (struct cmsghdr *)cast_ptr;
	uint8_t *p;

	memset(cmbuf, 0, cmspace);

	if (msg->msg_controllen < cmlen) {
		cmlen = msg->msg_controllen;
		msg->msg_flags |= MSG_CTRUNC;
	}

	if (msg->msg_controllen < cmspace) {
		cmspace = msg->msg_controllen;
	}

	/*
	 * We copy the full input data into an intermediate cmsghdr first
	 * in order to more easily cope with truncation.
	 */
	cm->cmsg_len = cmlen;
	cm->cmsg_level = level;
	cm->cmsg_type = type;
	memcpy(CMSG_DATA(cm), data, len);

	/*
	 * We now copy the possibly truncated buffer.
	 * We copy cmlen bytes, but consume cmspace bytes,
	 * leaving the possible padding uninitialiazed.
	 */
	p = (uint8_t *)msg->msg_control;
	memcpy(p, cm, cmlen);
	p += cmspace;
	msg->msg_control = p;
	msg->msg_controllen -= cmspace;

	return;
}

static int swrap_msghdr_add_pktinfo(struct socket_info *si,
				    struct msghdr *msg)
{
	/* Add packet info */
	switch (si->pktinfo) {
#if defined(IP_PKTINFO) && (defined(HAVE_STRUCT_IN_PKTINFO) || defined(IP_RECVDSTADDR))
	case AF_INET: {
		struct sockaddr_in *sin;
#if defined(HAVE_STRUCT_IN_PKTINFO)
		struct in_pktinfo pkt;
#elif defined(IP_RECVDSTADDR)
		struct in_addr pkt;
#endif

		if (si->bindname.sa_socklen == sizeof(struct sockaddr_in)) {
			sin = &si->bindname.sa.in;
		} else {
			if (si->myname.sa_socklen != sizeof(struct sockaddr_in)) {
				return 0;
			}
			sin = &si->myname.sa.in;
		}

		ZERO_STRUCT(pkt);

#if defined(HAVE_STRUCT_IN_PKTINFO)
		pkt.ipi_ifindex = socket_wrapper_default_iface();
		pkt.ipi_addr.s_addr = sin->sin_addr.s_addr;
#elif defined(IP_RECVDSTADDR)
		pkt = sin->sin_addr;
#endif

		swrap_msghdr_add_cmsghdr(msg, IPPROTO_IP, IP_PKTINFO,
					 &pkt, sizeof(pkt));

		break;
	}
#endif /* IP_PKTINFO */
#if defined(HAVE_IPV6)
	case AF_INET6: {
#if defined(IPV6_PKTINFO) && defined(HAVE_STRUCT_IN6_PKTINFO)
		struct sockaddr_in6 *sin6;
		struct in6_pktinfo pkt6;

		if (si->bindname.sa_socklen == sizeof(struct sockaddr_in6)) {
			sin6 = &si->bindname.sa.in6;
		} else {
			if (si->myname.sa_socklen != sizeof(struct sockaddr_in6)) {
				return 0;
			}
			sin6 = &si->myname.sa.in6;
		}

		ZERO_STRUCT(pkt6);

		pkt6.ipi6_ifindex = socket_wrapper_default_iface();
		pkt6.ipi6_addr = sin6->sin6_addr;

		swrap_msghdr_add_cmsghdr(msg, IPPROTO_IPV6, IPV6_PKTINFO,
					&pkt6, sizeof(pkt6));
#endif /* HAVE_STRUCT_IN6_PKTINFO */

		break;
	}
#endif /* IPV6_PKTINFO */
	default:
		return -1;
	}

	return 0;
}

static int swrap_msghdr_add_socket_info(struct socket_info *si,
					struct msghdr *omsg)
{
	int rc = 0;

	if (si->pktinfo > 0) {
		rc = swrap_msghdr_add_pktinfo(si, omsg);
	}

	return rc;
}

static int swrap_sendmsg_copy_cmsg(struct cmsghdr *cmsg,
				   uint8_t **cm_data,
				   size_t *cm_data_space);
static int swrap_sendmsg_filter_cmsg_socket(struct cmsghdr *cmsg,
					    uint8_t **cm_data,
					    size_t *cm_data_space);

static int swrap_sendmsg_filter_cmsghdr(struct msghdr *msg,
					uint8_t **cm_data,
					size_t *cm_data_space) {
	struct cmsghdr *cmsg;
	int rc = -1;

	/* Nothing to do */
	if (msg->msg_controllen == 0 || msg->msg_control == NULL) {
		return 0;
	}

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg)) {
		switch (cmsg->cmsg_level) {
		case IPPROTO_IP:
			rc = swrap_sendmsg_filter_cmsg_socket(cmsg,
							      cm_data,
							      cm_data_space);
			break;
		default:
			rc = swrap_sendmsg_copy_cmsg(cmsg,
						     cm_data,
						     cm_data_space);
			break;
		}
	}

	return rc;
}

static int swrap_sendmsg_copy_cmsg(struct cmsghdr *cmsg,
				   uint8_t **cm_data,
				   size_t *cm_data_space)
{
	size_t cmspace;
	uint8_t *p;

	cmspace =
		(*cm_data_space) +
		CMSG_SPACE(cmsg->cmsg_len - CMSG_ALIGN(sizeof(struct cmsghdr)));

	p = realloc((*cm_data), cmspace);
	if (p == NULL) {
		return -1;
	}
	(*cm_data) = p;

	p = (*cm_data) + (*cm_data_space);
	*cm_data_space = cmspace;

	memcpy(p, cmsg, cmsg->cmsg_len);

	return 0;
}

static int swrap_sendmsg_filter_cmsg_pktinfo(struct cmsghdr *cmsg,
					    uint8_t **cm_data,
					    size_t *cm_data_space);


static int swrap_sendmsg_filter_cmsg_socket(struct cmsghdr *cmsg,
					    uint8_t **cm_data,
					    size_t *cm_data_space)
{
	int rc = -1;

	switch(cmsg->cmsg_type) {
#ifdef IP_PKTINFO
	case IP_PKTINFO:
		rc = swrap_sendmsg_filter_cmsg_pktinfo(cmsg,
						       cm_data,
						       cm_data_space);
		break;
#endif
#ifdef IPV6_PKTINFO
	case IPV6_PKTINFO:
		rc = swrap_sendmsg_filter_cmsg_pktinfo(cmsg,
						       cm_data,
						       cm_data_space);
		break;
#endif
	default:
		break;
	}

	return rc;
}

static int swrap_sendmsg_filter_cmsg_pktinfo(struct cmsghdr *cmsg,
					     uint8_t **cm_data,
					     size_t *cm_data_space)
{
	(void)cmsg; /* unused */
	(void)cm_data; /* unused */
	(void)cm_data_space; /* unused */

	/*
	 * Passing a IP pktinfo to a unix socket might be rejected by the
	 * Kernel, at least on FreeBSD. So skip this cmsg.
	 */
	return 0;
}
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */

static ssize_t swrap_sendmsg_before(int fd,
				    struct socket_info *si,
				    struct msghdr *msg,
				    struct iovec *tmp_iov,
				    struct sockaddr_un *tmp_un,
				    const struct sockaddr_un **to_un,
				    const struct sockaddr **to,
				    int *bcast)
{
	size_t i, len = 0;
	ssize_t ret;

	if (to_un) {
		*to_un = NULL;
	}
	if (to) {
		*to = NULL;
	}
	if (bcast) {
		*bcast = 0;
	}

	switch (si->type) {
	case SOCK_STREAM:
		if (!si->connected) {
			errno = ENOTCONN;
			return -1;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
			size_t nlen;
			nlen = len + msg->msg_iov[i].iov_len;
			if (nlen > SOCKET_MAX_PACKET) {
				break;
			}
		}
		msg->msg_iovlen = i;
		if (msg->msg_iovlen == 0) {
			*tmp_iov = msg->msg_iov[0];
			tmp_iov->iov_len = MIN(tmp_iov->iov_len, SOCKET_MAX_PACKET);
			msg->msg_iov = tmp_iov;
			msg->msg_iovlen = 1;
		}
		break;

	case SOCK_DGRAM:
		if (si->connected) {
			if (msg->msg_name) {
				errno = EISCONN;
				return -1;
			}
		} else {
			const struct sockaddr *msg_name;
			msg_name = (const struct sockaddr *)msg->msg_name;

			if (msg_name == NULL) {
				errno = ENOTCONN;
				return -1;
			}


			ret = sockaddr_convert_to_un(si, msg_name, msg->msg_namelen,
						     tmp_un, 0, bcast);
			if (ret == -1) return -1;

			if (to_un) {
				*to_un = tmp_un;
			}
			if (to) {
				*to = msg_name;
			}
			msg->msg_name = tmp_un;
			msg->msg_namelen = sizeof(*tmp_un);
		}

		if (si->bound == 0) {
			ret = swrap_auto_bind(fd, si, si->family);
			if (ret == -1) {
				if (errno == ENOTSOCK) {
					swrap_remove_stale(fd);
					return -ENOTSOCK;
				} else {
					SWRAP_LOG(SWRAP_LOG_ERROR, "swrap_sendmsg_before failed");
					return -1;
				}
			}
		}

		if (!si->defer_connect) {
			break;
		}

		ret = sockaddr_convert_to_un(si,
					     &si->peername.sa.s,
					     si->peername.sa_socklen,
					     tmp_un,
					     0,
					     NULL);
		if (ret == -1) return -1;

		ret = libc_connect(fd,
				   (struct sockaddr *)(void *)tmp_un,
				   sizeof(*tmp_un));

		/* to give better errors */
		if (ret == -1 && errno == ENOENT) {
			errno = EHOSTUNREACH;
		}

		if (ret == -1) {
			return ret;
		}

		si->defer_connect = 0;
		break;
	default:
		errno = EHOSTUNREACH;
		return -1;
	}

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (msg->msg_controllen > 0 && msg->msg_control != NULL) {
		uint8_t *cmbuf = NULL;
		size_t cmlen = 0;

		ret = swrap_sendmsg_filter_cmsghdr(msg, &cmbuf, &cmlen);
		if (ret < 0) {
			free(cmbuf);
			return -1;
		}

		if (cmlen == 0) {
			msg->msg_controllen = 0;
			msg->msg_control = NULL;
		} else if (cmlen < msg->msg_controllen && cmbuf != NULL) {
			memcpy(msg->msg_control, cmbuf, cmlen);
			msg->msg_controllen = cmlen;
		}
		free(cmbuf);
	}
#endif

	return 0;
}

static void swrap_sendmsg_after(int fd,
				struct socket_info *si,
				struct msghdr *msg,
				const struct sockaddr *to,
				ssize_t ret)
{
	int saved_errno = errno;
	size_t i, len = 0;
	uint8_t *buf;
	off_t ofs = 0;
	size_t avail = 0;
	size_t remain;

	/* to give better errors */
	if (ret == -1) {
		if (saved_errno == ENOENT) {
			saved_errno = EHOSTUNREACH;
		} else if (saved_errno == ENOTSOCK) {
			/* If the fd is not a socket, remove it */
			swrap_remove_stale(fd);
		}
	}

	for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
		avail += msg->msg_iov[i].iov_len;
	}

	if (ret == -1) {
		remain = MIN(80, avail);
	} else {
		remain = ret;
	}

	/* we capture it as one single packet */
	buf = (uint8_t *)malloc(remain);
	if (!buf) {
		/* we just not capture the packet */
		errno = saved_errno;
		return;
	}

	for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
		size_t this_time = MIN(remain, (size_t)msg->msg_iov[i].iov_len);
		memcpy(buf + ofs,
		       msg->msg_iov[i].iov_base,
		       this_time);
		ofs += this_time;
		remain -= this_time;
	}
	len = ofs;

	switch (si->type) {
	case SOCK_STREAM:
		if (ret == -1) {
			swrap_pcap_dump_packet(si, NULL, SWRAP_SEND, buf, len);
			swrap_pcap_dump_packet(si, NULL, SWRAP_SEND_RST, NULL, 0);
		} else {
			swrap_pcap_dump_packet(si, NULL, SWRAP_SEND, buf, len);
		}
		break;

	case SOCK_DGRAM:
		if (si->connected) {
			to = &si->peername.sa.s;
		}
		if (ret == -1) {
			swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);
			swrap_pcap_dump_packet(si, to, SWRAP_SENDTO_UNREACH, buf, len);
		} else {
			swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);
		}
		break;
	}

	free(buf);
	errno = saved_errno;
}

static int swrap_recvmsg_before(int fd,
				struct socket_info *si,
				struct msghdr *msg,
				struct iovec *tmp_iov)
{
	size_t i, len = 0;
	ssize_t ret;

	(void)fd; /* unused */

	switch (si->type) {
	case SOCK_STREAM:
		if (!si->connected) {
			errno = ENOTCONN;
			return -1;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
			size_t nlen;
			nlen = len + msg->msg_iov[i].iov_len;
			if (nlen > SOCKET_MAX_PACKET) {
				break;
			}
		}
		msg->msg_iovlen = i;
		if (msg->msg_iovlen == 0) {
			*tmp_iov = msg->msg_iov[0];
			tmp_iov->iov_len = MIN(tmp_iov->iov_len, SOCKET_MAX_PACKET);
			msg->msg_iov = tmp_iov;
			msg->msg_iovlen = 1;
		}
		break;

	case SOCK_DGRAM:
		if (msg->msg_name == NULL) {
			errno = EINVAL;
			return -1;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		if (si->bound == 0) {
			ret = swrap_auto_bind(fd, si, si->family);
			if (ret == -1) {
				/*
				 * When attempting to read or write to a
				 * descriptor, if an underlying autobind fails
				 * because it's not a socket, stop intercepting
				 * uses of that descriptor.
				 */
				if (errno == ENOTSOCK) {
					swrap_remove_stale(fd);
					return -ENOTSOCK;
				} else {
					SWRAP_LOG(SWRAP_LOG_ERROR,
						  "swrap_recvmsg_before failed");
					return -1;
				}
			}
		}
		break;
	default:
		errno = EHOSTUNREACH;
		return -1;
	}

	return 0;
}

static int swrap_recvmsg_after(int fd,
			       struct socket_info *si,
			       struct msghdr *msg,
			       const struct sockaddr_un *un_addr,
			       socklen_t un_addrlen,
			       ssize_t ret)
{
	int saved_errno = errno;
	size_t i;
	uint8_t *buf = NULL;
	off_t ofs = 0;
	size_t avail = 0;
	size_t remain;
	int rc;

	/* to give better errors */
	if (ret == -1) {
		if (saved_errno == ENOENT) {
			saved_errno = EHOSTUNREACH;
		} else if (saved_errno == ENOTSOCK) {
			/* If the fd is not a socket, remove it */
			swrap_remove_stale(fd);
		}
	}

	for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
		avail += msg->msg_iov[i].iov_len;
	}

	if (avail == 0) {
		rc = 0;
		goto done;
	}

	if (ret == -1) {
		remain = MIN(80, avail);
	} else {
		remain = ret;
	}

	/* we capture it as one single packet */
	buf = (uint8_t *)malloc(remain);
	if (buf == NULL) {
		/* we just not capture the packet */
		errno = saved_errno;
		return -1;
	}

	for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
		size_t this_time = MIN(remain, (size_t)msg->msg_iov[i].iov_len);
		memcpy(buf + ofs,
		       msg->msg_iov[i].iov_base,
		       this_time);
		ofs += this_time;
		remain -= this_time;
	}

	switch (si->type) {
	case SOCK_STREAM:
		if (ret == -1 && saved_errno != EAGAIN && saved_errno != ENOBUFS) {
			swrap_pcap_dump_packet(si, NULL, SWRAP_RECV_RST, NULL, 0);
		} else if (ret == 0) { /* END OF FILE */
			swrap_pcap_dump_packet(si, NULL, SWRAP_RECV_RST, NULL, 0);
		} else if (ret > 0) {
			swrap_pcap_dump_packet(si, NULL, SWRAP_RECV, buf, ret);
		}
		break;

	case SOCK_DGRAM:
		if (ret == -1) {
			break;
		}

		if (un_addr != NULL) {
			rc = sockaddr_convert_from_un(si,
						      un_addr,
						      un_addrlen,
						      si->family,
						      msg->msg_name,
						      &msg->msg_namelen);
			if (rc == -1) {
				goto done;
			}

			swrap_pcap_dump_packet(si,
					  msg->msg_name,
					  SWRAP_RECVFROM,
					  buf,
					  ret);
		} else {
			swrap_pcap_dump_packet(si,
					  msg->msg_name,
					  SWRAP_RECV,
					  buf,
					  ret);
		}

		break;
	}

	rc = 0;
done:
	free(buf);
	errno = saved_errno;

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (rc == 0 &&
	    msg->msg_controllen > 0 &&
	    msg->msg_control != NULL) {
		rc = swrap_msghdr_add_socket_info(si, msg);
		if (rc < 0) {
			return -1;
		}
	}
#endif

	return rc;
}

/****************************************************************************
 *   RECVFROM
 ***************************************************************************/

static ssize_t swrap_recvfrom(int s, void *buf, size_t len, int flags,
			      struct sockaddr *from, socklen_t *fromlen)
{
	struct swrap_address from_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	ssize_t ret;
	struct socket_info *si = find_socket_info(s);
	struct swrap_address saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	struct msghdr msg;
	struct iovec tmp;
	int tret;

	if (!si) {
		return libc_recvfrom(s,
				     buf,
				     len,
				     flags,
				     from,
				     fromlen);
	}

	tmp.iov_base = buf;
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	if (from != NULL && fromlen != NULL) {
		msg.msg_name = from;   /* optional address */
		msg.msg_namelen = *fromlen; /* size of address */
	} else {
		msg.msg_name = &saddr.sa.s; /* optional address */
		msg.msg_namelen = saddr.sa_socklen; /* size of address */
	}
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	tret = swrap_recvmsg_before(s, si, &msg, &tmp);
	if (tret < 0) {
		return -1;
	}

	buf = msg.msg_iov[0].iov_base;
	len = msg.msg_iov[0].iov_len;

	ret = libc_recvfrom(s,
			    buf,
			    len,
			    flags,
			    &from_addr.sa.s,
			    &from_addr.sa_socklen);
	if (ret == -1) {
		return ret;
	}

	tret = swrap_recvmsg_after(s,
				   si,
				   &msg,
				   &from_addr.sa.un,
				   from_addr.sa_socklen,
				   ret);
	if (tret != 0) {
		return tret;
	}

	if (from != NULL && fromlen != NULL) {
		*fromlen = msg.msg_namelen;
	}

	return ret;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
ssize_t recvfrom(int s, void *buf, size_t len, int flags,
		 struct sockaddr *from, Psocklen_t fromlen)
#else
ssize_t recvfrom(int s, void *buf, size_t len, int flags,
		 struct sockaddr *from, socklen_t *fromlen)
#endif
{
	return swrap_recvfrom(s, buf, len, flags, from, (socklen_t *)fromlen);
}

/****************************************************************************
 *   SENDTO
 ***************************************************************************/

static ssize_t swrap_sendto(int s, const void *buf, size_t len, int flags,
			    const struct sockaddr *to, socklen_t tolen)
{
	struct msghdr msg;
	struct iovec tmp;
	struct swrap_address un_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	const struct sockaddr_un *to_un = NULL;
	ssize_t ret;
	int rc;
	struct socket_info *si = find_socket_info(s);
	int bcast = 0;

	if (!si) {
		return libc_sendto(s, buf, len, flags, to, tolen);
	}

	tmp.iov_base = discard_const_p(char, buf);
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	msg.msg_name = discard_const_p(struct sockaddr, to); /* optional address */
	msg.msg_namelen = tolen;       /* size of address */
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#if HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	rc = swrap_sendmsg_before(s,
				  si,
				  &msg,
				  &tmp,
				  &un_addr.sa.un,
				  &to_un,
				  &to,
				  &bcast);
	if (rc < 0) {
		return -1;
	}

	buf = msg.msg_iov[0].iov_base;
	len = msg.msg_iov[0].iov_len;

	if (bcast) {
		struct stat st;
		unsigned int iface;
		unsigned int prt = ntohs(((const struct sockaddr_in *)(const void *)to)->sin_port);
		char type;

		type = SOCKET_TYPE_CHAR_UDP;

		for(iface=0; iface <= MAX_WRAPPED_INTERFACES; iface++) {
			snprintf(un_addr.sa.un.sun_path,
				 sizeof(un_addr.sa.un.sun_path),
				 "%s/"SOCKET_FORMAT,
				 socket_wrapper_dir(), type, iface, prt);
			if (stat(un_addr.sa.un.sun_path, &st) != 0) continue;

			/* ignore the any errors in broadcast sends */
			libc_sendto(s,
				    buf,
				    len,
				    flags,
				    &un_addr.sa.s,
				    un_addr.sa_socklen);
		}

		swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);

		return len;
	}

	ret = libc_sendto(s,
			  buf,
			  len,
			  flags,
			  (struct sockaddr *)msg.msg_name,
			  msg.msg_namelen);

	swrap_sendmsg_after(s, si, &msg, to, ret);

	return ret;
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	return swrap_sendto(s, buf, len, flags, to, tolen);
}

/****************************************************************************
 *   READV
 ***************************************************************************/

static ssize_t swrap_recv(int s, void *buf, size_t len, int flags)
{
	struct socket_info *si;
	struct msghdr msg;
	struct swrap_address saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	struct iovec tmp;
	ssize_t ret;
	int tret;

	si = find_socket_info(s);
	if (si == NULL) {
		return libc_recv(s, buf, len, flags);
	}

	tmp.iov_base = buf;
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	msg.msg_name = &saddr.sa.s;    /* optional address */
	msg.msg_namelen = saddr.sa_socklen; /* size of address */
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	tret = swrap_recvmsg_before(s, si, &msg, &tmp);
	if (tret < 0) {
		return -1;
	}

	buf = msg.msg_iov[0].iov_base;
	len = msg.msg_iov[0].iov_len;

	ret = libc_recv(s, buf, len, flags);

	tret = swrap_recvmsg_after(s, si, &msg, NULL, 0, ret);
	if (tret != 0) {
		return tret;
	}

	return ret;
}

ssize_t recv(int s, void *buf, size_t len, int flags)
{
	return swrap_recv(s, buf, len, flags);
}

/****************************************************************************
 *   READ
 ***************************************************************************/

static ssize_t swrap_read(int s, void *buf, size_t len)
{
	struct socket_info *si;
	struct msghdr msg;
	struct iovec tmp;
	struct swrap_address saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	ssize_t ret;
	int tret;

	si = find_socket_info(s);
	if (si == NULL) {
		return libc_read(s, buf, len);
	}

	tmp.iov_base = buf;
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	msg.msg_name = &saddr.sa.ss;   /* optional address */
	msg.msg_namelen = saddr.sa_socklen; /* size of address */
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	tret = swrap_recvmsg_before(s, si, &msg, &tmp);
	if (tret < 0) {
		if (tret == -ENOTSOCK) {
			return libc_read(s, buf, len);
		}
		return -1;
	}

	buf = msg.msg_iov[0].iov_base;
	len = msg.msg_iov[0].iov_len;

	ret = libc_read(s, buf, len);

	tret = swrap_recvmsg_after(s, si, &msg, NULL, 0, ret);
	if (tret != 0) {
		return tret;
	}

	return ret;
}

ssize_t read(int s, void *buf, size_t len)
{
	return swrap_read(s, buf, len);
}

/****************************************************************************
 *   SEND
 ***************************************************************************/

static ssize_t swrap_send(int s, const void *buf, size_t len, int flags)
{
	struct msghdr msg;
	struct iovec tmp;
	struct sockaddr_un un_addr;
	ssize_t ret;
	int rc;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return libc_send(s, buf, len, flags);
	}

	tmp.iov_base = discard_const_p(char, buf);
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	msg.msg_name = NULL;           /* optional address */
	msg.msg_namelen = 0;           /* size of address */
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#if HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	rc = swrap_sendmsg_before(s, si, &msg, &tmp, &un_addr, NULL, NULL, NULL);
	if (rc < 0) {
		return -1;
	}

	buf = msg.msg_iov[0].iov_base;
	len = msg.msg_iov[0].iov_len;

	ret = libc_send(s, buf, len, flags);

	swrap_sendmsg_after(s, si, &msg, NULL, ret);

	return ret;
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	return swrap_send(s, buf, len, flags);
}

/****************************************************************************
 *   RECVMSG
 ***************************************************************************/

static ssize_t swrap_recvmsg(int s, struct msghdr *omsg, int flags)
{
	struct swrap_address from_addr = {
		.sa_socklen = sizeof(struct sockaddr_un),
	};
	struct socket_info *si;
	struct msghdr msg;
	struct iovec tmp;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	size_t msg_ctrllen_filled;
	size_t msg_ctrllen_left;
#endif

	ssize_t ret;
	int rc;

	si = find_socket_info(s);
	if (si == NULL) {
		return libc_recvmsg(s, omsg, flags);
	}

	tmp.iov_base = NULL;
	tmp.iov_len = 0;

	ZERO_STRUCT(msg);
	msg.msg_name = &from_addr.sa;              /* optional address */
	msg.msg_namelen = from_addr.sa_socklen;    /* size of address */
	msg.msg_iov = omsg->msg_iov;               /* scatter/gather array */
	msg.msg_iovlen = omsg->msg_iovlen;         /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg_ctrllen_filled = 0;
	msg_ctrllen_left = omsg->msg_controllen;

	msg.msg_control = omsg->msg_control;       /* ancillary data, see below */
	msg.msg_controllen = omsg->msg_controllen; /* ancillary data buffer len */
	msg.msg_flags = omsg->msg_flags;           /* flags on received message */
#endif

	rc = swrap_recvmsg_before(s, si, &msg, &tmp);
	if (rc < 0) {
		return -1;
	}

	ret = libc_recvmsg(s, &msg, flags);

	msg.msg_name = omsg->msg_name;
	msg.msg_namelen = omsg->msg_namelen;

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg_ctrllen_filled += msg.msg_controllen;
	msg_ctrllen_left -= msg.msg_controllen;

	if (omsg->msg_control != NULL) {
		uint8_t *p;

		p = omsg->msg_control;
		p += msg_ctrllen_filled;

		msg.msg_control = p;
		msg.msg_controllen = msg_ctrllen_left;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}
#endif

	rc = swrap_recvmsg_after(s,
				 si,
				 &msg,
				 &from_addr.sa.un,
				 from_addr.sa_socklen,
				 ret);
	if (rc != 0) {
		return rc;
	}

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (omsg->msg_control != NULL) {
		/* msg.msg_controllen = space left */
		msg_ctrllen_left = msg.msg_controllen;
		msg_ctrllen_filled = omsg->msg_controllen - msg_ctrllen_left;
	}

	/* Update the original message length */
	omsg->msg_controllen = msg_ctrllen_filled;
	omsg->msg_flags = msg.msg_flags;
#endif
	omsg->msg_iovlen = msg.msg_iovlen;

	return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return swrap_recvmsg(sockfd, msg, flags);
}

/****************************************************************************
 *   SENDMSG
 ***************************************************************************/

static ssize_t swrap_sendmsg(int s, const struct msghdr *omsg, int flags)
{
	struct msghdr msg;
	struct iovec tmp;
	struct sockaddr_un un_addr;
	const struct sockaddr_un *to_un = NULL;
	const struct sockaddr *to = NULL;
	ssize_t ret;
	int rc;
	struct socket_info *si = find_socket_info(s);
	int bcast = 0;

	if (!si) {
		return libc_sendmsg(s, omsg, flags);
	}

	ZERO_STRUCT(un_addr);

	tmp.iov_base = NULL;
	tmp.iov_len = 0;

	ZERO_STRUCT(msg);
	msg.msg_name = omsg->msg_name;             /* optional address */
	msg.msg_namelen = omsg->msg_namelen;       /* size of address */
	msg.msg_iov = omsg->msg_iov;               /* scatter/gather array */
	msg.msg_iovlen = omsg->msg_iovlen;         /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (msg.msg_controllen > 0 && msg.msg_control != NULL) {
		/* omsg is a const so use a local buffer for modifications */
		uint8_t cmbuf[omsg->msg_controllen];

		memcpy(cmbuf, omsg->msg_control, omsg->msg_controllen);

		msg.msg_control = cmbuf;       /* ancillary data, see below */
		msg.msg_controllen = omsg->msg_controllen; /* ancillary data buffer len */
	}
	msg.msg_flags = omsg->msg_flags;           /* flags on received message */
#endif

	rc = swrap_sendmsg_before(s, si, &msg, &tmp, &un_addr, &to_un, &to, &bcast);
	if (rc < 0) {
		return -1;
	}

	if (bcast) {
		struct stat st;
		unsigned int iface;
		unsigned int prt = ntohs(((const struct sockaddr_in *)(const void *)to)->sin_port);
		char type;
		size_t i, len = 0;
		uint8_t *buf;
		off_t ofs = 0;
		size_t avail = 0;
		size_t remain;

		for (i = 0; i < (size_t)msg.msg_iovlen; i++) {
			avail += msg.msg_iov[i].iov_len;
		}

		len = avail;
		remain = avail;

		/* we capture it as one single packet */
		buf = (uint8_t *)malloc(remain);
		if (!buf) {
			return -1;
		}

		for (i = 0; i < (size_t)msg.msg_iovlen; i++) {
			size_t this_time = MIN(remain, (size_t)msg.msg_iov[i].iov_len);
			memcpy(buf + ofs,
			       msg.msg_iov[i].iov_base,
			       this_time);
			ofs += this_time;
			remain -= this_time;
		}

		type = SOCKET_TYPE_CHAR_UDP;

		for(iface=0; iface <= MAX_WRAPPED_INTERFACES; iface++) {
			snprintf(un_addr.sun_path, sizeof(un_addr.sun_path), "%s/"SOCKET_FORMAT,
				 socket_wrapper_dir(), type, iface, prt);
			if (stat(un_addr.sun_path, &st) != 0) continue;

			msg.msg_name = &un_addr;           /* optional address */
			msg.msg_namelen = sizeof(un_addr); /* size of address */

			/* ignore the any errors in broadcast sends */
			libc_sendmsg(s, &msg, flags);
		}

		swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);
		free(buf);

		return len;
	}

	ret = libc_sendmsg(s, &msg, flags);

	swrap_sendmsg_after(s, si, &msg, to, ret);

	return ret;
}

ssize_t sendmsg(int s, const struct msghdr *omsg, int flags)
{
	return swrap_sendmsg(s, omsg, flags);
}

/****************************************************************************
 *   READV
 ***************************************************************************/

static ssize_t swrap_readv(int s, const struct iovec *vector, int count)
{
	struct socket_info *si;
	struct msghdr msg;
	struct iovec tmp;
	struct swrap_address saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage)
	};
	ssize_t ret;
	int rc;

	si = find_socket_info(s);
	if (si == NULL) {
		return libc_readv(s, vector, count);
	}

	tmp.iov_base = NULL;
	tmp.iov_len = 0;

	ZERO_STRUCT(msg);
	msg.msg_name = &saddr.sa.s; /* optional address */
	msg.msg_namelen = saddr.sa_socklen;      /* size of address */
	msg.msg_iov = discard_const_p(struct iovec, vector); /* scatter/gather array */
	msg.msg_iovlen = count;        /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	rc = swrap_recvmsg_before(s, si, &msg, &tmp);
	if (rc < 0) {
		if (rc == -ENOTSOCK) {
			return libc_readv(s, vector, count);
		}
		return -1;
	}

	ret = libc_readv(s, msg.msg_iov, msg.msg_iovlen);

	rc = swrap_recvmsg_after(s, si, &msg, NULL, 0, ret);
	if (rc != 0) {
		return rc;
	}

	return ret;
}

ssize_t readv(int s, const struct iovec *vector, int count)
{
	return swrap_readv(s, vector, count);
}

/****************************************************************************
 *   WRITEV
 ***************************************************************************/

static ssize_t swrap_writev(int s, const struct iovec *vector, int count)
{
	struct msghdr msg;
	struct iovec tmp;
	struct sockaddr_un un_addr;
	ssize_t ret;
	int rc;
	struct socket_info *si = find_socket_info(s);

	if (!si) {
		return libc_writev(s, vector, count);
	}

	tmp.iov_base = NULL;
	tmp.iov_len = 0;

	ZERO_STRUCT(msg);
	msg.msg_name = NULL;           /* optional address */
	msg.msg_namelen = 0;           /* size of address */
	msg.msg_iov = discard_const_p(struct iovec, vector); /* scatter/gather array */
	msg.msg_iovlen = count;        /* # elements in msg_iov */
#if HAVE_STRUCT_MSGHDR_MSG_CONTROL
	msg.msg_control = NULL;        /* ancillary data, see below */
	msg.msg_controllen = 0;        /* ancillary data buffer len */
	msg.msg_flags = 0;             /* flags on received message */
#endif

	rc = swrap_sendmsg_before(s, si, &msg, &tmp, &un_addr, NULL, NULL, NULL);
	if (rc < 0) {
		if (rc == -ENOTSOCK) {
			return libc_readv(s, vector, count);
		}
		return -1;
	}

	ret = libc_writev(s, msg.msg_iov, msg.msg_iovlen);

	swrap_sendmsg_after(s, si, &msg, NULL, ret);

	return ret;
}

ssize_t writev(int s, const struct iovec *vector, int count)
{
	return swrap_writev(s, vector, count);
}

/****************************
 * CLOSE
 ***************************/

static int swrap_close(int fd)
{
	struct socket_info *si = find_socket_info(fd);
	struct socket_info_fd *fi;
	int ret;

	if (!si) {
		return libc_close(fd);
	}

	for (fi = si->fds; fi; fi = fi->next) {
		if (fi->fd == fd) {
			SWRAP_DLIST_REMOVE(si->fds, fi);
			free(fi);
			break;
		}
	}

	if (si->fds) {
		/* there are still references left */
		return libc_close(fd);
	}

	SWRAP_DLIST_REMOVE(sockets, si);

	if (si->myname.sa_socklen > 0 && si->peername.sa_socklen > 0) {
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_SEND, NULL, 0);
	}

	ret = libc_close(fd);

	if (si->myname.sa_socklen > 0 && si->peername.sa_socklen > 0) {
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_RECV, NULL, 0);
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_ACK, NULL, 0);
	}

	if (si->un_addr.sun_path[0] != '\0') {
		unlink(si->un_addr.sun_path);
	}
	free(si);

	return ret;
}

int close(int fd)
{
	return swrap_close(fd);
}

/****************************
 * DUP
 ***************************/

static int swrap_dup(int fd)
{
	struct socket_info *si;
	struct socket_info_fd *fi;

	si = find_socket_info(fd);

	if (!si) {
		return libc_dup(fd);
	}

	fi = (struct socket_info_fd *)calloc(1, sizeof(struct socket_info_fd));
	if (fi == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fi->fd = libc_dup(fd);
	if (fi->fd == -1) {
		int saved_errno = errno;
		free(fi);
		errno = saved_errno;
		return -1;
	}

	/* Make sure we don't have an entry for the fd */
	swrap_remove_stale(fi->fd);

	SWRAP_DLIST_ADD(si->fds, fi);
	return fi->fd;
}

int dup(int fd)
{
	return swrap_dup(fd);
}

/****************************
 * DUP2
 ***************************/

static int swrap_dup2(int fd, int newfd)
{
	struct socket_info *si;
	struct socket_info_fd *fi;

	si = find_socket_info(fd);

	if (!si) {
		return libc_dup2(fd, newfd);
	}

	if (find_socket_info(newfd)) {
		/* dup2() does an implicit close of newfd, which we
		 * need to emulate */
		swrap_close(newfd);
	}

	fi = (struct socket_info_fd *)calloc(1, sizeof(struct socket_info_fd));
	if (fi == NULL) {
		errno = ENOMEM;
		return -1;
	}

	fi->fd = libc_dup2(fd, newfd);
	if (fi->fd == -1) {
		int saved_errno = errno;
		free(fi);
		errno = saved_errno;
		return -1;
	}

	/* Make sure we don't have an entry for the fd */
	swrap_remove_stale(fi->fd);

	SWRAP_DLIST_ADD(si->fds, fi);
	return fi->fd;
}

int dup2(int fd, int newfd)
{
	return swrap_dup2(fd, newfd);
}

/****************************
 * FCNTL
 ***************************/

static int swrap_vfcntl(int fd, int cmd, va_list va)
{
	struct socket_info_fd *fi;
	struct socket_info *si;
	int rc;

	si = find_socket_info(fd);
	if (si == NULL) {
		rc = libc_vfcntl(fd, cmd, va);

		return rc;
	}

	switch (cmd) {
	case F_DUPFD:
		fi = (struct socket_info_fd *)calloc(1, sizeof(struct socket_info_fd));
		if (fi == NULL) {
			errno = ENOMEM;
			return -1;
		}

		fi->fd = libc_vfcntl(fd, cmd, va);
		if (fi->fd == -1) {
			int saved_errno = errno;
			free(fi);
			errno = saved_errno;
			return -1;
		}

		/* Make sure we don't have an entry for the fd */
		swrap_remove_stale(fi->fd);

		SWRAP_DLIST_ADD(si->fds, fi);

		rc = fi->fd;
		break;
	default:
		rc = libc_vfcntl(fd, cmd, va);
		break;
	}

	return rc;
}

int fcntl(int fd, int cmd, ...)
{
	va_list va;
	int rc;

	va_start(va, cmd);

	rc = swrap_vfcntl(fd, cmd, va);

	va_end(va);

	return rc;
}

/****************************
 * EVENTFD
 ***************************/

#ifdef HAVE_EVENTFD
static int swrap_eventfd(int count, int flags)
{
	int fd;

	fd = libc_eventfd(count, flags);
	if (fd != -1) {
		swrap_remove_stale(fd);
	}

	return fd;
}

#ifdef HAVE_EVENTFD_UNSIGNED_INT
int eventfd(unsigned int count, int flags)
#else
int eventfd(int count, int flags)
#endif
{
	return swrap_eventfd(count, flags);
}
#endif

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
void swrap_destructor(void)
{
	struct socket_info *s = sockets;

	while (s != NULL) {
		struct socket_info_fd *f = s->fds;
		if (f != NULL) {
			swrap_close(f->fd);
		}
		s = sockets;
	}
}
