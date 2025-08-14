/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2005-2008, Jelmer Vernooij <jelmer@samba.org>
 * Copyright (c) 2006-2025, Stefan Metzmacher <metze@samba.org>
 * Copyright (c) 2013-2021, Andreas Schneider <asn@samba.org>
 * Copyright (c) 2014-2017, Michael Adam <obnox@samba.org>
 * Copyright (c) 2016-2018, Anoop C S <anoopcs@redhat.com>
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
 */

/*
   quic.ko wrapper library. It simulates the socket behavior for
   IPPROTO_QUIC, but currently only in a way to support everything
   Samba needs use SMB over QUIC.

   It works in combination with socket_wrapper, but it also
   works on top of real UDP sockets.
*/

#include "config.h"

/*
 * Make sure we do not redirect (f)open(at)() or fcntl() to their 64bit
 * variants
 */
#undef _FILE_OFFSET_BITS

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif
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
#include <linux/tls.h>
#include <netinet/quic.h>
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
#include <signal.h>
#include <pthread.h>
#include <assert.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "quic_ko_wrapper.h"

#ifdef __USE_FILE_OFFSET64
#error -D_FILE_OFFSET_BITS=64 should not be set for quic_ko_wrapper!
#endif

enum qwrap_dbglvl_e {
	QWRAP_LOG_ERROR = 0,
	QWRAP_LOG_WARN,
	QWRAP_LOG_DEBUG,
	QWRAP_LOG_TRACE
};

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif

#ifndef FALL_THROUGH
# ifdef HAVE_FALLTHROUGH_ATTRIBUTE
#  define FALL_THROUGH __attribute__ ((fallthrough))
# else /* HAVE_FALLTHROUGH_ATTRIBUTE */
#  define FALL_THROUGH ((void)0)
# endif /* HAVE_FALLTHROUGH_ATTRIBUTE */
#endif /* FALL_THROUGH */

#ifdef HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE __attribute__((no_sanitize_address))
#else
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
#endif

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define QWRAP_THREAD __thread
#else
# define QWRAP_THREAD
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

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#define UNUSED(x) (void)(x)

#define quic_ko_wrapper_init_mutex(m) \
	_quic_ko_wrapper_init_mutex(m, #m)

/* Add new global locks here please */
# define QWRAP_REINIT_ALL do { \
	int ret; \
	ret = quic_ko_wrapper_init_mutex(&sockets_mutex); \
	if (ret != 0) exit(-1); \
	ret = quic_ko_wrapper_init_mutex(&socket_reset_mutex); \
	if (ret != 0) exit(-1); \
	ret = quic_ko_wrapper_init_mutex(&first_free_mutex); \
	if (ret != 0) exit(-1); \
	ret = quic_ko_wrapper_init_mutex(&sockets_si_global); \
	if (ret != 0) exit(-1); \
} while(0)

# define QWRAP_LOCK_ALL do { \
	qwrap_mutex_lock(&sockets_mutex); \
	qwrap_mutex_lock(&socket_reset_mutex); \
	qwrap_mutex_lock(&first_free_mutex); \
	qwrap_mutex_lock(&sockets_si_global); \
} while(0)

# define QWRAP_UNLOCK_ALL do { \
	qwrap_mutex_unlock(&sockets_si_global); \
	qwrap_mutex_unlock(&first_free_mutex); \
	qwrap_mutex_unlock(&socket_reset_mutex); \
	qwrap_mutex_unlock(&sockets_mutex); \
} while(0)

#define QUIC_KO_INFO_CONTAINER(si) \
	(struct qwrap_socket_info_container *)(si)

#define QWRAP_LOCK_SI(si) do { \
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si); \
	if (sic != NULL) { \
		qwrap_mutex_lock(&sockets_si_global); \
	} else { \
		abort(); \
	} \
} while(0)

#define QWRAP_UNLOCK_SI(si) do { \
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si); \
	if (sic != NULL) { \
		qwrap_mutex_unlock(&sockets_si_global); \
	} else { \
		abort(); \
	} \
} while(0)

#if defined(HAVE_GETTIMEOFDAY_TZ) || defined(HAVE_GETTIMEOFDAY_TZ_VOID)
#define qwrapGetTimeOfDay(tval) gettimeofday(tval,NULL)
#else
#define qwrapGetTimeOfDay(tval)	gettimeofday(tval)
#endif

/*
 * Maximum number of socket_info structures that can
 * be used. Can be overriden by the environment variable
 * QUIC_KO_WRAPPER_MAX_SOCKETS.
 */
#define QUIC_KO_WRAPPER_MAX_SOCKETS_DEFAULT 65535

#define QUIC_KO_WRAPPER_MAX_SOCKETS_LIMIT 262140

struct qwrap_address {
	socklen_t sa_socklen;
	union {
		struct sockaddr sa;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
		struct sockaddr_storage ss;
	} u;
};

static int first_free;

struct qwrap_msgbuf {
	struct qwrap_msgbuf *next;
	uint8_t level;
	ssize_t datalen;
	uint8_t data[];
};

struct qwrap_socket_info
{
	int bound;
	int connected;
	int listening;
	int is_server;
	int handshake_done;

	ngtcp2_conn *conn;
	int64_t stream_id;
	struct qwrap_address laddr;
	struct qwrap_address raddr;
	ngtcp2_path path;

	struct {
		struct qwrap_msgbuf *first;
		struct qwrap_msgbuf *last;
		int cb_error;
	} hs_recvmsg_in, hs_recvmsg_out, stream_recvmsg;
};

struct qwrap_socket_info_meta
{
	unsigned int refcount;
	int next_free;
	/*
	 * As long as we don't use shared memory
	 * for the sockets array, we use
	 * sockets_si_global as a single mutex.
	 *
	 * pthread_mutex_t mutex;
	 */
};

struct qwrap_socket_info_container
{
	struct qwrap_socket_info info;
	struct qwrap_socket_info_meta meta;
};

static struct qwrap_socket_info_container *sockets;

static size_t socket_info_max = 0;

/*
 * Allocate the socket array always on the limit value. We want it to be
 * at least bigger than the default so if we reach the limit we can
 * still deal with duplicate fds pointing to the same socket_info.
 */
static size_t socket_fds_max = QUIC_KO_WRAPPER_MAX_SOCKETS_LIMIT;

/* Hash table to map fds to corresponding socket_info index */
static int *socket_fds_idx;

/* Mutex to guard the initialization of array of socket_info structures */
static pthread_mutex_t sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to guard the socket reset in qwrap_remove_wrapper() */
static pthread_mutex_t socket_reset_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to synchronize access to first free index in socket_info array */
static pthread_mutex_t first_free_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Mutex to synchronize access to to socket_info structures
 * We use a single global mutex in order to avoid leaking
 * ~ 27 copy on write memory per fork.
 * max_sockets=65535 * sizeof(struct qwrap_socket_info_container)=432 = 28311120
 */
static pthread_mutex_t sockets_si_global = PTHREAD_MUTEX_INITIALIZER;

/* Function prototypes */

#if ! defined(HAVE_CONSTRUCTOR_ATTRIBUTE) && defined(HAVE_PRAGMA_INIT)
/* xlC and other oldschool compilers support (only) this */
#pragma init (qwrap_constructor)
#endif
static void qwrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
#if ! defined(HAVE_DESTRUCTOR_ATTRIBUTE) && defined(HAVE_PRAGMA_FINI)
#pragma fini (qwrap_destructor)
#endif
static void qwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

#ifndef HAVE_GETPROGNAME
static const char *getprogname(void)
{
#if defined(HAVE_PROGRAM_INVOCATION_SHORT_NAME)
	return program_invocation_short_name;
#elif defined(HAVE_GETEXECNAME)
	return getexecname();
#else
	return NULL;
#endif /* HAVE_PROGRAM_INVOCATION_SHORT_NAME */
}
#endif /* HAVE_GETPROGNAME */

static void qwrap_log(enum qwrap_dbglvl_e dbglvl, const char *func, unsigned line, const char *format, ...) PRINTF_ATTRIBUTE(4, 5);
# define QWRAP_LOG(dbglvl, ...) qwrap_log((dbglvl), __func__, __LINE__, __VA_ARGS__)

static void qwrap_log(enum qwrap_dbglvl_e dbglvl,
		      const char *func,
		      unsigned line,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = "QWRAP";
	const char *progname = getprogname();

	d = getenv("QUIC_KO_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	if (lvl < dbglvl) {
		return;
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	switch (dbglvl) {
		case QWRAP_LOG_ERROR:
			prefix = "QWRAP_ERROR";
			break;
		case QWRAP_LOG_WARN:
			prefix = "QWRAP_WARN";
			break;
		case QWRAP_LOG_DEBUG:
			prefix = "QWRAP_DEBUG";
			break;
		case QWRAP_LOG_TRACE:
			prefix = "QWRAP_TRACE";
			break;
	}

	if (progname == NULL) {
		progname = "<unknown>";
	}

	fprintf(stderr,
		"%s[%s (%u)] - %s:%u: %s\n",
		prefix,
		progname,
		(unsigned int)getpid(),
		func,
		line,
		buffer);
}

static void dump_data(const char *name, const void *p, size_t len)
{
	UNUSED(p);
	QWRAP_LOG(QWRAP_LOG_TRACE, "%s: length=%zu", name, len);
}

/*********************************************************
 * QWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

#ifdef HAVE_ACCEPT4
typedef int (*__next_accept4)(int sockfd,
			      struct sockaddr *addr,
			      socklen_t *addrlen,
			      int flags);
#else
typedef int (*__next_accept)(int sockfd,
			     struct sockaddr *addr,
			     socklen_t *addrlen);
#endif
typedef int (*__next_bind)(int sockfd,
			   const struct sockaddr *addr,
			   socklen_t addrlen);
typedef int (*__next_close)(int fd);
#ifdef HAVE___CLOSE_NOCANCEL
typedef int (*__next___close_nocancel)(int fd);
#endif
typedef int (*__next_connect)(int sockfd,
			      const struct sockaddr *addr,
			      socklen_t addrlen);
typedef int (*__next_dup)(int fd);
typedef int (*__next_dup2)(int oldfd, int newfd);
typedef int (*__next_fcntl)(int fd, int cmd, ...);
#ifdef HAVE_FCNTL64
typedef int (*__next_fcntl64)(int fd, int cmd, ...);
#endif
typedef FILE *(*__next_fopen)(const char *name, const char *mode);
#ifdef HAVE_FOPEN64
typedef FILE *(*__next_fopen64)(const char *name, const char *mode);
#endif
#ifdef HAVE_EVENTFD
typedef int (*__next_eventfd)(int count, int flags);
#endif
typedef int (*__next_getsockopt)(int sockfd,
			       int level,
			       int optname,
			       void *optval,
			       socklen_t *optlen);
typedef int (*__next_ioctl)(int d, unsigned long int request, ...);
typedef int (*__next_listen)(int sockfd, int backlog);
typedef int (*__next_open)(const char *pathname, int flags, ...);
#ifdef HAVE_OPEN64
typedef int (*__next_open64)(const char *pathname, int flags, ...);
#endif /* HAVE_OPEN64 */
#ifdef HAVE_OPENAT64
typedef int (*__next_openat64)(int dirfd, const char *pathname, int flags, ...);
#endif /* HAVE_OPENAT64 */
typedef int (*__next_openat)(int dirfd, const char *path, int flags, ...);
typedef int (*__next_pipe)(int pipefd[2]);
typedef int (*__next_read)(int fd, void *buf, size_t count);
typedef ssize_t (*__next_readv)(int fd, const struct iovec *iov, int iovcnt);
typedef int (*__next_recv)(int sockfd, void *buf, size_t len, int flags);
typedef int (*__next_recvfrom)(int sockfd,
			     void *buf,
			     size_t len,
			     int flags,
			     struct sockaddr *src_addr,
			     socklen_t *addrlen);
typedef int (*__next_recvmsg)(int sockfd, const struct msghdr *msg, int flags);
#ifdef HAVE_RECVMMSG
#if defined(HAVE_RECVMMSG_SSIZE_T_CONST_TIMEOUT)
/* FreeBSD */
typedef ssize_t (*__next_recvmmsg)(int sockfd, struct mmsghdr *msgvec, size_t vlen, int flags, const struct timespec *timeout);
#elif defined(HAVE_RECVMMSG_CONST_TIMEOUT)
/* Linux legacy glibc < 2.21 */
typedef int (*__next_recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, const struct timespec *timeout);
#else
/* Linux glibc >= 2.21 */
typedef int (*__next_recvmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
#endif
#endif /* HAVE_RECVMMSG */
typedef int (*__next_send)(int sockfd, const void *buf, size_t len, int flags);
typedef int (*__next_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
#ifdef HAVE_SENDMMSG
#if defined(HAVE_SENDMMSG_SSIZE_T)
/* FreeBSD */
typedef ssize_t (*__next_sendmmsg)(int sockfd, struct mmsghdr *msgvec, size_t vlen, int flags);
#else
/* Linux */
typedef int (*__next_sendmmsg)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags);
#endif
#endif /* HAVE_SENDMMSG */
typedef int (*__next_sendto)(int sockfd,
			   const void *buf,
			   size_t len,
			   int flags,
			   const  struct sockaddr *dst_addr,
			   socklen_t addrlen);
typedef int (*__next_setsockopt)(int sockfd,
			       int level,
			       int optname,
			       const void *optval,
			       socklen_t optlen);
#ifdef HAVE_SIGNALFD
typedef int (*__next_signalfd)(int fd, const sigset_t *mask, int flags);
#endif
typedef int (*__next_socket)(int domain, int type, int protocol);
typedef int (*__next_socketpair)(int domain, int type, int protocol, int sv[2]);
#ifdef HAVE_TIMERFD_CREATE
typedef int (*__next_timerfd_create)(int clockid, int flags);
#endif
typedef ssize_t (*__next_write)(int fd, const void *buf, size_t count);
typedef ssize_t (*__next_writev)(int fd, const struct iovec *iov, int iovcnt);
typedef bool (*__next_socket_wrapper_enabled)(void);
typedef int (*__next_socket_wrapper_ipproto_quic_socket)(int family, int type);

#define QWRAP_SYMBOL_ENTRY(i) \
	union { \
		__next_##i f; \
		void *obj; \
	} _next_##i

struct qwrap_next_symbols {
#ifdef HAVE_ACCEPT4
	QWRAP_SYMBOL_ENTRY(accept4);
#else
	QWRAP_SYMBOL_ENTRY(accept);
#endif
	QWRAP_SYMBOL_ENTRY(bind);
	QWRAP_SYMBOL_ENTRY(close);
#ifdef HAVE___CLOSE_NOCANCEL
	QWRAP_SYMBOL_ENTRY(__close_nocancel);
#endif
	QWRAP_SYMBOL_ENTRY(connect);
	QWRAP_SYMBOL_ENTRY(dup);
	QWRAP_SYMBOL_ENTRY(dup2);
	QWRAP_SYMBOL_ENTRY(fcntl);
#ifdef HAVE_FCNTL64
	QWRAP_SYMBOL_ENTRY(fcntl64);
#endif
	QWRAP_SYMBOL_ENTRY(fopen);
#ifdef HAVE_FOPEN64
	QWRAP_SYMBOL_ENTRY(fopen64);
#endif
#ifdef HAVE_EVENTFD
	QWRAP_SYMBOL_ENTRY(eventfd);
#endif
	QWRAP_SYMBOL_ENTRY(getsockopt);
	QWRAP_SYMBOL_ENTRY(ioctl);
	QWRAP_SYMBOL_ENTRY(listen);
	QWRAP_SYMBOL_ENTRY(open);
#ifdef HAVE_OPEN64
	QWRAP_SYMBOL_ENTRY(open64);
#endif
#ifdef HAVE_OPENAT64
	QWRAP_SYMBOL_ENTRY(openat64);
#endif
	QWRAP_SYMBOL_ENTRY(openat);
	QWRAP_SYMBOL_ENTRY(pipe);
	QWRAP_SYMBOL_ENTRY(read);
	QWRAP_SYMBOL_ENTRY(readv);
	QWRAP_SYMBOL_ENTRY(recv);
	QWRAP_SYMBOL_ENTRY(recvfrom);
	QWRAP_SYMBOL_ENTRY(recvmsg);
#ifdef HAVE_RECVMMSG
	QWRAP_SYMBOL_ENTRY(recvmmsg);
#endif
	QWRAP_SYMBOL_ENTRY(send);
	QWRAP_SYMBOL_ENTRY(sendmsg);
#ifdef HAVE_SENDMMSG
	QWRAP_SYMBOL_ENTRY(sendmmsg);
#endif
	QWRAP_SYMBOL_ENTRY(sendto);
	QWRAP_SYMBOL_ENTRY(setsockopt);
#ifdef HAVE_SIGNALFD
	QWRAP_SYMBOL_ENTRY(signalfd);
#endif
	QWRAP_SYMBOL_ENTRY(socket);
	QWRAP_SYMBOL_ENTRY(socketpair);
#ifdef HAVE_TIMERFD_CREATE
	QWRAP_SYMBOL_ENTRY(timerfd_create);
#endif
	QWRAP_SYMBOL_ENTRY(write);
	QWRAP_SYMBOL_ENTRY(writev);
	QWRAP_SYMBOL_ENTRY(socket_wrapper_enabled);
	QWRAP_SYMBOL_ENTRY(socket_wrapper_ipproto_quic_socket);
};
#undef QWRAP_SYMBOL_ENTRY


struct qwrap {
	struct {
		struct qwrap_next_symbols symbols;
	} _next;
};

static struct qwrap qwrap;

static void *_qwrap_bind_symbol(const char *fn_name)
{
	void *func;

	func = dlsym(RTLD_NEXT, fn_name);
	if (func == NULL) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Failed to find %s: %s",
			  fn_name,
			  dlerror());
		exit(-1);
	}
return func;
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "Loaded %s",
		  fn_name);

	return func;
}

#define qwrap_mutex_lock(m) _qwrap_mutex_lock(m, #m, __func__, __LINE__)
static void _qwrap_mutex_lock(pthread_mutex_t *mutex, const char *name, const char *caller, unsigned line)
{
	int ret;

	ret = pthread_mutex_lock(mutex);
	if (ret != 0) {
		QWRAP_LOG(QWRAP_LOG_ERROR, "PID(%d):PPID(%d): %s(%u): Couldn't lock pthread mutex(%s) - %s",
			  getpid(), getppid(), caller, line, name, strerror(ret));
		abort();
	}
}

#define qwrap_mutex_unlock(m) _qwrap_mutex_unlock(m, #m, __func__, __LINE__)
static void _qwrap_mutex_unlock(pthread_mutex_t *mutex, const char *name, const char *caller, unsigned line)
{
	int ret;

	ret = pthread_mutex_unlock(mutex);
	if (ret != 0) {
		QWRAP_LOG(QWRAP_LOG_ERROR, "PID(%d):PPID(%d): %s(%u): Couldn't unlock pthread mutex(%s) - %s",
			  getpid(), getppid(), caller, line, name, strerror(ret));
		abort();
	}
}

/*
 * These macros have a thread race condition on purpose!
 *
 * This is an optimization to avoid locking each time we check if the symbol is
 * bound.
 */
#define qwrap_bind_symbol_next(sym_name) do { \
	qwrap._next.symbols._next_##sym_name.obj = \
		_qwrap_bind_symbol(#sym_name); \
} while(0);
#define qwrap_bind_symbol_next_optional(sym_name) do { \
	qwrap._next.symbols._next_##sym_name.obj = \
		dlsym(RTLD_NEXT, #sym_name); \
} while(0);

static void qwrap_bind_symbol_all(void);

/****************************************************************************
 *                               IMPORTANT
 ****************************************************************************
 *
 * Functions especially from libc need to be loaded individually, you can't
 * load all at once or gdb will segfault at startup. The same applies to
 * valgrind and has probably something todo with with the linker.  So we need
 * load each function at the point it is called the first time.
 *
 ****************************************************************************/

#ifdef HAVE_ACCEPT4
static int next_accept4(int sockfd,
			struct sockaddr *addr,
			socklen_t *addrlen,
			int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_accept4.f(sockfd, addr, addrlen, flags);
}

#else /* HAVE_ACCEPT4 */

static int next_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_accept.f(sockfd, addr, addrlen);
}
#endif /* HAVE_ACCEPT4 */

static int next_bind(int sockfd,
		     const struct sockaddr *addr,
		     socklen_t addrlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_bind.f(sockfd, addr, addrlen);
}

static int next_close(int fd)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_close.f(fd);
}

#ifdef HAVE___CLOSE_NOCANCEL
static int next___close_nocancel(int fd)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next___close_nocancel.f(fd);
}
#endif /* HAVE___CLOSE_NOCANCEL */

static int next_connect(int sockfd,
			const struct sockaddr *addr,
			socklen_t addrlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_connect.f(sockfd, addr, addrlen);
}

static int next_dup(int fd)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_dup.f(fd);
}

static int next_dup2(int oldfd, int newfd)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_dup2.f(oldfd, newfd);
}

#ifdef HAVE_EVENTFD
static int next_eventfd(int count, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_eventfd.f(count, flags);
}
#endif

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static int next_vfcntl(int fd, int cmd, va_list ap)
{
	void *arg;
	int rc;

	qwrap_bind_symbol_all();

	arg = va_arg(ap, void *);

	rc = qwrap._next.symbols._next_fcntl.f(fd, cmd, arg);

	return rc;
}

#ifdef HAVE_FCNTL64
DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static int next_vfcntl64(int fd, int cmd, va_list ap)
{
	void *arg;
	int rc;

	qwrap_bind_symbol_all();

	arg = va_arg(ap, void *);

	rc = qwrap._next.symbols._next_fcntl64.f(fd, cmd, arg);

	return rc;
}
#endif

static int next_getsockopt(int sockfd,
			   int level,
			   int optname,
			   void *optval,
			   socklen_t *optlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_getsockopt.f(sockfd,
						     level,
						     optname,
						     optval,
						     optlen);
}

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static int next_vioctl(int d, unsigned long int request, va_list ap)
{
	void *arg;
	int rc;

	qwrap_bind_symbol_all();

	arg = va_arg(ap, void *);

	rc = qwrap._next.symbols._next_ioctl.f(d, request, arg);

	return rc;
}

static int next_listen(int sockfd, int backlog)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_listen.f(sockfd, backlog);
}

static FILE *next_fopen(const char *name, const char *mode)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_fopen.f(name, mode);
}

#ifdef HAVE_FOPEN64
static FILE *next_fopen64(const char *name, const char *mode)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_fopen64.f(name, mode);
}
#endif /* HAVE_FOPEN64 */

static void qwrap_inject_o_largefile(int *flags)
{
	(void)*flags; /* maybe unused */
#if SIZE_MAX == 0xffffffffUL && defined(O_LARGEFILE)
#ifdef O_PATH
	if (((*flags) & O_PATH) == 0)
#endif
	{
		*flags |= O_LARGEFILE;
	}
#endif
}

static int next_vopen(const char *pathname, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	qwrap_bind_symbol_all();

	qwrap_inject_o_largefile(&flags);

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = qwrap._next.symbols._next_open.f(pathname, flags, (mode_t)mode);

	return fd;
}

#ifdef HAVE_OPEN64
static int next_vopen64(const char *pathname, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	qwrap_bind_symbol_all();

	qwrap_inject_o_largefile(&flags);

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = qwrap._next.symbols._next_open64.f(pathname, flags, (mode_t)mode);

	return fd;
}
#endif /* HAVE_OPEN64 */

#ifdef HAVE_OPENAT64
static int
next_vopenat64(int dirfd, const char *pathname, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	qwrap_bind_symbol_all();

	qwrap_inject_o_largefile(&flags);

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = qwrap._next.symbols._next_openat64.f(dirfd,
						 pathname,
						 flags,
						 (mode_t)mode);

	return fd;
}
#endif /* HAVE_OPENAT64 */

static int next_vopenat(int dirfd, const char *path, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	qwrap_bind_symbol_all();

	qwrap_inject_o_largefile(&flags);

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = qwrap._next.symbols._next_openat.f(dirfd,
					       path,
					       flags,
					       (mode_t)mode);

	return fd;
}

#if 0
static int next_openat(int dirfd, const char *path, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = next_vopenat(dirfd, path, flags, ap);
	va_end(ap);

	return fd;
}
#endif

static int next_pipe(int pipefd[2])
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_pipe.f(pipefd);
}

static int next_read(int fd, void *buf, size_t count)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_read.f(fd, buf, count);
}

static ssize_t next_readv(int fd, const struct iovec *iov, int iovcnt)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_readv.f(fd, iov, iovcnt);
}

static int next_recv(int sockfd, void *buf, size_t len, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_recv.f(sockfd, buf, len, flags);
}

static int next_recvfrom(int sockfd,
			 void *buf,
			 size_t len,
			 int flags,
			 struct sockaddr *src_addr,
			 socklen_t *addrlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_recvfrom.f(sockfd,
						   buf,
						   len,
						   flags,
						   src_addr,
						   addrlen);
}

static int next_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_recvmsg.f(sockfd, msg, flags);
}

#ifdef HAVE_RECVMMSG
#if defined(HAVE_RECVMMSG_SSIZE_T_CONST_TIMEOUT)
/* FreeBSD */
static ssize_t next_recvmmsg(int sockfd, struct mmsghdr *msgvec, size_t vlen, int flags, const struct timespec *timeout)
#elif defined(HAVE_RECVMMSG_CONST_TIMEOUT)
/* Linux legacy glibc < 2.21 */
static int next_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, const struct timespec *timeout)
#else
/* Linux glibc >= 2.21 */
static int next_recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout)
#endif
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_recvmmsg.f(sockfd, msgvec, vlen, flags, timeout);
}
#endif

static int next_send(int sockfd, const void *buf, size_t len, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_send.f(sockfd, buf, len, flags);
}

static int next_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_sendmsg.f(sockfd, msg, flags);
}

#ifdef HAVE_SENDMMSG
#if defined(HAVE_SENDMMSG_SSIZE_T)
/* FreeBSD */
static ssize_t next_sendmmsg(int sockfd, struct mmsghdr *msgvec, size_t vlen, int flags)
#else
/* Linux */
static int next_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
#endif
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_sendmmsg.f(sockfd, msgvec, vlen, flags);
}
#endif

static int next_sendto(int sockfd,
		       const void *buf,
		       size_t len,
		       int flags,
		       const  struct sockaddr *dst_addr,
		       socklen_t addrlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_sendto.f(sockfd,
						 buf,
						 len,
						 flags,
						 dst_addr,
						 addrlen);
}

static int next_setsockopt(int sockfd,
			   int level,
			   int optname,
			   const void *optval,
			   socklen_t optlen)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_setsockopt.f(sockfd,
						     level,
						     optname,
						     optval,
						     optlen);
}

#ifdef HAVE_SIGNALFD
static int next_signalfd(int fd, const sigset_t *mask, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_signalfd.f(fd, mask, flags);
}
#endif

static int next_socket(int domain, int type, int protocol)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_socket.f(domain, type, protocol);
}

static int next_socketpair(int domain, int type, int protocol, int sv[2])
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_socketpair.f(domain, type, protocol, sv);
}

#ifdef HAVE_TIMERFD_CREATE
static int next_timerfd_create(int clockid, int flags)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_timerfd_create.f(clockid, flags);
}
#endif

static ssize_t next_write(int fd, const void *buf, size_t count)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_write.f(fd, buf, count);
}

static ssize_t next_writev(int fd, const struct iovec *iov, int iovcnt)
{
	qwrap_bind_symbol_all();

	return qwrap._next.symbols._next_writev.f(fd, iov, iovcnt);
}

/* DO NOT call this function during library initialization! */
static void __qwrap_bind_symbol_all_once(void)
{
#ifdef HAVE_ACCEPT4
	qwrap_bind_symbol_next(accept4);
#else
	qwrap_bind_symbol_next(accept);
#endif
	qwrap_bind_symbol_next(bind);
	qwrap_bind_symbol_next(close);
#ifdef HAVE___CLOSE_NOCANCEL
	qwrap_bind_symbol_next(__close_nocancel);
#endif
	qwrap_bind_symbol_next(connect);
	qwrap_bind_symbol_next(dup);
	qwrap_bind_symbol_next(dup2);
	qwrap_bind_symbol_next(fcntl);
#ifdef HAVE_FCNTL64
	qwrap_bind_symbol_next(fcntl64);
#endif
	qwrap_bind_symbol_next(fopen);
#ifdef HAVE_FOPEN64
	qwrap_bind_symbol_next(fopen64);
#endif
#ifdef HAVE_EVENTFD
	qwrap_bind_symbol_next(eventfd);
#endif
	qwrap_bind_symbol_next(getsockopt);
	qwrap_bind_symbol_next(ioctl);
	qwrap_bind_symbol_next(listen);
	qwrap_bind_symbol_next(open);
#ifdef HAVE_OPEN64
	qwrap_bind_symbol_next(open64);
#endif
#ifdef HAVE_OPENAT64
	qwrap_bind_symbol_next(openat64);
#endif
	qwrap_bind_symbol_next(openat);
	qwrap_bind_symbol_next(pipe);
	qwrap_bind_symbol_next(read);
	qwrap_bind_symbol_next(readv);
	qwrap_bind_symbol_next(recv);
	qwrap_bind_symbol_next(recvfrom);
	qwrap_bind_symbol_next(recvmsg);
#ifdef HAVE_RECVMMSG
	qwrap_bind_symbol_next(recvmmsg);
#endif
	qwrap_bind_symbol_next(send);
	qwrap_bind_symbol_next(sendmsg);
#ifdef HAVE_SENDMMSG
	qwrap_bind_symbol_next(sendmmsg);
#endif
	qwrap_bind_symbol_next(sendto);
	qwrap_bind_symbol_next(setsockopt);
#ifdef HAVE_SIGNALFD
	qwrap_bind_symbol_next(signalfd);
#endif
	qwrap_bind_symbol_next(socket);
	qwrap_bind_symbol_next(socketpair);
#ifdef HAVE_TIMERFD_CREATE
	qwrap_bind_symbol_next(timerfd_create);
#endif
	qwrap_bind_symbol_next(write);
	qwrap_bind_symbol_next(writev);
	qwrap_bind_symbol_next_optional(socket_wrapper_enabled);
	qwrap_bind_symbol_next_optional(socket_wrapper_ipproto_quic_socket);
}

static void qwrap_bind_symbol_all(void)
{
	static pthread_once_t all_symbol_binding_once = PTHREAD_ONCE_INIT;

	pthread_once(&all_symbol_binding_once, __qwrap_bind_symbol_all_once);
}

static bool quic_ko_socket_wrapper_enabled(void)
{
	qwrap_bind_symbol_all();

	if (qwrap._next.symbols._next_socket_wrapper_enabled.f == NULL) {
		return false;
	}

	return qwrap._next.symbols._next_socket_wrapper_enabled.f();
}

static int quic_ko_socket_wrapper_ipproto_quic_socket(int family, int type)
{
	qwrap_bind_symbol_all();

	if (qwrap._next.symbols._next_socket_wrapper_ipproto_quic_socket.f == NULL) {
		QWRAP_LOG(QWRAP_LOG_ERROR, "socket_wrapper too old no "
			  "socket_wrapper_ipproto_quic_socket symbol found!");
		errno = EPROTONOSUPPORT;
		return -1;
	}

	return qwrap._next.symbols._next_socket_wrapper_ipproto_quic_socket.f(
		family, type);
}

/*********************************************************
 * QWRAP HELPER FUNCTIONS
 *********************************************************/

struct qwrap_sockaddr_buf {
	char str[128];
};

static const char *qwrap_sockaddr_string(struct qwrap_sockaddr_buf *buf,
					 const struct sockaddr *saddr)
{
	unsigned int port = 0;
	char addr[64] = {0,};

	switch (saddr->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *in =
		    (const struct sockaddr_in *)(const void *)saddr;

		port = ntohs(in->sin_port);

		inet_ntop(saddr->sa_family,
			  &in->sin_addr,
			  addr, sizeof(addr));
		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		const struct sockaddr_in6 *in6 =
		    (const struct sockaddr_in6 *)(const void *)saddr;

		port = ntohs(in6->sin6_port);

		inet_ntop(saddr->sa_family,
			  &in6->sin6_addr,
			  addr, sizeof(addr));
		break;
	}
#endif
	default:
		snprintf(addr, sizeof(addr),
			 "<Unknown address family %u>",
			 saddr->sa_family);
		break;
	}

	snprintf(buf->str, sizeof(buf->str),
		 "addr[%s]/port[%u]",
		 addr, port);

	return buf->str;
}

static struct qwrap_socket_info *qwrap_get_socket_info(int si_index)
{
	return (struct qwrap_socket_info *)(&(sockets[si_index].info));
}

static int qwrap_get_refcount(struct qwrap_socket_info *si)
{
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si);
	return sic->meta.refcount;
}

static void qwrap_inc_refcount(struct qwrap_socket_info *si)
{
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si);

	sic->meta.refcount += 1;
}

static void qwrap_dec_refcount(struct qwrap_socket_info *si)
{
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si);

	sic->meta.refcount -= 1;
}

static int qwrap_get_next_free(struct qwrap_socket_info *si)
{
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si);

	return sic->meta.next_free;
}

static void qwrap_set_next_free(struct qwrap_socket_info *si, int next_free)
{
	struct qwrap_socket_info_container *sic = QUIC_KO_INFO_CONTAINER(si);

	sic->meta.next_free = next_free;
}

static int _quic_ko_wrapper_init_mutex(pthread_mutex_t *m, const char *name)
{
	pthread_mutexattr_t ma;
	bool need_destroy = false;
	int ret = 0;

#define __CHECK(cmd) do { \
	ret = cmd; \
	if (ret != 0) { \
		QWRAP_LOG(QWRAP_LOG_ERROR, \
			  "%s: %s - failed %d", \
			  name, #cmd, ret); \
		goto done; \
	} \
} while(0)

	*m = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	__CHECK(pthread_mutexattr_init(&ma));
	need_destroy = true;
	__CHECK(pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK));
	__CHECK(pthread_mutex_init(m, &ma));
done:
	if (need_destroy) {
		pthread_mutexattr_destroy(&ma);
	}
	return ret;
}

static size_t quic_ko_wrapper_max_sockets(void)
{
	const char *s;
	size_t tmp;
	char *endp;

	if (socket_info_max != 0) {
		return socket_info_max;
	}

	socket_info_max = QUIC_KO_WRAPPER_MAX_SOCKETS_DEFAULT;

	s = getenv("QUIC_KO_WRAPPER_MAX_SOCKETS");
	if (s == NULL || s[0] == '\0') {
		goto done;
	}

	tmp = strtoul(s, &endp, 10);
	if (s == endp) {
		goto done;
	}
	if (tmp == 0) {
		tmp = QUIC_KO_WRAPPER_MAX_SOCKETS_DEFAULT;
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Invalid number of sockets specified, "
			  "using default (%zu)",
			  tmp);
	}

	if (tmp > QUIC_KO_WRAPPER_MAX_SOCKETS_LIMIT) {
		tmp = QUIC_KO_WRAPPER_MAX_SOCKETS_LIMIT;
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Invalid number of sockets specified, "
			  "using maximum (%zu).",
			  tmp);
	}

	socket_info_max = tmp;

done:
	return socket_info_max;
}

static void quic_ko_wrapper_init_fds_idx(void)
{
	int *tmp = NULL;
	size_t i;

	if (socket_fds_idx != NULL) {
		return;
	}

	tmp = (int *)calloc(socket_fds_max, sizeof(int));
	if (tmp == NULL) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Failed to allocate socket fds index array: %s",
			  strerror(errno));
		exit(-1);
	}

	for (i = 0; i < socket_fds_max; i++) {
		tmp[i] = -1;
	}

	socket_fds_idx = tmp;
}

static void quic_ko_wrapper_init_sockets(void)
{
	size_t max_sockets;
	size_t i;
	int ret = 0;

	qwrap_bind_symbol_all();

	qwrap_mutex_lock(&sockets_mutex);

	if (sockets != NULL) {
		qwrap_mutex_unlock(&sockets_mutex);
		return;
	}

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "QUIC_KO_WRAPPER_PACKAGE[%s] QUIC_KO_WRAPPER_VERSION[%s]",
		  QUIC_KO_WRAPPER_PACKAGE, QUIC_KO_WRAPPER_VERSION);

	quic_ko_wrapper_init_fds_idx();

	/* Needs to be called inside the sockets_mutex lock here. */
	max_sockets = quic_ko_wrapper_max_sockets();

	sockets = (struct qwrap_socket_info_container *)calloc(max_sockets,
					sizeof(struct qwrap_socket_info_container));

	if (sockets == NULL) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Failed to allocate sockets array: %s",
			  strerror(errno));
		qwrap_mutex_unlock(&sockets_mutex);
		exit(-1);
	}

	qwrap_mutex_lock(&first_free_mutex);
	qwrap_mutex_lock(&sockets_si_global);

	first_free = 0;

	for (i = 0; i < max_sockets; i++) {
		qwrap_set_next_free(&sockets[i].info, i+1);
	}

	/* mark the end of the free list */
	qwrap_set_next_free(&sockets[max_sockets-1].info, -1);

	qwrap_mutex_unlock(&sockets_si_global);
	qwrap_mutex_unlock(&first_free_mutex);
	qwrap_mutex_unlock(&sockets_mutex);
	if (ret != 0) {
		exit(-1);
	}
}

bool quic_ko_wrapper_enabled(void)
{
	const char *env = getenv("QUIC_KO_WRAPPER");
	if (env != NULL && env[0] == '1') {
		quic_ko_wrapper_init_sockets();
		return true;
	}

	return false;
}

static void set_socket_info_index(int fd, int idx)
{
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "fd=%d idx=%d",
		  fd, idx);
	socket_fds_idx[fd] = idx;
	/* This builtin issues a full memory barrier. */
	__sync_synchronize();
}

static void reset_socket_info_index(int fd)
{
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "fd=%d idx=%d",
		  fd, -1);
	set_socket_info_index(fd, -1);
}

static int find_qwrap_socket_index(int fd)
{
	if (fd < 0) {
		return -1;
	}

	if (socket_fds_idx == NULL) {
		return -1;
	}

	if ((size_t)fd >= socket_fds_max) {
		/*
		 * Do not add a log here as some applications do stupid things
		 * like:
		 *
		 *     for (fd = 0; fd <= getdtablesize(); fd++) {
		 *         close(fd)
		 *     };
		 *
		 * This would produce millions of lines of debug messages.
		 */
#if 0
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Looking for a socket info for the fd %d is over the "
			  "max socket index limit of %zu.",
			  fd,
			  socket_fds_max);
#endif
		return -1;
	}

	/* This builtin issues a full memory barrier. */
	__sync_synchronize();
	return socket_fds_idx[fd];
}

static int qwrap_add_socket_info(const struct qwrap_socket_info *si_input)
{
	struct qwrap_socket_info *si = NULL;
	int si_index = -1;

	if (si_input == NULL) {
		errno = EINVAL;
		return -1;
	}

	qwrap_mutex_lock(&first_free_mutex);
	if (first_free == -1) {
		errno = ENFILE;
		goto out;
	}

	si_index = first_free;
	si = qwrap_get_socket_info(si_index);

	QWRAP_LOCK_SI(si);

	first_free = qwrap_get_next_free(si);
	*si = *si_input;
	qwrap_inc_refcount(si);

	QWRAP_UNLOCK_SI(si);

out:
	qwrap_mutex_unlock(&first_free_mutex);

	return si_index;
}

static void qwrap_ngtcp2_log_printf(void *user_data, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
static void qwrap_ngtcp2_log_printf(void *user_data, const char *fmt, ...)
{
	char buffer[1024];
	va_list ap;

	UNUSED(user_data);

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	QWRAP_LOG(QWRAP_LOG_TRACE, "NGTCP2: %s\n", buffer);
}

static void qwrap_ngtcp2_qlog_write_cb(void *user_data, uint32_t flags,
				       const void *data, size_t datalen)
{
	QWRAP_LOG(QWRAP_LOG_TRACE, "NGTCP2: flags[%"PRIu32"] len[%zu] %*.*s\n",
		  flags, datalen,
		  (int)datalen, (int)datalen, (const char *)data);
}

static uint64_t qwrap_ngtcp2_timestamp(void)
{
	struct timespec tp;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	assert(ret == 0);

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static ngtcp2_encryption_level qwrap_to_ngtcp2_crypto_level(uint8_t level)
{
	switch (level) {
	case QUIC_CRYPTO_INITIAL:
		return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
	case QUIC_CRYPTO_HANDSHAKE:
		return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
	case QUIC_CRYPTO_APP:
		return NGTCP2_ENCRYPTION_LEVEL_1RTT;
	case QUIC_CRYPTO_EARLY:
		return NGTCP2_ENCRYPTION_LEVEL_0RTT;
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Unknown level=%u", level);
		assert(0);
		abort();
	}
}

static uint8_t qwrap_from_ngtcp2_crypto_level(ngtcp2_encryption_level level)
{
	switch (level) {
	case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
		return QUIC_CRYPTO_INITIAL;
	case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
		return QUIC_CRYPTO_HANDSHAKE;
	case NGTCP2_ENCRYPTION_LEVEL_1RTT:
		return QUIC_CRYPTO_APP;
	case NGTCP2_ENCRYPTION_LEVEL_0RTT:
		return QUIC_CRYPTO_EARLY;
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "Unknown level=%u", level);
		assert(0);
		abort();
	}
}

static gnutls_cipher_algorithm_t qwrap_tls_cipher_type(uint32_t cipher)
{
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128:
		return GNUTLS_CIPHER_AES_128_GCM;
	case TLS_CIPHER_AES_CCM_128:
		return GNUTLS_CIPHER_AES_128_CCM;
	case TLS_CIPHER_AES_GCM_256:
		return GNUTLS_CIPHER_AES_256_GCM;
	case TLS_CIPHER_CHACHA20_POLY1305:
		return GNUTLS_CIPHER_CHACHA20_POLY1305;
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR, "%s: %d", __func__, cipher);
		return GNUTLS_CIPHER_UNKNOWN;
	}
}

static gnutls_digest_algorithm_t qwrap_tls_digest_type(uint32_t cipher)
{
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128:
		return GNUTLS_DIG_SHA256;
	case TLS_CIPHER_AES_CCM_128:
		return GNUTLS_DIG_SHA256;
	case TLS_CIPHER_AES_GCM_256:
		return GNUTLS_DIG_SHA384;
	case TLS_CIPHER_CHACHA20_POLY1305:
		return GNUTLS_DIG_SHA256;
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR, "%s: %d", __func__, cipher);
		return GNUTLS_DIG_UNKNOWN;
	}
}

static gnutls_cipher_algorithm_t qwrap_tls_hp_cipher_type(uint32_t cipher)
{
	switch (cipher) {
	case TLS_CIPHER_AES_GCM_128:
	case TLS_CIPHER_AES_CCM_128:
		return GNUTLS_CIPHER_AES_128_CBC;
	case TLS_CIPHER_AES_GCM_256:
		return GNUTLS_CIPHER_AES_256_CBC;
	case TLS_CIPHER_CHACHA20_POLY1305:
		return GNUTLS_CIPHER_CHACHA20_32;
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR, "%s: %d", __func__, cipher);
		return GNUTLS_CIPHER_UNKNOWN;
	}
}

static uint64_t
qwrap_get_aead_max_encryption(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
		/* NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM */
		return (1ULL << 23);
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		/* NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305 */
		return (1ULL << 62);
	case GNUTLS_CIPHER_AES_128_CCM:
	case GNUTLS_CIPHER_AES_256_CCM:
		/* NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_CCM */
		return (2965820ULL);
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR, "%s: %d", __func__, cipher);
		return 0;
	}
}

static uint64_t
qwrap_get_aead_max_decryption_failure(gnutls_cipher_algorithm_t cipher)
{
	switch (cipher) {
	case GNUTLS_CIPHER_AES_128_GCM:
	case GNUTLS_CIPHER_AES_256_GCM:
		/* NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM */
		return (1ULL << 52);
	case GNUTLS_CIPHER_CHACHA20_POLY1305:
		/* NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305 */
		return (1ULL << 36);
	case GNUTLS_CIPHER_AES_128_CCM:
	case GNUTLS_CIPHER_AES_256_CCM:
		/* NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_CCM */
		return (2965820ULL);
	default:
		QWRAP_LOG(QWRAP_LOG_ERROR, "%s: %d", __func__, cipher);
		return 0;
	}
}

static int qwrap_ngtcp2_client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
	const ngtcp2_cid *dcid = ngtcp2_conn_get_dcid(conn);

	UNUSED(user_data);

	/*
	 * We only use ngtcp2_crypto_recv_client_initial_cb()
	 * instead of ngtcp2_crypto_client_initial_cb()
	 * as we only want ngtcp2_crypto_derive_and_install_initial_key().
	 *
	 * We don't want crypto_set_local_transport_params() and
	 * ngtcp2_crypto_read_write_crypto_data(), as these are filled with
	 * information from the caller as gnutls_session is maintained by
	 * the caller and libquic.
	 */
	return ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);
}

static int qwrap_ngtcp2_recv_crypto_data_cb(ngtcp2_conn *conn,
					    ngtcp2_encryption_level encryption_level,
					    uint64_t offset, const uint8_t *data,
					    size_t datalen, void *user_data)
{
	struct qwrap_socket_info *si = (struct qwrap_socket_info *)user_data;
	struct qwrap_msgbuf *msg = NULL;
	int ret;

	msg = malloc(sizeof(*msg) + datalen);
	if (msg == NULL) {
		return NGTCP2_ERR_NOMEM;
	}

	*msg = (struct qwrap_msgbuf) {
		.level = qwrap_from_ngtcp2_crypto_level(encryption_level),
		.datalen = datalen,
	};
	memcpy(msg->data, data, datalen);

	if (si->hs_recvmsg_out.last != NULL) {
		si->hs_recvmsg_out.last->next = msg;
	}
	si->hs_recvmsg_out.last = msg;
	if (si->hs_recvmsg_out.first == NULL) {
		si->hs_recvmsg_out.first = msg;
	}

	ret = 0;
	if (encryption_level == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
		/*
		 * This is a hack in order to pass 'data' to
		 * the caller as the caller needs to parse
		 * the remote transport parameters and
		 * application secrets in an async way
		 *
		 * So we need to keep the callers message
		 * in si->hs_recvmsg_in and replay to
		 * ngtcp2_conn_read_pkt() again.
		 * Otherwise the ngtcp2_conn core code
		 * will never reach the handshake completion.
		 */
		ret = NGTCP2_ERR_REQUIRED_TRANSPORT_PARAM;
	}
	si->hs_recvmsg_out.cb_error = ret;
	return ret;
}

static int qwrap_ngtcp2_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
					    int64_t stream_id, uint64_t offset,
					    const uint8_t *data, size_t datalen,
					    void *user_data, void *stream_user_data)
{
	struct qwrap_socket_info *si = (struct qwrap_socket_info *)user_data;
	struct qwrap_msgbuf *msg = NULL;
	int ret;

	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(START)... conn[%p] si[%p] datalen[%zu]\n", conn, si, datalen);
	if (si->stream_id != stream_id) {
		ret = NGTCP2_ERR_STREAM_NOT_FOUND;
		goto done;
	}
	dump_data("stream_data", data, datalen);
	msg = malloc(sizeof(*msg) + datalen);
	if (msg == NULL) {
		ret = NGTCP2_ERR_NOMEM;
		goto done;
	}

	*msg = (struct qwrap_msgbuf) {
		.datalen = datalen,
	};
	memcpy(msg->data, data, datalen);

	if (si->stream_recvmsg.last != NULL) {
		si->stream_recvmsg.last->next = msg;
	}
	si->stream_recvmsg.last = msg;
	if (si->stream_recvmsg.first == NULL) {
		si->stream_recvmsg.first = msg;
	}

	ret = 0;
done:
	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(END)... conn[%p] si[%p] ret[%d][%s]\n", conn, si, ret, ngtcp2_strerror(ret));
	return ret;
}

static int qwrap_ngtcp2_stream_open_cb(ngtcp2_conn *conn,
				       int64_t stream_id,
				       void *user_data)
{
	struct qwrap_socket_info *si = (struct qwrap_socket_info *)user_data;
	int ret;

	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(START)... conn[%p] si[%p]\n", conn, si);
	if (si->stream_id == -1) {
		si->stream_id = stream_id;
		ret = 0;
	} else {
		ret = NGTCP2_ERR_STREAM_LIMIT;
	}
	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(END)... conn[%p] si[%p] ret[%d][%s]\n", conn, si, ret, ngtcp2_strerror(ret));
	return ret;
}

static void qwrap_ngtcp2_rand_cb(uint8_t *dest, size_t destlen,
				 const ngtcp2_rand_ctx *rand_ctx)
{
	UNUSED(rand_ctx);
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
	return;
}

static int qwrap_ngtcp2_get_new_connection_id_cb(ngtcp2_conn *conn,
						 ngtcp2_cid *cid,
						 uint8_t *token, size_t cidlen,
						 void *user_data)
{
	struct qwrap_socket_info *si = (struct qwrap_socket_info *)user_data;
	int ret;

	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(START)... conn[%p] si[%p]\n", conn, si);
	ret = gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen);
	if (ret != 0) {
		QWRAP_LOG(QWRAP_LOG_TRACE, "Called(ERR1)... conn[%p] si[%p] ret[%d][%s]\n", conn, si, ret, gnutls_strerror(ret));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, token,
			 NGTCP2_STATELESS_RESET_TOKENLEN);
	if (ret != 0) {
		QWRAP_LOG(QWRAP_LOG_TRACE, "Called(ERR2)... conn[%p] si[%p] ret[%d][%s]\n", conn, si, ret, gnutls_strerror(ret));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	QWRAP_LOG(QWRAP_LOG_TRACE, "Called(END)... conn[%p] si[%p] ret[%d][%s]\n", conn, si, ret, gnutls_strerror(ret));
	return 0;
}

static int qwrap_socket_info_alloc_conn(int fd, struct qwrap_socket_info *si)
{
	ngtcp2_callbacks callbacks = {
		.client_initial = /* required client */
			qwrap_ngtcp2_client_initial_cb,
		.recv_client_initial = /* required server */
			ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = /* required */
			qwrap_ngtcp2_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb, /* required */
		.decrypt = ngtcp2_crypto_decrypt_cb, /* required */
		.hp_mask = ngtcp2_crypto_hp_mask_cb, /* required */
		.recv_stream_data =
			qwrap_ngtcp2_recv_stream_data_cb, /* used */
		.stream_open =
			qwrap_ngtcp2_stream_open_cb, /* used, server only ? */
		.recv_retry = ngtcp2_crypto_recv_retry_cb, /* required client */
		.rand = qwrap_ngtcp2_rand_cb, /* required */
		.get_new_connection_id = /* required */
			qwrap_ngtcp2_get_new_connection_id_cb,
		.update_key = ngtcp2_crypto_update_key_cb, /* required */
		.delete_crypto_aead_ctx = /* required */
			ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = /* required */
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = /* required */
			ngtcp2_crypto_get_path_challenge_data_cb,
		.version_negotiation = /* required */
			ngtcp2_crypto_version_negotiation_cb,
	};
	ngtcp2_cid odcid = {
		.datalen = 0,
	};
	ngtcp2_cid dcid = {
		.datalen = NGTCP2_MIN_INITIAL_DCIDLEN,
	};
	ngtcp2_cid scid = {
		.datalen = NGTCP2_MIN_INITIAL_DCIDLEN,
	};
	ngtcp2_settings settings = {};
	ngtcp2_transport_params params = {};
	uint32_t available_versions32[2];
	union {
		uint32_t v32[2];
		uint8_t v8[8];
	} available_versions;
	struct qwrap_sockaddr_buf bufl = {};
	struct qwrap_sockaddr_buf bufr = {};
	int ret;

	si->laddr = (struct qwrap_address) {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	si->raddr = (struct qwrap_address) {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};

	ret = getsockname(fd, &si->laddr.u.sa, &si->laddr.sa_socklen);
	if (ret != 0) {
		return -1;
	}

	ret = getpeername(fd, &si->raddr.u.sa, &si->raddr.sa_socklen);
	if (ret != 0) {
		return -1;
	}

	if (si->is_server) {
		uint8_t header[48] = { 0, };
		struct iovec tmp = {
			.iov_base = header,
			.iov_len = sizeof(header),
		};
		struct msghdr msg = {
			.msg_iov = &tmp,
			.msg_iovlen = 1,
		};
		union {
			uint64_t v64;
			uint32_t v32;
			uint16_t v16;
			uint8_t v8;
			uint8_t buf[8];
		} val;
		uint8_t ptype;
		uint32_t version;
		uint8_t *b = header;
		size_t hdrlen;
		size_t ofs = 0;
		ngtcp2_cid oscid = {
			.datalen = 0,
		};

		ret = next_recvmsg(fd, &msg, MSG_WAITALL | MSG_PEEK);
		hdrlen = ret;
		dump_data("peek_header", header, hdrlen);

		/* 1 byte header type and packet type */
		if ((ofs + 1) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if ((val.v8 & 0xC0) != 0xC0) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		ptype = (val.v8 & 0x30) >> 4;
		/* 4 bytes version */
		if ((ofs + 4) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 4);
		ofs += 4;
		version = ntohl(val.v32);
		switch (version) {
		case NGTCP2_PROTO_VER_V1:
			if (ptype > 3) {
				/* retry */
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			if (ptype == 0) {
				/* initial */
			}
			break;
		case NGTCP2_PROTO_VER_V2:
			if (ptype == 0) {
				/* retry */
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			if (ptype == 1) {
				/* initial */
			}
			break;
		default:
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		/* 1 byte dcid length */
		if ((ofs + 1) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if (val.v8 > NGTCP2_MAX_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		if (val.v8 < NGTCP2_MIN_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		odcid.datalen = val.v8;
		/* up to 20 bytes dcid */
		if ((ofs + val.v8) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(odcid.data, b + ofs, odcid.datalen);
		ofs += val.v8;

		/* 1 byte scid length */
		if ((ofs + 1) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if (val.v8 > NGTCP2_MAX_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		if (val.v8 < NGTCP2_MIN_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		oscid.datalen = val.v8;
		/* up to 20 bytes scid */
		if ((ofs + val.v8) > hdrlen) {
			QWRAP_LOG(QWRAP_LOG_TRACE, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(oscid.data, b + ofs, oscid.datalen);
		ofs += val.v8;

		dcid = oscid;

		ret = gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
		if (ret != 0) {
			return -1;
		}
	} else {
		ret = gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
		if (ret != 0) {
			return -1;
		}

		ret = gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
		if (ret != 0) {
			return -1;
		}
	}

	si->path = (ngtcp2_path) {
		.local = {
			.addr = &si->laddr.u.sa,
			.addrlen = si->laddr.sa_socklen,
		},
		.remote = {
			.addr = &si->raddr.u.sa,
			.addrlen = si->raddr.sa_socklen,
		},
	};

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "PATH[%p] local[%s] remote[%s]",
		  &si->path,
		  qwrap_sockaddr_string(&bufl, &si->laddr.u.sa),
		  qwrap_sockaddr_string(&bufr, &si->raddr.u.sa));

	available_versions32[0] = NGTCP2_PROTO_VER_V2;
	available_versions32[1] = NGTCP2_PROTO_VER_V1;

	available_versions.v32[0] = htonl(available_versions32[0]);
	available_versions.v32[1] = htonl(available_versions32[1]);

	ngtcp2_settings_default(&settings);

	settings.initial_ts = qwrap_ngtcp2_timestamp();
	settings.log_printf = qwrap_ngtcp2_log_printf;
	settings.qlog_write = qwrap_ngtcp2_qlog_write_cb;

	settings.available_versions = available_versions32;
	settings.available_versionslen = ARRAY_SIZE(available_versions32);

	/*
	 * Copied from quic_transport_param_init
	 */
	params.max_udp_payload_size = 65527 /* QUIC_MAX_UDP_PAYLOAD */;
	params.ack_delay_exponent = 3 /* QUIC_DEF_ACK_DELAY_EXPONENT */;
	params.max_ack_delay = 25000 /* QUIC_DEF_ACK_DELAY */;
	params.active_connection_id_limit = 7 /* QUIC_CONN_ID_DEF */;
	params.max_idle_timeout = 30000000 /* QUIC_DEF_IDLE_TIMEOUT */;
	params.initial_max_data = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 32;
	params.initial_max_stream_data_bidi_local = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_stream_data_bidi_remote = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_stream_data_uni = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_streams_bidi = 100 /* QUIC_DEF_STREAMS */;
	params.initial_max_streams_uni = 100 /* QUIC_DEF_STREAMS */;

	params.version_info_present = 1;
	params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
	params.version_info.available_versions = available_versions.v8;
	params.version_info.available_versionslen = ARRAY_SIZE(available_versions.v8);

	params.max_ack_delay *= NGTCP2_MICROSECONDS;
	params.max_idle_timeout *= NGTCP2_MICROSECONDS;

	if (si->is_server) {
		params.original_dcid_present = 1;
		params.original_dcid = odcid;
		ret = ngtcp2_conn_server_new(&si->conn,
					     &dcid,
					     &scid,
					     &si->path,
					     NGTCP2_PROTO_VER_V1,
					     &callbacks,
					     &settings,
					     &params,
					     NULL,
					     si);
		if (ret != 0) {
			return -1;
		}
	} else {
		ret = ngtcp2_conn_client_new(&si->conn,
					     &dcid,
					     &scid,
					     &si->path,
					     NGTCP2_PROTO_VER_V1,
					     &callbacks,
					     &settings,
					     &params,
					     NULL,
					     si);
		if (ret != 0) {
			return -1;
		}
	}

	/*
	 * Set an invalid value, which is supposed to
	 * be a prove that the value is not used
	 */
	ngtcp2_conn_set_tls_native_handle(si->conn, (gnutls_session_t)0x1);
	return 0;
}

static int qwrap_create_socket(struct qwrap_socket_info *si, int fd)
{
	int idx;

	if ((size_t)fd >= socket_fds_max) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  fd);
		errno = EMFILE;
		return -1;
	}

	idx = qwrap_add_socket_info(si);
	if (idx == -1) {
		return -1;
	}

	set_socket_info_index(fd, idx);

	return idx;
}

static struct qwrap_socket_info *find_qwrap_socket(int fd)
{
	int idx = find_qwrap_socket_index(fd);

	if (idx == -1) {
		return NULL;
	}

	return qwrap_get_socket_info(idx);
}

static ssize_t qwrap_recvmsg(int s, struct msghdr *omsg, int flags);
static ssize_t qwrap_sendmsg(int s, const struct msghdr *omsg, int flags);
static void qwrap_remove_stale(int fd);
static int qwrap_close(int fd);

/****************************************************************************
 *   SIGNALFD
 ***************************************************************************/

#ifdef HAVE_SIGNALFD
static int qwrap_signalfd(int fd, const sigset_t *mask, int flags)
{
	int rc;

	rc = next_signalfd(fd, mask, flags);
	if (rc != -1) {
		qwrap_remove_stale(fd);
	}

	return rc;
}

int signalfd(int fd, const sigset_t *mask, int flags)
{
	return qwrap_signalfd(fd, mask, flags);
}
#endif

/****************************************************************************
 *   SOCKET
 ***************************************************************************/

static int qwrap_socket(int family, int type, int protocol)
{
	struct qwrap_socket_info *si = NULL;
	struct qwrap_socket_info _si = { .stream_id = -1, };
	int fd;
	int ret;
	int real_type = type;
	bool maybe_quic = true;

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

	if (!quic_ko_wrapper_enabled()) {
		return next_socket(family, type, protocol);
	}

	switch (family) {
	case AF_INET:
		break;
	case AF_INET6:
		break;
	default:
		maybe_quic = false;
		break;
	}

	switch (real_type) {
	case SOCK_STREAM:
		break;
	case SOCK_DGRAM:
		break;
	default:
		maybe_quic = false;
		break;
	}

	switch (protocol) {
	case IPPROTO_QUIC:
		break;
	default:
		maybe_quic = false;
		break;
	}

	if (!maybe_quic) {
		fd = next_socket(family, type, protocol);
		if (fd != -1) {
			/* Check if we have a stale fd and remove it */
			QWRAP_LOG(QWRAP_LOG_TRACE,
				  "Non QUIC socket fd=%d",
				  fd);
			qwrap_remove_stale(fd);
			return fd;
		}
		return fd;
	}

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "Try %s QUIC socket for type %s protocol %s",
		  family == AF_INET ? "IPv4" : "IPv6",
		  real_type == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM",
		  "IPPROTO_QUIC");

	if (quic_ko_socket_wrapper_enabled()) {
		QWRAP_LOG(QWRAP_LOG_DEBUG, "socket_wrapper_enabled() => 1");
		fd = quic_ko_socket_wrapper_ipproto_quic_socket(family, type);
		if (fd == -1) {
			return -1;
		}
	} else {
		int next_type;
		int next_protocol;

		/*
		 * We must call next_socket with type, from the caller, not the
		 * version we removed SOCK_CLOEXEC and SOCK_NONBLOCK from
		 */
		next_type = type;
		next_type &= ~real_type;
		next_type |= SOCK_DGRAM;
		next_protocol = IPPROTO_UDP;
		QWRAP_LOG(QWRAP_LOG_DEBUG, "socket_wrapper_enabled() => 0");
		fd = next_socket(family, next_type, next_protocol);
		if (fd == -1) {
			return -1;
		}
	}

	/* Check if we have a stale fd and remove it */
	qwrap_remove_stale(fd);

	si = &_si;

	ret = qwrap_create_socket(si, fd);
	if (ret == -1) {
		int saved_errno = errno;
		next_close(fd);
		errno = saved_errno;
		return -1;
	}

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "Created %s socket for protocol %s, fd=%d",
		  family == AF_INET ? "IPv4" : "IPv6",
		  "QUIC",
		  fd);

	return fd;
}

int socket(int family, int type, int protocol)
{
	return qwrap_socket(family, type, protocol);
}

/****************************************************************************
 *   SOCKETPAIR
 ***************************************************************************/

static int qwrap_socketpair(int family, int type, int protocol, int sv[2])
{
	int rc;

	rc = next_socketpair(family, type, protocol, sv);
	if (rc != -1) {
		qwrap_remove_stale(sv[0]);
		qwrap_remove_stale(sv[1]);
	}

	return rc;
}

int socketpair(int family, int type, int protocol, int sv[2])
{
	return qwrap_socketpair(family, type, protocol, sv);
}

/****************************************************************************
 *   SOCKETPAIR
 ***************************************************************************/

#ifdef HAVE_TIMERFD_CREATE
static int qwrap_timerfd_create(int clockid, int flags)
{
	int fd;

	fd = next_timerfd_create(clockid, flags);
	if (fd != -1) {
		qwrap_remove_stale(fd);
	}

	return fd;
}

int timerfd_create(int clockid, int flags)
{
	return qwrap_timerfd_create(clockid, flags);
}
#endif

/****************************************************************************
 *   PIPE
 ***************************************************************************/

static int qwrap_pipe(int pipefd[2])
{
	int rc;

	rc = next_pipe(pipefd);
	if (rc != -1) {
		qwrap_remove_stale(pipefd[0]);
		qwrap_remove_stale(pipefd[1]);
	}

	return rc;
}

int pipe(int pipefd[2])
{
	return qwrap_pipe(pipefd);
}

/****************************************************************************
 *   ACCEPT
 ***************************************************************************/

static int qwrap_accept(int s,
			struct sockaddr *addr,
			socklen_t *addrlen,
			int flags)
{
	struct qwrap_socket_info *parent_si, *child_si;
	struct qwrap_sockaddr_buf buf = {};
	struct qwrap_socket_info new_si = { 0 };
	int fd;
	int idx;
	int ret;

	parent_si = find_qwrap_socket(s);
	if (!parent_si) {
#ifdef HAVE_ACCEPT4
		return next_accept4(s, addr, addrlen, flags);
#else
		UNUSED(flags);
		return next_accept(s, addr, addrlen);
#endif
	}

#ifdef HAVE_ACCEPT4
	ret = next_accept4(s, addr, addrlen, flags);
#else
	UNUSED(flags);
	ret = next_accept(s, addr, addrlen);
#endif
	if (ret == -1) {
		int saved_errno = errno;
		if (saved_errno == ENOTSOCK) {
			/* Remove stale fds */
			qwrap_remove_stale(s);
		}
		QWRAP_LOG(QWRAP_LOG_DEBUG,
			  "accept(), fd=%d ret=%d saved_errno=%d",
			  s, ret, saved_errno);
		errno = saved_errno;
		return ret;
	}

	fd = ret;

	/* Check if we have a stale fd and remove it */
	qwrap_remove_stale(fd);

	QWRAP_LOCK_SI(parent_si);

	child_si = &new_si;

	child_si->bound = 1;
	child_si->is_server = 1;
	child_si->connected = 1;
	child_si->conn = NULL;
	child_si->stream_id = -1;

	QWRAP_UNLOCK_SI(parent_si);

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "accept(%s), fd=%d",
		  qwrap_sockaddr_string(&buf, addr),
		  fd);

	idx = qwrap_create_socket(&new_si, fd);
	if (idx == -1) {
		int saved_errno = errno;
		next_close(fd);
		errno = saved_errno;
		return -1;
	}

	child_si = qwrap_get_socket_info(idx);
	QWRAP_LOCK_SI(child_si);
	ret = qwrap_socket_info_alloc_conn(fd, child_si);
	QWRAP_UNLOCK_SI(child_si);
	if (ret != 0) {
		qwrap_close(fd);
		errno = ENOSR;
		return -1;
	}

	return fd;
}

#ifdef HAVE_ACCEPT4
int accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	return qwrap_accept(s, addr, (socklen_t *)addrlen, flags);
}
#endif

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int accept(int s, struct sockaddr *addr, Psocklen_t addrlen)
#else
int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
#endif
{
	return qwrap_accept(s, addr, (socklen_t *)addrlen, 0);
}

/****************************************************************************
 *   CONNECT
 ***************************************************************************/

static int qwrap_connect(int s, const struct sockaddr *serv_addr,
			 socklen_t addrlen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct qwrap_sockaddr_buf buf = {};
	int ret;

	if (si == NULL) {
		return next_connect(s, serv_addr, addrlen);
	}

	QWRAP_LOCK_SI(si);

	ret = next_connect(s, serv_addr, addrlen);

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "connect(%s), fd=%d",
		  qwrap_sockaddr_string(&buf, serv_addr),
		  s);

	if (ret == 0) {
		ret = qwrap_socket_info_alloc_conn(s, si);
		if (ret != 0) {
			errno = ENOSR;
			ret = -1;
			goto done;
		}
		si->connected = 1;
	}

done:
	QWRAP_UNLOCK_SI(si);
	return ret;
}

int connect(int s, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	return qwrap_connect(s, serv_addr, addrlen);
}

/****************************************************************************
 *   BIND
 ***************************************************************************/

static int qwrap_bind(int s, const struct sockaddr *myaddr, socklen_t addrlen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct qwrap_sockaddr_buf buf = {};
	int ret_errno = errno;
	int ret;

	if (si == NULL) {
		return next_bind(s, myaddr, addrlen);
	}

	QWRAP_LOCK_SI(si);

	ret = next_bind(s, myaddr, addrlen);
	if (ret == -1) {
		ret_errno = errno;
	}

	QWRAP_LOG(QWRAP_LOG_DEBUG,
		  "bind(%s), fd=%d ret=%d ret_errno=%d",
		  qwrap_sockaddr_string(&buf, myaddr),
		  s, ret, ret_errno);

	if (ret == 0) {
		si->bound = 1;
	}

	QWRAP_UNLOCK_SI(si);
	errno = ret_errno;
	return ret;
}

int bind(int s, const struct sockaddr *myaddr, socklen_t addrlen)
{
	return qwrap_bind(s, myaddr, addrlen);
}

/****************************************************************************
 *   LISTEN
 ***************************************************************************/

static int qwrap_listen(int s, int backlog)
{
	int ret;
	struct qwrap_socket_info *si = find_qwrap_socket(s);

	if (si == NULL) {
		return next_listen(s, backlog);
	}

	QWRAP_LOCK_SI(si);

	ret = next_listen(s, backlog);
	if (ret == 0) {
		si->listening = 1;
	}

	QWRAP_UNLOCK_SI(si);

	return ret;
}

int listen(int s, int backlog)
{
	return qwrap_listen(s, backlog);
}

/****************************************************************************
 *   FOPEN
 ***************************************************************************/

static FILE *qwrap_fopen(const char *name, const char *mode)
{
	FILE *fp;

	fp = next_fopen(name, mode);
	if (fp != NULL) {
		int fd = fileno(fp);

		qwrap_remove_stale(fd);
	}

	return fp;
}

#undef fopen /* Needed for LFS handling */
FILE *fopen(const char *name, const char *mode)
{
	return qwrap_fopen(name, mode);
}

/****************************************************************************
 *   FOPEN64
 ***************************************************************************/

#ifdef HAVE_FOPEN64
static FILE *qwrap_fopen64(const char *name, const char *mode)
{
	FILE *fp;

	fp = next_fopen64(name, mode);
	if (fp != NULL) {
		int fd = fileno(fp);

		qwrap_remove_stale(fd);
	}

	return fp;
}

FILE *fopen64(const char *name, const char *mode)
{
	return qwrap_fopen64(name, mode);
}
#endif /* HAVE_FOPEN64 */

/****************************************************************************
 *   OPEN
 ***************************************************************************/

static int qwrap_vopen(const char *pathname, int flags, va_list ap)
{
	int ret;

	ret = next_vopen(pathname, flags, ap);
	if (ret != -1) {
		/*
		 * There are methods for closing descriptors (libc-internal code
		 * paths, direct syscalls) which close descriptors in ways that
		 * we can't intercept, so try to recover when we notice that
		 * that's happened
		 */
		qwrap_remove_stale(ret);
	}
	return ret;
}

#undef open /* Needed for LFS handling */
int open(const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = qwrap_vopen(pathname, flags, ap);
	va_end(ap);

	return fd;
}

/****************************************************************************
 *   OPEN64
 ***************************************************************************/

#ifdef HAVE_OPEN64
static int qwrap_vopen64(const char *pathname, int flags, va_list ap)
{
	int ret;

	ret = next_vopen64(pathname, flags, ap);
	if (ret != -1) {
		/*
		 * There are methods for closing descriptors (libc-internal code
		 * paths, direct syscalls) which close descriptors in ways that
		 * we can't intercept, so try to recover when we notice that
		 * that's happened
		 */
		qwrap_remove_stale(ret);
	}
	return ret;
}

int open64(const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = qwrap_vopen64(pathname, flags, ap);
	va_end(ap);

	return fd;
}
#endif /* HAVE_OPEN64 */

/****************************************************************************
 *   OPENAT64
 ***************************************************************************/

#ifdef HAVE_OPENAT64
static int
qwrap_vopenat64(int dirfd, const char *pathname, int flags, va_list ap)
{
	int ret;

	ret = next_vopenat64(dirfd, pathname, flags, ap);
	if (ret != -1) {
		/*
		 * There are methods for closing descriptors (libc-internal code
		 * paths, direct syscalls) which close descriptors in ways that
		 * we can't intercept, so try to recover when we notice that
		 * that's happened
		 */
		qwrap_remove_stale(ret);
	}
	return ret;
}

int openat64(int dirfd, const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = qwrap_vopenat64(dirfd, pathname, flags, ap);
	va_end(ap);

	return fd;
}
#endif /* HAVE_OPENAT64 */

/****************************************************************************
 *   OPENAT
 ***************************************************************************/

static int qwrap_vopenat(int dirfd, const char *path, int flags, va_list ap)
{
	int ret;

	ret = next_vopenat(dirfd, path, flags, ap);
	if (ret != -1) {
		/*
		 * There are methods for closing descriptors (libc-internal code
		 * paths, direct syscalls) which close descriptors in ways that
		 * we can't intercept, so try to recover when we notice that
		 * that's happened
		 */
		qwrap_remove_stale(ret);
	}

	return ret;
}

#undef openat /* Needed for LFS handling */
int openat(int dirfd, const char *path, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = qwrap_vopenat(dirfd, path, flags, ap);
	va_end(ap);

	return fd;
}

static ssize_t qwrap_call_ngtcp2_conn_read_pkt(struct qwrap_socket_info *si,
					       const char *comment)
{
	ssize_t ret = 0;

	while (si->hs_recvmsg_in.first != NULL) {
		struct qwrap_msgbuf *hs_msg = si->hs_recvmsg_in.first;

		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "%s: ngtcp2_conn_read_pkt hs_done[%u] replay[%u] datalen[%zu]\n",
			  comment, si->handshake_done, hs_msg->level, hs_msg->datalen);
		ret = ngtcp2_conn_read_pkt(si->conn,
					   &si->path,
					   NULL,
					   hs_msg->data,
					   hs_msg->datalen,
					   qwrap_ngtcp2_timestamp());
		si->handshake_done = ngtcp2_conn_get_handshake_completed(si->conn);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			"%s: ngtcp2_conn_read_pkt hs_done[%u] datalen[%zu] et[%zu] %s\n",
			comment, si->handshake_done, hs_msg->datalen, ret, ngtcp2_strerror(ret));
		if (ret < 0) {
			if (ret == si->hs_recvmsg_out.cb_error) {
				si->hs_recvmsg_out.cb_error = 0;
				if (hs_msg->level == UINT8_MAX) {
					goto remove_msg;
				}
				hs_msg->level = UINT8_MAX;
				break;
			}
			si->hs_recvmsg_out.cb_error = 0;
			return ret;
		}

remove_msg:
		si->hs_recvmsg_in.first = hs_msg->next;
		if (si->hs_recvmsg_in.first == NULL) {
			si->hs_recvmsg_in.last = NULL;
		}

		free(hs_msg);

		if (si->hs_recvmsg_out.first != NULL) {
			break;
		}
	}

	return 0;
}

/****************************************************************************
 *   GETSOCKOPT
 ***************************************************************************/

static int qwrap_getsockopt(int s, int level, int optname,
			    void *optval, socklen_t *optlen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	const char *ons = "<unknown>";
	struct quic_stream_info sinfo = {};
	ngtcp2_ssize nwrite;
	int ret;

	if (si == NULL || level != SOL_QUIC) {
		return next_getsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	QWRAP_LOCK_SI(si);

	switch (optname) {
	case QUIC_SOCKOPT_TOKEN:
		ons = "TOKEN";

		if (si->is_server) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		*optlen = 0;
		ret = 0;
		break;
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		ons = "TRANSPORT_PARAM_EXT";

		nwrite = ngtcp2_conn_encode_local_transport_params(si->conn, optval, *optlen);
		if (nwrite < 0) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		*optlen = nwrite;
		ret = 0;
		break;
	case QUIC_SOCKOPT_STREAM_OPEN:
		ons = "SOCKOPT_STREAM_OPEN";

		if (*optlen < sizeof(sinfo)) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		memcpy(&sinfo, optval, sizeof(sinfo));

		if (!si->handshake_done) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		if (si->is_server) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		if (sinfo.stream_id != -1) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		if (sinfo.stream_flags != 0) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		ret = ngtcp2_conn_open_bidi_stream(si->conn,
						   &si->stream_id,
						   si);
		if (ret != 0) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		*optlen = sizeof(sinfo);
		ret = 0;
		break;
	default:
		errno = ENOPROTOOPT;
		ret = -1;
		break;
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC getsockopt(fd=%d) optname[%d/%s] connected[%u] handshake_done[%u] ret[%d] optlen[%zu]\n",
		  s, optname, ons, si->connected, si->handshake_done, ret, (size_t)*optlen);
	if (ret == 0) {
		dump_data(ons, optval, *optlen);
	}

	goto done;

done:
	QWRAP_UNLOCK_SI(si);
	return ret;
}

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int getsockopt(int s, int level, int optname, void *optval, Psocklen_t optlen)
#else
int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
#endif
{
	return qwrap_getsockopt(s, level, optname, optval, (socklen_t *)optlen);
}

/****************************************************************************
 *   SETSOCKOPT
 ***************************************************************************/

static int qwrap_setsockopt(int s, int level, int optname,
			    const void *optval, socklen_t optlen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct quic_crypto_secret secret = {};
	gnutls_cipher_algorithm_t cipher = GNUTLS_CIPHER_UNKNOWN;
	uint8_t keylen = 0;
	gnutls_digest_algorithm_t hash = GNUTLS_DIG_UNKNOWN;
	gnutls_cipher_algorithm_t hp_cipher = GNUTLS_CIPHER_UNKNOWN;
	const ngtcp2_crypto_ctx *ctx = NULL;
	ngtcp2_encryption_level elevel = 0;
	const char *ons = "<unknown>";
	int ret;

	if (si == NULL || level != SOL_QUIC) {
		return next_setsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	QWRAP_LOCK_SI(si);

	switch (optname) {
	case QUIC_SOCKOPT_TRANSPORT_PARAM_EXT:
		ons = "TRANSPORT_PARAM_EXT";

		ret = ngtcp2_conn_decode_and_set_remote_transport_params(si->conn,
									 optval,
									 optlen);
		if (ret != 0) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		qwrap_call_ngtcp2_conn_read_pkt(si, "set_param_ext");

		ret = 0;
		break;
	case QUIC_SOCKOPT_CRYPTO_SECRET:
		ons = "CRYPTO_SECRET";
		if (optlen != sizeof(secret)) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		memcpy(&secret, optval, optlen);

		cipher = qwrap_tls_cipher_type(secret.type);
		if (cipher == GNUTLS_CIPHER_UNKNOWN) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		hash = qwrap_tls_digest_type(secret.type);
		if (hash == GNUTLS_DIG_UNKNOWN) {
			errno = EINVAL;
			ret = -1;
			break;
		}
		keylen = gnutls_hash_get_len(hash);

		hp_cipher = qwrap_tls_hp_cipher_type(secret.type);
		if (hp_cipher == GNUTLS_CIPHER_UNKNOWN) {
			errno = EINVAL;
			ret = -1;
			break;
		}

		ctx = ngtcp2_conn_get_crypto_ctx(si->conn);

		if (!ctx->aead.native_handle) {
			ngtcp2_crypto_ctx cctx = {};

			cctx.aead.native_handle = (void *)cipher;
			cctx.aead.max_overhead = gnutls_cipher_get_tag_size(cipher);
			cctx.md.native_handle = (void *)hash;
			cctx.hp.native_handle = (void *)hp_cipher;
			cctx.max_encryption = qwrap_get_aead_max_encryption(cipher);
			cctx.max_decryption_failure = qwrap_get_aead_max_decryption_failure(cipher);

			ngtcp2_conn_set_crypto_ctx(si->conn, &cctx);
			ctx = ngtcp2_conn_get_crypto_ctx(si->conn);
		}

		elevel = qwrap_to_ngtcp2_crypto_level(secret.level);
		if (secret.send) {
			ret = ngtcp2_crypto_derive_and_install_tx_key(si->conn,
								      NULL,
								      NULL,
								      NULL,
								      elevel,
								      secret.secret,
								      keylen);
		} else {
			ret = ngtcp2_crypto_derive_and_install_rx_key(si->conn,
								      NULL,
								      NULL,
								      NULL,
								      elevel,
								      secret.secret,
								      keylen);
		}
		gnutls_memset(&secret.secret, 0, sizeof(secret.secret));
		if (ret != 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			errno = EINVAL;
			ret = -1;
			break;
		}

		if (secret.level == QUIC_CRYPTO_APP && !secret.send) {
			ngtcp2_conn_tls_handshake_completed(si->conn);
			qwrap_call_ngtcp2_conn_read_pkt(si, "secret_tls_complete");
			si->handshake_done = ngtcp2_conn_get_handshake_completed(si->conn);
		}
		ret = 0;
		break;
	default:
		errno = ENOPROTOOPT;
		ret = -1;
		break;
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC setsockopt(fd=%d) optname[%d/%s] connected[%u] handshake_done[%u] ret[%d] %s\n",
		  s, optname, ons, si->connected, si->handshake_done, ret, strerror(ret == -1 ? errno : 0));
	dump_data(ons, optval, optlen);

	goto done;

done:
	QWRAP_UNLOCK_SI(si);
	return ret;
}

int setsockopt(int s, int level, int optname,
	       const void *optval, socklen_t optlen)
{
	return qwrap_setsockopt(s, level, optname, optval, optlen);
}

/****************************************************************************
 *   IOCTL
 ***************************************************************************/

static int qwrap_vioctl(int s, unsigned long int r, va_list va)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	va_list ap;
	int *value_ptr = NULL;
	int rc;

	if (si == NULL) {
		return next_vioctl(s, r, va);
	}

	QWRAP_LOCK_SI(si);

	if (!si->connected) {
		QWRAP_UNLOCK_SI(si);
		errno = ENOTCONN;
		return -1;
	}

	va_copy(ap, va);

	switch (r) {
	case FIONREAD:
		value_ptr = ((int *)va_arg(ap, int *));
		*value_ptr = 0;
		if (si->stream_recvmsg.first != NULL) {
			/* TODO iterate over all??? */
			*value_ptr = si->stream_recvmsg.first->datalen;
		}
		rc = 0;
		break;
#ifdef FIONWRITE
	case FIONWRITE:
		/* this is FreeBSD */
		FALL_THROUGH; /* to TIOCOUTQ */
#endif /* FIONWRITE */
	case TIOCOUTQ: /* same as SIOCOUTQ on Linux */
		/*
		 * This may return more bytes then the application
		 * sent into the socket, for tcp it should
		 * return the number of unacked bytes.
		 *
		 * On AF_UNIX, all bytes are immediately acked!
		 */
		value_ptr = ((int *)va_arg(ap, int *));
		/* TODO: maybe ngtcp2_conn_get_conn_info bytes_in_flight??? */
		*value_ptr = 0;
		rc = 0;
		break;
	default:
		rc = next_vioctl(s, r, va);
		break;
	}

	va_end(ap);

	QWRAP_UNLOCK_SI(si);
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

	rc = qwrap_vioctl(s, (unsigned long int) r, va);

	va_end(va);

	return rc;
}

/*****************
 * CMSG
 *****************/

union __qwrap_fds {
	const uint8_t *p;
	int *fds;
};

union __qwrap_cmsghdr {
	const uint8_t *p;
	struct cmsghdr *cmsg;
};

static ssize_t qwrap_sendmsg_unix_scm_rights(const struct cmsghdr *cmsg)
{
	size_t size_fds_in;
	size_t num_fds_in;
	union __qwrap_fds __fds_in = { .p = NULL, };
	const int *fds_in = NULL;
	size_t i;

	if (cmsg->cmsg_len < CMSG_LEN(0)) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu < CMSG_LEN(0)=%zu",
			  (size_t)cmsg->cmsg_len,
			  CMSG_LEN(0));
		errno = EINVAL;
		return -1;
	}
	size_fds_in = cmsg->cmsg_len - CMSG_LEN(0);
	if ((size_fds_in % sizeof(int)) != 0) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu => (size_fds_in=%zu %% sizeof(int)=%zu) != 0",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  sizeof(int));
		errno = EINVAL;
		return -1;
	}
	num_fds_in = size_fds_in / sizeof(int);
	if (num_fds_in == 0) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu,size_fds_in=%zu => "
			  "num_fds_in=%zu",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  num_fds_in);
		errno = EINVAL;
		return -1;
	}
	__fds_in.p = CMSG_DATA(cmsg);
	fds_in = __fds_in.fds;

	for (i = 0; i < num_fds_in; i++) {
		int si_idx;

		si_idx = find_qwrap_socket_index(fds_in[i]);
		if (si_idx == -1) {
			continue;
		}

		/*
		 * Passing a IPPROTO_QUIC socket is not supported
		 * yet
		 */
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "fds_in[%zu]=%d is an IPPROTO_QUIC socket! Not supported!",
			  i, fds_in[i]);
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static size_t qwrap_sendmsg_unix_sol_socket(const struct cmsghdr *cmsg)
{
	ssize_t ret = -1;

	switch (cmsg->cmsg_type) {
	case SCM_RIGHTS:
		ret = qwrap_sendmsg_unix_scm_rights(cmsg);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

static void qwrap_recvmsg_unix_scm_rights(const struct cmsghdr *cmsg)
{
	size_t size_fds_in;
	size_t num_fds_in;
	union __qwrap_fds __fds_in = { .p = NULL, };
	const int *fds_in = NULL;
	size_t i;

	if (cmsg->cmsg_len < CMSG_LEN(0)) {
		return;
	}
	size_fds_in = cmsg->cmsg_len - CMSG_LEN(0);
	if ((size_fds_in % sizeof(int)) != 0) {
		return;
	}
	num_fds_in = size_fds_in / sizeof(int);
	__fds_in.p = CMSG_DATA(cmsg);
	fds_in = __fds_in.fds;

	for (i = 0; i < num_fds_in; i++) {
		/* Check if we have a stale fd and remove it */
		qwrap_remove_stale(fds_in[i]);
	}

	return;
}

static void qwrap_recvmsg_unix_sol_socket(const struct cmsghdr *cmsg)
{
	switch (cmsg->cmsg_type) {
	case SCM_RIGHTS:
		qwrap_recvmsg_unix_scm_rights(cmsg);
		break;
	default:
		break;
	}

	return;
}

static size_t qwrap_sendmsg_before_unix(const struct msghdr *_msg_in)
{
	struct msghdr *msg_in = discard_const_p(struct msghdr, _msg_in);
	struct cmsghdr *cmsg = NULL;
	size_t ret = -1;

	/* Nothing to do */
	if (msg_in->msg_controllen == 0 || msg_in->msg_control == NULL) {
		return 0;
	}

	for (cmsg = CMSG_FIRSTHDR(msg_in);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg_in, cmsg))
	{
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			ret = qwrap_sendmsg_unix_sol_socket(cmsg);
			if (ret < 0) {
				return ret;
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

static ssize_t qwrap_recvmsg_after_unix(struct msghdr *msg, ssize_t ret)
{
	struct cmsghdr *cmsg = NULL;
	int saved_errno = errno;

	if (ret < 0) {
		return ret;
	}

	/* Nothing to do */
	if (msg->msg_controllen == 0 || msg->msg_control == NULL) {
		return ret;
	}

	for (cmsg = CMSG_FIRSTHDR(msg);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg, cmsg))
	{
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			qwrap_recvmsg_unix_sol_socket(cmsg);
			break;
		default:
			break;
		}
	}

	errno = saved_errno;
	return ret;
}

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
static void qwrap_msghdr_add_cmsghdr(struct msghdr *msg,
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

/****************************************************************************
 *   RECVFROM
 ***************************************************************************/

static ssize_t qwrap_recvfrom(int s, void *buf, size_t len, int flags,
			      struct sockaddr *from, socklen_t *fromlen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = discard_const_p(char, buf),
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_name = from,
		.msg_namelen = fromlen != NULL ? *fromlen : 0,
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	if (si == NULL) {
		return next_recvfrom(s,
				     buf,
				     len,
				     flags,
				     from,
				     fromlen);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recvfrom(fd=%d) => qwrap_recvmsg\n",
		  s);

	ret = qwrap_recvmsg(s, &msg, flags);
	if (ret >= 0 && from != NULL && fromlen != NULL) {
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
	return qwrap_recvfrom(s, buf, len, flags, from, (socklen_t *)fromlen);
}

/****************************************************************************
 *   SENDTO
 ***************************************************************************/

static ssize_t qwrap_sendto(int s, const void *buf, size_t len, int flags,
			    const struct sockaddr *to, socklen_t tolen)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = discard_const_p(char, buf),
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_name = discard_const_p(struct sockaddr, to),
		.msg_namelen = tolen,
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};

	if (si == NULL) {
		return next_sendto(s, buf, len, flags, to, tolen);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC sendto(fd=%d) => qwrap_sendmsg\n",
		  s);

	return qwrap_sendmsg(s, &msg, flags);
}

ssize_t sendto(int s, const void *buf, size_t len, int flags,
	       const struct sockaddr *to, socklen_t tolen)
{
	return qwrap_sendto(s, buf, len, flags, to, tolen);
}

/****************************************************************************
 *   READV
 ***************************************************************************/

static ssize_t qwrap_recv(int s, void *buf, size_t len, int flags)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};

	if (si == NULL) {
		return next_recv(s, buf, len, flags);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recv(fd=%d) => qwrap_recvmsg\n",
		  s);

	return qwrap_recvmsg(s, &msg, flags);
}

ssize_t recv(int s, void *buf, size_t len, int flags)
{
	return qwrap_recv(s, buf, len, flags);
}

/****************************************************************************
 *   READ
 ***************************************************************************/

static ssize_t qwrap_read(int s, void *buf, size_t len)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = buf,
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};
	ssize_t ret;

	if (si == NULL) {
		return next_read(s, buf, len);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC read(fd=%d) => qwrap_recvmsg\n",
		  s);

	ret = qwrap_recvmsg(s, &msg, 0);
	if (ret == -1 && errno == ENOTSOCK) {
		qwrap_remove_stale(s);
		return next_read(s, buf, len);
	}
	return ret;
}

ssize_t read(int s, void *buf, size_t len)
{
	return qwrap_read(s, buf, len);
}

/****************************************************************************
 *   WRITE
 ***************************************************************************/

static ssize_t qwrap_write(int s, const void *buf, size_t len)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = discard_const_p(char, buf),
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};

	if (si == NULL) {
		return next_write(s, buf, len);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC write(fd=%d) => qwrap_sendmsg\n",
		  s);

	return qwrap_sendmsg(s, &msg, 0);
}

ssize_t write(int s, const void *buf, size_t len)
{
	return qwrap_write(s, buf, len);
}

/****************************************************************************
 *   SEND
 ***************************************************************************/

static ssize_t qwrap_send(int s, const void *buf, size_t len, int flags)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct iovec tmp = {
		.iov_base = discard_const_p(char, buf),
		.iov_len = len,
	};
	struct msghdr msg = {
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};

	if (si == NULL) {
		return next_send(s, buf, len, flags);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC send(fd=%d) => qwrap_sendmsg\n",
		  s);

	return qwrap_sendmsg(s, &msg, flags);
}

ssize_t send(int s, const void *buf, size_t len, int flags)
{
	return qwrap_send(s, buf, len, flags);
}

/****************************************************************************
 *   RECVMSG
 ***************************************************************************/

static ssize_t qwrap_recvmsg_handshake(int s,
				       struct qwrap_socket_info *si,
				       struct msghdr *omsg,
				       size_t requested_bytes,
				       int flags)
{
	struct iovec *iovs = omsg->msg_iov;
	int iovscnt = omsg->msg_iovlen;
	ssize_t bytes = 0;
	struct msghdr msg = { .msg_iov = NULL, };
	struct iovec tmp;
	struct qwrap_msgbuf *hs_msg = NULL;
	size_t msg_ctrllen_left;
	void *msg_control = NULL;
	uint8_t buf[1500];
	int retry_errno = EAGAIN;
	ssize_t ret;

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC START recvmsg(fd=%d) handshake_done[%u] requested_bytes[%zu]\n",
		  s, si->handshake_done, requested_bytes);

	if (flags & MSG_PEEK) {
		QWRAP_LOG(QWRAP_LOG_WARN, "MSG_PEEK not supportedr");
		errno = EINVAL;
		return -1;
	}

	ret = qwrap_call_ngtcp2_conn_read_pkt(si, "recvmsg_hs1");
	if (ret < 0) {
		ngtcp2_conn_set_tls_error(si->conn, ret);
		errno = ECONNRESET;
		return -1;
	}

	if (si->hs_recvmsg_out.first != NULL) {
		goto return_hs_out;
	}

	tmp.iov_base = buf;
	tmp.iov_len = sizeof(buf);
	msg = (struct msghdr) {
		.msg_iov = &tmp,
		.msg_iovlen = 1,
	};

	ret = next_recvmsg(s, &msg, flags);
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recvmsg(fd=%d) NEXT ret[%zd] %d %s\n",
		  s, ret, ret == -1 ? errno : 0, strerror(ret == -1 ? errno : 0));
	if (ret < 0) {
		return ret;
	}
	retry_errno = EINTR;
	tmp.iov_len = ret;

	dump_data("next_recvmsg_hs_data", tmp.iov_base, tmp.iov_len);

	while (tmp.iov_len != 0) {
		union {
			uint64_t v64;
			uint32_t v32;
			uint16_t v16;
			uint8_t v8;
			uint8_t buf[8];
		} val;
		uint8_t ptype;
		uint32_t version;
		uint8_t *b = tmp.iov_base;
		size_t ofs = 0;
		int skip_token = 0;
		uint64_t length = 0;

		if (tmp.iov_len < 7) {
			dump_data("invalid_packet", tmp.iov_base, tmp.iov_len);
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		dump_data("packet_header", b, MIN(48, tmp.iov_len));
		/* 1 byte header type and packet type */
		if ((ofs + 1) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if ((val.v8 & 0xC0) == 0x40) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Short header");
			length = tmp.iov_len;
			goto got_full_packet;
		}
		if ((val.v8 & 0xC0) != 0xC0) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		ptype = (val.v8 & 0x30) >> 4;
		/* 4 bytes version */
		if ((ofs + 4) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 4);
		ofs += 4;
		version = ntohl(val.v32);
		switch (version) {
		case NGTCP2_PROTO_VER_V1:
			if (ptype > 3) {
				/* retry */
				QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			if (ptype == 0) {
				/* initial */
				skip_token = 1;
			}
			break;
		case NGTCP2_PROTO_VER_V2:
			if (ptype == 0) {
				/* retry */
				QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			if (ptype == 1) {
				/* initial */
				skip_token = 1;
			}
			break;
		default:
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		/* 1 byte dcid length */
		if ((ofs + 1) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if (val.v8 > NGTCP2_MAX_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		if (val.v8 < NGTCP2_MIN_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		/* up to 20 bytes dcid */
		if ((ofs + val.v8) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		ofs += val.v8;

		/* 1 byte scid length */
		if ((ofs + 1) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		ofs += 1;
		if (val.v8 > NGTCP2_MAX_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		if (val.v8 < NGTCP2_MIN_CIDLEN) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		/* up to 20 bytes scid */
		if ((ofs + val.v8) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		ofs += val.v8;

		if (skip_token) {
			/* 1 byte token length */
			if ((ofs + 1) > tmp.iov_len) {
				QWRAP_LOG(QWRAP_LOG_WARN,
					  "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			memcpy(val.buf, b + ofs, 1);
			ofs += 1;
			/* up to 256 bytes scid */
			if ((ofs + val.v8) > tmp.iov_len) {
				QWRAP_LOG(QWRAP_LOG_WARN,
					  "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			ofs += val.v8;
		}

		/* 1 byte variable length header */
		if ((ofs + 1) > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		memcpy(val.buf, b + ofs, 1);
		switch (val.v8 >> 6) {
		case 0:
			length += val.v8 & 0x3F;
			ofs += 1;
			break;
		case 1:
			if ((ofs + 2) > tmp.iov_len) {
				QWRAP_LOG(QWRAP_LOG_WARN,
					  "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			memcpy(val.buf, b + ofs, 2);
			ofs += 2;
			val.v16 = ntohs(val.v16);
			length += val.v16 & 0x3FFF;
			break;
		case 2:
			if ((ofs + 4) > tmp.iov_len) {
				QWRAP_LOG(QWRAP_LOG_WARN,
					  "Invalid Packet header");
				errno = EINVAL;
				return -1;
			}
			memcpy(val.buf, b + ofs, 4);
			ofs += 4;
			val.v32 = ntohl(val.v32);
			length += val.v32 & 0x3FFFFFFF;
			break;
		default:
			/* 64-bit length values can't happen here... */
			QWRAP_LOG(QWRAP_LOG_WARN, "Invalid Packet header");
			errno = EINVAL;
			return -1;
		}
		if (length > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN,
				  "Invalid Length Value "
				  "length[%"PRIu64"][0x%"PRIx64"] > "
				  "iov_len[%zu][0x%zx]",
				  length, length,
				  tmp.iov_len,
				  tmp.iov_len);
			errno = EINVAL;
			return -1;
		}
		length += ofs;
		if (length > tmp.iov_len) {
			QWRAP_LOG(QWRAP_LOG_WARN,
				  "Invalid Packet Length "
				  "length[%"PRIu64"][0x%"PRIx64"] > "
				  "iov_len[%zu][0x%zx]",
				  length, length,
				  tmp.iov_len,
				  tmp.iov_len);
			errno = EINVAL;
			return -1;
		}
got_full_packet:
		dump_data("packet_full", b, length);
		hs_msg = malloc(sizeof(*hs_msg) + length);
		if (hs_msg == NULL) {
			errno = ENOMEM;
			return -1;
		}

		*hs_msg = (struct qwrap_msgbuf) {
			.datalen = length,
		};
		memcpy(hs_msg->data, b, length);
		b += length;
		tmp.iov_base = b;
		tmp.iov_len -= length;

		if (si->hs_recvmsg_in.last != NULL) {
			si->hs_recvmsg_in.last->next = hs_msg;
		}
		si->hs_recvmsg_in.last = hs_msg;
		if (si->hs_recvmsg_in.first == NULL) {
			si->hs_recvmsg_in.first = hs_msg;
		}
	}

	ret = qwrap_call_ngtcp2_conn_read_pkt(si, "recvmsg_hs2");
	if (ret < 0) {
		ngtcp2_conn_set_tls_error(si->conn, ret);
		errno = ECONNRESET;
		return -1;
	}

return_hs_out:
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC OUT recvmsg(fd=%d) hs_recvmsg_out[%p]\n",
		  s, si->hs_recvmsg_out.first);

	if (si->hs_recvmsg_out.first != NULL) {
		struct quic_handshake_info hinfo = {};

		hs_msg = si->hs_recvmsg_out.first;

		if (requested_bytes < hs_msg->datalen) {
			errno = EINVAL;
			return -1;
		}
		dump_data("hinfo out", hs_msg->data, hs_msg->datalen);

		msg_control = omsg->msg_control;
		msg_ctrllen_left = omsg->msg_controllen;

		hinfo.crypto_level = hs_msg->level;
		qwrap_msghdr_add_cmsghdr(omsg,
					 SOL_QUIC,
					 QUIC_HANDSHAKE_INFO,
					 &hinfo,
					 sizeof(hinfo));
		if (omsg->msg_flags & MSG_CTRUNC) {
			errno = EINVAL;
			return -1;
		}

		omsg->msg_control = msg_control;
		omsg->msg_controllen = msg_ctrllen_left - omsg->msg_controllen;

		while (iovscnt > 0 && hs_msg != NULL) {
			struct iovec vec = iovs[0];
			uint8_t *b = vec.iov_base;
			size_t cs;

			if (vec.iov_len == 0) {
				iovs += 1;
				iovscnt -= 1;
				continue;
			}

			cs = MIN(vec.iov_len, hs_msg->datalen);
			memcpy(b, hs_msg->data, cs);

			bytes += cs;

			b += cs;
			vec.iov_base = b;
			vec.iov_len -= cs;

			if (cs < hs_msg->datalen) {
				memmove(hs_msg->data,
					hs_msg->data + cs,
					hs_msg->datalen - cs);
			}
			hs_msg->datalen -= cs;

			if (hs_msg->datalen == 0) {
				si->hs_recvmsg_out.first = hs_msg->next;
				if (si->hs_recvmsg_out.first == NULL) {
					si->hs_recvmsg_out.last = NULL;
				}
				SAFE_FREE(hs_msg);
			}

			if (vec.iov_len == 0) {
				iovs += 1;
				iovscnt -= 1;
			} else {
				assert(hs_msg == NULL);
			}
		}

		assert(bytes > 0);
		assert(hs_msg == NULL);
	}

	if (bytes == 0) {
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d) stream RETRY: %s\n",
			  s, strerror(retry_errno));
		errno = retry_errno;
		return -1;
	}
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recvmsg(fd=%d) stream bytes[%zu]\n",
		  s, bytes);
	return bytes;
}

static ssize_t qwrap_recvmsg_stream(int s,
				    struct qwrap_socket_info *si,
				    struct msghdr *omsg,
				    size_t requested_bytes,
				    int flags)
{
	struct iovec *iovs = omsg->msg_iov;
	int iovscnt = omsg->msg_iovlen;
	int retry_errno = EAGAIN;
	ssize_t bytes = 0;
	ssize_t ret;

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC START recvmsg(fd=%d) requested_bytes[%zu]\n",
		  s, requested_bytes);

	if (flags & MSG_PEEK) {
		QWRAP_LOG(QWRAP_LOG_WARN, "MSG_PEEK not supportedr");
		errno = EINVAL;
		return -1;
	}

	if (!si->is_server && si->stream_id == -1) {
		QWRAP_LOG(QWRAP_LOG_WARN, "stream_id == -1");
		errno = ENOTCONN;
		return -1;
	}

	while (si->stream_recvmsg.first == NULL) {
		struct msghdr msg;
		struct iovec tmp;
		uint8_t buf[1500];

		tmp = (struct iovec) {
			.iov_base = buf,
			.iov_len = sizeof(buf),
		};
		msg = (struct msghdr) {
			.msg_iov = &tmp,
			.msg_iovlen = 1,
		};

		ret = next_recvmsg(s, &msg, flags);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d) stream NEXT ret[%zd] %d %s\n",
			  s, ret, ret == -1 ? errno : 0, strerror(ret == -1 ? errno : 0));
		if (ret < 0) {
			if (errno == EAGAIN) {
				errno = retry_errno;
			}
			return ret;
		}
		retry_errno = EINTR;
		tmp.iov_len = ret;

		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d): stream ngtcp2_conn_read_pkt tmp.iov_len[%zu]\n",
			  s, tmp.iov_len);
		dump_data("next_recvmsg_hs_data", tmp.iov_base, tmp.iov_len);
		ret = ngtcp2_conn_read_pkt(si->conn,
					   &si->path,
					   NULL,
					   tmp.iov_base,
					   tmp.iov_len,
					   qwrap_ngtcp2_timestamp());
		QWRAP_LOG(QWRAP_LOG_TRACE,
			"QUIC recvmsg(fd=%d): stream ngtcp2_conn_read_pkt tmp.iov_len[%zu] ret[%zu] %s\n",
			s, tmp.iov_len, ret, ngtcp2_strerror(ret));
		if (ret < 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			errno = ECONNRESET;
			return -1;
		}
	}

	while (si->handshake_done) {
		struct msghdr msg;
		struct iovec tmp;
		uint8_t buf[1500];

		ret = ngtcp2_conn_write_pkt(si->conn,
					    NULL,
					    NULL,
					    buf,
					    sizeof(buf),
					    qwrap_ngtcp2_timestamp());
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC FLUSH sendmsg(fd=%d) "
			  "ngtcp2_conn_write_pkt ret[%zd] %s\n",
			  s, ret, ngtcp2_strerror(ret));
		if (ret == 0) {
			break;
		}
		if (ret < 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			errno = ECONNRESET;
			return -1;
		}

		tmp.iov_base = buf;
		tmp.iov_len = ret;
		msg = (struct msghdr) {
			.msg_iov = &tmp,
			.msg_iovlen = 1,
		};
		dump_data("flush socket out", tmp.iov_base, tmp.iov_len);
		ret = next_sendmsg(s, &msg, MSG_NOSIGNAL);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC FLUSH sendmsg(fd=%d, iov_len=%zu) NEXT ret[%zd] %d %s\n",
			  s, tmp.iov_len, ret, ret == -1 ? errno : 0, strerror(ret == -1 ? errno : 0));
		if (ret < 0) {
			return ret;
		}
		ngtcp2_conn_update_pkt_tx_time(si->conn, qwrap_ngtcp2_timestamp());
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC STREAM recvmsg(fd=%d) stream_recvmsg[%p]\n",
		  s, si->stream_recvmsg.first);

	while (iovscnt > 0 && si->stream_recvmsg.first != NULL) {
		struct iovec vec = iovs[0];
		size_t cs;

		if (vec.iov_len == 0) {
			iovs += 1;
			iovscnt -= 1;
			continue;
		}

		while (si->stream_recvmsg.first != NULL) {
			struct qwrap_msgbuf *smsg = NULL;
			uint8_t *b = vec.iov_base;

			smsg = si->stream_recvmsg.first;

			cs = MIN(vec.iov_len, smsg->datalen);
			dump_data("stream out", smsg->data, cs);
			memcpy(b, smsg->data, cs);

			bytes += cs;

			b += cs;
			vec.iov_base = b;
			vec.iov_len -= cs;

			ngtcp2_conn_extend_max_offset(si->conn, cs);
			ngtcp2_conn_extend_max_stream_offset(si->conn,
							     si->stream_id,
							     cs);

			if (cs < smsg->datalen) {
				memmove(smsg->data,
					smsg->data + cs,
					smsg->datalen - cs);
			}
			smsg->datalen -= cs;

			if (smsg->datalen == 0) {
				si->stream_recvmsg.first = smsg->next;
				if (si->stream_recvmsg.first == NULL) {
					si->stream_recvmsg.last = NULL;
				}
				SAFE_FREE(smsg);
			}

			if (vec.iov_len == 0) {
				iovs += 1;
				iovscnt -= 1;
				break;
			}
		}
	}

	if (bytes == 0) {
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d) stream RETRY: %s\n",
			  s, strerror(retry_errno));
		errno = retry_errno;
		return -1;
	}
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recvmsg(fd=%d) stream bytes[%zu]\n",
		  s, bytes);
	return bytes;
}

static ssize_t qwrap_recvmsg(int s, struct msghdr *omsg, int flags)
{
	struct qwrap_socket_info *si = NULL;
	size_t requested_bytes = 0;
	size_t ret;
	int i;

	si = find_qwrap_socket(s);
	if (si == NULL) {
		ret = next_recvmsg(s, omsg, flags);
		return qwrap_recvmsg_after_unix(omsg, ret);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC START recvmsg(fd=%d) connected[%u] handshake_done[%u] ...\n",
		  s, si->connected, si->handshake_done);

	if (omsg->msg_iovlen > IOV_MAX) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < omsg->msg_iovlen; i++) {
		size_t v = omsg->msg_iov[i].iov_len;

		if (v > SSIZE_MAX) {
			errno = EINVAL;
			return -1;
		}
		requested_bytes += v;
		if (requested_bytes > SSIZE_MAX) {
			errno = EINVAL;
			return -1;
		}
	}

	if (requested_bytes == 0) {
		errno = EINVAL;
		return -1;
	}

	QWRAP_LOCK_SI(si);
	if (si->conn == NULL) {
		QWRAP_UNLOCK_SI(si);
		errno = ENOTCONN;
		return -1;
	}

	ret = qwrap_call_ngtcp2_conn_read_pkt(si, "recvmsg_start");
	if (ret < 0) {
		ngtcp2_conn_set_tls_error(si->conn, ret);
		QWRAP_UNLOCK_SI(si);
		errno = ECONNRESET;
		return -1;
	}

	if (!si->handshake_done ||
	    si->hs_recvmsg_in.first != NULL ||
	    si->hs_recvmsg_out.first != NULL)
	{
		ret = qwrap_recvmsg_handshake(s,
					      si,
					      omsg,
					      requested_bytes,
					      flags);
	} else {
		ret = qwrap_recvmsg_stream(s,
					   si,
					   omsg,
					   requested_bytes,
					   flags);
	}

	QWRAP_UNLOCK_SI(si);
	return ret;
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	return qwrap_recvmsg(sockfd, msg, flags);
}

/****************************************************************************
 *   RECVMMSG
 ***************************************************************************/

#ifdef HAVE_RECVMMSG
#if defined(HAVE_RECVMMSG_SSIZE_T_CONST_TIMEOUT)
/* FreeBSD */
static ssize_t qwrap_recvmmsg(int s, struct mmsghdr *omsgvec, size_t vlen, int flags, const struct timespec *timeout)
#elif defined(HAVE_RECVMMSG_CONST_TIMEOUT)
/* Linux legacy glibc < 2.21 */
static int qwrap_recvmmsg(int s, struct mmsghdr *omsgvec, unsigned int vlen, int flags, const struct timespec *timeout)
#else
/* Linux glibc >= 2.21 */
static int qwrap_recvmmsg(int s, struct mmsghdr *omsgvec, unsigned int vlen, int flags, struct timespec *timeout)
#endif
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	unsigned int i;
	int ret;

	if (si == NULL) {
		ret = next_recvmmsg(s, omsgvec, vlen, flags, timeout);

		for (i = 0; i < vlen; i++) {
			struct msghdr *omsg = &omsgvec[i].msg_hdr;
			qwrap_recvmsg_after_unix(omsg, ret);
		}

		return ret;
	}

	if (vlen == 0) {
		errno = EINVAL;
		ret = -1;
	}

	for (i = 0; i < vlen; i++) {
		struct msghdr *omsg = &omsgvec[i].msg_hdr;

		ret = qwrap_recvmsg(s, omsg, flags);
		if (ret < 0) {
			break;
		}
		omsgvec[i].msg_len = ret;
		if (flags & MSG_WAITFORONE) {
			flags |= MSG_DONTWAIT;
		}
	}

	if (i != 0) {
		ret = i;
	}
	return ret;
}

#if defined(HAVE_RECVMMSG_SSIZE_T_CONST_TIMEOUT)
/* FreeBSD */
ssize_t recvmmsg(int sockfd, struct mmsghdr *msgvec, size_t vlen, int flags, const struct timespec *timeout)
#elif defined(HAVE_RECVMMSG_CONST_TIMEOUT)
/* Linux legacy glibc < 2.21 */
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, const struct timespec *timeout)
#else
/* Linux glibc >= 2.21 */
int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout)
#endif
{
	return qwrap_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
}
#endif /* HAVE_RECVMMSG */

/****************************************************************************
 *   SENDMSG
 ***************************************************************************/

static ssize_t qwrap_sendmsg(int s, const struct msghdr *omsg, int flags)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct msghdr msg = { .msg_iov = NULL, };
	struct cmsghdr *cmsg = NULL;
	struct quic_handshake_info *hinfo = NULL;
	ngtcp2_vec _datav[omsg->msg_iovlen];
	ngtcp2_vec *datav = NULL;
	size_t datavcnt;
	ssize_t bytes = 0;
	struct iovec tmp;
	int rflags = MSG_PEEK | MSG_DONTWAIT;
	ssize_t ret;
	bool allow_retry = true;

	if (si == NULL) {
		ret = qwrap_sendmsg_before_unix(omsg);
		if (ret < 0) {
			return ret;
		}

		return next_sendmsg(s, omsg, flags);
	}

	for (cmsg = CMSG_FIRSTHDR(discard_const_p(struct msghdr, omsg));
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(discard_const_p(struct msghdr, omsg), cmsg))
	{
		if (cmsg->cmsg_level != SOL_QUIC) {
			continue;
		}

		if (cmsg->cmsg_type == QUIC_HANDSHAKE_INFO) {
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(*hinfo))) {
				continue;
			}

			hinfo = (struct quic_handshake_info *)CMSG_DATA(cmsg);
			break;
		}
	}

	QWRAP_LOCK_SI(si);
	if (hinfo == NULL && si->handshake_done == 0) {
		QWRAP_UNLOCK_SI(si);
		errno = EINVAL;
		return -1;
	}

	if (si->conn == NULL) {
		QWRAP_UNLOCK_SI(si);
		errno = ENOTCONN;
		return -1;
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC sendmsg(fd=%d) handshake_done[%u] hinfo[%p] more[%u]\n",
		  s, si->handshake_done, hinfo, !!(flags & MSG_MORE));

	if (hinfo != NULL) {
		ngtcp2_encryption_level level =
			qwrap_to_ngtcp2_crypto_level(hinfo->crypto_level);

		if (omsg->msg_iovlen != 1) {
			QWRAP_UNLOCK_SI(si);
			QWRAP_LOG(QWRAP_LOG_WARN,
				  "Handshake message only supports "
				  "msg_iovlen==1 yet got %zu",
				  omsg->msg_iovlen);
			errno = EINVAL;
			return -1;
		}

		qwrap_call_ngtcp2_conn_read_pkt(si, "sendmsg_hs");
		dump_data("hinfo in",
			  omsg->msg_iov[0].iov_base,
			  omsg->msg_iov[0].iov_len);
		ret = ngtcp2_conn_submit_crypto_data(si->conn,
						     level,
						     omsg->msg_iov[0].iov_base,
						     omsg->msg_iov[0].iov_len);
		if (ret != 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			QWRAP_UNLOCK_SI(si);
			if (!(flags & MSG_NOSIGNAL)) {
				kill(getpid(), SIGPIPE);
			}
			errno = EPIPE;
			return -1;
		}
		if (flags & MSG_MORE) {
			QWRAP_UNLOCK_SI(si);
			return omsg->msg_iov[0].iov_len;
		}

		bytes = omsg->msg_iov[0].iov_len;

		datav = NULL;
		datavcnt = 0;
	} else {
		size_t vi;
		size_t di;

		for (vi = 0, di = 0; vi < omsg->msg_iovlen; vi++) {
			if (omsg->msg_iov[vi].iov_len == 0) {
				continue;
			}

			_datav[di] = (struct ngtcp2_vec) {
				.base = omsg->msg_iov[vi].iov_base,
				.len = omsg->msg_iov[vi].iov_len,
			};
			dump_data("data inX", _datav[di].base, _datav[di].len);
			di++;
		}

		datav = _datav;
		datavcnt = di;
	}

retry_flush:
	while (si->handshake_done) {
		struct qwrap_msgbuf *last_msg = si->stream_recvmsg.last;
		uint8_t buf[1500];

		tmp = (struct iovec) {
			.iov_base = buf,
			.iov_len = sizeof(buf),
		};
		msg = (struct msghdr) {
			.msg_iov = &tmp,
			.msg_iovlen = 1,
		};

		ret = next_recvmsg(s, &msg, rflags);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d, rflags=0x%x) NEXT ret[%zd] %d %s\n",
			  s, rflags, ret,
			  ret == -1 ? errno : 0, strerror(ret == -1 ? errno : 0));
		rflags |= MSG_PEEK;
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			if (errno == EAGAIN) {
				break;
			}
			if (errno == EWOULDBLOCK) {
				break;
			}
			QWRAP_UNLOCK_SI(si);
			return ret;
		}
		tmp.iov_len = ret;

		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC recvmsg(fd=%d): stream ngtcp2_conn_read_pkt "
			  "tmp.iov_len[%zu]\n",
			  s, tmp.iov_len);
		dump_data("next_recvmsg_hs_data", tmp.iov_base, tmp.iov_len);
		ret = ngtcp2_conn_read_pkt(si->conn,
					   &si->path,
					   NULL,
					   tmp.iov_base,
					   tmp.iov_len,
					   qwrap_ngtcp2_timestamp());
		QWRAP_LOG(QWRAP_LOG_TRACE,
			"QUIC recvmsg(fd=%d): stream ngtcp2_conn_read_pkt "
			"tmp.iov_len[%zu] ret[%zu] %s\n",
			s, tmp.iov_len, ret, ngtcp2_strerror(ret));
		if (ret < 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			QWRAP_UNLOCK_SI(si);
			if (!(flags & MSG_NOSIGNAL)) {
				kill(getpid(), SIGPIPE);
			}
			errno = EPIPE;
			return -1;
		}
		if (last_msg == si->stream_recvmsg.last) {
			/*
			 * If the packet didn't contain
			 * new stream messages we can
			 * recv it without MSG_PEEK.
			 */
			rflags &= ~MSG_PEEK;
		}
		allow_retry = true;
	}

	while (1) {
		uint8_t buf[1500];
		ngtcp2_ssize nwritten = -1;
		uint32_t sflags = NGTCP2_WRITE_STREAM_FLAG_NONE;

		if (flags & MSG_MORE) {
			sflags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
		}

		ret = ngtcp2_conn_writev_stream(si->conn,
					        NULL,
					        NULL,
					        buf,
					        sizeof(buf),
					        &nwritten,
					        sflags,
					        si->stream_id,
					        datav,
					        datavcnt,
					        qwrap_ngtcp2_timestamp());
		si->handshake_done = ngtcp2_conn_get_handshake_completed(si->conn);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC sendmsg(fd=%d) handshake_done[%u] sid[%"PRIi64"] "
			  "ngtcp2_conn_writev_stream ret[%zd] %s nwritten[%zd]\n",
			  s, si->handshake_done, si->stream_id,
			  ret, ngtcp2_strerror(ret), nwritten);
		if (ret == 0) {
			if (datavcnt != 0 && allow_retry) {
				allow_retry = false;
				goto retry_flush;
			}
			break;
		}
		if (ret == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
			if (allow_retry) {
				allow_retry = false;
				goto retry_flush;
			}
			break;
		}
		if (ret < 0) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			QWRAP_UNLOCK_SI(si);
			if (!(flags & MSG_NOSIGNAL)) {
				kill(getpid(), SIGPIPE);
			}
			errno = EPIPE;
			return -1;
		}

		tmp = (struct iovec) {
			.iov_base = buf,
			.iov_len = ret,
		};
		msg = (struct msghdr) {
			.msg_iov = &tmp,
			.msg_iovlen = 1,
		};
		dump_data("socket out", tmp.iov_base, tmp.iov_len);
		ret = next_sendmsg(s, &msg, flags);
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC sendmsg(fd=%d, iov_len=%zu) handshake_done[%u] "
			  "datavcnt[%zd] NEXT ret[%zd] %d %s\n",
			  s, tmp.iov_len, si->handshake_done,
			  datavcnt, ret,
			  ret == -1 ? errno : 0, strerror(ret == -1 ? errno : 0));
		if (ret < 0) {
			QWRAP_UNLOCK_SI(si);
			return ret;
		}

		if (nwritten == -1 || datavcnt == 0) {
			continue;
		}

		bytes += nwritten;

		while (datavcnt > 0) {
			if (nwritten >= datav[0].len) {
				nwritten -= datav[0].len;
				datav++;
				datavcnt--;
				continue;
			}

			datav[0].base += nwritten;
			datav[0].len -= nwritten;
			break;
		}
	}

	ngtcp2_conn_update_pkt_tx_time(si->conn, qwrap_ngtcp2_timestamp());
	if (bytes == 0) {
		int retry_errno = EAGAIN;
		QWRAP_LOG(QWRAP_LOG_TRACE,
			  "QUIC OUT sendmsg(fd=%d) RETRY: %s\n",
			  s, strerror(retry_errno));
		QWRAP_UNLOCK_SI(si);
		errno = retry_errno;
		return -1;
	}
	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC OUT sendmsg(fd=%d) bytes[%zd]\n",
		  s, bytes);
	QWRAP_UNLOCK_SI(si);
	return bytes;
}

ssize_t sendmsg(int s, const struct msghdr *omsg, int flags)
{
	return qwrap_sendmsg(s, omsg, flags);
}

/****************************************************************************
 *   SENDMMSG
 ***************************************************************************/

#ifdef HAVE_SENDMMSG
#if defined(HAVE_SENDMMSG_SSIZE_T)
/* FreeBSD */
static ssize_t qwrap_sendmmsg(int s, struct mmsghdr *omsgvec, size_t vlen, int flags)
#else
/* Linux */
static int qwrap_sendmmsg(int s, struct mmsghdr *omsgvec, unsigned int vlen, int flags)
#endif
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	unsigned int i;
	int ret;

	if (si == NULL) {
		for (i = 0; i < vlen; i++) {
			struct msghdr *omsg = &omsgvec[i].msg_hdr;

			ret = qwrap_sendmsg_before_unix(omsg);
			if (ret < 0) {
				return ret;
			}
		}

		return next_sendmmsg(s, omsgvec, vlen, flags);
	}

	if (vlen == 0) {
		errno = EINVAL;
		ret = -1;
	}

	for (i = 0; i < vlen; i++) {
		struct msghdr *omsg = &omsgvec[i].msg_hdr;

		ret = qwrap_sendmsg(s, omsg, flags);
		if (ret < 0) {
			break;
		}
		omsgvec[i].msg_len = ret;
	}

	if (i != 0) {
		ret = i;
	}
	return ret;
}

#if defined(HAVE_SENDMMSG_SSIZE_T)
/* FreeBSD */
ssize_t sendmmsg(int s, struct mmsghdr *msgvec, size_t vlen, int flags)
#else
/* Linux */
int sendmmsg(int s, struct mmsghdr *msgvec, unsigned int vlen, int flags)
#endif
{
	return qwrap_sendmmsg(s, msgvec, vlen, flags);
}
#endif /* HAVE_SENDMMSG */

/****************************************************************************
 *   READV
 ***************************************************************************/

static ssize_t qwrap_readv(int s, const struct iovec *vector, int count)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct msghdr msg = {
		.msg_iov = discard_const_p(struct iovec, vector),
		.msg_iovlen = count,
	};
	ssize_t ret;

	if (si == NULL) {
		return next_readv(s, vector, count);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC recv(fd=%d) => qwrap_recvmsg\n",
		  s);

	ret = qwrap_recvmsg(s, &msg, 0);
	if (ret == -1 && errno == ENOTSOCK) {
		qwrap_remove_stale(s);
		return next_readv(s, vector, count);
	}
	return ret;
}

ssize_t readv(int s, const struct iovec *vector, int count)
{
	return qwrap_readv(s, vector, count);
}

/****************************************************************************
 *   WRITEV
 ***************************************************************************/

static ssize_t qwrap_writev(int s, const struct iovec *vector, int count)
{
	struct qwrap_socket_info *si = find_qwrap_socket(s);
	struct msghdr msg = {
		.msg_iov = discard_const_p(struct iovec, vector),
		.msg_iovlen = count,
	};

	if (si == NULL) {
		return next_writev(s, vector, count);
	}

	QWRAP_LOG(QWRAP_LOG_TRACE,
		  "QUIC writev(fd=%d) => qwrap_sendmsg()\n",
		  s);

	return qwrap_sendmsg(s, &msg, 0);
}

ssize_t writev(int s, const struct iovec *vector, int count)
{
	return qwrap_writev(s, vector, count);
}

/****************************
 * CLOSE
 ***************************/

static void qwrap_close_msg_and_free(int fd,
				     struct qwrap_socket_info *si,
				     const ngtcp2_ccerr *ccerr)
{
	struct qwrap_msgbuf *msg = NULL;
	struct qwrap_msgbuf *msg_next = NULL;

	for (msg = si->hs_recvmsg_in.first; msg != NULL; msg = msg_next) {
		msg_next = msg->next;
		SAFE_FREE(msg);
	}
	si->hs_recvmsg_in.first = NULL;
	si->hs_recvmsg_in.last = NULL;
	for (msg = si->hs_recvmsg_out.first; msg != NULL; msg = msg_next) {
		msg_next = msg->next;
		SAFE_FREE(msg);
	}
	si->hs_recvmsg_out.first = NULL;
	si->hs_recvmsg_out.last = NULL;
	for (msg = si->stream_recvmsg.first; msg != NULL; msg = msg_next) {
		msg_next = msg->next;
		SAFE_FREE(msg);
	}
	si->stream_recvmsg.first = NULL;
	si->stream_recvmsg.last = NULL;

	if (!si->connected) {
		return;
	}

	if (si->conn == NULL) {
		return;
	}

	if (ccerr != NULL) {
		uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
		ngtcp2_ssize ret;

		ret = ngtcp2_conn_write_connection_close(si->conn,
							 &si->path,
							 NULL,
							 buf,
							 sizeof(buf),
							 ccerr,
							 qwrap_ngtcp2_timestamp());
		if (ret > 0) {
			next_send(fd, buf, ret, MSG_NOSIGNAL | MSG_DONTWAIT);
		}
	}

	ngtcp2_conn_del(si->conn);
	si->conn = NULL;
	si->connected = 0;
}

static int qwrap_remove_wrapper(const char *__func_name,
				unsigned __line,
				const ngtcp2_ccerr *ccerr,
				int (*__close_fd_fn)(int fd),
				int fd)
{
	struct qwrap_socket_info *si = NULL;
	int si_index;
	int ret_errno = errno;
	int ret;

	qwrap_mutex_lock(&socket_reset_mutex);

	si_index = find_qwrap_socket_index(fd);
	if (si_index == -1) {
		qwrap_mutex_unlock(&socket_reset_mutex);
		return __close_fd_fn(fd);
	}

	qwrap_log(QWRAP_LOG_TRACE, __func_name, __line,
		  "Remove wrapper for fd=%d", fd);
	reset_socket_info_index(fd);

	si = qwrap_get_socket_info(si_index);

	qwrap_mutex_lock(&first_free_mutex);
	QWRAP_LOCK_SI(si);

	qwrap_close_msg_and_free(fd, si, ccerr);

	ret = __close_fd_fn(fd);
	if (ret == -1) {
		ret_errno = errno;
	}

	qwrap_dec_refcount(si);

	if (qwrap_get_refcount(si) > 0) {
		/* there are still references left */
		goto out;
	}

	qwrap_set_next_free(si, first_free);
	first_free = si_index;

out:
	QWRAP_UNLOCK_SI(si);
	qwrap_mutex_unlock(&first_free_mutex);
	qwrap_mutex_unlock(&socket_reset_mutex);

	errno = ret_errno;
	return ret;
}

static int qwrap_noop_close(int fd)
{
	(void)fd; /* unused */
	return 0;
}

static void qwrap_remove_stale(int fd)
{
	qwrap_remove_wrapper(__func__, __LINE__, NULL, qwrap_noop_close, fd);
}

/*
 * This allows quic_ko_wrapper aware applications to
 * indicate that the given fd does not belong to
 * an inet socket.
 *
 * We already overload a lot of unrelated functions
 * like eventfd(), timerfd_create(), ... in order to
 * call qwrap_remove_stale() on the returned fd, but
 * we'll never be able to handle all possible syscalls.
 *
 * quic_ko_wrapper_indicate_no_inet_fd() gives them a way
 * to do the same.
 *
 * We don't export qwrap_remove_stale() in order to
 * make it easier to analyze QUIC_KO_WRAPPER_DEBUGLEVEL=3
 * log files.
 */
void quic_ko_wrapper_indicate_no_inet_fd(int fd)
{
	qwrap_remove_wrapper(__func__, __LINE__, NULL, qwrap_noop_close, fd);
}

static int qwrap_close(int fd)
{
	ngtcp2_ccerr ccerr;
	ngtcp2_ccerr_default(&ccerr);
	return qwrap_remove_wrapper(__func__, __LINE__, &ccerr, next_close, fd);
}

int close(int fd)
{
	return qwrap_close(fd);
}

#ifdef HAVE___CLOSE_NOCANCEL

static int qwrap___close_nocancel(int fd)
{
	ngtcp2_ccerr ccerr;
	ngtcp2_ccerr_default(&ccerr);
	return qwrap_remove_wrapper(__func__, __LINE__, &ccerr,
				    next___close_nocancel, fd);
}

int __close_nocancel(int fd);
int __close_nocancel(int fd)
{
	return qwrap___close_nocancel(fd);
}

#endif /* HAVE___CLOSE_NOCANCEL */

/****************************
 * DUP
 ***************************/

static int qwrap_dup(int fd)
{
	struct qwrap_socket_info *si;
	int dup_fd, idx;

	idx = find_qwrap_socket_index(fd);
	if (idx == -1) {
		return next_dup(fd);
	}

	si = qwrap_get_socket_info(idx);

	dup_fd = next_dup(fd);
	if (dup_fd == -1) {
		int saved_errno = errno;
		errno = saved_errno;
		return -1;
	}

	if ((size_t)dup_fd >= socket_fds_max) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  dup_fd);
		next_close(dup_fd);
		errno = EMFILE;
		return -1;
	}

	QWRAP_LOCK_SI(si);

	qwrap_inc_refcount(si);

	QWRAP_UNLOCK_SI(si);

	/* Make sure we don't have an entry for the fd */
	qwrap_remove_stale(dup_fd);

	set_socket_info_index(dup_fd, idx);

	return dup_fd;
}

int dup(int fd)
{
	return qwrap_dup(fd);
}

/****************************
 * DUP2
 ***************************/

static int qwrap_dup2(int fd, int newfd)
{
	struct qwrap_socket_info *si;
	int dup_fd, idx;

	idx = find_qwrap_socket_index(fd);
	if (idx == -1) {
		return next_dup2(fd, newfd);
	}

	si = qwrap_get_socket_info(idx);

	if (fd == newfd) {
		/*
		 * According to the manpage:
		 *
		 * "If oldfd is a valid file descriptor, and newfd has the same
		 * value as oldfd, then dup2() does nothing, and returns newfd."
		 */
		return newfd;
	}

	if ((size_t)newfd >= socket_fds_max) {
		QWRAP_LOG(QWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  newfd);
		errno = EMFILE;
		return -1;
	}

	if (find_qwrap_socket(newfd)) {
		/* dup2() does an implicit close of newfd, which we
		 * need to emulate */
		qwrap_close(newfd);
	}

	dup_fd = next_dup2(fd, newfd);
	if (dup_fd == -1) {
		int saved_errno = errno;
		errno = saved_errno;
		return -1;
	}

	QWRAP_LOCK_SI(si);

	qwrap_inc_refcount(si);

	QWRAP_UNLOCK_SI(si);

	/* Make sure we don't have an entry for the fd */
	qwrap_remove_stale(dup_fd);

	set_socket_info_index(dup_fd, idx);

	return dup_fd;
}

int dup2(int fd, int newfd)
{
	return qwrap_dup2(fd, newfd);
}

/****************************
 * FCNTL
 ***************************/

static int qwrap_vfcntl(int fd, int cmd, va_list va)
{
	struct qwrap_socket_info *si;
	int rc, dup_fd, idx;

	idx = find_qwrap_socket_index(fd);
	if (idx == -1) {
		return next_vfcntl(fd, cmd, va);
	}

	si = qwrap_get_socket_info(idx);

	switch (cmd) {
	case F_DUPFD:
		dup_fd = next_vfcntl(fd, cmd, va);
		if (dup_fd == -1) {
			int saved_errno = errno;
			errno = saved_errno;
			return -1;
		}

		/* Make sure we don't have an entry for the fd */
		qwrap_remove_stale(dup_fd);

		if ((size_t)dup_fd >= socket_fds_max) {
			QWRAP_LOG(QWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  dup_fd);
			next_close(dup_fd);
			errno = EMFILE;
			return -1;
		}

		QWRAP_LOCK_SI(si);

		qwrap_inc_refcount(si);

		QWRAP_UNLOCK_SI(si);


		set_socket_info_index(dup_fd, idx);

		rc = dup_fd;
		break;
	default:
		rc = next_vfcntl(fd, cmd, va);
		break;
	}

	return rc;
}

#undef fcntl /* Needed for LFS handling */
int fcntl(int fd, int cmd, ...)
{
	va_list va;
	int rc;

	va_start(va, cmd);

	rc = qwrap_vfcntl(fd, cmd, va);

	va_end(va);

	return rc;
}

/****************************
 * FCNTL64
 ***************************/

#ifdef HAVE_FCNTL64
static int qwrap_vfcntl64(int fd, int cmd, va_list va)
{
	struct qwrap_socket_info *si;
	int rc, dup_fd, idx;

	idx = find_qwrap_socket_index(fd);
	if (idx == -1) {
		return next_vfcntl64(fd, cmd, va);
	}

	si = qwrap_get_socket_info(idx);

	switch (cmd) {
	case F_DUPFD:
		dup_fd = next_vfcntl64(fd, cmd, va);
		if (dup_fd == -1) {
			int saved_errno = errno;
			errno = saved_errno;
			return -1;
		}

		/* Make sure we don't have an entry for the fd */
		qwrap_remove_stale(dup_fd);

		if ((size_t)dup_fd >= socket_fds_max) {
			QWRAP_LOG(QWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  dup_fd);
			next_close(dup_fd);
			errno = EMFILE;
			return -1;
		}

		QWRAP_LOCK_SI(si);

		qwrap_inc_refcount(si);

		QWRAP_UNLOCK_SI(si);


		set_socket_info_index(dup_fd, idx);

		rc = dup_fd;
		break;
	default:
		rc = next_vfcntl64(fd, cmd, va);
		break;
	}

	return rc;
}

int fcntl64(int fd, int cmd, ...)
{
	va_list va;
	int rc;

	va_start(va, cmd);

	rc = qwrap_vfcntl64(fd, cmd, va);

	va_end(va);

	return rc;
}
#endif

/****************************
 * EVENTFD
 ***************************/

#ifdef HAVE_EVENTFD
static int qwrap_eventfd(int count, int flags)
{
	int fd;

	fd = next_eventfd(count, flags);
	if (fd != -1) {
		qwrap_remove_stale(fd);
	}

	return fd;
}

#ifdef HAVE_EVENTFD_UNSIGNED_INT
int eventfd(unsigned int count, int flags)
#else
int eventfd(int count, int flags)
#endif
{
	return qwrap_eventfd(count, flags);
}
#endif

#ifdef HAVE_PLEDGE
int pledge(const char *promises, const char *paths[])
{
	(void)promises; /* unused */
	(void)paths; /* unused */

	return 0;
}
#endif /* HAVE_PLEDGE */

static void qwrap_thread_prepare(void)
{
	/*
	 * This function should only be called here!!
	 *
	 * We bind all symobls to avoid deadlocks of the fork is
	 * interrupted by a signal handler using a symbol of this
	 * library.
	 */
	qwrap_bind_symbol_all();

	QWRAP_LOCK_ALL;
}

static void qwrap_thread_parent(void)
{
	QWRAP_UNLOCK_ALL;
}

static void qwrap_thread_child(void)
{
	QWRAP_REINIT_ALL;
}

/****************************
 * CONSTRUCTOR
 ***************************/
static void qwrap_constructor(void)
{
	QWRAP_REINIT_ALL;

	/*
	* If we hold a lock and the application forks, then the child
	* is not able to unlock the mutex and we are in a deadlock.
	* This should prevent such deadlocks.
	*/
	pthread_atfork(&qwrap_thread_prepare,
		       &qwrap_thread_parent,
		       &qwrap_thread_child);
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
static void qwrap_destructor(void)
{
	size_t i;

	if (socket_fds_idx != NULL) {
		for (i = 0; i < socket_fds_max; ++i) {
			if (socket_fds_idx[i] != -1) {
				qwrap_close(i);
			}
		}
		SAFE_FREE(socket_fds_idx);
	}

	SAFE_FREE(sockets);
}

#if defined(HAVE__SOCKET) && defined(HAVE__CLOSE)
/*
 * On FreeBSD 12 (and maybe other platforms)
 * system libraries like libresolv prefix there
 * syscalls with '_' in order to always use
 * the symbols from libc.
 *
 * In the interaction with resolv_wrapper,
 * we need to inject socket wrapper into libresolv,
 * which means we need to private all socket
 * related syscalls also with the '_' prefix.
 *
 * This is tested in Samba's 'make test',
 * there we noticed that providing '_read',
 * '_open' and '_close' would cause errors, which
 * means we skip '_read', '_write' and
 * all non socket related calls without
 * further analyzing the problem.
 */
#define QWRAP_SYMBOL_ALIAS(__sym, __aliassym) \
	extern typeof(__sym) __aliassym __attribute__ ((alias(#__sym)))

#ifdef HAVE_ACCEPT4
QWRAP_SYMBOL_ALIAS(accept4, _accept4);
#endif
QWRAP_SYMBOL_ALIAS(accept, _accept);
QWRAP_SYMBOL_ALIAS(bind, _bind);
QWRAP_SYMBOL_ALIAS(connect, _connect);
QWRAP_SYMBOL_ALIAS(dup, _dup);
QWRAP_SYMBOL_ALIAS(dup2, _dup2);
QWRAP_SYMBOL_ALIAS(fcntl, _fcntl);
QWRAP_SYMBOL_ALIAS(getsockopt, _getsockopt);
QWRAP_SYMBOL_ALIAS(ioctl, _ioctl);
QWRAP_SYMBOL_ALIAS(listen, _listen);
QWRAP_SYMBOL_ALIAS(readv, _readv);
QWRAP_SYMBOL_ALIAS(recv, _recv);
QWRAP_SYMBOL_ALIAS(recvfrom, _recvfrom);
QWRAP_SYMBOL_ALIAS(recvmsg, _recvmsg);
QWRAP_SYMBOL_ALIAS(send, _send);
QWRAP_SYMBOL_ALIAS(sendmsg, _sendmsg);
QWRAP_SYMBOL_ALIAS(sendto, _sendto);
QWRAP_SYMBOL_ALIAS(setsockopt, _setsockopt);
QWRAP_SYMBOL_ALIAS(socket, _socket);
QWRAP_SYMBOL_ALIAS(socketpair, _socketpair);
QWRAP_SYMBOL_ALIAS(writev, _writev);

#endif /* QUIC_KO_WRAPPER_EXPORT_UNDERSCORE_SYMBOLS */
