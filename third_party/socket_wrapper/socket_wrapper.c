/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2005-2008, Jelmer Vernooij <jelmer@samba.org>
 * Copyright (c) 2006-2021, Stefan Metzmacher <metze@samba.org>
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
#ifdef HAVE_NETINET_TCP_FSM_H
#include <netinet/tcp_fsm.h>
#endif
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
#include <pthread.h>

#include "socket_wrapper.h"

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

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#define UNUSED(x) (void)(x)

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

#define socket_wrapper_init_mutex(m) \
	_socket_wrapper_init_mutex(m, #m)

/* Add new global locks here please */
# define SWRAP_REINIT_ALL do { \
	int ret; \
	ret = socket_wrapper_init_mutex(&sockets_mutex); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&socket_reset_mutex); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&first_free_mutex); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&sockets_si_global); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&autobind_start_mutex); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&pcap_dump_mutex); \
	if (ret != 0) exit(-1); \
	ret = socket_wrapper_init_mutex(&mtu_update_mutex); \
	if (ret != 0) exit(-1); \
} while(0)

# define SWRAP_LOCK_ALL do { \
	swrap_mutex_lock(&sockets_mutex); \
	swrap_mutex_lock(&socket_reset_mutex); \
	swrap_mutex_lock(&first_free_mutex); \
	swrap_mutex_lock(&sockets_si_global); \
	swrap_mutex_lock(&autobind_start_mutex); \
	swrap_mutex_lock(&pcap_dump_mutex); \
	swrap_mutex_lock(&mtu_update_mutex); \
} while(0)

# define SWRAP_UNLOCK_ALL do { \
	swrap_mutex_unlock(&mtu_update_mutex); \
	swrap_mutex_unlock(&pcap_dump_mutex); \
	swrap_mutex_unlock(&autobind_start_mutex); \
	swrap_mutex_unlock(&sockets_si_global); \
	swrap_mutex_unlock(&first_free_mutex); \
	swrap_mutex_unlock(&socket_reset_mutex); \
	swrap_mutex_unlock(&sockets_mutex); \
} while(0)

#define SOCKET_INFO_CONTAINER(si) \
	(struct socket_info_container *)(si)

#define SWRAP_LOCK_SI(si) do { \
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si); \
	if (sic != NULL) { \
		swrap_mutex_lock(&sockets_si_global); \
	} else { \
		abort(); \
	} \
} while(0)

#define SWRAP_UNLOCK_SI(si) do { \
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si); \
	if (sic != NULL) { \
		swrap_mutex_unlock(&sockets_si_global); \
	} else { \
		abort(); \
	} \
} while(0)

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
 * Set the packet MTU to 1500 bytes for stream sockets to make it it easier to
 * format PCAP capture files (as the caller will simply continue from here).
 */
#define SOCKET_WRAPPER_MTU_DEFAULT 1500
#define SOCKET_WRAPPER_MTU_MIN     512
#define SOCKET_WRAPPER_MTU_MAX     32768

#define SOCKET_MAX_SOCKETS 1024

/*
 * Maximum number of socket_info structures that can
 * be used. Can be overriden by the environment variable
 * SOCKET_WRAPPER_MAX_SOCKETS.
 */
#define SOCKET_WRAPPER_MAX_SOCKETS_DEFAULT 65535

#define SOCKET_WRAPPER_MAX_SOCKETS_LIMIT 262140

/* This limit is to avoid broadcast sendto() needing to stat too many
 * files.  It may be raised (with a performance cost) to up to 254
 * without changing the format above */
#define MAX_WRAPPED_INTERFACES 64

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

static int first_free;

struct socket_info
{
	/*
	 * Remember to update swrap_unix_scm_right_magic
	 * on any change.
	 */

	int family;
	int type;
	int protocol;
	int bound;
	int bcast;
	int is_server;
	int connected;
	int defer_connect;
	int pktinfo;
	int tcp_nodelay;
	int listening;
	int fd_passed;

	/* The unix path so we can unlink it on close() */
	struct sockaddr_un un_addr;

	struct swrap_address bindname;
	struct swrap_address myname;
	struct swrap_address peername;

	struct {
		unsigned long pck_snd;
		unsigned long pck_rcv;
	} io;
};

struct socket_info_meta
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

struct socket_info_container
{
	struct socket_info info;
	struct socket_info_meta meta;
};

static struct socket_info_container *sockets;

static size_t socket_info_max = 0;

/*
 * Allocate the socket array always on the limit value. We want it to be
 * at least bigger than the default so if we reach the limit we can
 * still deal with duplicate fds pointing to the same socket_info.
 */
static size_t socket_fds_max = SOCKET_WRAPPER_MAX_SOCKETS_LIMIT;

/* Hash table to map fds to corresponding socket_info index */
static int *socket_fds_idx;

/* Mutex for syncronizing port selection during swrap_auto_bind() */
static pthread_mutex_t autobind_start_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to guard the initialization of array of socket_info structures */
static pthread_mutex_t sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to guard the socket reset in swrap_remove_wrapper() */
static pthread_mutex_t socket_reset_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to synchronize access to first free index in socket_info array */
static pthread_mutex_t first_free_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Mutex to synchronize access to to socket_info structures
 * We use a single global mutex in order to avoid leaking
 * ~ 38M copy on write memory per fork.
 * max_sockets=65535 * sizeof(struct socket_info_container)=592 = 38796720
 */
static pthread_mutex_t sockets_si_global = PTHREAD_MUTEX_INITIALIZER;

/* Mutex to synchronize access to packet capture dump file */
static pthread_mutex_t pcap_dump_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Mutex for synchronizing mtu value fetch*/
static pthread_mutex_t mtu_update_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Function prototypes */

#if ! defined(HAVE_CONSTRUCTOR_ATTRIBUTE) && defined(HAVE_PRAGMA_INIT)
/* xlC and other oldschool compilers support (only) this */
#pragma init (swrap_constructor)
#endif
void swrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
#if ! defined(HAVE_DESTRUCTOR_ATTRIBUTE) && defined(HAVE_PRAGMA_FINI)
#pragma fini (swrap_destructor)
#endif
void swrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

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
	const char *prefix = "SWRAP";
	const char *progname = getprogname();

	d = getenv("SOCKET_WRAPPER_DEBUGLEVEL");
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
		case SWRAP_LOG_ERROR:
			prefix = "SWRAP_ERROR";
			break;
		case SWRAP_LOG_WARN:
			prefix = "SWRAP_WARN";
			break;
		case SWRAP_LOG_DEBUG:
			prefix = "SWRAP_DEBUG";
			break;
		case SWRAP_LOG_TRACE:
			prefix = "SWRAP_TRACE";
			break;
	}

	if (progname == NULL) {
		progname = "<unknown>";
	}

	fprintf(stderr,
		"%s[%s (%u)] - %s: %s\n",
		prefix,
		progname,
		(unsigned int)getpid(),
		func,
		buffer);
}

/*********************************************************
 * SWRAP LOADING LIBC FUNCTIONS
 *********************************************************/

#include <dlfcn.h>

#ifdef HAVE_ACCEPT4
typedef int (*__libc_accept4)(int sockfd,
			      struct sockaddr *addr,
			      socklen_t *addrlen,
			      int flags);
#else
typedef int (*__libc_accept)(int sockfd,
			     struct sockaddr *addr,
			     socklen_t *addrlen);
#endif
typedef int (*__libc_bind)(int sockfd,
			   const struct sockaddr *addr,
			   socklen_t addrlen);
typedef int (*__libc_close)(int fd);
#ifdef HAVE___CLOSE_NOCANCEL
typedef int (*__libc___close_nocancel)(int fd);
#endif
typedef int (*__libc_connect)(int sockfd,
			      const struct sockaddr *addr,
			      socklen_t addrlen);
typedef int (*__libc_dup)(int fd);
typedef int (*__libc_dup2)(int oldfd, int newfd);
typedef int (*__libc_fcntl)(int fd, int cmd, ...);
typedef FILE *(*__libc_fopen)(const char *name, const char *mode);
#ifdef HAVE_FOPEN64
typedef FILE *(*__libc_fopen64)(const char *name, const char *mode);
#endif
#ifdef HAVE_EVENTFD
typedef int (*__libc_eventfd)(int count, int flags);
#endif
typedef int (*__libc_getpeername)(int sockfd,
				  struct sockaddr *addr,
				  socklen_t *addrlen);
typedef int (*__libc_getsockname)(int sockfd,
				  struct sockaddr *addr,
				  socklen_t *addrlen);
typedef int (*__libc_getsockopt)(int sockfd,
			       int level,
			       int optname,
			       void *optval,
			       socklen_t *optlen);
typedef int (*__libc_ioctl)(int d, unsigned long int request, ...);
typedef int (*__libc_listen)(int sockfd, int backlog);
typedef int (*__libc_open)(const char *pathname, int flags, ...);
#ifdef HAVE_OPEN64
typedef int (*__libc_open64)(const char *pathname, int flags, ...);
#endif /* HAVE_OPEN64 */
typedef int (*__libc_openat)(int dirfd, const char *path, int flags, ...);
typedef int (*__libc_pipe)(int pipefd[2]);
typedef int (*__libc_read)(int fd, void *buf, size_t count);
typedef ssize_t (*__libc_readv)(int fd, const struct iovec *iov, int iovcnt);
typedef int (*__libc_recv)(int sockfd, void *buf, size_t len, int flags);
typedef int (*__libc_recvfrom)(int sockfd,
			     void *buf,
			     size_t len,
			     int flags,
			     struct sockaddr *src_addr,
			     socklen_t *addrlen);
typedef int (*__libc_recvmsg)(int sockfd, const struct msghdr *msg, int flags);
typedef int (*__libc_send)(int sockfd, const void *buf, size_t len, int flags);
typedef int (*__libc_sendmsg)(int sockfd, const struct msghdr *msg, int flags);
typedef int (*__libc_sendto)(int sockfd,
			   const void *buf,
			   size_t len,
			   int flags,
			   const  struct sockaddr *dst_addr,
			   socklen_t addrlen);
typedef int (*__libc_setsockopt)(int sockfd,
			       int level,
			       int optname,
			       const void *optval,
			       socklen_t optlen);
#ifdef HAVE_SIGNALFD
typedef int (*__libc_signalfd)(int fd, const sigset_t *mask, int flags);
#endif
typedef int (*__libc_socket)(int domain, int type, int protocol);
typedef int (*__libc_socketpair)(int domain, int type, int protocol, int sv[2]);
#ifdef HAVE_TIMERFD_CREATE
typedef int (*__libc_timerfd_create)(int clockid, int flags);
#endif
typedef ssize_t (*__libc_write)(int fd, const void *buf, size_t count);
typedef ssize_t (*__libc_writev)(int fd, const struct iovec *iov, int iovcnt);

#define SWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libc_##i f; \
		void *obj; \
	} _libc_##i

struct swrap_libc_symbols {
#ifdef HAVE_ACCEPT4
	SWRAP_SYMBOL_ENTRY(accept4);
#else
	SWRAP_SYMBOL_ENTRY(accept);
#endif
	SWRAP_SYMBOL_ENTRY(bind);
	SWRAP_SYMBOL_ENTRY(close);
#ifdef HAVE___CLOSE_NOCANCEL
	SWRAP_SYMBOL_ENTRY(__close_nocancel);
#endif
	SWRAP_SYMBOL_ENTRY(connect);
	SWRAP_SYMBOL_ENTRY(dup);
	SWRAP_SYMBOL_ENTRY(dup2);
	SWRAP_SYMBOL_ENTRY(fcntl);
	SWRAP_SYMBOL_ENTRY(fopen);
#ifdef HAVE_FOPEN64
	SWRAP_SYMBOL_ENTRY(fopen64);
#endif
#ifdef HAVE_EVENTFD
	SWRAP_SYMBOL_ENTRY(eventfd);
#endif
	SWRAP_SYMBOL_ENTRY(getpeername);
	SWRAP_SYMBOL_ENTRY(getsockname);
	SWRAP_SYMBOL_ENTRY(getsockopt);
	SWRAP_SYMBOL_ENTRY(ioctl);
	SWRAP_SYMBOL_ENTRY(listen);
	SWRAP_SYMBOL_ENTRY(open);
#ifdef HAVE_OPEN64
	SWRAP_SYMBOL_ENTRY(open64);
#endif
	SWRAP_SYMBOL_ENTRY(openat);
	SWRAP_SYMBOL_ENTRY(pipe);
	SWRAP_SYMBOL_ENTRY(read);
	SWRAP_SYMBOL_ENTRY(readv);
	SWRAP_SYMBOL_ENTRY(recv);
	SWRAP_SYMBOL_ENTRY(recvfrom);
	SWRAP_SYMBOL_ENTRY(recvmsg);
	SWRAP_SYMBOL_ENTRY(send);
	SWRAP_SYMBOL_ENTRY(sendmsg);
	SWRAP_SYMBOL_ENTRY(sendto);
	SWRAP_SYMBOL_ENTRY(setsockopt);
#ifdef HAVE_SIGNALFD
	SWRAP_SYMBOL_ENTRY(signalfd);
#endif
	SWRAP_SYMBOL_ENTRY(socket);
	SWRAP_SYMBOL_ENTRY(socketpair);
#ifdef HAVE_TIMERFD_CREATE
	SWRAP_SYMBOL_ENTRY(timerfd_create);
#endif
	SWRAP_SYMBOL_ENTRY(write);
	SWRAP_SYMBOL_ENTRY(writev);
};

struct swrap {
	struct {
		void *handle;
		void *socket_handle;
		struct swrap_libc_symbols symbols;
	} libc;
};

static struct swrap swrap;

/* prototypes */
static char *socket_wrapper_dir(void);

#define LIBC_NAME "libc.so"

enum swrap_lib {
    SWRAP_LIBC,
    SWRAP_LIBSOCKET,
};

static const char *swrap_str_lib(enum swrap_lib lib)
{
	switch (lib) {
	case SWRAP_LIBC:
		return "libc";
	case SWRAP_LIBSOCKET:
		return "libsocket";
	}

	/* Compiler would warn us about unhandled enum value if we get here */
	return "unknown";
}

static void *swrap_load_lib_handle(enum swrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	const char *env_preload = getenv("LD_PRELOAD");
	const char *env_deepbind = getenv("SOCKET_WRAPPER_DISABLE_DEEPBIND");
	bool enable_deepbind = true;

	/* Don't do a deepbind if we run with libasan */
	if (env_preload != NULL && strlen(env_preload) < 1024) {
		const char *p = strstr(env_preload, "libasan.so");
		if (p != NULL) {
			enable_deepbind = false;
		}
	}

	if (env_deepbind != NULL && strlen(env_deepbind) >= 1) {
		enable_deepbind = false;
	}

	if (enable_deepbind) {
		flags |= RTLD_DEEPBIND;
	}
#endif

	switch (lib) {
	case SWRAP_LIBSOCKET:
#ifdef HAVE_LIBSOCKET
		handle = swrap.libc.socket_handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libsocket.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			swrap.libc.socket_handle = handle;
		}
		break;
#endif
	case SWRAP_LIBC:
		handle = swrap.libc.handle;
#ifdef LIBC_SO
		if (handle == NULL) {
			handle = dlopen(LIBC_SO, flags);

			swrap.libc.handle = handle;
		}
#endif
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			swrap.libc.handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = swrap.libc.handle = swrap.libc.socket_handle = RTLD_NEXT;
#else
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_swrap_bind_symbol(enum swrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = swrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Failed to find %s: %s",
			  fn_name,
			  dlerror());
		exit(-1);
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "Loaded %s from %s",
		  fn_name,
		  swrap_str_lib(lib));

	return func;
}

#define swrap_mutex_lock(m) _swrap_mutex_lock(m, #m, __func__, __LINE__)
static void _swrap_mutex_lock(pthread_mutex_t *mutex, const char *name, const char *caller, unsigned line)
{
	int ret;

	ret = pthread_mutex_lock(mutex);
	if (ret != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "PID(%d):PPID(%d): %s(%u): Couldn't lock pthread mutex(%s) - %s",
			  getpid(), getppid(), caller, line, name, strerror(ret));
		abort();
	}
}

#define swrap_mutex_unlock(m) _swrap_mutex_unlock(m, #m, __func__, __LINE__)
static void _swrap_mutex_unlock(pthread_mutex_t *mutex, const char *name, const char *caller, unsigned line)
{
	int ret;

	ret = pthread_mutex_unlock(mutex);
	if (ret != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "PID(%d):PPID(%d): %s(%u): Couldn't unlock pthread mutex(%s) - %s",
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
#define _swrap_bind_symbol_generic(lib, sym_name) do { \
	swrap.libc.symbols._libc_##sym_name.obj = \
		_swrap_bind_symbol(lib, #sym_name); \
} while(0);

#define swrap_bind_symbol_libc(sym_name) \
	_swrap_bind_symbol_generic(SWRAP_LIBC, sym_name)

#define swrap_bind_symbol_libsocket(sym_name) \
	_swrap_bind_symbol_generic(SWRAP_LIBSOCKET, sym_name)

static void swrap_bind_symbol_all(void);

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
static int libc_accept4(int sockfd,
			struct sockaddr *addr,
			socklen_t *addrlen,
			int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_accept4.f(sockfd, addr, addrlen, flags);
}

#else /* HAVE_ACCEPT4 */

static int libc_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_accept.f(sockfd, addr, addrlen);
}
#endif /* HAVE_ACCEPT4 */

static int libc_bind(int sockfd,
		     const struct sockaddr *addr,
		     socklen_t addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_bind.f(sockfd, addr, addrlen);
}

static int libc_close(int fd)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_close.f(fd);
}

#ifdef HAVE___CLOSE_NOCANCEL
static int libc___close_nocancel(int fd)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc___close_nocancel.f(fd);
}
#endif /* HAVE___CLOSE_NOCANCEL */

static int libc_connect(int sockfd,
			const struct sockaddr *addr,
			socklen_t addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_connect.f(sockfd, addr, addrlen);
}

static int libc_dup(int fd)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_dup.f(fd);
}

static int libc_dup2(int oldfd, int newfd)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_dup2.f(oldfd, newfd);
}

#ifdef HAVE_EVENTFD
static int libc_eventfd(int count, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_eventfd.f(count, flags);
}
#endif

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static int libc_vfcntl(int fd, int cmd, va_list ap)
{
	void *arg;
	int rc;

	swrap_bind_symbol_all();

	arg = va_arg(ap, void *);

	rc = swrap.libc.symbols._libc_fcntl.f(fd, cmd, arg);

	return rc;
}

static int libc_getpeername(int sockfd,
			    struct sockaddr *addr,
			    socklen_t *addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_getpeername.f(sockfd, addr, addrlen);
}

static int libc_getsockname(int sockfd,
			    struct sockaddr *addr,
			    socklen_t *addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_getsockname.f(sockfd, addr, addrlen);
}

static int libc_getsockopt(int sockfd,
			   int level,
			   int optname,
			   void *optval,
			   socklen_t *optlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_getsockopt.f(sockfd,
						     level,
						     optname,
						     optval,
						     optlen);
}

DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static int libc_vioctl(int d, unsigned long int request, va_list ap)
{
	void *arg;
	int rc;

	swrap_bind_symbol_all();

	arg = va_arg(ap, void *);

	rc = swrap.libc.symbols._libc_ioctl.f(d, request, arg);

	return rc;
}

static int libc_listen(int sockfd, int backlog)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_listen.f(sockfd, backlog);
}

static FILE *libc_fopen(const char *name, const char *mode)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_fopen.f(name, mode);
}

#ifdef HAVE_FOPEN64
static FILE *libc_fopen64(const char *name, const char *mode)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_fopen64.f(name, mode);
}
#endif /* HAVE_FOPEN64 */

static int libc_vopen(const char *pathname, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	swrap_bind_symbol_all();

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = swrap.libc.symbols._libc_open.f(pathname, flags, (mode_t)mode);

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

#ifdef HAVE_OPEN64
static int libc_vopen64(const char *pathname, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	swrap_bind_symbol_all();

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = swrap.libc.symbols._libc_open64.f(pathname, flags, (mode_t)mode);

	return fd;
}
#endif /* HAVE_OPEN64 */

static int libc_vopenat(int dirfd, const char *path, int flags, va_list ap)
{
	int mode = 0;
	int fd;

	swrap_bind_symbol_all();

	if (flags & O_CREAT) {
		mode = va_arg(ap, int);
	}
	fd = swrap.libc.symbols._libc_openat.f(dirfd,
					       path,
					       flags,
					       (mode_t)mode);

	return fd;
}

#if 0
static int libc_openat(int dirfd, const char *path, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = libc_vopenat(dirfd, path, flags, ap);
	va_end(ap);

	return fd;
}
#endif

static int libc_pipe(int pipefd[2])
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_pipe.f(pipefd);
}

static int libc_read(int fd, void *buf, size_t count)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_read.f(fd, buf, count);
}

static ssize_t libc_readv(int fd, const struct iovec *iov, int iovcnt)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_readv.f(fd, iov, iovcnt);
}

static int libc_recv(int sockfd, void *buf, size_t len, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_recv.f(sockfd, buf, len, flags);
}

static int libc_recvfrom(int sockfd,
			 void *buf,
			 size_t len,
			 int flags,
			 struct sockaddr *src_addr,
			 socklen_t *addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_recvfrom.f(sockfd,
						   buf,
						   len,
						   flags,
						   src_addr,
						   addrlen);
}

static int libc_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_recvmsg.f(sockfd, msg, flags);
}

static int libc_send(int sockfd, const void *buf, size_t len, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_send.f(sockfd, buf, len, flags);
}

static int libc_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_sendmsg.f(sockfd, msg, flags);
}

static int libc_sendto(int sockfd,
		       const void *buf,
		       size_t len,
		       int flags,
		       const  struct sockaddr *dst_addr,
		       socklen_t addrlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_sendto.f(sockfd,
						 buf,
						 len,
						 flags,
						 dst_addr,
						 addrlen);
}

static int libc_setsockopt(int sockfd,
			   int level,
			   int optname,
			   const void *optval,
			   socklen_t optlen)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_setsockopt.f(sockfd,
						     level,
						     optname,
						     optval,
						     optlen);
}

#ifdef HAVE_SIGNALFD
static int libc_signalfd(int fd, const sigset_t *mask, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_signalfd.f(fd, mask, flags);
}
#endif

static int libc_socket(int domain, int type, int protocol)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_socket.f(domain, type, protocol);
}

static int libc_socketpair(int domain, int type, int protocol, int sv[2])
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_socketpair.f(domain, type, protocol, sv);
}

#ifdef HAVE_TIMERFD_CREATE
static int libc_timerfd_create(int clockid, int flags)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_timerfd_create.f(clockid, flags);
}
#endif

static ssize_t libc_write(int fd, const void *buf, size_t count)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_write.f(fd, buf, count);
}

static ssize_t libc_writev(int fd, const struct iovec *iov, int iovcnt)
{
	swrap_bind_symbol_all();

	return swrap.libc.symbols._libc_writev.f(fd, iov, iovcnt);
}

/* DO NOT call this function during library initialization! */
static void __swrap_bind_symbol_all_once(void)
{
#ifdef HAVE_ACCEPT4
	swrap_bind_symbol_libsocket(accept4);
#else
	swrap_bind_symbol_libsocket(accept);
#endif
	swrap_bind_symbol_libsocket(bind);
	swrap_bind_symbol_libc(close);
#ifdef HAVE___CLOSE_NOCANCEL
	swrap_bind_symbol_libc(__close_nocancel);
#endif
	swrap_bind_symbol_libsocket(connect);
	swrap_bind_symbol_libc(dup);
	swrap_bind_symbol_libc(dup2);
	swrap_bind_symbol_libc(fcntl);
	swrap_bind_symbol_libc(fopen);
#ifdef HAVE_FOPEN64
	swrap_bind_symbol_libc(fopen64);
#endif
#ifdef HAVE_EVENTFD
	swrap_bind_symbol_libc(eventfd);
#endif
	swrap_bind_symbol_libsocket(getpeername);
	swrap_bind_symbol_libsocket(getsockname);
	swrap_bind_symbol_libsocket(getsockopt);
	swrap_bind_symbol_libc(ioctl);
	swrap_bind_symbol_libsocket(listen);
	swrap_bind_symbol_libc(open);
#ifdef HAVE_OPEN64
	swrap_bind_symbol_libc(open64);
#endif
	swrap_bind_symbol_libc(openat);
	swrap_bind_symbol_libsocket(pipe);
	swrap_bind_symbol_libc(read);
	swrap_bind_symbol_libsocket(readv);
	swrap_bind_symbol_libsocket(recv);
	swrap_bind_symbol_libsocket(recvfrom);
	swrap_bind_symbol_libsocket(recvmsg);
	swrap_bind_symbol_libsocket(send);
	swrap_bind_symbol_libsocket(sendmsg);
	swrap_bind_symbol_libsocket(sendto);
	swrap_bind_symbol_libsocket(setsockopt);
#ifdef HAVE_SIGNALFD
	swrap_bind_symbol_libsocket(signalfd);
#endif
	swrap_bind_symbol_libsocket(socket);
	swrap_bind_symbol_libsocket(socketpair);
#ifdef HAVE_TIMERFD_CREATE
	swrap_bind_symbol_libc(timerfd_create);
#endif
	swrap_bind_symbol_libc(write);
	swrap_bind_symbol_libsocket(writev);
}

static void swrap_bind_symbol_all(void)
{
	static pthread_once_t all_symbol_binding_once = PTHREAD_ONCE_INIT;

	pthread_once(&all_symbol_binding_once, __swrap_bind_symbol_all_once);
}

/*********************************************************
 * SWRAP HELPER FUNCTIONS
 *********************************************************/

/*
 * We return 127.0.0.0 (default) or 10.53.57.0.
 *
 * This can be controlled by:
 * SOCKET_WRAPPER_IPV4_NETWORK=127.0.0.0 (default)
 * or
 * SOCKET_WRAPPER_IPV4_NETWORK=10.53.57.0
 */
static in_addr_t swrap_ipv4_net(void)
{
	static int initialized;
	static in_addr_t hv;
	const char *net_str = NULL;
	struct in_addr nv;
	int ret;

	if (initialized) {
		return hv;
	}
	initialized = 1;

	net_str = getenv("SOCKET_WRAPPER_IPV4_NETWORK");
	if (net_str == NULL) {
		net_str = "127.0.0.0";
	}

	ret = inet_pton(AF_INET, net_str, &nv);
	if (ret <= 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "INVALID IPv4 Network [%s]",
			  net_str);
		abort();
	}

	hv = ntohl(nv.s_addr);

	switch (hv) {
	case 0x7f000000:
		/* 127.0.0.0 */
		break;
	case 0x0a353900:
		/* 10.53.57.0 */
		break;
	default:
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "INVALID IPv4 Network [%s][0x%x] should be "
			  "127.0.0.0 or 10.53.57.0",
			  net_str, (unsigned)hv);
		abort();
	}

	return hv;
}

/*
 * This returns 127.255.255.255 or 10.255.255.255
 */
static in_addr_t swrap_ipv4_bcast(void)
{
	in_addr_t hv;

	hv = swrap_ipv4_net();
	hv |= IN_CLASSA_HOST;

	return hv;
}

/*
 * This returns 127.0.0.${iface} or 10.53.57.${iface}
 */
static in_addr_t swrap_ipv4_iface(unsigned int iface)
{
	in_addr_t hv;

	if (iface == 0 || iface > MAX_WRAPPED_INTERFACES) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "swrap_ipv4_iface(%u) invalid!",
			  iface);
		abort();
		return -1;
	}

	hv = swrap_ipv4_net();
	hv |= iface;

	return hv;
}

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

static struct socket_info *swrap_get_socket_info(int si_index)
{
	return (struct socket_info *)(&(sockets[si_index].info));
}

static int swrap_get_refcount(struct socket_info *si)
{
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si);
	return sic->meta.refcount;
}

static void swrap_inc_refcount(struct socket_info *si)
{
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si);

	sic->meta.refcount += 1;
}

static void swrap_dec_refcount(struct socket_info *si)
{
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si);

	sic->meta.refcount -= 1;
}

static int swrap_get_next_free(struct socket_info *si)
{
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si);

	return sic->meta.next_free;
}

static void swrap_set_next_free(struct socket_info *si, int next_free)
{
	struct socket_info_container *sic = SOCKET_INFO_CONTAINER(si);

	sic->meta.next_free = next_free;
}

static int swrap_un_path(struct sockaddr_un *un,
			 const char *swrap_dir,
			 char type,
			 unsigned int iface,
			 unsigned int prt)
{
	int ret;

	ret = snprintf(un->sun_path,
		       sizeof(un->sun_path),
		       "%s/"SOCKET_FORMAT,
		       swrap_dir,
		       type,
		       iface,
		       prt);
	if ((size_t)ret >= sizeof(un->sun_path)) {
		return ENAMETOOLONG;
	}

	return 0;
}

static int swrap_un_path_EINVAL(struct sockaddr_un *un,
				const char *swrap_dir)
{
	int ret;

	ret = snprintf(un->sun_path,
		       sizeof(un->sun_path),
		       "%s/EINVAL",
		       swrap_dir);

	if ((size_t)ret >= sizeof(un->sun_path)) {
		return ENAMETOOLONG;
	}

	return 0;
}

static bool swrap_dir_usable(const char *swrap_dir)
{
	struct sockaddr_un un;
	int ret;

	ret = swrap_un_path(&un, swrap_dir, SOCKET_TYPE_CHAR_TCP, 0, 0);
	if (ret == 0) {
		return true;
	}

	ret = swrap_un_path_EINVAL(&un, swrap_dir);
	if (ret == 0) {
		return true;
	}

	return false;
}

static char *socket_wrapper_dir(void)
{
	char *swrap_dir = NULL;
	char *s = getenv("SOCKET_WRAPPER_DIR");
	char *t;
	bool ok;

	if (s == NULL || s[0] == '\0') {
		SWRAP_LOG(SWRAP_LOG_WARN, "SOCKET_WRAPPER_DIR not set");
		return NULL;
	}

	swrap_dir = realpath(s, NULL);
	if (swrap_dir == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Unable to resolve socket_wrapper dir path: %s - %s",
			  s,
			  strerror(errno));
		abort();
	}

	ok = swrap_dir_usable(swrap_dir);
	if (ok) {
		goto done;
	}

	free(swrap_dir);

	ok = swrap_dir_usable(s);
	if (!ok) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "SOCKET_WRAPPER_DIR is too long");
		abort();
	}

	t = getenv("SOCKET_WRAPPER_DIR_ALLOW_ORIG");
	if (t == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "realpath(SOCKET_WRAPPER_DIR) too long and "
			  "SOCKET_WRAPPER_DIR_ALLOW_ORIG not set");
		abort();

	}

	swrap_dir = strdup(s);
	if (swrap_dir == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Unable to duplicate socket_wrapper dir path");
		abort();
	}

	SWRAP_LOG(SWRAP_LOG_WARN,
		  "realpath(SOCKET_WRAPPER_DIR) too long, "
		  "using original SOCKET_WRAPPER_DIR\n");

done:
	SWRAP_LOG(SWRAP_LOG_TRACE, "socket_wrapper_dir: %s", swrap_dir);
	return swrap_dir;
}

static unsigned int socket_wrapper_mtu(void)
{
	static unsigned int max_mtu = 0;
	unsigned int tmp;
	const char *s;
	char *endp;

	swrap_mutex_lock(&mtu_update_mutex);

	if (max_mtu != 0) {
		goto done;
	}

	max_mtu = SOCKET_WRAPPER_MTU_DEFAULT;

	s = getenv("SOCKET_WRAPPER_MTU");
	if (s == NULL) {
		goto done;
	}

	tmp = strtol(s, &endp, 10);
	if (s == endp) {
		goto done;
	}

	if (tmp < SOCKET_WRAPPER_MTU_MIN || tmp > SOCKET_WRAPPER_MTU_MAX) {
		goto done;
	}
	max_mtu = tmp;

done:
	swrap_mutex_unlock(&mtu_update_mutex);
	return max_mtu;
}

static int _socket_wrapper_init_mutex(pthread_mutex_t *m, const char *name)
{
	pthread_mutexattr_t ma;
	bool need_destroy = false;
	int ret = 0;

#define __CHECK(cmd) do { \
	ret = cmd; \
	if (ret != 0) { \
		SWRAP_LOG(SWRAP_LOG_ERROR, \
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

static size_t socket_wrapper_max_sockets(void)
{
	const char *s;
	size_t tmp;
	char *endp;

	if (socket_info_max != 0) {
		return socket_info_max;
	}

	socket_info_max = SOCKET_WRAPPER_MAX_SOCKETS_DEFAULT;

	s = getenv("SOCKET_WRAPPER_MAX_SOCKETS");
	if (s == NULL || s[0] == '\0') {
		goto done;
	}

	tmp = strtoul(s, &endp, 10);
	if (s == endp) {
		goto done;
	}
	if (tmp == 0) {
		tmp = SOCKET_WRAPPER_MAX_SOCKETS_DEFAULT;
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Invalid number of sockets specified, "
			  "using default (%zu)",
			  tmp);
	}

	if (tmp > SOCKET_WRAPPER_MAX_SOCKETS_LIMIT) {
		tmp = SOCKET_WRAPPER_MAX_SOCKETS_LIMIT;
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Invalid number of sockets specified, "
			  "using maximum (%zu).",
			  tmp);
	}

	socket_info_max = tmp;

done:
	return socket_info_max;
}

static void socket_wrapper_init_fds_idx(void)
{
	int *tmp = NULL;
	size_t i;

	if (socket_fds_idx != NULL) {
		return;
	}

	tmp = (int *)calloc(socket_fds_max, sizeof(int));
	if (tmp == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Failed to allocate socket fds index array: %s",
			  strerror(errno));
		exit(-1);
	}

	for (i = 0; i < socket_fds_max; i++) {
		tmp[i] = -1;
	}

	socket_fds_idx = tmp;
}

static void socket_wrapper_init_sockets(void)
{
	size_t max_sockets;
	size_t i;
	int ret = 0;

	swrap_bind_symbol_all();

	swrap_mutex_lock(&sockets_mutex);

	if (sockets != NULL) {
		swrap_mutex_unlock(&sockets_mutex);
		return;
	}

	SWRAP_LOG(SWRAP_LOG_DEBUG,
		  "SOCKET_WRAPPER_PACKAGE[%s] SOCKET_WRAPPER_VERSION[%s]",
		  SOCKET_WRAPPER_PACKAGE, SOCKET_WRAPPER_VERSION);

	/*
	 * Intialize the static cache early before
	 * any thread is able to start.
	 */
	(void)swrap_ipv4_net();

	socket_wrapper_init_fds_idx();

	/* Needs to be called inside the sockets_mutex lock here. */
	max_sockets = socket_wrapper_max_sockets();

	sockets = (struct socket_info_container *)calloc(max_sockets,
					sizeof(struct socket_info_container));

	if (sockets == NULL) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Failed to allocate sockets array: %s",
			  strerror(errno));
		swrap_mutex_unlock(&sockets_mutex);
		exit(-1);
	}

	swrap_mutex_lock(&first_free_mutex);
	swrap_mutex_lock(&sockets_si_global);

	first_free = 0;

	for (i = 0; i < max_sockets; i++) {
		swrap_set_next_free(&sockets[i].info, i+1);
	}

	/* mark the end of the free list */
	swrap_set_next_free(&sockets[max_sockets-1].info, -1);

	swrap_mutex_unlock(&sockets_si_global);
	swrap_mutex_unlock(&first_free_mutex);
	swrap_mutex_unlock(&sockets_mutex);
	if (ret != 0) {
		exit(-1);
	}
}

bool socket_wrapper_enabled(void)
{
	char *s = socket_wrapper_dir();

	if (s == NULL) {
		return false;
	}

	SAFE_FREE(s);

	socket_wrapper_init_sockets();

	return true;
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

static void set_socket_info_index(int fd, int idx)
{
	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "fd=%d idx=%d",
		  fd, idx);
	socket_fds_idx[fd] = idx;
	/* This builtin issues a full memory barrier. */
	__sync_synchronize();
}

static void reset_socket_info_index(int fd)
{
	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "fd=%d idx=%d",
		  fd, -1);
	set_socket_info_index(fd, -1);
}

static int find_socket_info_index(int fd)
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
		SWRAP_LOG(SWRAP_LOG_ERROR,
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

static int swrap_add_socket_info(const struct socket_info *si_input)
{
	struct socket_info *si = NULL;
	int si_index = -1;

	if (si_input == NULL) {
		errno = EINVAL;
		return -1;
	}

	swrap_mutex_lock(&first_free_mutex);
	if (first_free == -1) {
		errno = ENFILE;
		goto out;
	}

	si_index = first_free;
	si = swrap_get_socket_info(si_index);

	SWRAP_LOCK_SI(si);

	first_free = swrap_get_next_free(si);
	*si = *si_input;
	swrap_inc_refcount(si);

	SWRAP_UNLOCK_SI(si);

out:
	swrap_mutex_unlock(&first_free_mutex);

	return si_index;
}

static int swrap_create_socket(struct socket_info *si, int fd)
{
	int idx;

	if ((size_t)fd >= socket_fds_max) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  fd);
		errno = EMFILE;
		return -1;
	}

	idx = swrap_add_socket_info(si);
	if (idx == -1) {
		return -1;
	}

	set_socket_info_index(fd, idx);

	return idx;
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
		SWRAP_LOG(SWRAP_LOG_ERROR, "sun_path[%s] p[%s]",
			  un->sun_path, p);
		errno = EINVAL;
		return -1;
	}

	if (iface == 0 || iface > MAX_WRAPPED_INTERFACES) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "type %c iface %u port %u",
			  type, iface, prt);
		errno = EINVAL;
		return -1;
	}

	if (prt > 0xFFFF) {
		SWRAP_LOG(SWRAP_LOG_ERROR, "type %c iface %u port %u",
			  type, iface, prt);
		errno = EINVAL;
		return -1;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE, "type %c iface %u port %u",
		  type, iface, prt);

	switch(type) {
	case SOCKET_TYPE_CHAR_TCP:
	case SOCKET_TYPE_CHAR_UDP: {
		struct sockaddr_in *in2 = (struct sockaddr_in *)(void *)in;

		if ((*len) < sizeof(*in2)) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "V4: *len(%zu) < sizeof(*in2)=%zu",
				  (size_t)*len, sizeof(*in2));
			errno = EINVAL;
			return -1;
		}

		memset(in2, 0, sizeof(*in2));
		in2->sin_family = AF_INET;
		in2->sin_addr.s_addr = htonl(swrap_ipv4_iface(iface));
		in2->sin_port = htons(prt);

		*len = sizeof(*in2);
		break;
	}
#ifdef HAVE_IPV6
	case SOCKET_TYPE_CHAR_TCP_V6:
	case SOCKET_TYPE_CHAR_UDP_V6: {
		struct sockaddr_in6 *in2 = (struct sockaddr_in6 *)(void *)in;

		if ((*len) < sizeof(*in2)) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "V6: *len(%zu) < sizeof(*in2)=%zu",
				  (size_t)*len, sizeof(*in2));
			SWRAP_LOG(SWRAP_LOG_ERROR, "LINE:%d", __LINE__);
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
		SWRAP_LOG(SWRAP_LOG_ERROR, "type %c iface %u port %u",
			  type, iface, prt);
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
	char *swrap_dir = NULL;

	if (bcast) *bcast = 0;

	switch (inaddr->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *in =
		    (const struct sockaddr_in *)(const void *)inaddr;
		unsigned int addr = ntohl(in->sin_addr.s_addr);
		char u_type = '\0';
		char b_type = '\0';
		char a_type = '\0';
		const unsigned int sw_net_addr = swrap_ipv4_net();
		const unsigned int sw_bcast_addr = swrap_ipv4_bcast();

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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
			errno = ESOCKTNOSUPPORT;
			return -1;
		}

		prt = ntohs(in->sin_port);
		if (a_type && addr == 0xFFFFFFFF) {
			/* 255.255.255.255 only udp */
			is_bcast = 2;
			type = a_type;
			iface = socket_wrapper_default_iface();
		} else if (b_type && addr == sw_bcast_addr) {
			/*
			 * 127.255.255.255
			 * or
			 * 10.255.255.255
			 * only udp
			 */
			is_bcast = 1;
			type = b_type;
			iface = socket_wrapper_default_iface();
		} else if ((addr & 0xFFFFFF00) == sw_net_addr) {
			/* 127.0.0.X or 10.53.57.X */
			is_bcast = 0;
			type = u_type;
			iface = (addr & 0x000000FF);
		} else {
			char str[256] = {0,};
			inet_ntop(inaddr->sa_family,
				  &in->sin_addr,
				  str, sizeof(str));
			SWRAP_LOG(SWRAP_LOG_WARN,
				  "str[%s] prt[%u]",
				  str, (unsigned)prt);
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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
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
			char str[256] = {0,};
			inet_ntop(inaddr->sa_family,
				  &in->sin6_addr,
				  str, sizeof(str));
			SWRAP_LOG(SWRAP_LOG_WARN,
				  "str[%s] prt[%u]",
				  str, (unsigned)prt);
			errno = ENETUNREACH;
			return -1;
		}

		break;
	}
#endif
	default:
		SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family!");
		errno = ENETUNREACH;
		return -1;
	}

	if (prt == 0) {
		SWRAP_LOG(SWRAP_LOG_WARN, "Port not set");
		errno = EINVAL;
		return -1;
	}

	swrap_dir = socket_wrapper_dir();
	if (swrap_dir == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (is_bcast) {
		swrap_un_path_EINVAL(un, swrap_dir);
		SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);
		SAFE_FREE(swrap_dir);
		/* the caller need to do more processing */
		return 0;
	}

	swrap_un_path(un, swrap_dir, type, iface, prt);
	SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);

	SAFE_FREE(swrap_dir);

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
	char *swrap_dir = NULL;

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
		const unsigned int sw_net_addr = swrap_ipv4_net();
		const unsigned int sw_bcast_addr = swrap_ipv4_bcast();

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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
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
		} else if (b_type && addr == sw_bcast_addr) {
			/* 127.255.255.255 only udp */
			is_bcast = 1;
			type = b_type;
			iface = socket_wrapper_default_iface();
		} else if ((addr & 0xFFFFFF00) == sw_net_addr) {
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
			bind_in.sin_addr.s_addr = htonl(swrap_ipv4_iface(iface));
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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
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
		SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family");
		errno = EADDRNOTAVAIL;
		return -1;
	}


	if (bcast) *bcast = is_bcast;

	if (iface == 0 || iface > MAX_WRAPPED_INTERFACES) {
		errno = EINVAL;
		return -1;
	}

	swrap_dir = socket_wrapper_dir();
	if (swrap_dir == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (prt == 0) {
		/* handle auto-allocation of ephemeral ports */
		for (prt = 5001; prt < 10000; prt++) {
			swrap_un_path(un, swrap_dir, type, iface, prt);
			if (stat(un->sun_path, &st) == 0) continue;

			set_port(si->family, prt, &si->myname);
			set_port(si->family, prt, &si->bindname);

			break;
		}

		if (prt == 10000) {
			errno = ENFILE;
			SAFE_FREE(swrap_dir);
			return -1;
		}
	}

	swrap_un_path(un, swrap_dir, type, iface, prt);
	SWRAP_LOG(SWRAP_LOG_DEBUG, "un path [%s]", un->sun_path);

	SAFE_FREE(swrap_dir);

	return 0;
}

static struct socket_info *find_socket_info(int fd)
{
	int idx = find_socket_info_index(fd);

	if (idx == -1) {
		return NULL;
	}

	return swrap_get_socket_info(idx);
}

#if 0 /* FIXME */
static bool check_addr_port_in_use(const struct sockaddr *sa, socklen_t len)
{
	struct socket_info_fd *f;
	const struct socket_info *last_s = NULL;

	/* first catch invalid input */
	switch (sa->sa_family) {
	case AF_INET:
		if (len < sizeof(struct sockaddr_in)) {
			return false;
		}
		break;
#ifdef HAVE_IPV6
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

	for (f = socket_fds; f; f = f->next) {
		struct socket_info *s = swrap_get_socket_info(f->si_index);

		if (s == last_s) {
			continue;
		}
		last_s = s;

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
#ifdef HAVE_IPV6
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

static void swrap_remove_stale(int fd);

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

		FALL_THROUGH;
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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
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
	SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family");
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
			SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown socket type!");
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

	SWRAP_LOG(SWRAP_LOG_ERROR, "Unknown address family");
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
	SWRAP_LOG(SWRAP_LOG_TRACE, "SOCKET_WRAPPER_PCAP_FILE: %s", s);
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
	uint8_t *base = NULL;
	uint8_t *buf = NULL;
	union {
		uint8_t *ptr;
		struct swrap_packet_frame *frame;
	} f;
	union {
		uint8_t *ptr;
		union swrap_packet_ip *ip;
	} i;
	union swrap_packet_payload *pay;
	size_t packet_len;
	size_t alloc_len;
	size_t nonwire_len = sizeof(struct swrap_packet_frame);
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
		ip_hdr_len = sizeof(i.ip->v4);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		src_in6 = (const struct sockaddr_in6 *)(const void *)src;
		dest_in6 = (const struct sockaddr_in6 *)(const void *)dest;
		src_port = src_in6->sin6_port;
		dest_port = dest_in6->sin6_port;
		ip_hdr_len = sizeof(i.ip->v6);
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
		wire_len += icmp_hdr_len;
	}

	packet_len = nonwire_len + wire_len;
	alloc_len = packet_len;
	if (alloc_len < SWRAP_PACKET_MIN_ALLOC) {
		alloc_len = SWRAP_PACKET_MIN_ALLOC;
	}

	base = (uint8_t *)calloc(1, alloc_len);
	if (base == NULL) {
		return NULL;
	}

	buf = base;
	f.ptr = buf;

	f.frame->seconds		= tval->tv_sec;
	f.frame->micro_seconds	= tval->tv_usec;
	f.frame->recorded_length	= wire_len - icmp_truncate_len;
	f.frame->full_length	= wire_len - icmp_truncate_len;

	buf += SWRAP_PACKET_FRAME_SIZE;

	i.ptr = buf;
	switch (src->sa_family) {
	case AF_INET:
		if (src_in == NULL || dest_in == NULL) {
			SAFE_FREE(base);
			return NULL;
		}

		i.ip->v4.ver_hdrlen	= 0x45; /* version 4 and 5 * 32 bit words */
		i.ip->v4.tos		= 0x00;
		i.ip->v4.packet_length	= htons(wire_len - icmp_truncate_len);
		i.ip->v4.identification	= htons(0xFFFF);
		i.ip->v4.flags		= 0x40; /* BIT 1 set - means don't fragment */
		i.ip->v4.fragment	= htons(0x0000);
		i.ip->v4.ttl		= 0xFF;
		i.ip->v4.protocol	= protocol;
		i.ip->v4.hdr_checksum	= htons(0x0000);
		i.ip->v4.src_addr	= src_in->sin_addr.s_addr;
		i.ip->v4.dest_addr	= dest_in->sin_addr.s_addr;
		buf += SWRAP_PACKET_IP_V4_SIZE;
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (src_in6 == NULL || dest_in6 == NULL) {
			SAFE_FREE(base);
			return NULL;
		}

		i.ip->v6.ver_prio		= 0x60; /* version 4 and 5 * 32 bit words */
		i.ip->v6.flow_label_high	= 0x00;
		i.ip->v6.flow_label_low	= 0x0000;
		i.ip->v6.payload_length	= htons(wire_len - icmp_truncate_len); /* TODO */
		i.ip->v6.next_header	= protocol;
		memcpy(i.ip->v6.src_addr, src_in6->sin6_addr.s6_addr, 16);
		memcpy(i.ip->v6.dest_addr, dest_in6->sin6_addr.s6_addr, 16);
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
			i.ptr = buf;
			i.ip->v4.ver_hdrlen	= 0x45; /* version 4 and 5 * 32 bit words */
			i.ip->v4.tos		= 0x00;
			i.ip->v4.packet_length	= htons(wire_len - icmp_hdr_len);
			i.ip->v4.identification	= htons(0xFFFF);
			i.ip->v4.flags		= 0x40; /* BIT 1 set - means don't fragment */
			i.ip->v4.fragment	= htons(0x0000);
			i.ip->v4.ttl		= 0xFF;
			i.ip->v4.protocol	= icmp_protocol;
			i.ip->v4.hdr_checksum	= htons(0x0000);
			i.ip->v4.src_addr	= dest_in->sin_addr.s_addr;
			i.ip->v4.dest_addr	= src_in->sin_addr.s_addr;

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
			i.ptr = buf;
			i.ip->v6.ver_prio		= 0x60; /* version 4 and 5 * 32 bit words */
			i.ip->v6.flow_label_high	= 0x00;
			i.ip->v6.flow_label_low	= 0x0000;
			i.ip->v6.payload_length	= htons(wire_len - icmp_truncate_len); /* TODO */
			i.ip->v6.next_header	= protocol;
			memcpy(i.ip->v6.src_addr, dest_in6->sin6_addr.s6_addr, 16);
			memcpy(i.ip->v6.dest_addr, src_in6->sin6_addr.s6_addr, 16);

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

	if (fd != -1) {
		return fd;
	}

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

		if (libc_write(fd, &file_hdr, sizeof(file_hdr)) != sizeof(file_hdr)) {
			libc_close(fd);
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
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		src_addr  = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x02; /* SYN */

		si->io.pck_snd += 1;

		break;

	case SWRAP_CONNECT_RECV:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x12; /** SYN,ACK */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_CONNECT_UNREACH:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		dest_addr = &si->myname.sa.s;
		src_addr  = addr;

		/* Unreachable: resend the data of SWRAP_CONNECT_SEND */
		tcp_seqno = si->io.pck_snd - 1;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x02; /* SYN */
		unreachable = 1;

		break;

	case SWRAP_CONNECT_ACK:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		src_addr  = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x10; /* ACK */

		break;

	case SWRAP_ACCEPT_SEND:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		dest_addr = &si->myname.sa.s;
		src_addr = addr;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x02; /* SYN */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_ACCEPT_RECV:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		src_addr = &si->myname.sa.s;
		dest_addr = addr;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x12; /* SYN,ACK */

		si->io.pck_snd += 1;

		break;

	case SWRAP_ACCEPT_ACK:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

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
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		src_addr  = &si->myname.sa.s;
		dest_addr = &si->peername.sa.s;

		tcp_seqno = si->io.pck_snd;
		tcp_ack = si->io.pck_rcv;
		tcp_ctl = 0x11; /* FIN, ACK */

		si->io.pck_snd += 1;

		break;

	case SWRAP_CLOSE_RECV:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

		dest_addr = &si->myname.sa.s;
		src_addr  = &si->peername.sa.s;

		tcp_seqno = si->io.pck_rcv;
		tcp_ack = si->io.pck_snd;
		tcp_ctl = 0x11; /* FIN,ACK */

		si->io.pck_rcv += 1;

		break;

	case SWRAP_CLOSE_ACK:
		if (si->type != SOCK_STREAM) {
			return NULL;
		}

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

	swrap_mutex_lock(&pcap_dump_mutex);

	file_name = swrap_pcap_init_file();
	if (!file_name) {
		goto done;
	}

	packet = swrap_pcap_marshall_packet(si,
					    addr,
					    type,
					    buf,
					    len,
					    &packet_len);
	if (packet == NULL) {
		goto done;
	}

	fd = swrap_pcap_get_fd(file_name);
	if (fd != -1) {
		if (libc_write(fd, packet, packet_len) != (ssize_t)packet_len) {
			free(packet);
			goto done;
		}
	}

	free(packet);

done:
	swrap_mutex_unlock(&pcap_dump_mutex);
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
	struct socket_info *si = NULL;
	struct socket_info _si = { 0 };
	int fd;
	int ret;
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
#ifdef AF_NETLINK
	case AF_NETLINK:
#endif /* AF_NETLINK */
#ifdef AF_PACKET
	case AF_PACKET:
#endif /* AF_PACKET */
	case AF_UNIX:
		fd = libc_socket(family, type, protocol);
		if (fd != -1) {
			/* Check if we have a stale fd and remove it */
			swrap_remove_stale(fd);
			SWRAP_LOG(SWRAP_LOG_TRACE,
				  "Unix socket fd=%d",
				  fd);
		}
		return fd;
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
		FALL_THROUGH;
	case 17:
		if (real_type == SOCK_DGRAM) {
			break;
		}
		FALL_THROUGH;
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
	swrap_remove_stale(fd);

	si = &_si;
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
#ifdef HAVE_IPV6
	case AF_INET6: {
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
		};

		si->myname.sa_socklen = sizeof(struct sockaddr_in6);
		memcpy(&si->myname.sa.in6, &sin6, si->myname.sa_socklen);
		break;
	}
#endif
	default:
		errno = EINVAL;
		return -1;
	}

	ret = swrap_create_socket(si, fd);
	if (ret == -1) {
		int saved_errno = errno;
		libc_close(fd);
		errno = saved_errno;
		return -1;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "Created %s socket for protocol %s, fd=%d",
		  family == AF_INET ? "IPv4" : "IPv6",
		  real_type == SOCK_DGRAM ? "UDP" : "TCP",
		  fd);

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

static int swrap_accept(int s,
			struct sockaddr *addr,
			socklen_t *addrlen,
			int flags)
{
	struct socket_info *parent_si, *child_si;
	struct socket_info new_si = { 0 };
	int fd;
	int idx;
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
#ifdef HAVE_ACCEPT4
		return libc_accept4(s, addr, addrlen, flags);
#else
		UNUSED(flags);
		return libc_accept(s, addr, addrlen);
#endif
	}


	/*
	 * prevent parent_si from being altered / closed
	 * while we read it
	 */
	SWRAP_LOCK_SI(parent_si);

	/*
	 * assume out sockaddr have the same size as the in parent
	 * socket family
	 */
	in_addr.sa_socklen = socket_length(parent_si->family);
	if (in_addr.sa_socklen <= 0) {
		SWRAP_UNLOCK_SI(parent_si);
		errno = EINVAL;
		return -1;
	}

	SWRAP_UNLOCK_SI(parent_si);

#ifdef HAVE_ACCEPT4
	ret = libc_accept4(s, &un_addr.sa.s, &un_addr.sa_socklen, flags);
#else
	UNUSED(flags);
	ret = libc_accept(s, &un_addr.sa.s, &un_addr.sa_socklen);
#endif
	if (ret == -1) {
		int saved_errno = errno;
		if (saved_errno == ENOTSOCK) {
			/* Remove stale fds */
			swrap_remove_stale(s);
		}
		errno = saved_errno;
		return ret;
	}

	fd = ret;

	/* Check if we have a stale fd and remove it */
	swrap_remove_stale(fd);

	if (un_addr.sa.un.sun_path[0] == '\0') {
		/*
		 * FreeBSD seems to have a problem where
		 * accept4() on the unix socket doesn't
		 * ECONNABORTED for already disconnected connections.
		 *
		 * Let's try libc_getpeername() to get the peer address
		 * as a fallback, but it'll likely return ENOTCONN,
		 * which we have to map to ECONNABORTED.
		 */
		un_addr.sa_socklen = sizeof(struct sockaddr_un),
		ret = libc_getpeername(fd, &un_addr.sa.s, &un_addr.sa_socklen);
		if (ret == -1) {
			int saved_errno = errno;
			libc_close(fd);
			if (saved_errno == ENOTCONN) {
				/*
				 * If the connection is already disconnected
				 * we should return ECONNABORTED.
				 */
				saved_errno = ECONNABORTED;
			}
			errno = saved_errno;
			return ret;
		}
	}

	ret = libc_getsockname(fd,
			       &un_my_addr.sa.s,
			       &un_my_addr.sa_socklen);
	if (ret == -1) {
		int saved_errno = errno;
		libc_close(fd);
		if (saved_errno == ENOTCONN) {
			/*
			 * If the connection is already disconnected
			 * we should return ECONNABORTED.
			 */
			saved_errno = ECONNABORTED;
		}
		errno = saved_errno;
		return ret;
	}

	SWRAP_LOCK_SI(parent_si);

	ret = sockaddr_convert_from_un(parent_si,
				       &un_addr.sa.un,
				       un_addr.sa_socklen,
				       parent_si->family,
				       &in_addr.sa.s,
				       &in_addr.sa_socklen);
	if (ret == -1) {
		int saved_errno = errno;
		SWRAP_UNLOCK_SI(parent_si);
		libc_close(fd);
		errno = saved_errno;
		return ret;
	}

	child_si = &new_si;

	child_si->family = parent_si->family;
	child_si->type = parent_si->type;
	child_si->protocol = parent_si->protocol;
	child_si->bound = 1;
	child_si->is_server = 1;
	child_si->connected = 1;

	SWRAP_UNLOCK_SI(parent_si);

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

	ret = sockaddr_convert_from_un(child_si,
				       &un_my_addr.sa.un,
				       un_my_addr.sa_socklen,
				       child_si->family,
				       &in_my_addr.sa.s,
				       &in_my_addr.sa_socklen);
	if (ret == -1) {
		int saved_errno = errno;
		libc_close(fd);
		errno = saved_errno;
		return ret;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "accept() path=%s, fd=%d",
		  un_my_addr.sa.un.sun_path, s);

	child_si->myname = (struct swrap_address) {
		.sa_socklen = in_my_addr.sa_socklen,
	};
	memcpy(&child_si->myname.sa.ss, &in_my_addr.sa.ss, in_my_addr.sa_socklen);

	idx = swrap_create_socket(&new_si, fd);
	if (idx == -1) {
		int saved_errno = errno;
		libc_close(fd);
		errno = saved_errno;
		return -1;
	}

	if (addr != NULL) {
		struct socket_info *si = swrap_get_socket_info(idx);

		SWRAP_LOCK_SI(si);
		swrap_pcap_dump_packet(si, addr, SWRAP_ACCEPT_SEND, NULL, 0);
		swrap_pcap_dump_packet(si, addr, SWRAP_ACCEPT_RECV, NULL, 0);
		swrap_pcap_dump_packet(si, addr, SWRAP_ACCEPT_ACK, NULL, 0);
		SWRAP_UNLOCK_SI(si);
	}

	return fd;
}

#ifdef HAVE_ACCEPT4
int accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	return swrap_accept(s, addr, (socklen_t *)addrlen, flags);
}
#endif

#ifdef HAVE_ACCEPT_PSOCKLEN_T
int accept(int s, struct sockaddr *addr, Psocklen_t addrlen)
#else
int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
#endif
{
	return swrap_accept(s, addr, (socklen_t *)addrlen, 0);
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
	char *swrap_dir = NULL;

	swrap_mutex_lock(&autobind_start_mutex);

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
			ret = -1;
			goto done;
		}

		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		in.sin_addr.s_addr = htonl(swrap_ipv4_iface(
					   socket_wrapper_default_iface()));

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
			ret = -1;
			goto done;
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
			ret = -1;
			goto done;
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
		ret = -1;
		goto done;
	}

	if (autobind_start > 60000) {
		autobind_start = 10000;
	}

	swrap_dir = socket_wrapper_dir();
	if (swrap_dir == NULL) {
		errno = EINVAL;
		ret = -1;
		goto done;
	}

	for (i = 0; i < SOCKET_MAX_SOCKETS; i++) {
		port = autobind_start + i;
		swrap_un_path(&un_addr.sa.un,
			      swrap_dir,
			      type,
			      socket_wrapper_default_iface(),
			      port);
		if (stat(un_addr.sa.un.sun_path, &st) == 0) continue;

		ret = libc_bind(fd, &un_addr.sa.s, un_addr.sa_socklen);
		if (ret == -1) {
			goto done;
		}

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
		ret = -1;
		goto done;
	}

	si->family = family;
	set_port(si->family, port, &si->myname);

	ret = 0;

done:
	SAFE_FREE(swrap_dir);
	swrap_mutex_unlock(&autobind_start_mutex);
	return ret;
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

	SWRAP_LOCK_SI(si);

	if (si->bound == 0) {
		ret = swrap_auto_bind(s, si, serv_addr->sa_family);
		if (ret == -1) {
			goto done;
		}
	}

	if (si->family != serv_addr->sa_family) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "called for fd=%d (family=%d) called with invalid family=%d",
			  s, si->family, serv_addr->sa_family);
		errno = EINVAL;
		ret = -1;
		goto done;
	}

	ret = sockaddr_convert_to_un(si, serv_addr,
				     addrlen, &un_addr.sa.un, 0, &bcast);
	if (ret == -1) {
		goto done;
	}

	if (bcast) {
		errno = ENETUNREACH;
		ret = -1;
		goto done;
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

done:
	SWRAP_UNLOCK_SI(si);
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

	SWRAP_LOCK_SI(si);

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
		ret = -1;
		goto out;
	}

#if 0 /* FIXME */
	in_use = check_addr_port_in_use(myaddr, addrlen);
	if (in_use) {
		errno = EADDRINUSE;
		ret = -1;
		goto out;
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
	if (ret == -1) {
		goto out;
	}

	unlink(un_addr.sa.un.sun_path);

	ret = libc_bind(s, &un_addr.sa.s, un_addr.sa_socklen);

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "bind() path=%s, fd=%d",
		  un_addr.sa.un.sun_path, s);

	if (ret == 0) {
		si->bound = 1;
	}

out:
	SWRAP_UNLOCK_SI(si);

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

	SWRAP_LOCK_SI(si);

	if (si->bound == 0) {
		ret = swrap_auto_bind(s, si, si->family);
		if (ret == -1) {
			errno = EADDRINUSE;
			goto out;
		}
	}

	ret = libc_listen(s, backlog);
	if (ret == 0) {
		si->listening = 1;
	}

out:
	SWRAP_UNLOCK_SI(si);

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
 *   FOPEN64
 ***************************************************************************/

#ifdef HAVE_FOPEN64
static FILE *swrap_fopen64(const char *name, const char *mode)
{
	FILE *fp;

	fp = libc_fopen64(name, mode);
	if (fp != NULL) {
		int fd = fileno(fp);

		swrap_remove_stale(fd);
	}

	return fp;
}

FILE *fopen64(const char *name, const char *mode)
{
	return swrap_fopen64(name, mode);
}
#endif /* HAVE_FOPEN64 */

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
 *   OPEN64
 ***************************************************************************/

#ifdef HAVE_OPEN64
static int swrap_vopen64(const char *pathname, int flags, va_list ap)
{
	int ret;

	ret = libc_vopen64(pathname, flags, ap);
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

int open64(const char *pathname, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = swrap_vopen64(pathname, flags, ap);
	va_end(ap);

	return fd;
}
#endif /* HAVE_OPEN64 */

/****************************************************************************
 *   OPENAT
 ***************************************************************************/

static int swrap_vopenat(int dirfd, const char *path, int flags, va_list ap)
{
	int ret;

	ret = libc_vopenat(dirfd, path, flags, ap);
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

int openat(int dirfd, const char *path, int flags, ...)
{
	va_list ap;
	int fd;

	va_start(ap, flags);
	fd = swrap_vopenat(dirfd, path, flags, ap);
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
	int ret = -1;

	if (!si) {
		return libc_getpeername(s, name, addrlen);
	}

	SWRAP_LOCK_SI(si);

	if (si->peername.sa_socklen == 0)
	{
		errno = ENOTCONN;
		goto out;
	}

	len = MIN(*addrlen, si->peername.sa_socklen);
	if (len == 0) {
		ret = 0;
		goto out;
	}

	memcpy(name, &si->peername.sa.ss, len);
	*addrlen = si->peername.sa_socklen;

	ret = 0;
out:
	SWRAP_UNLOCK_SI(si);

	return ret;
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
	int ret = -1;

	if (!si) {
		return libc_getsockname(s, name, addrlen);
	}

	SWRAP_LOCK_SI(si);

	len = MIN(*addrlen, si->myname.sa_socklen);
	if (len == 0) {
		ret = 0;
		goto out;
	}

	memcpy(name, &si->myname.sa.ss, len);
	*addrlen = si->myname.sa_socklen;

	ret = 0;
out:
	SWRAP_UNLOCK_SI(si);

	return ret;
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
	int ret;

	if (!si) {
		return libc_getsockopt(s,
				       level,
				       optname,
				       optval,
				       optlen);
	}

	SWRAP_LOCK_SI(si);

	if (level == SOL_SOCKET) {
		switch (optname) {
#ifdef SO_DOMAIN
		case SO_DOMAIN:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->family;
			ret = 0;
			goto done;
#endif /* SO_DOMAIN */

#ifdef SO_PROTOCOL
		case SO_PROTOCOL:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->protocol;
			ret = 0;
			goto done;
#endif /* SO_PROTOCOL */
		case SO_TYPE:
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->type;
			ret = 0;
			goto done;
		default:
			ret = libc_getsockopt(s,
					      level,
					      optname,
					      optval,
					      optlen);
			goto done;
		}
	} else if (level == IPPROTO_TCP) {
		switch (optname) {
#ifdef TCP_NODELAY
		case TCP_NODELAY:
			/*
			 * This enables sending packets directly out over TCP.
			 * As a unix socket is doing that any way, report it as
			 * enabled.
			 */
			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			*optlen = sizeof(int);
			*(int *)optval = si->tcp_nodelay;

			ret = 0;
			goto done;
#endif /* TCP_NODELAY */
#ifdef TCP_INFO
		case TCP_INFO: {
			struct tcp_info info;
			socklen_t ilen = sizeof(info);

#ifdef HAVE_NETINET_TCP_FSM_H
/* This is FreeBSD */
# define __TCP_LISTEN TCPS_LISTEN
# define __TCP_ESTABLISHED TCPS_ESTABLISHED
# define __TCP_CLOSE TCPS_CLOSED
#else
/* This is Linux */
# define __TCP_LISTEN TCP_LISTEN
# define __TCP_ESTABLISHED TCP_ESTABLISHED
# define __TCP_CLOSE TCP_CLOSE
#endif

			ZERO_STRUCT(info);
			if (si->listening) {
				info.tcpi_state = __TCP_LISTEN;
			} else if (si->connected) {
				/*
				 * For now we just fake a few values
				 * supported both by FreeBSD and Linux
				 */
				info.tcpi_state = __TCP_ESTABLISHED;
				info.tcpi_rto = 200000;  /* 200 msec */
				info.tcpi_rtt = 5000;    /* 5 msec */
				info.tcpi_rttvar = 5000; /* 5 msec */
			} else {
				info.tcpi_state = __TCP_CLOSE;
				info.tcpi_rto = 1000000;  /* 1 sec */
				info.tcpi_rtt = 0;
				info.tcpi_rttvar = 250000; /* 250 msec */
			}

			if (optval == NULL || optlen == NULL ||
			    *optlen < (socklen_t)ilen) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			*optlen = ilen;
			memcpy(optval, &info, ilen);

			ret = 0;
			goto done;
		}
#endif /* TCP_INFO */
		default:
			break;
		}
	}

	errno = ENOPROTOOPT;
	ret = -1;

done:
	SWRAP_UNLOCK_SI(si);
	return ret;
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
	int ret;

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

	SWRAP_LOCK_SI(si);

	if (level == IPPROTO_TCP) {
		switch (optname) {
#ifdef TCP_NODELAY
		case TCP_NODELAY: {
			int i;

			/*
			 * This enables sending packets directly out over TCP.
			 * A unix socket is doing that any way.
			 */
			if (optval == NULL || optlen == 0 ||
			    optlen < (socklen_t)sizeof(int)) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}

			i = *discard_const_p(int, optval);
			if (i != 0 && i != 1) {
				errno = EINVAL;
				ret = -1;
				goto done;
			}
			si->tcp_nodelay = i;

			ret = 0;
			goto done;
		}
#endif /* TCP_NODELAY */
		default:
			break;
		}
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
		ret = 0;
		goto done;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (level == IPPROTO_IPV6) {
#ifdef IPV6_RECVPKTINFO
			if (optname == IPV6_RECVPKTINFO) {
				si->pktinfo = AF_INET6;
			}
#endif /* IPV6_PKTINFO */
		}
		ret = 0;
		goto done;
#endif
	default:
		errno = ENOPROTOOPT;
		ret = -1;
		goto done;
	}

done:
	SWRAP_UNLOCK_SI(si);
	return ret;
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
	int *value_ptr = NULL;
	int rc;

	if (!si) {
		return libc_vioctl(s, r, va);
	}

	SWRAP_LOCK_SI(si);

	va_copy(ap, va);

	rc = libc_vioctl(s, r, va);

	switch (r) {
	case FIONREAD:
		if (rc == 0) {
			value_ptr = ((int *)va_arg(ap, int *));
		}

		if (rc == -1 && errno != EAGAIN && errno != ENOBUFS) {
			swrap_pcap_dump_packet(si, NULL, SWRAP_PENDING_RST, NULL, 0);
		} else if (value_ptr != NULL && *value_ptr == 0) { /* END OF FILE */
			swrap_pcap_dump_packet(si, NULL, SWRAP_PENDING_RST, NULL, 0);
		}
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
		if (rc == 0) {
			value_ptr = ((int *)va_arg(ap, int *));
			*value_ptr = 0;
		}
		break;
	}

	va_end(ap);

	SWRAP_UNLOCK_SI(si);
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

static int swrap_sendmsg_copy_cmsg(const struct cmsghdr *cmsg,
				   uint8_t **cm_data,
				   size_t *cm_data_space);
static int swrap_sendmsg_filter_cmsg_ipproto_ip(const struct cmsghdr *cmsg,
						uint8_t **cm_data,
						size_t *cm_data_space);
static int swrap_sendmsg_filter_cmsg_sol_socket(const struct cmsghdr *cmsg,
						uint8_t **cm_data,
						size_t *cm_data_space);

static int swrap_sendmsg_filter_cmsghdr(const struct msghdr *_msg,
					uint8_t **cm_data,
					size_t *cm_data_space)
{
	struct msghdr *msg = discard_const_p(struct msghdr, _msg);
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
			rc = swrap_sendmsg_filter_cmsg_ipproto_ip(cmsg,
								  cm_data,
								  cm_data_space);
			break;
		case SOL_SOCKET:
			rc = swrap_sendmsg_filter_cmsg_sol_socket(cmsg,
								  cm_data,
								  cm_data_space);
			break;
		default:
			rc = swrap_sendmsg_copy_cmsg(cmsg,
						     cm_data,
						     cm_data_space);
			break;
		}
		if (rc < 0) {
			int saved_errno = errno;
			SAFE_FREE(*cm_data);
			*cm_data_space = 0;
			errno = saved_errno;
			return rc;
		}
	}

	return rc;
}

static int swrap_sendmsg_copy_cmsg(const struct cmsghdr *cmsg,
				   uint8_t **cm_data,
				   size_t *cm_data_space)
{
	size_t cmspace;
	uint8_t *p;

	cmspace = *cm_data_space + CMSG_ALIGN(cmsg->cmsg_len);

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

static int swrap_sendmsg_filter_cmsg_pktinfo(const struct cmsghdr *cmsg,
					    uint8_t **cm_data,
					    size_t *cm_data_space);


static int swrap_sendmsg_filter_cmsg_ipproto_ip(const struct cmsghdr *cmsg,
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

static int swrap_sendmsg_filter_cmsg_pktinfo(const struct cmsghdr *cmsg,
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

static int swrap_sendmsg_filter_cmsg_sol_socket(const struct cmsghdr *cmsg,
						uint8_t **cm_data,
						size_t *cm_data_space)
{
	int rc = -1;

	switch (cmsg->cmsg_type) {
	case SCM_RIGHTS:
		SWRAP_LOG(SWRAP_LOG_TRACE,
			  "Ignoring SCM_RIGHTS on inet socket!");
		rc = 0;
		break;
#ifdef SCM_CREDENTIALS
	case SCM_CREDENTIALS:
		SWRAP_LOG(SWRAP_LOG_TRACE,
			  "Ignoring SCM_CREDENTIALS on inet socket!");
		rc = 0;
		break;
#endif /* SCM_CREDENTIALS */
	default:
		rc = swrap_sendmsg_copy_cmsg(cmsg,
					     cm_data,
					     cm_data_space);
		break;
	}

	return rc;
}

static const uint64_t swrap_unix_scm_right_magic = 0x8e0e13f27c42fc36;

/*
 * We only allow up to 6 fds at a time
 * as that's more than enough for Samba
 * and it means we can keep the logic simple
 * and work with fixed size arrays.
 *
 * We also keep sizeof(struct swrap_unix_scm_rights)
 * under PIPE_BUF (4096) in order to allow a non-blocking
 * write into the pipe.
 */
#ifndef PIPE_BUF
#define PIPE_BUF 4096
#endif
#define SWRAP_MAX_PASSED_FDS ((size_t)6)
#define SWRAP_MAX_PASSED_SOCKET_INFO SWRAP_MAX_PASSED_FDS
struct swrap_unix_scm_rights_payload {
	uint8_t num_idxs;
	int8_t idxs[SWRAP_MAX_PASSED_FDS];
	struct socket_info infos[SWRAP_MAX_PASSED_SOCKET_INFO];
};
struct swrap_unix_scm_rights {
	uint64_t magic;
	char package_name[sizeof(SOCKET_WRAPPER_PACKAGE)];
	char package_version[sizeof(SOCKET_WRAPPER_VERSION)];
	uint32_t full_size;
	uint32_t payload_size;
	struct swrap_unix_scm_rights_payload payload;
};

static void swrap_dec_fd_passed_array(size_t num, struct socket_info **array)
{
	int saved_errno = errno;
	size_t i;

	for (i = 0; i < num; i++) {
		struct socket_info *si = array[i];
		if (si == NULL) {
			continue;
		}

		SWRAP_LOCK_SI(si);
		swrap_dec_refcount(si);
		if (si->fd_passed > 0) {
			si->fd_passed -= 1;
		}
		SWRAP_UNLOCK_SI(si);
		array[i] = NULL;
	}

	errno = saved_errno;
}

static void swrap_undo_si_idx_array(size_t num, int *array)
{
	int saved_errno = errno;
	size_t i;

	swrap_mutex_lock(&first_free_mutex);

	for (i = 0; i < num; i++) {
		struct socket_info *si = NULL;

		if (array[i] == -1) {
			continue;
		}

		si = swrap_get_socket_info(array[i]);
		if (si == NULL) {
			continue;
		}

		SWRAP_LOCK_SI(si);
		swrap_dec_refcount(si);
		SWRAP_UNLOCK_SI(si);

		swrap_set_next_free(si, first_free);
		first_free = array[i];
		array[i] = -1;
	}

	swrap_mutex_unlock(&first_free_mutex);
	errno = saved_errno;
}

static void swrap_close_fd_array(size_t num, const int *array)
{
	int saved_errno = errno;
	size_t i;

	for (i = 0; i < num; i++) {
		if (array[i] == -1) {
			continue;
		}
		libc_close(array[i]);
	}

	errno = saved_errno;
}

union __swrap_fds {
	const uint8_t *p;
	int *fds;
};

union __swrap_cmsghdr {
	const uint8_t *p;
	struct cmsghdr *cmsg;
};

static int swrap_sendmsg_unix_scm_rights(const struct cmsghdr *cmsg,
					 uint8_t **cm_data,
					 size_t *cm_data_space,
					 int *scm_rights_pipe_fd)
{
	struct swrap_unix_scm_rights info;
	struct swrap_unix_scm_rights_payload *payload = NULL;
	int si_idx_array[SWRAP_MAX_PASSED_FDS];
	struct socket_info *si_array[SWRAP_MAX_PASSED_FDS] = { NULL, };
	size_t info_idx = 0;
	size_t size_fds_in;
	size_t num_fds_in;
	union __swrap_fds __fds_in = { .p = NULL, };
	const int *fds_in = NULL;
	size_t num_fds_out;
	size_t size_fds_out;
	union __swrap_fds __fds_out = { .p = NULL, };
	int *fds_out = NULL;
	size_t cmsg_len;
	size_t cmsg_space;
	size_t new_cm_data_space;
	union __swrap_cmsghdr __new_cmsg = { .p = NULL, };
	struct cmsghdr *new_cmsg = NULL;
	uint8_t *p = NULL;
	size_t i;
	int pipefd[2] = { -1, -1 };
	int rc;
	ssize_t sret;

	/*
	 * We pass this a buffer to the kernel make sure any padding
	 * is also cleared.
	 */
	ZERO_STRUCT(info);
	info.magic = swrap_unix_scm_right_magic;
	memcpy(info.package_name,
	       SOCKET_WRAPPER_PACKAGE,
	       sizeof(info.package_name));
	memcpy(info.package_version,
	       SOCKET_WRAPPER_VERSION,
	       sizeof(info.package_version));
	info.full_size = sizeof(info);
	info.payload_size = sizeof(info.payload);
	payload = &info.payload;

	if (*scm_rights_pipe_fd != -1) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "Two SCM_RIGHTS headers are not supported by socket_wrapper");
		errno = EINVAL;
		return -1;
	}

	if (cmsg->cmsg_len < CMSG_LEN(0)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu < CMSG_LEN(0)=%zu",
			  (size_t)cmsg->cmsg_len,
			  CMSG_LEN(0));
		errno = EINVAL;
		return -1;
	}
	size_fds_in = cmsg->cmsg_len - CMSG_LEN(0);
	if ((size_fds_in % sizeof(int)) != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu => (size_fds_in=%zu %% sizeof(int)=%zu) != 0",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  sizeof(int));
		errno = EINVAL;
		return -1;
	}
	num_fds_in = size_fds_in / sizeof(int);
	if (num_fds_in > SWRAP_MAX_PASSED_FDS) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu,size_fds_in=%zu => "
			  "num_fds_in=%zu > "
			  "SWRAP_MAX_PASSED_FDS(%zu)",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  num_fds_in,
			  SWRAP_MAX_PASSED_FDS);
		errno = EINVAL;
		return -1;
	}
	if (num_fds_in == 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
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
	num_fds_out = num_fds_in + 1;

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "num_fds_in=%zu num_fds_out=%zu",
		  num_fds_in, num_fds_out);

	size_fds_out = sizeof(int) * num_fds_out;
	cmsg_len = CMSG_LEN(size_fds_out);
	cmsg_space = CMSG_SPACE(size_fds_out);

	new_cm_data_space = *cm_data_space + cmsg_space;

	p = realloc((*cm_data), new_cm_data_space);
	if (p == NULL) {
		return -1;
	}
	(*cm_data) = p;
	p = (*cm_data) + (*cm_data_space);
	memset(p, 0, cmsg_space);
	__new_cmsg.p = p;
	new_cmsg = __new_cmsg.cmsg;
	*new_cmsg = *cmsg;
	__fds_out.p = CMSG_DATA(new_cmsg);
	fds_out = __fds_out.fds;
	memcpy(fds_out, fds_in, size_fds_in);
	new_cmsg->cmsg_len = cmsg->cmsg_len;

	for (i = 0; i < num_fds_in; i++) {
		size_t j;

		payload->idxs[i] = -1;
		payload->num_idxs++;

		si_idx_array[i] = find_socket_info_index(fds_in[i]);
		if (si_idx_array[i] == -1) {
			continue;
		}

		si_array[i] = swrap_get_socket_info(si_idx_array[i]);
		if (si_array[i] == NULL) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "fds_in[%zu]=%d si_idx_array[%zu]=%d missing!",
				  i, fds_in[i], i, si_idx_array[i]);
			errno = EINVAL;
			return -1;
		}

		for (j = 0; j < i; j++) {
			if (si_array[j] == si_array[i]) {
				payload->idxs[i] = payload->idxs[j];
				break;
			}
		}
		if (payload->idxs[i] == -1) {
			if (info_idx >= SWRAP_MAX_PASSED_SOCKET_INFO) {
				SWRAP_LOG(SWRAP_LOG_ERROR,
					  "fds_in[%zu]=%d,si_idx_array[%zu]=%d: "
					  "info_idx=%zu >= SWRAP_MAX_PASSED_FDS(%zu)!",
					  i, fds_in[i], i, si_idx_array[i],
					  info_idx,
					  SWRAP_MAX_PASSED_SOCKET_INFO);
				errno = EINVAL;
				return -1;
			}
			payload->idxs[i] = info_idx;
			info_idx += 1;
			continue;
		}
	}

	for (i = 0; i < num_fds_in; i++) {
		struct socket_info *si = si_array[i];

		if (si == NULL) {
			SWRAP_LOG(SWRAP_LOG_TRACE,
				  "fds_in[%zu]=%d not an inet socket",
				  i, fds_in[i]);
			continue;
		}

		SWRAP_LOG(SWRAP_LOG_TRACE,
			  "fds_in[%zu]=%d si_idx_array[%zu]=%d "
			  "passing as info.idxs[%zu]=%d!",
			  i, fds_in[i],
			  i, si_idx_array[i],
			  i, payload->idxs[i]);

		SWRAP_LOCK_SI(si);
		si->fd_passed += 1;
		payload->infos[payload->idxs[i]] = *si;
		payload->infos[payload->idxs[i]].fd_passed = 0;
		SWRAP_UNLOCK_SI(si);
	}

	rc = pipe(pipefd);
	if (rc == -1) {
		int saved_errno = errno;
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "pipe() failed - %d %s",
			  saved_errno,
			  strerror(saved_errno));
		swrap_dec_fd_passed_array(num_fds_in, si_array);
		errno = saved_errno;
		return -1;
	}

	sret = libc_write(pipefd[1], &info, sizeof(info));
	if (sret != sizeof(info)) {
		int saved_errno = errno;
		if (sret != -1) {
			saved_errno = EINVAL;
		}
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "write() failed - sret=%zd - %d %s",
			  sret, saved_errno,
			  strerror(saved_errno));
		swrap_dec_fd_passed_array(num_fds_in, si_array);
		libc_close(pipefd[1]);
		libc_close(pipefd[0]);
		errno = saved_errno;
		return -1;
	}
	libc_close(pipefd[1]);

	/*
	 * Add the pipe read end to the end of the passed fd array
	 */
	fds_out[num_fds_in] = pipefd[0];
	new_cmsg->cmsg_len = cmsg_len;

	/* we're done ... */
	*scm_rights_pipe_fd = pipefd[0];
	*cm_data_space = new_cm_data_space;

	return 0;
}

static int swrap_sendmsg_unix_sol_socket(const struct cmsghdr *cmsg,
					 uint8_t **cm_data,
					 size_t *cm_data_space,
					 int *scm_rights_pipe_fd)
{
	int rc = -1;

	switch (cmsg->cmsg_type) {
	case SCM_RIGHTS:
		rc = swrap_sendmsg_unix_scm_rights(cmsg,
						   cm_data,
						   cm_data_space,
						   scm_rights_pipe_fd);
		break;
	default:
		rc = swrap_sendmsg_copy_cmsg(cmsg,
					     cm_data,
					     cm_data_space);
		break;
	}

	return rc;
}

static int swrap_recvmsg_unix_scm_rights(const struct cmsghdr *cmsg,
					 uint8_t **cm_data,
					 size_t *cm_data_space)
{
	int scm_rights_pipe_fd = -1;
	struct swrap_unix_scm_rights info;
	struct swrap_unix_scm_rights_payload *payload = NULL;
	int si_idx_array[SWRAP_MAX_PASSED_FDS];
	size_t size_fds_in;
	size_t num_fds_in;
	union __swrap_fds __fds_in = { .p = NULL, };
	const int *fds_in = NULL;
	size_t num_fds_out;
	size_t size_fds_out;
	union __swrap_fds __fds_out = { .p = NULL, };
	int *fds_out = NULL;
	size_t cmsg_len;
	size_t cmsg_space;
	size_t new_cm_data_space;
	union __swrap_cmsghdr __new_cmsg = { .p = NULL, };
	struct cmsghdr *new_cmsg = NULL;
	uint8_t *p = NULL;
	ssize_t sret;
	size_t i;
	int cmp;

	if (cmsg->cmsg_len < CMSG_LEN(0)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu < CMSG_LEN(0)=%zu",
			  (size_t)cmsg->cmsg_len,
			  CMSG_LEN(0));
		errno = EINVAL;
		return -1;
	}
	size_fds_in = cmsg->cmsg_len - CMSG_LEN(0);
	if ((size_fds_in % sizeof(int)) != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu => (size_fds_in=%zu %% sizeof(int)=%zu) != 0",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  sizeof(int));
		errno = EINVAL;
		return -1;
	}
	num_fds_in = size_fds_in / sizeof(int);
	if (num_fds_in > (SWRAP_MAX_PASSED_FDS + 1)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "cmsg->cmsg_len=%zu,size_fds_in=%zu => "
			  "num_fds_in=%zu > SWRAP_MAX_PASSED_FDS+1(%zu)",
			  (size_t)cmsg->cmsg_len,
			  size_fds_in,
			  num_fds_in,
			  SWRAP_MAX_PASSED_FDS+1);
		errno = EINVAL;
		return -1;
	}
	if (num_fds_in <= 1) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
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
	num_fds_out = num_fds_in - 1;

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "num_fds_in=%zu num_fds_out=%zu",
		  num_fds_in, num_fds_out);

	for (i = 0; i < num_fds_in; i++) {
		/* Check if we have a stale fd and remove it */
		swrap_remove_stale(fds_in[i]);
	}

	scm_rights_pipe_fd = fds_in[num_fds_out];
	size_fds_out = sizeof(int) * num_fds_out;
	cmsg_len = CMSG_LEN(size_fds_out);
	cmsg_space = CMSG_SPACE(size_fds_out);

	new_cm_data_space = *cm_data_space + cmsg_space;

	p = realloc((*cm_data), new_cm_data_space);
	if (p == NULL) {
		swrap_close_fd_array(num_fds_in, fds_in);
		return -1;
	}
	(*cm_data) = p;
	p = (*cm_data) + (*cm_data_space);
	memset(p, 0, cmsg_space);
	__new_cmsg.p = p;
	new_cmsg = __new_cmsg.cmsg;
	*new_cmsg = *cmsg;
	__fds_out.p = CMSG_DATA(new_cmsg);
	fds_out = __fds_out.fds;
	memcpy(fds_out, fds_in, size_fds_out);
	new_cmsg->cmsg_len = cmsg_len;

	sret = read(scm_rights_pipe_fd, &info, sizeof(info));
	if (sret != sizeof(info)) {
		int saved_errno = errno;
		if (sret != -1) {
			saved_errno = EINVAL;
		}
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "read() failed - sret=%zd - %d %s",
			  sret, saved_errno,
			  strerror(saved_errno));
		swrap_close_fd_array(num_fds_in, fds_in);
		errno = saved_errno;
		return -1;
	}
	libc_close(scm_rights_pipe_fd);
	payload = &info.payload;

	if (info.magic != swrap_unix_scm_right_magic) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.magic=0x%llx != swrap_unix_scm_right_magic=0x%llx",
			  (unsigned long long)info.magic,
			  (unsigned long long)swrap_unix_scm_right_magic);
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	cmp = memcmp(info.package_name,
		     SOCKET_WRAPPER_PACKAGE,
		     sizeof(info.package_name));
	if (cmp != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.package_name='%.*s' != '%s'",
			  (int)sizeof(info.package_name),
			  info.package_name,
			  SOCKET_WRAPPER_PACKAGE);
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	cmp = memcmp(info.package_version,
		     SOCKET_WRAPPER_VERSION,
		     sizeof(info.package_version));
	if (cmp != 0) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.package_version='%.*s' != '%s'",
			  (int)sizeof(info.package_version),
			  info.package_version,
			  SOCKET_WRAPPER_VERSION);
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	if (info.full_size != sizeof(info)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.full_size=%zu != sizeof(info)=%zu",
			  (size_t)info.full_size,
			  sizeof(info));
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	if (info.payload_size != sizeof(info.payload)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.payload_size=%zu != sizeof(info.payload)=%zu",
			  (size_t)info.payload_size,
			  sizeof(info.payload));
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	if (payload->num_idxs != num_fds_out) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "info.num_idxs=%u != num_fds_out=%zu",
			  payload->num_idxs, num_fds_out);
		swrap_close_fd_array(num_fds_out, fds_out);
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < num_fds_out; i++) {
		size_t j;

		si_idx_array[i] = -1;

		if (payload->idxs[i] == -1) {
			SWRAP_LOG(SWRAP_LOG_TRACE,
				  "fds_out[%zu]=%d not an inet socket",
				  i, fds_out[i]);
			continue;
		}

		if (payload->idxs[i] < 0) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "fds_out[%zu]=%d info.idxs[%zu]=%d < 0!",
				  i, fds_out[i], i, payload->idxs[i]);
			swrap_close_fd_array(num_fds_out, fds_out);
			errno = EINVAL;
			return -1;
		}

		if (payload->idxs[i] >= payload->num_idxs) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "fds_out[%zu]=%d info.idxs[%zu]=%d >= %u!",
				  i, fds_out[i], i, payload->idxs[i],
				  payload->num_idxs);
			swrap_close_fd_array(num_fds_out, fds_out);
			errno = EINVAL;
			return -1;
		}

		if ((size_t)fds_out[i] >= socket_fds_max) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
				  "The max socket index limit of %zu has been reached, "
				  "trying to add %d",
				  socket_fds_max,
				  fds_out[i]);
			swrap_close_fd_array(num_fds_out, fds_out);
			errno = EMFILE;
			return -1;
		}

		SWRAP_LOG(SWRAP_LOG_TRACE,
			  "fds_in[%zu]=%d "
			  "received as info.idxs[%zu]=%d!",
			  i, fds_out[i],
			  i, payload->idxs[i]);

		for (j = 0; j < i; j++) {
			if (payload->idxs[j] == -1) {
				continue;
			}
			if (payload->idxs[j] == payload->idxs[i]) {
				si_idx_array[i] = si_idx_array[j];
			}
		}
		if (si_idx_array[i] == -1) {
			const struct socket_info *si = &payload->infos[payload->idxs[i]];

			si_idx_array[i] = swrap_add_socket_info(si);
			if (si_idx_array[i] == -1) {
				int saved_errno = errno;
				SWRAP_LOG(SWRAP_LOG_ERROR,
					  "The max socket index limit of %zu has been reached, "
					  "trying to add %d",
					  socket_fds_max,
					  fds_out[i]);
				swrap_undo_si_idx_array(i, si_idx_array);
				swrap_close_fd_array(num_fds_out, fds_out);
				errno = saved_errno;
				return -1;
			}
			SWRAP_LOG(SWRAP_LOG_TRACE,
				  "Imported %s socket for protocol %s, fd=%d",
				  si->family == AF_INET ? "IPv4" : "IPv6",
				  si->type == SOCK_DGRAM ? "UDP" : "TCP",
				  fds_out[i]);
		}
	}

	for (i = 0; i < num_fds_out; i++) {
		if (si_idx_array[i] == -1) {
			continue;
		}
		set_socket_info_index(fds_out[i], si_idx_array[i]);
	}

	/* we're done ... */
	*cm_data_space = new_cm_data_space;

	return 0;
}

static int swrap_recvmsg_unix_sol_socket(const struct cmsghdr *cmsg,
					 uint8_t **cm_data,
					 size_t *cm_data_space)
{
	int rc = -1;

	switch (cmsg->cmsg_type) {
	case SCM_RIGHTS:
		rc = swrap_recvmsg_unix_scm_rights(cmsg,
						   cm_data,
						   cm_data_space);
		break;
	default:
		rc = swrap_sendmsg_copy_cmsg(cmsg,
					     cm_data,
					     cm_data_space);
		break;
	}

	return rc;
}

#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */

static int swrap_sendmsg_before_unix(const struct msghdr *_msg_in,
				     struct msghdr *msg_tmp,
				     int *scm_rights_pipe_fd)
{
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	struct msghdr *msg_in = discard_const_p(struct msghdr, _msg_in);
	struct cmsghdr *cmsg = NULL;
	uint8_t *cm_data = NULL;
	size_t cm_data_space = 0;
	int rc = -1;

	*msg_tmp = *msg_in;
	*scm_rights_pipe_fd = -1;

	/* Nothing to do */
	if (msg_in->msg_controllen == 0 || msg_in->msg_control == NULL) {
		return 0;
	}

	for (cmsg = CMSG_FIRSTHDR(msg_in);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg_in, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			rc = swrap_sendmsg_unix_sol_socket(cmsg,
							   &cm_data,
							   &cm_data_space,
							   scm_rights_pipe_fd);
			break;

		default:
			rc = swrap_sendmsg_copy_cmsg(cmsg,
						     &cm_data,
						     &cm_data_space);
			break;
		}
		if (rc < 0) {
			int saved_errno = errno;
			SAFE_FREE(cm_data);
			errno = saved_errno;
			return rc;
		}
	}

	msg_tmp->msg_controllen = cm_data_space;
	msg_tmp->msg_control = cm_data;

	return 0;
#else /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	*msg_tmp = *_msg_in;
	return 0;
#endif /* ! HAVE_STRUCT_MSGHDR_MSG_CONTROL */
}

static ssize_t swrap_sendmsg_after_unix(struct msghdr *msg_tmp,
					ssize_t ret,
					int scm_rights_pipe_fd)
{
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	int saved_errno = errno;
	SAFE_FREE(msg_tmp->msg_control);
	if (scm_rights_pipe_fd != -1) {
		libc_close(scm_rights_pipe_fd);
	}
	errno = saved_errno;
#endif /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	return ret;
}

static int swrap_recvmsg_before_unix(struct msghdr *msg_in,
				     struct msghdr *msg_tmp,
				     uint8_t **tmp_control)
{
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	const size_t cm_extra_space = CMSG_SPACE(sizeof(int));
	uint8_t *cm_data = NULL;
	size_t cm_data_space = 0;

	*msg_tmp = *msg_in;
	*tmp_control = NULL;

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "msg_in->msg_controllen=%zu",
		  (size_t)msg_in->msg_controllen);

	/* Nothing to do */
	if (msg_in->msg_controllen == 0 || msg_in->msg_control == NULL) {
		return 0;
	}

	/*
	 * We need to give the kernel a bit more space in order
	 * recv the pipe fd, added by swrap_sendmsg_before_unix()).
	 * swrap_recvmsg_after_unix() will hide it again.
	 */
	cm_data_space = msg_in->msg_controllen;
	if (cm_data_space < (INT32_MAX - cm_extra_space)) {
		cm_data_space += cm_extra_space;
	}
	cm_data = calloc(1, cm_data_space);
	if (cm_data == NULL) {
		return -1;
	}

	msg_tmp->msg_controllen = cm_data_space;
	msg_tmp->msg_control = cm_data;
	*tmp_control = cm_data;

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "msg_tmp->msg_controllen=%zu",
		  (size_t)msg_tmp->msg_controllen);
	return 0;
#else /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	*msg_tmp = *msg_in;
	*tmp_control = NULL;
	return 0;
#endif /* ! HAVE_STRUCT_MSGHDR_MSG_CONTROL */
}

static ssize_t swrap_recvmsg_after_unix(struct msghdr *msg_tmp,
					uint8_t **tmp_control,
					struct msghdr *msg_out,
					ssize_t ret)
{
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	struct cmsghdr *cmsg = NULL;
	uint8_t *cm_data = NULL;
	size_t cm_data_space = 0;
	int rc = -1;

	if (ret < 0) {
		int saved_errno = errno;
		SWRAP_LOG(SWRAP_LOG_TRACE, "ret=%zd - %d - %s", ret,
			  saved_errno, strerror(saved_errno));
		SAFE_FREE(*tmp_control);
		/* msg_out should not be touched on error */
		errno = saved_errno;
		return ret;
	}

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "msg_tmp->msg_controllen=%zu",
		  (size_t)msg_tmp->msg_controllen);

	/* Nothing to do */
	if (msg_tmp->msg_controllen == 0 || msg_tmp->msg_control == NULL) {
		int saved_errno = errno;
		*msg_out = *msg_tmp;
		SAFE_FREE(*tmp_control);
		errno = saved_errno;
		return ret;
	}

	for (cmsg = CMSG_FIRSTHDR(msg_tmp);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(msg_tmp, cmsg)) {
		switch (cmsg->cmsg_level) {
		case SOL_SOCKET:
			rc = swrap_recvmsg_unix_sol_socket(cmsg,
							   &cm_data,
							   &cm_data_space);
			break;

		default:
			rc = swrap_sendmsg_copy_cmsg(cmsg,
						     &cm_data,
						     &cm_data_space);
			break;
		}
		if (rc < 0) {
			int saved_errno = errno;
			SAFE_FREE(cm_data);
			SAFE_FREE(*tmp_control);
			errno = saved_errno;
			return rc;
		}
	}

	/*
	 * msg_tmp->msg_control (*tmp_control) was created by
	 * swrap_recvmsg_before_unix() and msg_out->msg_control
	 * is still the buffer of the caller.
	 */
	msg_tmp->msg_control = msg_out->msg_control;
	msg_tmp->msg_controllen = msg_out->msg_controllen;
	*msg_out = *msg_tmp;

	cm_data_space = MIN(cm_data_space, msg_out->msg_controllen);
	memcpy(msg_out->msg_control, cm_data, cm_data_space);
	msg_out->msg_controllen = cm_data_space;
	SAFE_FREE(cm_data);
	SAFE_FREE(*tmp_control);

	SWRAP_LOG(SWRAP_LOG_TRACE,
		  "msg_out->msg_controllen=%zu",
		  (size_t)msg_out->msg_controllen);
	return ret;
#else /* HAVE_STRUCT_MSGHDR_MSG_CONTROL */
	int saved_errno = errno;
	*msg_out = *msg_tmp;
	SAFE_FREE(*tmp_control);
	errno = saved_errno;
	return ret;
#endif /* ! HAVE_STRUCT_MSGHDR_MSG_CONTROL */
}

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
	ssize_t ret = -1;

	if (to_un) {
		*to_un = NULL;
	}
	if (to) {
		*to = NULL;
	}
	if (bcast) {
		*bcast = 0;
	}

	SWRAP_LOCK_SI(si);

	switch (si->type) {
	case SOCK_STREAM: {
		unsigned long mtu;

		if (!si->connected) {
			errno = ENOTCONN;
			goto out;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		mtu = socket_wrapper_mtu();
		for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
			size_t nlen;
			nlen = len + msg->msg_iov[i].iov_len;
			if (nlen < len) {
				/* overflow */
				errno = EMSGSIZE;
				goto out;
			}
			if (nlen > mtu) {
				break;
			}
		}
		msg->msg_iovlen = i;
		if (msg->msg_iovlen == 0) {
			*tmp_iov = msg->msg_iov[0];
			tmp_iov->iov_len = MIN((size_t)tmp_iov->iov_len,
					       (size_t)mtu);
			msg->msg_iov = tmp_iov;
			msg->msg_iovlen = 1;
		}
		break;
	}
	case SOCK_DGRAM:
		if (si->connected) {
			if (msg->msg_name != NULL) {
				/*
				 * We are dealing with unix sockets and if we
				 * are connected, we should only talk to the
				 * connected unix path. Using the fd to send
				 * to another server would be hard to achieve.
				 */
				msg->msg_name = NULL;
				msg->msg_namelen = 0;
			}
		} else {
			const struct sockaddr *msg_name;
			msg_name = (const struct sockaddr *)msg->msg_name;

			if (msg_name == NULL) {
				errno = ENOTCONN;
				goto out;
			}


			ret = sockaddr_convert_to_un(si, msg_name, msg->msg_namelen,
						     tmp_un, 0, bcast);
			if (ret == -1) {
				goto out;
			}

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
				SWRAP_UNLOCK_SI(si);
				if (errno == ENOTSOCK) {
					swrap_remove_stale(fd);
					ret = -ENOTSOCK;
				} else {
					SWRAP_LOG(SWRAP_LOG_ERROR, "swrap_sendmsg_before failed");
				}
				return ret;
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
		if (ret == -1) {
			goto out;
		}

		ret = libc_connect(fd,
				   (struct sockaddr *)(void *)tmp_un,
				   sizeof(*tmp_un));

		/* to give better errors */
		if (ret == -1 && errno == ENOENT) {
			errno = EHOSTUNREACH;
		}

		if (ret == -1) {
			goto out;
		}

		si->defer_connect = 0;
		break;
	default:
		errno = EHOSTUNREACH;
		goto out;
	}

	ret = 0;
out:
	SWRAP_UNLOCK_SI(si);

	return ret;
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

	SWRAP_LOCK_SI(si);

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

	SWRAP_UNLOCK_SI(si);

	free(buf);
	errno = saved_errno;
}

static int swrap_recvmsg_before(int fd,
				struct socket_info *si,
				struct msghdr *msg,
				struct iovec *tmp_iov)
{
	size_t i, len = 0;
	int ret = -1;

	SWRAP_LOCK_SI(si);

	(void)fd; /* unused */

	switch (si->type) {
	case SOCK_STREAM: {
		unsigned int mtu;
		if (!si->connected) {
			errno = ENOTCONN;
			goto out;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		mtu = socket_wrapper_mtu();
		for (i = 0; i < (size_t)msg->msg_iovlen; i++) {
			size_t nlen;
			nlen = len + msg->msg_iov[i].iov_len;
			if (nlen > mtu) {
				break;
			}
		}
		msg->msg_iovlen = i;
		if (msg->msg_iovlen == 0) {
			*tmp_iov = msg->msg_iov[0];
			tmp_iov->iov_len = MIN((size_t)tmp_iov->iov_len,
					       (size_t)mtu);
			msg->msg_iov = tmp_iov;
			msg->msg_iovlen = 1;
		}
		break;
	}
	case SOCK_DGRAM:
		if (msg->msg_name == NULL) {
			errno = EINVAL;
			goto out;
		}

		if (msg->msg_iovlen == 0) {
			break;
		}

		if (si->bound == 0) {
			ret = swrap_auto_bind(fd, si, si->family);
			if (ret == -1) {
				SWRAP_UNLOCK_SI(si);
				/*
				 * When attempting to read or write to a
				 * descriptor, if an underlying autobind fails
				 * because it's not a socket, stop intercepting
				 * uses of that descriptor.
				 */
				if (errno == ENOTSOCK) {
					swrap_remove_stale(fd);
					ret = -ENOTSOCK;
				} else {
					SWRAP_LOG(SWRAP_LOG_ERROR,
						  "swrap_recvmsg_before failed");
				}
				return ret;
			}
		}
		break;
	default:
		errno = EHOSTUNREACH;
		goto out;
	}

	ret = 0;
out:
	SWRAP_UNLOCK_SI(si);

	return ret;
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

	SWRAP_LOCK_SI(si);

	/* Convert the socket address before we leave */
	if (si->type == SOCK_DGRAM && un_addr != NULL) {
		rc = sockaddr_convert_from_un(si,
					      un_addr,
					      un_addrlen,
					      si->family,
					      msg->msg_name,
					      &msg->msg_namelen);
		if (rc == -1) {
			goto done;
		}
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
		SWRAP_UNLOCK_SI(si);
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
			SWRAP_UNLOCK_SI(si);
			return -1;
		}
	}
#endif

	SWRAP_UNLOCK_SI(si);
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
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
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
		char *swrap_dir = NULL;

		type = SOCKET_TYPE_CHAR_UDP;

		swrap_dir = socket_wrapper_dir();
		if (swrap_dir == NULL) {
			return -1;
		}

		for(iface=0; iface <= MAX_WRAPPED_INTERFACES; iface++) {
			swrap_un_path(&un_addr.sa.un,
				      swrap_dir,
				      type,
				      iface,
				      prt);
			if (stat(un_addr.sa.un.sun_path, &st) != 0) continue;

			/* ignore the any errors in broadcast sends */
			libc_sendto(s,
				    buf,
				    len,
				    flags,
				    &un_addr.sa.s,
				    un_addr.sa_socklen);
		}

		SAFE_FREE(swrap_dir);

		SWRAP_LOCK_SI(si);

		swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);

		SWRAP_UNLOCK_SI(si);

		return len;
	}

	SWRAP_LOCK_SI(si);
	/*
	 * If it is a dgram socket and we are connected, don't include the
	 * 'to' address.
	 */
	if (si->type == SOCK_DGRAM && si->connected) {
		ret = libc_sendto(s,
				  buf,
				  len,
				  flags,
				  NULL,
				  0);
	} else {
		ret = libc_sendto(s,
				  buf,
				  len,
				  flags,
				  (struct sockaddr *)msg.msg_name,
				  msg.msg_namelen);
	}

	SWRAP_UNLOCK_SI(si);

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
 *   WRITE
 ***************************************************************************/

static ssize_t swrap_write(int s, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec tmp;
	struct sockaddr_un un_addr;
	ssize_t ret;
	int rc;
	struct socket_info *si;

	si = find_socket_info(s);
	if (si == NULL) {
		return libc_write(s, buf, len);
	}

	tmp.iov_base = discard_const_p(char, buf);
	tmp.iov_len = len;

	ZERO_STRUCT(msg);
	msg.msg_name = NULL;           /* optional address */
	msg.msg_namelen = 0;           /* size of address */
	msg.msg_iov = &tmp;            /* scatter/gather array */
	msg.msg_iovlen = 1;            /* # elements in msg_iov */
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
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

	ret = libc_write(s, buf, len);

	swrap_sendmsg_after(s, si, &msg, NULL, ret);

	return ret;
}

ssize_t write(int s, const void *buf, size_t len)
{
	return swrap_write(s, buf, len);
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
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
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
	struct swrap_address convert_addr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
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
		uint8_t *tmp_control = NULL;
		rc = swrap_recvmsg_before_unix(omsg, &msg, &tmp_control);
		if (rc < 0) {
			return rc;
		}
		ret = libc_recvmsg(s, &msg, flags);
		return swrap_recvmsg_after_unix(&msg, &tmp_control, omsg, ret);
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

	/*
	 * We convert the unix address to a IP address so we need a buffer
	 * which can store the address in case of SOCK_DGRAM, see below.
	 */
	msg.msg_name = &convert_addr.sa;
	msg.msg_namelen = convert_addr.sa_socklen;

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

	SWRAP_LOCK_SI(si);

	/*
	 * From the manpage:
	 *
	 * The  msg_name  field  points  to a caller-allocated buffer that is
	 * used to return the source address if the socket is unconnected.  The
	 * caller should set msg_namelen to the size of this buffer before this
	 * call; upon return from a successful call, msg_name will contain the
	 * length of the returned address.  If the application  does  not  need
	 * to know the source address, msg_name can be specified as NULL.
	 */
	if (si->type == SOCK_STREAM) {
		omsg->msg_namelen = 0;
	} else if (omsg->msg_name != NULL &&
	           omsg->msg_namelen != 0 &&
	           omsg->msg_namelen >= msg.msg_namelen) {
		memcpy(omsg->msg_name, msg.msg_name, msg.msg_namelen);
		omsg->msg_namelen = msg.msg_namelen;
	}

	SWRAP_UNLOCK_SI(si);

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
		int scm_rights_pipe_fd = -1;

		rc = swrap_sendmsg_before_unix(omsg, &msg,
					       &scm_rights_pipe_fd);
		if (rc < 0) {
			return rc;
		}
		ret = libc_sendmsg(s, &msg, flags);
		return swrap_sendmsg_after_unix(&msg, ret, scm_rights_pipe_fd);
	}

	ZERO_STRUCT(un_addr);

	tmp.iov_base = NULL;
	tmp.iov_len = 0;

	ZERO_STRUCT(msg);

	SWRAP_LOCK_SI(si);

	if (si->connected == 0) {
		msg.msg_name = omsg->msg_name;             /* optional address */
		msg.msg_namelen = omsg->msg_namelen;       /* size of address */
	}
	msg.msg_iov = omsg->msg_iov;               /* scatter/gather array */
	msg.msg_iovlen = omsg->msg_iovlen;         /* # elements in msg_iov */

	SWRAP_UNLOCK_SI(si);

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	if (omsg != NULL && omsg->msg_controllen > 0 && omsg->msg_control != NULL) {
		uint8_t *cmbuf = NULL;
		size_t cmlen = 0;

		rc = swrap_sendmsg_filter_cmsghdr(omsg, &cmbuf, &cmlen);
		if (rc < 0) {
			return rc;
		}

		if (cmlen == 0) {
			msg.msg_controllen = 0;
			msg.msg_control = NULL;
		} else {
			msg.msg_control = cmbuf;
			msg.msg_controllen = cmlen;
		}
	}
	msg.msg_flags = omsg->msg_flags;           /* flags on received message */
#endif
	rc = swrap_sendmsg_before(s, si, &msg, &tmp, &un_addr, &to_un, &to, &bcast);
	if (rc < 0) {
		int saved_errno = errno;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
		SAFE_FREE(msg.msg_control);
#endif
		errno = saved_errno;
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
		char *swrap_dir = NULL;

		for (i = 0; i < (size_t)msg.msg_iovlen; i++) {
			avail += msg.msg_iov[i].iov_len;
		}

		len = avail;
		remain = avail;

		/* we capture it as one single packet */
		buf = (uint8_t *)malloc(remain);
		if (!buf) {
			int saved_errno = errno;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
			SAFE_FREE(msg.msg_control);
#endif
			errno = saved_errno;
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

		swrap_dir = socket_wrapper_dir();
		if (swrap_dir == NULL) {
			int saved_errno = errno;
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
			SAFE_FREE(msg.msg_control);
#endif
			SAFE_FREE(buf);
			errno = saved_errno;
			return -1;
		}

		for(iface=0; iface <= MAX_WRAPPED_INTERFACES; iface++) {
			swrap_un_path(&un_addr, swrap_dir, type, iface, prt);
			if (stat(un_addr.sun_path, &st) != 0) continue;

			msg.msg_name = &un_addr;           /* optional address */
			msg.msg_namelen = sizeof(un_addr); /* size of address */

			/* ignore the any errors in broadcast sends */
			libc_sendmsg(s, &msg, flags);
		}

		SAFE_FREE(swrap_dir);

		SWRAP_LOCK_SI(si);

		swrap_pcap_dump_packet(si, to, SWRAP_SENDTO, buf, len);
		free(buf);

		SWRAP_UNLOCK_SI(si);

		return len;
	}

	ret = libc_sendmsg(s, &msg, flags);

	swrap_sendmsg_after(s, si, &msg, to, ret);

#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
	{
		int saved_errno = errno;
		SAFE_FREE(msg.msg_control);
		errno = saved_errno;
	}
#endif

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
#ifdef HAVE_STRUCT_MSGHDR_MSG_CONTROL
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

static int swrap_remove_wrapper(const char *__func_name,
				int (*__close_fd_fn)(int fd),
				int fd)
{
	struct socket_info *si = NULL;
	int si_index;
	int ret_errno = errno;
	int ret;

	swrap_mutex_lock(&socket_reset_mutex);

	si_index = find_socket_info_index(fd);
	if (si_index == -1) {
		swrap_mutex_unlock(&socket_reset_mutex);
		return __close_fd_fn(fd);
	}

	swrap_log(SWRAP_LOG_TRACE, __func_name, "Remove wrapper for fd=%d", fd);
	reset_socket_info_index(fd);

	si = swrap_get_socket_info(si_index);

	swrap_mutex_lock(&first_free_mutex);
	SWRAP_LOCK_SI(si);

	ret = __close_fd_fn(fd);
	if (ret == -1) {
		ret_errno = errno;
	}

	swrap_dec_refcount(si);

	if (swrap_get_refcount(si) > 0) {
		/* there are still references left */
		goto out;
	}

	if (si->fd_passed) {
		goto set_next_free;
	}

	if (si->myname.sa_socklen > 0 && si->peername.sa_socklen > 0) {
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_SEND, NULL, 0);
	}

	if (si->myname.sa_socklen > 0 && si->peername.sa_socklen > 0) {
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_RECV, NULL, 0);
		swrap_pcap_dump_packet(si, NULL, SWRAP_CLOSE_ACK, NULL, 0);
	}

	if (si->un_addr.sun_path[0] != '\0') {
		unlink(si->un_addr.sun_path);
	}

set_next_free:
	swrap_set_next_free(si, first_free);
	first_free = si_index;

out:
	SWRAP_UNLOCK_SI(si);
	swrap_mutex_unlock(&first_free_mutex);
	swrap_mutex_unlock(&socket_reset_mutex);

	errno = ret_errno;
	return ret;
}

static int swrap_noop_close(int fd)
{
	(void)fd; /* unused */
	return 0;
}

static void swrap_remove_stale(int fd)
{
	swrap_remove_wrapper(__func__, swrap_noop_close, fd);
}

/*
 * This allows socket_wrapper aware applications to
 * indicate that the given fd does not belong to
 * an inet socket.
 *
 * We already overload a lot of unrelated functions
 * like eventfd(), timerfd_create(), ... in order to
 * call swrap_remove_stale() on the returned fd, but
 * we'll never be able to handle all possible syscalls.
 *
 * socket_wrapper_indicate_no_inet_fd() gives them a way
 * to do the same.
 *
 * We don't export swrap_remove_stale() in order to
 * make it easier to analyze SOCKET_WRAPPER_DEBUGLEVEL=3
 * log files.
 */
void socket_wrapper_indicate_no_inet_fd(int fd)
{
	swrap_remove_wrapper(__func__, swrap_noop_close, fd);
}

static int swrap_close(int fd)
{
	return swrap_remove_wrapper(__func__, libc_close, fd);
}

int close(int fd)
{
	return swrap_close(fd);
}

#ifdef HAVE___CLOSE_NOCANCEL

static int swrap___close_nocancel(int fd)
{
	return swrap_remove_wrapper(__func__, libc___close_nocancel, fd);
}

int __close_nocancel(int fd);
int __close_nocancel(int fd)
{
	return swrap___close_nocancel(fd);
}

#endif /* HAVE___CLOSE_NOCANCEL */

/****************************
 * DUP
 ***************************/

static int swrap_dup(int fd)
{
	struct socket_info *si;
	int dup_fd, idx;

	idx = find_socket_info_index(fd);
	if (idx == -1) {
		return libc_dup(fd);
	}

	si = swrap_get_socket_info(idx);

	dup_fd = libc_dup(fd);
	if (dup_fd == -1) {
		int saved_errno = errno;
		errno = saved_errno;
		return -1;
	}

	if ((size_t)dup_fd >= socket_fds_max) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  dup_fd);
		libc_close(dup_fd);
		errno = EMFILE;
		return -1;
	}

	SWRAP_LOCK_SI(si);

	swrap_inc_refcount(si);

	SWRAP_UNLOCK_SI(si);

	/* Make sure we don't have an entry for the fd */
	swrap_remove_stale(dup_fd);

	set_socket_info_index(dup_fd, idx);

	return dup_fd;
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
	int dup_fd, idx;

	idx = find_socket_info_index(fd);
	if (idx == -1) {
		return libc_dup2(fd, newfd);
	}

	si = swrap_get_socket_info(idx);

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
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  newfd);
		errno = EMFILE;
		return -1;
	}

	if (find_socket_info(newfd)) {
		/* dup2() does an implicit close of newfd, which we
		 * need to emulate */
		swrap_close(newfd);
	}

	dup_fd = libc_dup2(fd, newfd);
	if (dup_fd == -1) {
		int saved_errno = errno;
		errno = saved_errno;
		return -1;
	}

	SWRAP_LOCK_SI(si);

	swrap_inc_refcount(si);

	SWRAP_UNLOCK_SI(si);

	/* Make sure we don't have an entry for the fd */
	swrap_remove_stale(dup_fd);

	set_socket_info_index(dup_fd, idx);

	return dup_fd;
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
	struct socket_info *si;
	int rc, dup_fd, idx;

	idx = find_socket_info_index(fd);
	if (idx == -1) {
		return libc_vfcntl(fd, cmd, va);
	}

	si = swrap_get_socket_info(idx);

	switch (cmd) {
	case F_DUPFD:
		dup_fd = libc_vfcntl(fd, cmd, va);
		if (dup_fd == -1) {
			int saved_errno = errno;
			errno = saved_errno;
			return -1;
		}

		/* Make sure we don't have an entry for the fd */
		swrap_remove_stale(dup_fd);

		if ((size_t)dup_fd >= socket_fds_max) {
			SWRAP_LOG(SWRAP_LOG_ERROR,
			  "The max socket index limit of %zu has been reached, "
			  "trying to add %d",
			  socket_fds_max,
			  dup_fd);
			libc_close(dup_fd);
			errno = EMFILE;
			return -1;
		}

		SWRAP_LOCK_SI(si);

		swrap_inc_refcount(si);

		SWRAP_UNLOCK_SI(si);


		set_socket_info_index(dup_fd, idx);

		rc = dup_fd;
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

#ifdef HAVE_PLEDGE
int pledge(const char *promises, const char *paths[])
{
	(void)promises; /* unused */
	(void)paths; /* unused */

	return 0;
}
#endif /* HAVE_PLEDGE */

static void swrap_thread_prepare(void)
{
	/*
	 * This function should only be called here!!
	 *
	 * We bind all symobls to avoid deadlocks of the fork is
	 * interrupted by a signal handler using a symbol of this
	 * library.
	 */
	swrap_bind_symbol_all();

	SWRAP_LOCK_ALL;
}

static void swrap_thread_parent(void)
{
	SWRAP_UNLOCK_ALL;
}

static void swrap_thread_child(void)
{
	SWRAP_REINIT_ALL;
}

/****************************
 * CONSTRUCTOR
 ***************************/
void swrap_constructor(void)
{
	if (PIPE_BUF < sizeof(struct swrap_unix_scm_rights)) {
		SWRAP_LOG(SWRAP_LOG_ERROR,
			  "PIPE_BUF=%zu < "
			  "sizeof(struct swrap_unix_scm_rights)=%zu\n"
			  "sizeof(struct swrap_unix_scm_rights_payload)=%zu "
			  "sizeof(struct socket_info)=%zu",
			  (size_t)PIPE_BUF,
			  sizeof(struct swrap_unix_scm_rights),
			  sizeof(struct swrap_unix_scm_rights_payload),
			  sizeof(struct socket_info));
		exit(-1);
	}

	SWRAP_REINIT_ALL;

	/*
	* If we hold a lock and the application forks, then the child
	* is not able to unlock the mutex and we are in a deadlock.
	* This should prevent such deadlocks.
	*/
	pthread_atfork(&swrap_thread_prepare,
		       &swrap_thread_parent,
		       &swrap_thread_child);
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
void swrap_destructor(void)
{
	size_t i;

	if (socket_fds_idx != NULL) {
		for (i = 0; i < socket_fds_max; ++i) {
			if (socket_fds_idx[i] != -1) {
				swrap_close(i);
			}
		}
		SAFE_FREE(socket_fds_idx);
	}

	SAFE_FREE(sockets);

	if (swrap.libc.handle != NULL) {
		dlclose(swrap.libc.handle);
	}
	if (swrap.libc.socket_handle) {
		dlclose(swrap.libc.socket_handle);
	}
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
 * there we noticed that providing '_read'
 * and '_open' would cause errors, which
 * means we skip '_read', '_write' and
 * all non socket related calls without
 * further analyzing the problem.
 */
#define SWRAP_SYMBOL_ALIAS(__sym, __aliassym) \
	extern typeof(__sym) __aliassym __attribute__ ((alias(#__sym)))

#ifdef HAVE_ACCEPT4
SWRAP_SYMBOL_ALIAS(accept4, _accept4);
#endif
SWRAP_SYMBOL_ALIAS(accept, _accept);
SWRAP_SYMBOL_ALIAS(bind, _bind);
SWRAP_SYMBOL_ALIAS(close, _close);
SWRAP_SYMBOL_ALIAS(connect, _connect);
SWRAP_SYMBOL_ALIAS(dup, _dup);
SWRAP_SYMBOL_ALIAS(dup2, _dup2);
SWRAP_SYMBOL_ALIAS(fcntl, _fcntl);
SWRAP_SYMBOL_ALIAS(getpeername, _getpeername);
SWRAP_SYMBOL_ALIAS(getsockname, _getsockname);
SWRAP_SYMBOL_ALIAS(getsockopt, _getsockopt);
SWRAP_SYMBOL_ALIAS(ioctl, _ioctl);
SWRAP_SYMBOL_ALIAS(listen, _listen);
SWRAP_SYMBOL_ALIAS(readv, _readv);
SWRAP_SYMBOL_ALIAS(recv, _recv);
SWRAP_SYMBOL_ALIAS(recvfrom, _recvfrom);
SWRAP_SYMBOL_ALIAS(recvmsg, _recvmsg);
SWRAP_SYMBOL_ALIAS(send, _send);
SWRAP_SYMBOL_ALIAS(sendmsg, _sendmsg);
SWRAP_SYMBOL_ALIAS(sendto, _sendto);
SWRAP_SYMBOL_ALIAS(setsockopt, _setsockopt);
SWRAP_SYMBOL_ALIAS(socket, _socket);
SWRAP_SYMBOL_ALIAS(socketpair, _socketpair);
SWRAP_SYMBOL_ALIAS(writev, _writev);

#endif /* SOCKET_WRAPPER_EXPORT_UNDERSCORE_SYMBOLS */
