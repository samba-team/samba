/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2007,      Stefan Metzmacher <metze@samba.org>
 * Copyright (c) 2009,      Guenther Deschner <gd@samba.org>
 * Copyright (c) 2014-2015, Michael Adam <obnox@samba.org>
 * Copyright (c) 2015,      Robin Hack <hack.robin@gmail.com>
 * Copyright (c) 2013-2018, Andreas Schneider <asn@samba.org>
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

#include "config.h"

#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <netinet/in.h>

#include <search.h>
#include <assert.h>

/*
 * Defining _POSIX_PTHREAD_SEMANTICS before including pwd.h and grp.h  gives us
 * the posix getpwnam_r(), getpwuid_r(), getgrnam_r and getgrgid_r calls on
 * Solaris
 */
#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS
#endif

#include <pwd.h>
#include <grp.h>
#ifdef HAVE_SHADOW_H
#include <shadow.h>
#endif /* HAVE_SHADOW_H */

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <dlfcn.h>

#if defined(HAVE_NSS_H)
/* Linux and BSD */
#include <nss.h>

typedef enum nss_status NSS_STATUS;
#elif defined(HAVE_NSS_COMMON_H)
/* Solaris */
#include <nss_common.h>
#include <nss_dbdefs.h>
#include <nsswitch.h>

typedef nss_status_t NSS_STATUS;

# define NSS_STATUS_SUCCESS     NSS_SUCCESS
# define NSS_STATUS_NOTFOUND    NSS_NOTFOUND
# define NSS_STATUS_UNAVAIL     NSS_UNAVAIL
# define NSS_STATUS_TRYAGAIN    NSS_TRYAGAIN
#else
# error "No nsswitch support detected"
#endif

#ifndef PTR_DIFF
#define PTR_DIFF(p1, p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))
#endif

#ifndef _PUBLIC_
#define _PUBLIC_
#endif

#ifndef EAI_NODATA
#define EAI_NODATA EAI_NONAME
#endif

#ifndef EAI_ADDRFAMILY
#define EAI_ADDRFAMILY EAI_FAMILY
#endif

#ifndef __STRING
#define __STRING(x)    #x
#endif

#ifndef __STRINGSTRING
#define __STRINGSTRING(x) __STRING(x)
#endif

#ifndef __LINESTR__
#define __LINESTR__ __STRINGSTRING(__LINE__)
#endif

#ifndef __location__
#define __location__ __FILE__ ":" __LINESTR__
#endif

#ifndef DNS_NAME_MAX
#define DNS_NAME_MAX 255
#endif

/* GCC have printf type attribute check. */
#ifdef HAVE_ATTRIBUTE_PRINTF_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_ATTRIBUTE_PRINTF_FORMAT */

#ifdef HAVE_CONSTRUCTOR_ATTRIBUTE
#define CONSTRUCTOR_ATTRIBUTE __attribute__ ((constructor))
#else
#define CONSTRUCTOR_ATTRIBUTE
#endif /* HAVE_CONSTRUCTOR_ATTRIBUTE */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#ifdef HAVE_IPV6
#define NWRAP_INET_ADDRSTRLEN INET6_ADDRSTRLEN
#else
#define NWRAP_INET_ADDRSTRLEN INET_ADDRSTRLEN
#endif

#define NWRAP_LOCK(m) do { \
	pthread_mutex_lock(&( m ## _mutex)); \
} while(0)

#define NWRAP_UNLOCK(m) do { \
	pthread_mutex_unlock(&( m ## _mutex)); \
} while(0)

static pthread_mutex_t libc_symbol_binding_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nss_module_symbol_binding_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool nwrap_initialized = false;
static pthread_mutex_t nwrap_initialized_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The mutex or accessing the id */
static pthread_mutex_t nwrap_global_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nwrap_gr_global_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nwrap_he_global_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nwrap_pw_global_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nwrap_sp_global_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Add new global locks here please */
/* Also don't forget to add locks to
 * nwrap_init() function.
 */
# define NWRAP_LOCK_ALL do { \
	NWRAP_LOCK(libc_symbol_binding); \
	NWRAP_LOCK(nss_module_symbol_binding); \
	NWRAP_LOCK(nwrap_initialized); \
	NWRAP_LOCK(nwrap_global); \
	NWRAP_LOCK(nwrap_gr_global); \
	NWRAP_LOCK(nwrap_he_global); \
	NWRAP_LOCK(nwrap_pw_global); \
	NWRAP_LOCK(nwrap_sp_global); \
} while (0);

# define NWRAP_UNLOCK_ALL do {\
	NWRAP_UNLOCK(nwrap_sp_global); \
	NWRAP_UNLOCK(nwrap_pw_global); \
	NWRAP_UNLOCK(nwrap_he_global); \
	NWRAP_UNLOCK(nwrap_gr_global); \
	NWRAP_UNLOCK(nwrap_global); \
	NWRAP_UNLOCK(nwrap_initialized); \
	NWRAP_UNLOCK(nss_module_symbol_binding); \
	NWRAP_UNLOCK(libc_symbol_binding); \
} while (0);

static void nwrap_init(void);

static void nwrap_thread_prepare(void)
{
	nwrap_init();
	NWRAP_LOCK_ALL;
}

static void nwrap_thread_parent(void)
{
	NWRAP_UNLOCK_ALL;
}

static void nwrap_thread_child(void)
{
	NWRAP_UNLOCK_ALL;
}

enum nwrap_dbglvl_e {
	NWRAP_LOG_ERROR = 0,
	NWRAP_LOG_WARN,
	NWRAP_LOG_DEBUG,
	NWRAP_LOG_TRACE
};

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

static void nwrap_log(enum nwrap_dbglvl_e dbglvl, const char *func, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define NWRAP_LOG(dbglvl, ...) nwrap_log((dbglvl), __func__, __VA_ARGS__)

static void nwrap_log(enum nwrap_dbglvl_e dbglvl,
		      const char *func,
		      const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = "NWRAP";
	const char *progname = getprogname();

	d = getenv("NSS_WRAPPER_DEBUGLEVEL");
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
		case NWRAP_LOG_ERROR:
			prefix = "NWRAP_ERROR";
			break;
		case NWRAP_LOG_WARN:
			prefix = "NWRAP_WARN";
			break;
		case NWRAP_LOG_DEBUG:
			prefix = "NWRAP_DEBUG";
			break;
		case NWRAP_LOG_TRACE:
			prefix = "NWRAP_TRACE";
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

/*****************
 * LIBC
 *****************/

#define LIBC_NAME "libc.so"

typedef struct passwd *(*__libc_getpwnam)(const char *name);

typedef int (*__libc_getpwnam_r)(const char *name,
				 struct passwd *pwd,
				 char *buf,
				 size_t buflen,
				 struct passwd **result);

typedef struct passwd *(*__libc_getpwuid)(uid_t uid);

typedef int (*__libc_getpwuid_r)(uid_t uid,
				 struct passwd *pwd,
				 char *buf,
				 size_t buflen,
				 struct passwd **result);

typedef void (*__libc_setpwent)(void);

typedef struct passwd *(*__libc_getpwent)(void);

#ifdef HAVE_GETPWENT_R
# ifdef HAVE_SOLARIS_GETPWENT_R
typedef struct passwd *(*__libc_getpwent_r)(struct passwd *pwbuf,
					    char *buf,
					    size_t buflen);
# else /* HAVE_SOLARIS_GETPWENT_R */
typedef int (*__libc_getpwent_r)(struct passwd *pwbuf,
				 char *buf,
				 size_t buflen,
				 struct passwd **pwbufp);
# endif /* HAVE_SOLARIS_GETPWENT_R */
#endif /* HAVE_GETPWENT_R */

typedef void (*__libc_endpwent)(void);

typedef int (*__libc_initgroups)(const char *user, gid_t gid);

typedef struct group *(*__libc_getgrnam)(const char *name);

typedef int (*__libc_getgrnam_r)(const char *name,
				 struct group *grp,
				 char *buf,
				 size_t buflen,
				 struct group **result);

typedef struct group *(*__libc_getgrgid)(gid_t gid);

typedef int (*__libc_getgrgid_r)(gid_t gid,
				 struct group *grp,
				 char *buf,
				 size_t buflen,
				 struct group **result);

typedef void (*__libc_setgrent)(void);

typedef struct group *(*__libc_getgrent)(void);

#ifdef HAVE_GETGRENT_R
# ifdef HAVE_SOLARIS_GETGRENT_R
typedef struct group *(*__libc_getgrent_r)(struct group *group,
					   char *buf,
					   size_t buflen);
# else /* HAVE_SOLARIS_GETGRENT_R */
typedef int (*__libc_getgrent_r)(struct group *group,
				 char *buf,
				 size_t buflen,
				 struct group **result);
# endif /* HAVE_SOLARIS_GETGRENT_R */
#endif /* HAVE_GETGRENT_R */

typedef void (*__libc_endgrent)(void);

typedef int (*__libc_getgrouplist)(const char *user,
				   gid_t group,
				   gid_t *groups,
				   int *ngroups);

typedef void (*__libc_sethostent)(int stayopen);

typedef struct hostent *(*__libc_gethostent)(void);

typedef void (*__libc_endhostent)(void);

typedef struct hostent *(*__libc_gethostbyname)(const char *name);

#ifdef HAVE_GETHOSTBYNAME2 /* GNU extension */
typedef struct hostent *(*__libc_gethostbyname2)(const char *name, int af);
#endif

#ifdef HAVE_GETHOSTBYNAME2_R /* GNU extension */
typedef int (*__libc_gethostbyname2_r)(const char *name,
			      int af,
			      struct hostent *ret,
			      char *buf,
			      size_t buflen,
			      struct hostent **result,
			      int *h_errnop);
#endif

typedef struct hostent *(*__libc_gethostbyaddr)(const void *addr,
						socklen_t len,
						int type);

typedef int (*__libc_getaddrinfo)(const char *node,
				  const char *service,
				  const struct addrinfo *hints,
				  struct addrinfo **res);
typedef int (*__libc_getnameinfo)(const struct sockaddr *sa,
				  socklen_t salen,
				  char *host,
				  size_t hostlen,
				  char *serv,
				  size_t servlen,
				  int flags);

typedef int (*__libc_gethostname)(char *name, size_t len);

#ifdef HAVE_GETHOSTBYNAME_R
typedef int (*__libc_gethostbyname_r)(const char *name,
			     struct hostent *ret,
			     char *buf, size_t buflen,
			     struct hostent **result, int *h_errnop);
#endif

#ifdef HAVE_GETHOSTBYADDR_R
typedef int (*__libc_gethostbyaddr_r)(const void *addr,
				      socklen_t len,
				      int type,
				      struct hostent *ret,
				      char *buf,
				      size_t buflen,
				      struct hostent **result,
				      int *h_errnop);
#endif

#define NWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libc_##i f; \
		void *obj; \
	} _libc_##i

struct nwrap_libc_symbols {
	NWRAP_SYMBOL_ENTRY(getpwnam);
	NWRAP_SYMBOL_ENTRY(getpwnam_r);
	NWRAP_SYMBOL_ENTRY(getpwuid);
	NWRAP_SYMBOL_ENTRY(getpwuid_r);
	NWRAP_SYMBOL_ENTRY(setpwent);
	NWRAP_SYMBOL_ENTRY(getpwent);
#ifdef HAVE_GETPWENT_R
	NWRAP_SYMBOL_ENTRY(getpwent_r);
#endif
	NWRAP_SYMBOL_ENTRY(endpwent);

	NWRAP_SYMBOL_ENTRY(initgroups);
	NWRAP_SYMBOL_ENTRY(getgrnam);
	NWRAP_SYMBOL_ENTRY(getgrnam_r);
	NWRAP_SYMBOL_ENTRY(getgrgid);
	NWRAP_SYMBOL_ENTRY(getgrgid_r);
	NWRAP_SYMBOL_ENTRY(setgrent);
	NWRAP_SYMBOL_ENTRY(getgrent);
#ifdef HAVE_GETGRENT_R
	NWRAP_SYMBOL_ENTRY(getgrent_r);
#endif
	NWRAP_SYMBOL_ENTRY(endgrent);
	NWRAP_SYMBOL_ENTRY(getgrouplist);

	NWRAP_SYMBOL_ENTRY(sethostent);
	NWRAP_SYMBOL_ENTRY(gethostent);
	NWRAP_SYMBOL_ENTRY(endhostent);
	NWRAP_SYMBOL_ENTRY(gethostbyname);
#ifdef HAVE_GETHOSTBYNAME_R
	NWRAP_SYMBOL_ENTRY(gethostbyname_r);
#endif
#ifdef HAVE_GETHOSTBYNAME2
	NWRAP_SYMBOL_ENTRY(gethostbyname2);
#endif
#ifdef HAVE_GETHOSTBYNAME2_R
	NWRAP_SYMBOL_ENTRY(gethostbyname2_r);
#endif
	NWRAP_SYMBOL_ENTRY(gethostbyaddr);
#ifdef HAVE_GETHOSTBYADDR_R
	NWRAP_SYMBOL_ENTRY(gethostbyaddr_r);
#endif
	NWRAP_SYMBOL_ENTRY(getaddrinfo);
	NWRAP_SYMBOL_ENTRY(getnameinfo);
	NWRAP_SYMBOL_ENTRY(gethostname);
};
#undef NWRAP_SYMBOL_ENTRY

typedef NSS_STATUS (*__nss_getpwnam_r)(const char *name,
				       struct passwd *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_getpwuid_r)(uid_t uid,
				       struct passwd *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_setpwent)(void);
typedef NSS_STATUS (*__nss_getpwent_r)(struct passwd *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_endpwent)(void);
typedef NSS_STATUS (*__nss_initgroups)(const char *user,
				       gid_t group,
				       long int *start,
				       long int *size,
				       gid_t **groups,
				       long int limit,
				       int *errnop);
typedef NSS_STATUS (*__nss_getgrnam_r)(const char *name,
				       struct group *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_getgrgid_r)(gid_t gid,
				       struct group *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_setgrent)(void);
typedef NSS_STATUS (*__nss_getgrent_r)(struct group *result,
				       char *buffer,
				       size_t buflen,
				       int *errnop);
typedef NSS_STATUS (*__nss_endgrent)(void);
typedef NSS_STATUS (*__nss_gethostbyaddr_r)(const void *addr,
					    socklen_t addrlen,
					    int af,
					    struct hostent *result,
					    char *buffer,
					    size_t buflen,
					    int *errnop,
					    int *h_errnop);
typedef NSS_STATUS (*__nss_gethostbyname2_r)(const char *name,
					     int af,
					     struct hostent *result,
					     char *buffer,
					     size_t buflen,
					     int *errnop,
					     int *h_errnop);

#define NWRAP_NSS_MODULE_SYMBOL_ENTRY(i) \
	union { \
		__nss_##i f; \
		void *obj; \
	} _nss_##i

struct nwrap_nss_module_symbols {
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getpwnam_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getpwuid_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(setpwent);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getpwent_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(endpwent);

	NWRAP_NSS_MODULE_SYMBOL_ENTRY(initgroups);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getgrnam_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getgrgid_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(setgrent);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(getgrent_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(endgrent);

	NWRAP_NSS_MODULE_SYMBOL_ENTRY(gethostbyaddr_r);
	NWRAP_NSS_MODULE_SYMBOL_ENTRY(gethostbyname2_r);
};

struct nwrap_backend {
	const char *name;
	const char *so_path;
	void *so_handle;
	struct nwrap_ops *ops;
	struct nwrap_nss_module_symbols *symbols;
};

struct nwrap_vector;

struct nwrap_ops {
	struct passwd *	(*nw_getpwnam)(struct nwrap_backend *b,
				       const char *name);
	int		(*nw_getpwnam_r)(struct nwrap_backend *b,
					 const char *name, struct passwd *pwdst,
					 char *buf, size_t buflen, struct passwd **pwdstp);
	struct passwd *	(*nw_getpwuid)(struct nwrap_backend *b,
				       uid_t uid);
	int		(*nw_getpwuid_r)(struct nwrap_backend *b,
					 uid_t uid, struct passwd *pwdst,
					 char *buf, size_t buflen, struct passwd **pwdstp);
	void		(*nw_setpwent)(struct nwrap_backend *b);
	struct passwd *	(*nw_getpwent)(struct nwrap_backend *b);
	int		(*nw_getpwent_r)(struct nwrap_backend *b,
					 struct passwd *pwdst, char *buf,
					 size_t buflen, struct passwd **pwdstp);
	void		(*nw_endpwent)(struct nwrap_backend *b);
	int		(*nw_initgroups)(struct nwrap_backend *b,
					 const char *user, gid_t group);
	struct group *	(*nw_getgrnam)(struct nwrap_backend *b,
				       const char *name);
	int		(*nw_getgrnam_r)(struct nwrap_backend *b,
					 const char *name, struct group *grdst,
					 char *buf, size_t buflen, struct group **grdstp);
	struct group *	(*nw_getgrgid)(struct nwrap_backend *b,
				       gid_t gid);
	int		(*nw_getgrgid_r)(struct nwrap_backend *b,
					 gid_t gid, struct group *grdst,
					 char *buf, size_t buflen, struct group **grdstp);
	void		(*nw_setgrent)(struct nwrap_backend *b);
	struct group *	(*nw_getgrent)(struct nwrap_backend *b);
	int		(*nw_getgrent_r)(struct nwrap_backend *b,
					 struct group *grdst, char *buf,
					 size_t buflen, struct group **grdstp);
	void		(*nw_endgrent)(struct nwrap_backend *b);
	struct hostent *(*nw_gethostbyaddr)(struct nwrap_backend *b,
					    const void *addr,
					    socklen_t len, int type);
	struct hostent *(*nw_gethostbyname)(struct nwrap_backend *b,
					    const char *name);
	struct hostent *(*nw_gethostbyname2)(struct nwrap_backend *b,
					     const char *name, int af);
	int		(*nw_gethostbyname2_r)(struct nwrap_backend *b,
					       const char *name, int af,
					       struct hostent *hedst,
					       char *buf, size_t buflen,
					       struct hostent **hedstp);
};

/* Public prototypes */

bool nss_wrapper_enabled(void);
bool nss_wrapper_shadow_enabled(void);
bool nss_wrapper_hosts_enabled(void);

/* prototypes for files backend */


static struct passwd *nwrap_files_getpwnam(struct nwrap_backend *b,
					   const char *name);
static int nwrap_files_getpwnam_r(struct nwrap_backend *b,
				  const char *name, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp);
static struct passwd *nwrap_files_getpwuid(struct nwrap_backend *b,
					   uid_t uid);
static int nwrap_files_getpwuid_r(struct nwrap_backend *b,
				  uid_t uid, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp);
static void nwrap_files_setpwent(struct nwrap_backend *b);
static struct passwd *nwrap_files_getpwent(struct nwrap_backend *b);
static int nwrap_files_getpwent_r(struct nwrap_backend *b,
				  struct passwd *pwdst, char *buf,
				  size_t buflen, struct passwd **pwdstp);
static void nwrap_files_endpwent(struct nwrap_backend *b);
static int nwrap_files_initgroups(struct nwrap_backend *b,
				  const char *user, gid_t group);
static struct group *nwrap_files_getgrnam(struct nwrap_backend *b,
					  const char *name);
static int nwrap_files_getgrnam_r(struct nwrap_backend *b,
				  const char *name, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp);
static struct group *nwrap_files_getgrgid(struct nwrap_backend *b,
					  gid_t gid);
static int nwrap_files_getgrgid_r(struct nwrap_backend *b,
				  gid_t gid, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp);
static void nwrap_files_setgrent(struct nwrap_backend *b);
static struct group *nwrap_files_getgrent(struct nwrap_backend *b);
static int nwrap_files_getgrent_r(struct nwrap_backend *b,
				  struct group *grdst, char *buf,
				  size_t buflen, struct group **grdstp);
static void nwrap_files_endgrent(struct nwrap_backend *b);
static struct hostent *nwrap_files_gethostbyaddr(struct nwrap_backend *b,
						 const void *addr,
						 socklen_t len, int type);
static struct hostent *nwrap_files_gethostbyname(struct nwrap_backend *b,
						 const char *name);
#ifdef HAVE_GETHOSTBYNAME2
static struct hostent *nwrap_files_gethostbyname2(struct nwrap_backend *b,
						  const char *name, int af);
#endif /* HAVE_GETHOSTBYNAME2 */
static int nwrap_files_gethostbyname2_r(struct nwrap_backend *b,
					const char *name, int af,
					struct hostent *hedst,
					char *buf, size_t buflen,
					struct hostent **hedstp);

/* prototypes for module backend */

static struct passwd *nwrap_module_getpwent(struct nwrap_backend *b);
static int nwrap_module_getpwent_r(struct nwrap_backend *b,
				   struct passwd *pwdst, char *buf,
				   size_t buflen, struct passwd **pwdstp);
static struct passwd *nwrap_module_getpwnam(struct nwrap_backend *b,
					    const char *name);
static int nwrap_module_getpwnam_r(struct nwrap_backend *b,
				   const char *name, struct passwd *pwdst,
				   char *buf, size_t buflen, struct passwd **pwdstp);
static struct passwd *nwrap_module_getpwuid(struct nwrap_backend *b,
					    uid_t uid);
static int nwrap_module_getpwuid_r(struct nwrap_backend *b,
				   uid_t uid, struct passwd *pwdst,
				   char *buf, size_t buflen, struct passwd **pwdstp);
static void nwrap_module_setpwent(struct nwrap_backend *b);
static void nwrap_module_endpwent(struct nwrap_backend *b);
static struct group *nwrap_module_getgrent(struct nwrap_backend *b);
static int nwrap_module_getgrent_r(struct nwrap_backend *b,
				   struct group *grdst, char *buf,
				   size_t buflen, struct group **grdstp);
static struct group *nwrap_module_getgrnam(struct nwrap_backend *b,
					   const char *name);
static int nwrap_module_getgrnam_r(struct nwrap_backend *b,
				   const char *name, struct group *grdst,
				   char *buf, size_t buflen, struct group **grdstp);
static struct group *nwrap_module_getgrgid(struct nwrap_backend *b,
					   gid_t gid);
static int nwrap_module_getgrgid_r(struct nwrap_backend *b,
				   gid_t gid, struct group *grdst,
				   char *buf, size_t buflen, struct group **grdstp);
static void nwrap_module_setgrent(struct nwrap_backend *b);
static void nwrap_module_endgrent(struct nwrap_backend *b);
static int nwrap_module_initgroups(struct nwrap_backend *b,
				   const char *user, gid_t group);
static struct hostent *nwrap_module_gethostbyaddr(struct nwrap_backend *b,
						  const void *addr,
						  socklen_t len, int type);
static struct hostent *nwrap_module_gethostbyname(struct nwrap_backend *b,
						  const char *name);
static struct hostent *nwrap_module_gethostbyname2(struct nwrap_backend *b,
						   const char *name, int af);
static int nwrap_module_gethostbyname2_r(struct nwrap_backend *b,
					 const char *name, int af,
					 struct hostent *hedst,
					 char *buf, size_t buflen,
					 struct hostent **hedstp);

struct nwrap_ops nwrap_files_ops = {
	.nw_getpwnam	= nwrap_files_getpwnam,
	.nw_getpwnam_r	= nwrap_files_getpwnam_r,
	.nw_getpwuid	= nwrap_files_getpwuid,
	.nw_getpwuid_r	= nwrap_files_getpwuid_r,
	.nw_setpwent	= nwrap_files_setpwent,
	.nw_getpwent	= nwrap_files_getpwent,
	.nw_getpwent_r	= nwrap_files_getpwent_r,
	.nw_endpwent	= nwrap_files_endpwent,
	.nw_initgroups	= nwrap_files_initgroups,
	.nw_getgrnam	= nwrap_files_getgrnam,
	.nw_getgrnam_r	= nwrap_files_getgrnam_r,
	.nw_getgrgid	= nwrap_files_getgrgid,
	.nw_getgrgid_r	= nwrap_files_getgrgid_r,
	.nw_setgrent	= nwrap_files_setgrent,
	.nw_getgrent	= nwrap_files_getgrent,
	.nw_getgrent_r	= nwrap_files_getgrent_r,
	.nw_endgrent	= nwrap_files_endgrent,
	.nw_gethostbyaddr 	= nwrap_files_gethostbyaddr,
	.nw_gethostbyname	= nwrap_files_gethostbyname,
#ifdef HAVE_GETHOSTBYNAME2
	.nw_gethostbyname2	= nwrap_files_gethostbyname2,
#endif /* HAVE_GETHOSTBYNAME2 */
	.nw_gethostbyname2_r	= nwrap_files_gethostbyname2_r,
};

struct nwrap_ops nwrap_module_ops = {
	.nw_getpwnam	= nwrap_module_getpwnam,
	.nw_getpwnam_r	= nwrap_module_getpwnam_r,
	.nw_getpwuid	= nwrap_module_getpwuid,
	.nw_getpwuid_r	= nwrap_module_getpwuid_r,
	.nw_setpwent	= nwrap_module_setpwent,
	.nw_getpwent	= nwrap_module_getpwent,
	.nw_getpwent_r	= nwrap_module_getpwent_r,
	.nw_endpwent	= nwrap_module_endpwent,
	.nw_initgroups	= nwrap_module_initgroups,
	.nw_getgrnam	= nwrap_module_getgrnam,
	.nw_getgrnam_r	= nwrap_module_getgrnam_r,
	.nw_getgrgid	= nwrap_module_getgrgid,
	.nw_getgrgid_r	= nwrap_module_getgrgid_r,
	.nw_setgrent	= nwrap_module_setgrent,
	.nw_getgrent	= nwrap_module_getgrent,
	.nw_getgrent_r	= nwrap_module_getgrent_r,
	.nw_endgrent	= nwrap_module_endgrent,
	.nw_gethostbyaddr 	= nwrap_module_gethostbyaddr,
	.nw_gethostbyname	= nwrap_module_gethostbyname,
	.nw_gethostbyname2	= nwrap_module_gethostbyname2,
	.nw_gethostbyname2_r	= nwrap_module_gethostbyname2_r,
};

struct nwrap_libc {
	void *handle;
	void *nsl_handle;
	void *sock_handle;
	struct nwrap_libc_symbols symbols;
};

struct nwrap_main {
	size_t num_backends;
	struct nwrap_backend *backends;
	struct nwrap_libc *libc;
};

static struct nwrap_main *nwrap_main_global;
static struct nwrap_main __nwrap_main_global;

/*
 * PROTOTYPES
 */
static int nwrap_convert_he_ai(const struct hostent *he,
			       unsigned short port,
			       const struct addrinfo *hints,
			       struct addrinfo **pai,
			       bool skip_canonname);

/*
 * VECTORS
 */

#define DEFAULT_VECTOR_CAPACITY 16

struct nwrap_vector {
	void **items;
	size_t count;
	size_t capacity;
};

/* Macro returns pointer to first element of vector->items array.
 *
 * nwrap_vector is used as a memory backend which take care of
 * memory allocations and other stuff like memory growing.
 * nwrap_vectors should not be considered as some abstract structures.
 * On this level, vectors are more handy than direct realloc/malloc
 * calls.
 *
 * nwrap_vector->items is array inside nwrap_vector which can be
 * directly pointed by libc structure assembled by cwrap itself.
 *
 * EXAMPLE:
 *
 * 1) struct hostent contains char **h_addr_list element.
 * 2) nwrap_vector holds array of pointers to addresses.
 *    It's easier to use vector to store results of
 *    file parsing etc.
 *
 * Now, pretend that cwrap assembled struct hostent and
 * we need to set h_addr_list to point to nwrap_vector.
 * Idea behind is to shield users from internal nwrap_vector
 * implementation.
 * (Yes, not fully - array terminated by NULL is needed because
 * it's result expected by libc function caller.)
 *
 *
 * CODE EXAMPLE:
 *
 * struct hostent he;
 * struct nwrap_vector *vector = malloc(sizeof(struct nwrap_vector));
 * ... don't care about failed allocation now ...
 *
 * ... fill nwrap vector ...
 *
 * struct hostent he;
 * he.h_addr_list = nwrap_vector_head(vector);
 *
 */
#define nwrap_vector_head(vect) ((void *)((vect)->items))

#define nwrap_vector_foreach(item, vect, iter) \
	for (iter = 0, (item) = (vect).items == NULL ? NULL : (vect).items[0]; \
	     item != NULL; \
	     (item) = (vect).items[++iter])

#define nwrap_vector_is_initialized(vector) ((vector)->items != NULL)

static inline bool nwrap_vector_init(struct nwrap_vector *const vector)
{
	if (vector == NULL) {
		return false;
	}

	/* count is initialized by ZERO_STRUCTP */
	ZERO_STRUCTP(vector);
	vector->items = malloc(sizeof(void *) * (DEFAULT_VECTOR_CAPACITY + 1));
	if (vector->items == NULL) {
		return false;
	}
	vector->capacity = DEFAULT_VECTOR_CAPACITY;
	memset(vector->items, '\0', sizeof(void *) * (DEFAULT_VECTOR_CAPACITY + 1));

	return true;
}

static bool nwrap_vector_add_item(struct nwrap_vector *vector, void *const item)
{
	assert (vector != NULL);

	if (vector->items == NULL) {
		nwrap_vector_init(vector);
	}

	if (vector->count == vector->capacity) {
		/* Items array _MUST_ be NULL terminated because it's passed
		 * as result to caller which expect NULL terminated array from libc.
		 */
		void **items = realloc(vector->items, sizeof(void *) * ((vector->capacity * 2) + 1));
		if (items == NULL) {
			return false;
		}
		vector->items = items;

		/* Don't count ending NULL to capacity */
		vector->capacity *= 2;
	}

	vector->items[vector->count] = item;

	vector->count += 1;
	vector->items[vector->count] = NULL;

	return true;
}

static bool nwrap_vector_merge(struct nwrap_vector *dst,
			       struct nwrap_vector *src)
{
	void **dst_items = NULL;
	size_t count;

	if (src->count == 0) {
		return true;
	}

	count = dst->count + src->count;

	/* We don't need reallocation if we have enough capacity. */
	if (src->count > (dst->capacity - dst->count)) {
		dst_items = (void **)realloc(dst->items, (count + 1) * sizeof(void *));
		if (dst_items == NULL) {
			return false;
		}
		dst->items = dst_items;
		dst->capacity = count;
	}

	memcpy((void *)(((long *)dst->items) + dst->count),
	       src->items,
	       src->count * sizeof(void *));
	dst->count = count;

	return true;
}

struct nwrap_cache {
	const char *path;
	int fd;
	FILE *fp;
	struct stat st;
	void *private_data;

	struct nwrap_vector lines;

	bool (*parse_line)(struct nwrap_cache *, char *line);
	void (*unload)(struct nwrap_cache *);
};

/* passwd */
struct nwrap_pw {
	struct nwrap_cache *cache;

	struct passwd *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_pw;
struct nwrap_pw nwrap_pw_global;

static bool nwrap_pw_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_pw_unload(struct nwrap_cache *nwrap);

/* shadow */
#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)
struct nwrap_sp {
	struct nwrap_cache *cache;

	struct spwd *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_sp;
struct nwrap_sp nwrap_sp_global;

static bool nwrap_sp_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_sp_unload(struct nwrap_cache *nwrap);
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

/* group */
struct nwrap_gr {
	struct nwrap_cache *cache;

	struct group *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_gr;
struct nwrap_gr nwrap_gr_global;

/* hosts */
static bool nwrap_he_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_he_unload(struct nwrap_cache *nwrap);

struct nwrap_addrdata {
	unsigned char host_addr[16]; /* IPv4 or IPv6 address */
};

static size_t max_hostents = 100;

struct nwrap_entdata {
	struct nwrap_addrdata addr;
	struct hostent ht;

	struct nwrap_vector nwrap_addrdata;

	ssize_t aliases_count;
};

struct nwrap_entlist {
	struct nwrap_entlist *next;
	struct nwrap_entdata *ed;
};

struct nwrap_he {
	struct nwrap_cache *cache;

	struct nwrap_vector entries;
	struct nwrap_vector lists;

	int num;
	int idx;
};

static struct nwrap_cache __nwrap_cache_he;
static struct nwrap_he nwrap_he_global;


/*********************************************************
 * NWRAP PROTOTYPES
 *********************************************************/

static bool nwrap_gr_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_gr_unload(struct nwrap_cache *nwrap);
void nwrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
void nwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * NWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum nwrap_lib {
    NWRAP_LIBC,
    NWRAP_LIBNSL,
    NWRAP_LIBSOCKET,
};

static const char *nwrap_str_lib(enum nwrap_lib lib)
{
	switch (lib) {
	case NWRAP_LIBC:
		return "libc";
	case NWRAP_LIBNSL:
		return "libnsl";
	case NWRAP_LIBSOCKET:
		return "libsocket";
	}

	/* Compiler would warn us about unhandled enum value if we get here */
	return "unknown";
}

static void *nwrap_load_lib_handle(enum nwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	const char *env_preload = getenv("LD_PRELOAD");
	const char *env_deepbind = getenv("NSS_WRAPPER_DISABLE_DEEPBIND");
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
	case NWRAP_LIBNSL:
#ifdef HAVE_LIBNSL
		handle = nwrap_main_global->libc->nsl_handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libnsl.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			nwrap_main_global->libc->nsl_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case NWRAP_LIBSOCKET:
#ifdef HAVE_LIBSOCKET
		handle = nwrap_main_global->libc->sock_handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libsocket.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			nwrap_main_global->libc->sock_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case NWRAP_LIBC:
		handle = nwrap_main_global->libc->handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			nwrap_main_global->libc->handle = handle;
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = nwrap_main_global->libc->handle
		       = nwrap_main_global->libc->sock_handle
		       = nwrap_main_global->libc->nsl_handle
		       = RTLD_NEXT;
#else
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_nwrap_bind_symbol(enum nwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	nwrap_init();

	handle = nwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
				"Failed to find %s: %s\n",
				fn_name, dlerror());
		exit(-1);
	}

	NWRAP_LOG(NWRAP_LOG_TRACE,
			"Loaded %s from %s",
			fn_name, nwrap_str_lib(lib));
	return func;
}

#define nwrap_bind_symbol_libc(sym_name) \
	NWRAP_LOCK(libc_symbol_binding); \
	if (nwrap_main_global->libc->symbols._libc_##sym_name.obj == NULL) { \
		nwrap_main_global->libc->symbols._libc_##sym_name.obj = \
			_nwrap_bind_symbol(NWRAP_LIBC, #sym_name); \
	} \
	NWRAP_UNLOCK(libc_symbol_binding)

#define nwrap_bind_symbol_libc_posix(sym_name) \
	NWRAP_LOCK(libc_symbol_binding); \
	if (nwrap_main_global->libc->symbols._libc_##sym_name.obj == NULL) { \
		nwrap_main_global->libc->symbols._libc_##sym_name.obj = \
			_nwrap_bind_symbol(NWRAP_LIBC, "__posix_" #sym_name); \
	} \
	NWRAP_UNLOCK(libc_symbol_binding)

#define nwrap_bind_symbol_libnsl(sym_name) \
	NWRAP_LOCK(libc_symbol_binding); \
	if (nwrap_main_global->libc->symbols._libc_##sym_name.obj == NULL) { \
		nwrap_main_global->libc->symbols._libc_##sym_name.obj = \
			_nwrap_bind_symbol(NWRAP_LIBNSL, #sym_name); \
	} \
	NWRAP_UNLOCK(libc_symbol_binding)

#define nwrap_bind_symbol_libsocket(sym_name) \
	NWRAP_LOCK(libc_symbol_binding); \
	if (nwrap_main_global->libc->symbols._libc_##sym_name.obj == NULL) { \
		nwrap_main_global->libc->symbols._libc_##sym_name.obj = \
			_nwrap_bind_symbol(NWRAP_LIBSOCKET, #sym_name); \
	} \
	NWRAP_UNLOCK(libc_symbol_binding)

/* INTERNAL HELPER FUNCTIONS */
static void nwrap_lines_unload(struct nwrap_cache *const nwrap)
{
	size_t p;
	void *item;
	nwrap_vector_foreach(item, nwrap->lines, p) {
		/* Maybe some vectors were merged ... */
		SAFE_FREE(item);
	}
	SAFE_FREE(nwrap->lines.items);
	ZERO_STRUCTP(&nwrap->lines);
}

/*
 * IMPORTANT
 *
 * Functions expeciall from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
static struct passwd *libc_getpwnam(const char *name)
{
	nwrap_bind_symbol_libc(getpwnam);

	return nwrap_main_global->libc->symbols._libc_getpwnam.f(name);
}

#ifdef HAVE_GETPWNAM_R
static int libc_getpwnam_r(const char *name,
			   struct passwd *pwd,
			   char *buf,
			   size_t buflen,
			   struct passwd **result)
{
#ifdef HAVE___POSIX_GETPWNAM_R
	nwrap_bind_symbol_libc_posix(getpwnam_r);
#else
	nwrap_bind_symbol_libc(getpwnam_r);
#endif

	return nwrap_main_global->libc->symbols._libc_getpwnam_r.f(name,
								   pwd,
								   buf,
								   buflen,
								   result);
}
#endif

static struct passwd *libc_getpwuid(uid_t uid)
{
	nwrap_bind_symbol_libc(getpwuid);

	return nwrap_main_global->libc->symbols._libc_getpwuid.f(uid);
}

#ifdef HAVE_GETPWUID_R
static int libc_getpwuid_r(uid_t uid,
			   struct passwd *pwd,
			   char *buf,
			   size_t buflen,
			   struct passwd **result)
{
#ifdef HAVE___POSIX_GETPWUID_R
	nwrap_bind_symbol_libc_posix(getpwuid_r);
#else
	nwrap_bind_symbol_libc(getpwuid_r);
#endif

	return nwrap_main_global->libc->symbols._libc_getpwuid_r.f(uid,
								   pwd,
								   buf,
								   buflen,
								   result);
}
#endif

static inline void str_tolower(char *dst, char *src)
{
	register char *src_tmp = src;
	register char *dst_tmp = dst;

	while (*src_tmp != '\0') {
		*dst_tmp = tolower(*src_tmp);
		++src_tmp;
		++dst_tmp;
	}
}

static bool str_tolower_copy(char **dst_name, const char *const src_name)
{
	char *h_name_lower;

	if ((dst_name == NULL) || (src_name == NULL)) {
		return false;
	}

	h_name_lower = strdup(src_name);
	if (h_name_lower == NULL) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Out of memory while strdup");
		return false;
	}

	str_tolower(h_name_lower, h_name_lower);
	*dst_name = h_name_lower;
	return true;
}

static void libc_setpwent(void)
{
	nwrap_bind_symbol_libc(setpwent);

	nwrap_main_global->libc->symbols._libc_setpwent.f();
}

static struct passwd *libc_getpwent(void)
{
	nwrap_bind_symbol_libc(getpwent);

	return nwrap_main_global->libc->symbols._libc_getpwent.f();
}

#ifdef HAVE_GETPWENT_R
#  ifdef HAVE_SOLARIS_GETPWENT_R
static struct passwd *libc_getpwent_r(struct passwd *pwdst,
				      char *buf,
				      int buflen)
{
	nwrap_bind_symbol_libc(getpwent_r);

	return nwrap_main_global->libc->symbols._libc_getpwent_r.f(pwdst,
								   buf,
								   buflen);
}
#  else /* HAVE_SOLARIS_GETPWENT_R */
static int libc_getpwent_r(struct passwd *pwdst,
			   char *buf,
			   size_t buflen,
			   struct passwd **pwdstp)
{
	nwrap_bind_symbol_libc(getpwent_r);

	return nwrap_main_global->libc->symbols._libc_getpwent_r.f(pwdst,
								   buf,
								   buflen,
								   pwdstp);
}
#  endif /* HAVE_SOLARIS_GETPWENT_R */
#endif /* HAVE_GETPWENT_R */

static void libc_endpwent(void)
{
	nwrap_bind_symbol_libc(endpwent);

	nwrap_main_global->libc->symbols._libc_endpwent.f();
}

static int libc_initgroups(const char *user, gid_t gid)
{
	nwrap_bind_symbol_libc(initgroups);

	return nwrap_main_global->libc->symbols._libc_initgroups.f(user, gid);
}

static struct group *libc_getgrnam(const char *name)
{
	nwrap_bind_symbol_libc(getgrnam);

	return nwrap_main_global->libc->symbols._libc_getgrnam.f(name);
}

#ifdef HAVE_GETGRNAM_R
static int libc_getgrnam_r(const char *name,
			   struct group *grp,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
#ifdef HAVE___POSIX_GETGRNAM_R
	nwrap_bind_symbol_libc_posix(getgrnam_r);
#else
	nwrap_bind_symbol_libc(getgrnam_r);
#endif

	return nwrap_main_global->libc->symbols._libc_getgrnam_r.f(name,
								   grp,
								   buf,
								   buflen,
								   result);
}
#endif

static struct group *libc_getgrgid(gid_t gid)
{
	nwrap_bind_symbol_libc(getgrgid);

	return nwrap_main_global->libc->symbols._libc_getgrgid.f(gid);
}

#ifdef HAVE_GETGRGID_R
static int libc_getgrgid_r(gid_t gid,
			   struct group *grp,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
#ifdef HAVE___POSIX_GETGRGID_R
	if (nwrap_main_global->libc->symbols._libc_getgrgid_r == NULL) {
		*(void **) (&nwrap_main_global->libc->symbols._libc_getgrgid_r) =
			_nwrap_bind_symbol_libc("__posix_getgrgid_r");
	}
#else
	nwrap_bind_symbol_libc(getgrgid_r);
#endif

	return nwrap_main_global->libc->symbols._libc_getgrgid_r.f(gid,
								   grp,
								   buf,
								   buflen,
								   result);
}
#endif

static void libc_setgrent(void)
{
	nwrap_bind_symbol_libc(setgrent);

	nwrap_main_global->libc->symbols._libc_setgrent.f();
}

static struct group *libc_getgrent(void)
{
	nwrap_bind_symbol_libc(getgrent);

	return nwrap_main_global->libc->symbols._libc_getgrent.f();
}

#ifdef HAVE_GETGRENT_R
#  ifdef HAVE_SOLARIS_GETGRENT_R
static struct group *libc_getgrent_r(struct group *group,
				     char *buf,
				     size_t buflen)
{
	nwrap_bind_symbol_libc(getgrent_r);

	return nwrap_main_global->libc->symbols._libc_getgrent_r.f(group,
								   buf,
								   buflen);
}
#  else /* HAVE_SOLARIS_GETGRENT_R */
static int libc_getgrent_r(struct group *group,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
	nwrap_bind_symbol_libc(getgrent_r);

	return nwrap_main_global->libc->symbols._libc_getgrent_r.f(group,
								   buf,
								   buflen,
								   result);
}
#  endif /* HAVE_SOLARIS_GETGRENT_R */
#endif /* HAVE_GETGRENT_R */

static void libc_endgrent(void)
{
	nwrap_bind_symbol_libc(endgrent);

	nwrap_main_global->libc->symbols._libc_endgrent.f();
}

#ifdef HAVE_GETGROUPLIST
static int libc_getgrouplist(const char *user,
			     gid_t group,
			     gid_t *groups,
			     int *ngroups)
{
	nwrap_bind_symbol_libc(getgrouplist);

	return nwrap_main_global->libc->symbols._libc_getgrouplist.f(user,
								     group,
								     groups,
								     ngroups);
}
#endif

static void libc_sethostent(int stayopen)
{
	nwrap_bind_symbol_libnsl(sethostent);

	nwrap_main_global->libc->symbols._libc_sethostent.f(stayopen);
}

static struct hostent *libc_gethostent(void)
{
	nwrap_bind_symbol_libnsl(gethostent);

	return nwrap_main_global->libc->symbols._libc_gethostent.f();
}

static void libc_endhostent(void)
{
	nwrap_bind_symbol_libnsl(endhostent);

	nwrap_main_global->libc->symbols._libc_endhostent.f();
}

static struct hostent *libc_gethostbyname(const char *name)
{
	nwrap_bind_symbol_libnsl(gethostbyname);

	return nwrap_main_global->libc->symbols._libc_gethostbyname.f(name);
}

#ifdef HAVE_GETHOSTBYNAME2 /* GNU extension */
static struct hostent *libc_gethostbyname2(const char *name, int af)
{
	nwrap_bind_symbol_libnsl(gethostbyname2);

	return nwrap_main_global->libc->symbols._libc_gethostbyname2.f(name, af);
}
#endif

#ifdef HAVE_GETHOSTBYNAME2_R /* GNU extension */
static int libc_gethostbyname2_r(const char *name,
				 int af,
				 struct hostent *ret,
				 char *buf,
				 size_t buflen,
				 struct hostent **result,
				 int *h_errnop)
{
	nwrap_bind_symbol_libnsl(gethostbyname2_r);

	return nwrap_main_global->libc->symbols._libc_gethostbyname2_r.f(name,
									 af,
									 ret,
									 buf,
									 buflen,
									 result,
									 h_errnop);
}
#endif

static struct hostent *libc_gethostbyaddr(const void *addr,
					  socklen_t len,
					  int type)
{
	nwrap_bind_symbol_libnsl(gethostbyaddr);

	return nwrap_main_global->libc->symbols._libc_gethostbyaddr.f(addr,
								      len,
								      type);
}

static int libc_gethostname(char *name, size_t len)
{
	nwrap_bind_symbol_libnsl(gethostname);

	return nwrap_main_global->libc->symbols._libc_gethostname.f(name, len);
}

#ifdef HAVE_GETHOSTBYNAME_R
static int libc_gethostbyname_r(const char *name,
				struct hostent *ret,
				char *buf,
				size_t buflen,
				struct hostent **result,
				int *h_errnop)
{
	nwrap_bind_symbol_libnsl(gethostbyname_r);

	return nwrap_main_global->libc->symbols._libc_gethostbyname_r.f(name,
									ret,
									buf,
									buflen,
									result,
									h_errnop);
}
#endif

#ifdef HAVE_GETHOSTBYADDR_R
static int libc_gethostbyaddr_r(const void *addr,
				socklen_t len,
				int type,
				struct hostent *ret,
				char *buf,
				size_t buflen,
				struct hostent **result,
				int *h_errnop)
{
	nwrap_bind_symbol_libnsl(gethostbyaddr_r);

	return nwrap_main_global->libc->symbols._libc_gethostbyaddr_r.f(addr,
									len,
									type,
									ret,
									buf,
									buflen,
									result,
									h_errnop);
}
#endif

static int libc_getaddrinfo(const char *node,
			    const char *service,
			    const struct addrinfo *hints,
			    struct addrinfo **res)
{
	nwrap_bind_symbol_libsocket(getaddrinfo);

	return nwrap_main_global->libc->symbols._libc_getaddrinfo.f(node,
								    service,
								    hints,
								    res);
}

static int libc_getnameinfo(const struct sockaddr *sa,
			    socklen_t salen,
			    char *host,
			    size_t hostlen,
			    char *serv,
			    size_t servlen,
			    int flags)
{
	nwrap_bind_symbol_libsocket(getnameinfo);

	return nwrap_main_global->libc->symbols._libc_getnameinfo.f(sa,
								    salen,
								    host,
								    hostlen,
								    serv,
								    servlen,
								    flags);
}

/*********************************************************
 * NWRAP NSS MODULE LOADER FUNCTIONS
 *********************************************************/

static void *_nwrap_bind_nss_module_symbol(struct nwrap_backend *b,
					   const char *fn_name)
{
	void *res = NULL;
	char *s = NULL;
	int rc;

	if (b->so_handle == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "No handle");
		return NULL;
	}

	rc = asprintf(&s, "_nss_%s_%s", b->name, fn_name);
	if (rc == -1) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		return NULL;
	}

	res = dlsym(b->so_handle, s);
	if (res == NULL) {
		NWRAP_LOG(NWRAP_LOG_WARN,
			  "Cannot find function %s in %s",
			  s, b->so_path);
	}
	SAFE_FREE(s);
	return res;
}

#define nwrap_nss_module_bind_symbol(sym_name) \
	NWRAP_LOCK(nss_module_symbol_binding); \
	if (symbols->_nss_##sym_name.obj == NULL) { \
		symbols->_nss_##sym_name.obj = \
			_nwrap_bind_nss_module_symbol(b, #sym_name); \
	} \
	NWRAP_UNLOCK(nss_module_symbol_binding)

#define nwrap_nss_module_bind_symbol2(sym_name, alt_name) \
	NWRAP_LOCK(nss_module_symbol_binding); \
	if (symbols->_nss_##sym_name.obj == NULL) { \
		symbols->_nss_##sym_name.obj = \
			_nwrap_bind_nss_module_symbol(b, #alt_name); \
	} \
	NWRAP_UNLOCK(nss_module_symbol_binding)

static struct nwrap_nss_module_symbols *
nwrap_bind_nss_module_symbols(struct nwrap_backend *b)
{
	struct nwrap_nss_module_symbols *symbols;

	if (!b->so_handle) {
		return NULL;
	}

	symbols = calloc(1, sizeof(struct nwrap_nss_module_symbols));
	if (symbols == NULL) {
		return NULL;
	}

	nwrap_nss_module_bind_symbol(getpwnam_r);
	nwrap_nss_module_bind_symbol(getpwuid_r);
	nwrap_nss_module_bind_symbol(setpwent);
	nwrap_nss_module_bind_symbol(getpwent_r);
	nwrap_nss_module_bind_symbol(endpwent);
	nwrap_nss_module_bind_symbol2(initgroups, initgroups_dyn);
	nwrap_nss_module_bind_symbol(getgrnam_r);
	nwrap_nss_module_bind_symbol(getgrgid_r);
	nwrap_nss_module_bind_symbol(setgrent);
	nwrap_nss_module_bind_symbol(getgrent_r);
	nwrap_nss_module_bind_symbol(endgrent);
	nwrap_nss_module_bind_symbol(gethostbyaddr_r);
	nwrap_nss_module_bind_symbol(gethostbyname2_r);

	return symbols;
}

static void *nwrap_load_module(const char *so_path)
{
	void *h;

	if (!so_path || !strlen(so_path)) {
		return NULL;
	}

	h = dlopen(so_path, RTLD_LAZY);
	if (!h) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Cannot open shared library %s",
			  so_path);
		return NULL;
	}

	return h;
}

static bool nwrap_module_init(const char *name,
			      struct nwrap_ops *ops,
			      const char *so_path,
			      size_t *num_backends,
			      struct nwrap_backend **backends)
{
	struct nwrap_backend *b = NULL;
	size_t n = *num_backends + 1;

	b = realloc(*backends, sizeof(struct nwrap_backend) * n);
	if (b == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		return false;
	}
	*backends = b;

	b = &((*backends)[*num_backends]);

	*b = (struct nwrap_backend) {
		.name = name,
		.ops = ops,
		.so_path = so_path,
	};

	if (so_path != NULL) {
		b->so_handle = nwrap_load_module(so_path);
		b->symbols = nwrap_bind_nss_module_symbols(b);
		if (b->symbols == NULL) {
			return false;
		}
	}

	*num_backends = n;

	return true;
}

static void nwrap_libc_init(struct nwrap_main *r)
{
	r->libc = calloc(1, sizeof(struct nwrap_libc));
	if (r->libc == NULL) {
		printf("Failed to allocate memory for libc");
		exit(-1);
	}
}

static void nwrap_backend_init(struct nwrap_main *r)
{
	const char *module_so_path = getenv("NSS_WRAPPER_MODULE_SO_PATH");
	const char *module_fn_name = getenv("NSS_WRAPPER_MODULE_FN_PREFIX");

	r->num_backends = 0;
	r->backends = NULL;

	if (!nwrap_module_init("files", &nwrap_files_ops, NULL,
			       &r->num_backends,
			       &r->backends)) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Failed to initialize 'files' backend");
		return;
	}

	if (module_so_path != NULL &&
	    module_so_path[0] != '\0' &&
	    module_fn_name != NULL &&
	    module_fn_name[0] != '\0') {
		if (!nwrap_module_init(module_fn_name,
				       &nwrap_module_ops,
				       module_so_path,
				       &r->num_backends,
				       &r->backends)) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Failed to initialize '%s' backend",
				  module_fn_name);
			return;
		}
	}
}

static void nwrap_init(void)
{
	const char *env;
	char *endptr;
	size_t max_hostents_tmp;
	int ok;

	NWRAP_LOCK(nwrap_initialized);
	if (nwrap_initialized) {
		NWRAP_UNLOCK(nwrap_initialized);
		return;
	}

	/*
	 * Still holding nwrap_initialized lock here.
	 * We don't use NWRAP_(UN)LOCK_ALL macros here because we
	 * want to avoid overhead when other threads do their job.
	 */
	NWRAP_LOCK(nwrap_global);
	NWRAP_LOCK(nwrap_gr_global);
	NWRAP_LOCK(nwrap_he_global);
	NWRAP_LOCK(nwrap_pw_global);
	NWRAP_LOCK(nwrap_sp_global);

	nwrap_initialized = true;

	env = getenv("NSS_WRAPPER_MAX_HOSTENTS");
	if (env != NULL) {
		max_hostents_tmp = (size_t)strtoul(env, &endptr, 10);
		if ((*env == '\0') ||
		    (*endptr != '\0') ||
		    (max_hostents_tmp == 0)) {
			NWRAP_LOG(NWRAP_LOG_DEBUG,
				  "Error parsing NSS_WRAPPER_MAX_HOSTENTS "
				  "value or value is too small. "
				  "Using default value: %lu.",
				  (unsigned long)max_hostents);
		} else {
			max_hostents = max_hostents_tmp;
		}
	}
	/* Initialize hash table */
	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "Initializing hash table of size %lu items.",
		  (unsigned long)max_hostents);
	ok = hcreate(max_hostents);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Failed to initialize hash table");
		exit(-1);
	}

	nwrap_main_global = &__nwrap_main_global;

	nwrap_libc_init(nwrap_main_global);

	nwrap_backend_init(nwrap_main_global);

	/* passwd */
	nwrap_pw_global.cache = &__nwrap_cache_pw;

	nwrap_pw_global.cache->path = getenv("NSS_WRAPPER_PASSWD");
	nwrap_pw_global.cache->fp = NULL;
	nwrap_pw_global.cache->fd = -1;
	nwrap_pw_global.cache->private_data = &nwrap_pw_global;
	nwrap_pw_global.cache->parse_line = nwrap_pw_parse_line;
	nwrap_pw_global.cache->unload = nwrap_pw_unload;

	/* shadow */
#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)
	nwrap_sp_global.cache = &__nwrap_cache_sp;

	nwrap_sp_global.cache->path = getenv("NSS_WRAPPER_SHADOW");
	nwrap_sp_global.cache->fp = NULL;
	nwrap_sp_global.cache->fd = -1;
	nwrap_sp_global.cache->private_data = &nwrap_sp_global;
	nwrap_sp_global.cache->parse_line = nwrap_sp_parse_line;
	nwrap_sp_global.cache->unload = nwrap_sp_unload;
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

	/* group */
	nwrap_gr_global.cache = &__nwrap_cache_gr;

	nwrap_gr_global.cache->path = getenv("NSS_WRAPPER_GROUP");
	nwrap_gr_global.cache->fp = NULL;
	nwrap_gr_global.cache->fd = -1;
	nwrap_gr_global.cache->private_data = &nwrap_gr_global;
	nwrap_gr_global.cache->parse_line = nwrap_gr_parse_line;
	nwrap_gr_global.cache->unload = nwrap_gr_unload;

	/* hosts */
	nwrap_he_global.cache = &__nwrap_cache_he;

	nwrap_he_global.cache->path = getenv("NSS_WRAPPER_HOSTS");
	nwrap_he_global.cache->fp = NULL;
	nwrap_he_global.cache->fd = -1;
	nwrap_he_global.cache->private_data = &nwrap_he_global;
	nwrap_he_global.cache->parse_line = nwrap_he_parse_line;
	nwrap_he_global.cache->unload = nwrap_he_unload;

	/* We hold all locks here so we can use NWRAP_UNLOCK_ALL. */
	NWRAP_UNLOCK_ALL;
}

bool nss_wrapper_enabled(void)
{
	nwrap_init();

	if (nwrap_pw_global.cache->path == NULL ||
	    nwrap_pw_global.cache->path[0] == '\0') {
		return false;
	}
	if (nwrap_gr_global.cache->path == NULL ||
	    nwrap_gr_global.cache->path[0] == '\0') {
		return false;
	}

	return true;
}

#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)
bool nss_wrapper_shadow_enabled(void)
{
	nwrap_init();

	if (nwrap_sp_global.cache->path == NULL ||
	    nwrap_sp_global.cache->path[0] == '\0') {
		return false;
	}

	return true;
}
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

bool nss_wrapper_hosts_enabled(void)
{
	nwrap_init();

	if (nwrap_he_global.cache->path == NULL ||
	    nwrap_he_global.cache->path[0] == '\0') {
		return false;
	}

	return true;
}

static bool nwrap_hostname_enabled(void)
{
	nwrap_init();

	if (getenv("NSS_WRAPPER_HOSTNAME") == NULL) {
		return false;
	}

	return true;
}

static bool nwrap_parse_file(struct nwrap_cache *nwrap)
{
	char *line = NULL;
	ssize_t n;
	/* Unused but getline needs it */
	size_t len;
	bool ok;

	if (nwrap->st.st_size == 0) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "size == 0");
		return true;
	}

	/* Support for 32-bit system I guess */
	if (nwrap->st.st_size > INT32_MAX) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Size[%u] larger than INT32_MAX",
			  (unsigned)nwrap->st.st_size);
		return false;
	}

	rewind(nwrap->fp);

	do {
		n = getline(&line, &len, nwrap->fp);
		if (n < 0) {
			SAFE_FREE(line);
			if (feof(nwrap->fp)) {
				break;
			}

			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to read line from file: %s",
				  nwrap->path);
			return false;
		}

		if (line[n - 1] == '\n') {
			line[n - 1] = '\0';
		}

		if (line[0] == '\0') {
			SAFE_FREE(line);
			continue;
		}

		ok = nwrap->parse_line(nwrap, line);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to parse line file: %s",
				  line);
			SAFE_FREE(line);
			return false;
		}

		/* Line is parsed without issues so add it to list */
		ok = nwrap_vector_add_item(&(nwrap->lines), (void *const) line);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to add line to vector");
			return false;
		}

		/* This forces getline to allocate new memory for line. */
		line = NULL;
	} while (!feof(nwrap->fp));

	return true;
}

static void nwrap_files_cache_unload(struct nwrap_cache *nwrap)
{
	nwrap->unload(nwrap);

	nwrap_lines_unload(nwrap);
}

static bool nwrap_files_cache_reload(struct nwrap_cache *nwrap)
{
	struct stat st;
	int ret;
	bool ok;
	bool retried = false;

	assert(nwrap != NULL);

reopen:
	if (nwrap->fd < 0) {
		nwrap->fp = fopen(nwrap->path, "re");
		if (nwrap->fp == NULL) {
			nwrap->fd = -1;
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to open '%s' readonly %d:%s",
				  nwrap->path, nwrap->fd,
				  strerror(errno));
			return false;

		}
		nwrap->fd = fileno(nwrap->fp);
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Open '%s'", nwrap->path);
	}

	ret = fstat(nwrap->fd, &st);
	if (ret != 0) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "fstat(%s) - %d:%s",
			  nwrap->path,
			  ret,
			  strerror(errno));
		fclose(nwrap->fp);
		nwrap->fp = NULL;
		nwrap->fd = -1;
		return false;
	}

	if (retried == false && st.st_nlink == 0) {
		/* maybe someone has replaced the file... */
		NWRAP_LOG(NWRAP_LOG_TRACE,
			  "st_nlink == 0, reopen %s",
			  nwrap->path);
		retried = true;
		memset(&nwrap->st, 0, sizeof(nwrap->st));
		fclose(nwrap->fp);
		nwrap->fp = NULL;
		nwrap->fd = -1;
		goto reopen;
	}

	if (st.st_mtime == nwrap->st.st_mtime) {
		NWRAP_LOG(NWRAP_LOG_TRACE,
			  "st_mtime[%u] hasn't changed, skip reload",
			  (unsigned)st.st_mtime);
		return true;
	}

	NWRAP_LOG(NWRAP_LOG_TRACE,
		  "st_mtime has changed [%u] => [%u], start reload",
		  (unsigned)st.st_mtime,
		  (unsigned)nwrap->st.st_mtime);

	nwrap->st = st;

	nwrap_files_cache_unload(nwrap);

	ok = nwrap_parse_file(nwrap);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Failed to reload %s", nwrap->path);
		nwrap_files_cache_unload(nwrap);
		return false;
	}

	NWRAP_LOG(NWRAP_LOG_TRACE, "Reloaded %s", nwrap->path);
	return true;
}

/*
 * the caller has to call nwrap_unload() on failure
 */
static bool nwrap_pw_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_pw *nwrap_pw;
	char *c;
	char *p;
	char *e;
	struct passwd *pw;
	size_t list_size;

	nwrap_pw = (struct nwrap_pw *)nwrap->private_data;

	list_size = sizeof(*nwrap_pw->list) * (nwrap_pw->num+1);
	pw = (struct passwd *)realloc(nwrap_pw->list, list_size);
	if (!pw) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "realloc(%u) failed",
			  (unsigned)list_size);
		return false;
	}
	nwrap_pw->list = pw;

	pw = &nwrap_pw->list[nwrap_pw->num];

	c = line;

	/* name */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s'",
			  line,
			  c);
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_name = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "name[%s]\n", pw->pw_name);

	/* password */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_passwd = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "password[%s]\n", pw->pw_passwd);

	/* uid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	pw->pw_uid = (uid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "uid[%u]", pw->pw_uid);

	/* gid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	pw->pw_gid = (gid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "gid[%u]\n", pw->pw_gid);

#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	pw->pw_class = discard_const_p(char, "");

	NWRAP_LOG(NWRAP_LOG_TRACE, "class[%s]", pw->pw_class);
#endif /* HAVE_STRUCT_PASSWD_PW_CLASS */

#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	pw->pw_change = 0;

	NWRAP_LOG(NWRAP_LOG_TRACE,
		  "change[%lu]",
		  (unsigned long)pw->pw_change);
#endif /* HAVE_STRUCT_PASSWD_PW_CHANGE */

#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	pw->pw_expire = 0;

	NWRAP_LOG(NWRAP_LOG_TRACE,
		  "expire[%lu]",
		  (unsigned long)pw->pw_expire);
#endif /* HAVE_STRUCT_PASSWD_PW_EXPIRE */

	/* gecos */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_gecos = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "gecos[%s]", pw->pw_gecos);

	/* dir */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "'%s'", c);
		return false;
	}
	*p = '\0';
	p++;
	pw->pw_dir = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "dir[%s]", pw->pw_dir);

	/* shell */
	pw->pw_shell = c;
	NWRAP_LOG(NWRAP_LOG_TRACE, "shell[%s]", pw->pw_shell);

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "Added user[%s:%s:%u:%u:%s:%s:%s]",
		  pw->pw_name, pw->pw_passwd,
		  pw->pw_uid, pw->pw_gid,
		  pw->pw_gecos, pw->pw_dir, pw->pw_shell);

	nwrap_pw->num++;
	return true;
}

static void nwrap_pw_unload(struct nwrap_cache *nwrap)
{
	struct nwrap_pw *nwrap_pw;
	nwrap_pw = (struct nwrap_pw *)nwrap->private_data;

	SAFE_FREE(nwrap_pw->list);
	nwrap_pw->num = 0;
	nwrap_pw->idx = 0;
}

static int nwrap_pw_copy_r(const struct passwd *src, struct passwd *dst,
			   char *buf, size_t buflen, struct passwd **dstp)
{
	char *first;
	char *last;
	off_t ofs;

	first = src->pw_name;

	last = src->pw_shell;
	while (*last) last++;

	ofs = PTR_DIFF(last + 1, first);

	if (ofs > (off_t) buflen) {
		return ERANGE;
	}

	memcpy(buf, first, ofs);

	ofs = PTR_DIFF(src->pw_name, first);
	dst->pw_name = buf + ofs;
	ofs = PTR_DIFF(src->pw_passwd, first);
	dst->pw_passwd = buf + ofs;
	dst->pw_uid = src->pw_uid;
	dst->pw_gid = src->pw_gid;
#ifdef HAVE_STRUCT_PASSWD_PW_CLASS
	ofs = PTR_DIFF(src->pw_class, first);
	dst->pw_class = buf + ofs;
#endif /* HAVE_STRUCT_PASSWD_PW_CLASS */

#ifdef HAVE_STRUCT_PASSWD_PW_CHANGE
	dst->pw_change = 0;
#endif /* HAVE_STRUCT_PASSWD_PW_CHANGE */

#ifdef HAVE_STRUCT_PASSWD_PW_EXPIRE
	dst->pw_expire = 0;
#endif /* HAVE_STRUCT_PASSWD_PW_EXPIRE */

	ofs = PTR_DIFF(src->pw_gecos, first);
	dst->pw_gecos = buf + ofs;
	ofs = PTR_DIFF(src->pw_dir, first);
	dst->pw_dir = buf + ofs;
	ofs = PTR_DIFF(src->pw_shell, first);
	dst->pw_shell = buf + ofs;

	if (dstp) {
		*dstp = dst;
	}

	return 0;
}

#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)
static bool nwrap_sp_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_sp *nwrap_sp;
	struct spwd *sp;
	size_t list_size;
	char *c;
	char *e;
	char *p;

	nwrap_sp = (struct nwrap_sp *)nwrap->private_data;

	list_size = sizeof(*nwrap_sp->list) * (nwrap_sp->num+1);
	sp = (struct spwd *)realloc(nwrap_sp->list, list_size);
	if (sp == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "realloc(%u) failed",
			  (unsigned)list_size);
		return false;
	}
	nwrap_sp->list = sp;

	sp = &nwrap_sp->list[nwrap_sp->num];

	c = line;

	/* name */
	p = strchr(c, ':');
	if (p == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "name -- Invalid line[%s]: '%s'",
			  line,
			  c);
		return false;
	}
	*p = '\0';
	p++;
	sp->sp_namp = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "name[%s]\n", sp->sp_namp);

	/* pwd */
	p = strchr(c, ':');
	if (p == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "pwd -- Invalid line[%s]: '%s'",
			  line,
			  c);
		return false;
	}
	*p = '\0';
	p++;
	sp->sp_pwdp = c;
	c = p;

	/* lstchg (long) */
	if (c[0] == ':') {
		sp->sp_lstchg = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "lstchg -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_lstchg = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "lstchg -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "lstchg -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "lstchg -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	/* min (long) */
	if (c[0] == ':') {
		sp->sp_min = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "min -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_min = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "min -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "min -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "min -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	/* max (long) */
	if (c[0] == ':') {
		sp->sp_max = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "max -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_max = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "max -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "max -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "max -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	/* warn (long) */
	if (c[0] == ':') {
		sp->sp_warn = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "warn -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_warn = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "warn -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "warn -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "warn -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	/* inact (long) */
	if (c[0] == ':') {
		sp->sp_inact = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "inact -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_inact = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "inact -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "inact -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "inact -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	/* expire (long) */
	if (c[0] == ':') {
		sp->sp_expire = -1;
		p++;
	} else {
		p = strchr(c, ':');
		if (p == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "expire -- Invalid line[%s]: '%s'",
				  line,
				  c);
			return false;
		}
		*p = '\0';
		p++;
		sp->sp_expire = strtol(c, &e, 10);
		if (c == e) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "expire -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e == NULL) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "expire -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
		if (e[0] != '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "expire -- Invalid line[%s]: '%s' - %s",
				  line, c, strerror(errno));
			return false;
		}
	}
	c = p;

	nwrap_sp->num++;
	return true;
}

static void nwrap_sp_unload(struct nwrap_cache *nwrap)
{
	struct nwrap_sp *nwrap_sp;
	nwrap_sp = (struct nwrap_sp *)nwrap->private_data;

	SAFE_FREE(nwrap_sp->list);
	nwrap_sp->num = 0;
	nwrap_sp->idx = 0;
}
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

/*
 * the caller has to call nwrap_unload() on failure
 */
static bool nwrap_gr_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_gr *nwrap_gr;
	char *c;
	char *p;
	char *e;
	struct group *gr;
	size_t list_size;
	unsigned nummem;

	nwrap_gr = (struct nwrap_gr *)nwrap->private_data;

	list_size = sizeof(*nwrap_gr->list) * (nwrap_gr->num+1);
	gr = (struct group *)realloc(nwrap_gr->list, list_size);
	if (!gr) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "realloc failed");
		return false;
	}
	nwrap_gr->list = gr;

	gr = &nwrap_gr->list[nwrap_gr->num];

	c = line;

	/* name */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	gr->gr_name = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "name[%s]", gr->gr_name);

	/* password */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	gr->gr_passwd = c;
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "password[%s]", gr->gr_passwd);

	/* gid */
	p = strchr(c, ':');
	if (!p) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Invalid line[%s]: '%s'", line, c);
		return false;
	}
	*p = '\0';
	p++;
	e = NULL;
	gr->gr_gid = (gid_t)strtoul(c, &e, 10);
	if (c == e) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	if (e[0] != '\0') {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s' - %s",
			  line, c, strerror(errno));
		return false;
	}
	c = p;

	NWRAP_LOG(NWRAP_LOG_TRACE, "gid[%u]", gr->gr_gid);

	/* members */
	gr->gr_mem = (char **)malloc(sizeof(char *));
	if (!gr->gr_mem) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		return false;
	}
	gr->gr_mem[0] = NULL;

	for(nummem = 0; p != NULL && p[0] != '\0'; nummem++) {
		char **m;
		size_t m_size;
		c = p;
		p = strchr(c, ',');
		if (p) {
			*p = '\0';
			p++;
		}

		if (strlen(c) == 0) {
			break;
		}

		m_size = sizeof(char *) * (nummem+2);
		m = (char **)realloc(gr->gr_mem, m_size);
		if (!m) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "realloc(%zd) failed",
				  m_size);
			return false;
		}
		gr->gr_mem = m;
		gr->gr_mem[nummem] = c;
		gr->gr_mem[nummem+1] = NULL;

		NWRAP_LOG(NWRAP_LOG_TRACE,
			  "member[%u]: '%s'",
			  nummem, gr->gr_mem[nummem]);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "Added group[%s:%s:%u:] with %u members",
		  gr->gr_name, gr->gr_passwd, gr->gr_gid, nummem);

	nwrap_gr->num++;
	return true;
}

static void nwrap_gr_unload(struct nwrap_cache *nwrap)
{
	int i;
	struct nwrap_gr *nwrap_gr;
	nwrap_gr = (struct nwrap_gr *)nwrap->private_data;

	if (nwrap_gr->list) {
		for (i=0; i < nwrap_gr->num; i++) {
			SAFE_FREE(nwrap_gr->list[i].gr_mem);
		}
		SAFE_FREE(nwrap_gr->list);
	}

	nwrap_gr->num = 0;
	nwrap_gr->idx = 0;
}

static int nwrap_gr_copy_r(const struct group *src, struct group *dst,
			   char *buf, size_t buflen, struct group **dstp)
{
	char *p = NULL;
	uintptr_t align = 0;
	unsigned int gr_mem_cnt = 0;
	unsigned i;
	size_t total_len;
	size_t gr_name_len = strlen(src->gr_name) + 1;
	size_t gr_passwd_len = strlen(src->gr_passwd) + 1;
	union {
		char *ptr;
		char **data;
	} g_mem;

	for (i = 0; src->gr_mem[i] != NULL; i++) {
		gr_mem_cnt++;
	}

	/* Align the memory for storing pointers */
	align = __alignof__(char *) - ((p - (char *)0) % __alignof__(char *));
	total_len = align +
		    (1 + gr_mem_cnt) * sizeof(char *) +
		    gr_name_len + gr_passwd_len;

	if (total_len > buflen) {
		errno = ERANGE;
		return -1;
	}
	buflen -= total_len;

	/* gr_mem */
	p = buf + align;
	g_mem.ptr = p;
	dst->gr_mem = g_mem.data;

	/* gr_name */
	p += (1 + gr_mem_cnt) * sizeof(char *);
	dst->gr_name = p;

	/* gr_passwd */
	p += gr_name_len;
	dst->gr_passwd = p;

	/* gr_mem[x] */
	p += gr_passwd_len;

	/* gr_gid */
	dst->gr_gid = src->gr_gid;

	memcpy(dst->gr_name, src->gr_name, gr_name_len);

	memcpy(dst->gr_passwd, src->gr_passwd, gr_passwd_len);

	/* Set the terminating entry */
	dst->gr_mem[gr_mem_cnt] = NULL;

	/* Now add the group members content */
	total_len = 0;
	for (i = 0; i < gr_mem_cnt; i++) {
		size_t len = strlen(src->gr_mem[i]) + 1;

		dst->gr_mem[i] = p;
		total_len += len;
		p += len;
	}

	if (total_len > buflen) {
		errno = ERANGE;
		return -1;
	}

	for (i = 0; i < gr_mem_cnt; i++) {
		size_t len = strlen(src->gr_mem[i]) + 1;

		memcpy(dst->gr_mem[i],
		       src->gr_mem[i],
		       len);
	}

	if (dstp != NULL) {
		*dstp = dst;
	}

	return 0;
}

static struct nwrap_entlist *nwrap_entlist_init(struct nwrap_entdata *ed)
{
	struct nwrap_entlist *el;

	if (ed == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "entry is NULL, can't create list item");
		return NULL;
	}

	el = (struct nwrap_entlist *)malloc(sizeof(struct nwrap_entlist));
	if (el == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "malloc failed");
		return NULL;
	}

	el->next = NULL;
	el->ed = ed;

	return el;
}

static bool nwrap_ed_inventarize_add_new(char *const h_name,
					 struct nwrap_entdata *const ed)
{
	ENTRY e;
	ENTRY *p;
	struct nwrap_entlist *el;
	bool ok;

	if (h_name == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "h_name NULL - can't add");
		return false;
	}

	el = nwrap_entlist_init(ed);
	if (el == NULL) {
		return false;
	}

	e.key = h_name;
	e.data = (void *)el;

	p = hsearch(e, ENTER);
	if (p == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Hash table is full (%s)!",
			  strerror(errno));
		return false;
	}

	ok = nwrap_vector_add_item(&(nwrap_he_global.lists), (void *)el);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Failed to add list entry to vector.");
		return false;
	}

	return true;
}

static bool nwrap_ed_inventarize_add_to_existing(struct nwrap_entdata *const ed,
						 struct nwrap_entlist *const el)
{
	struct nwrap_entlist *cursor;
	struct nwrap_entlist *el_new;

	if (el == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "list is NULL, can not add");
		return false;
	}


	for (cursor = el; cursor->next != NULL; cursor = cursor->next)
	{
		if (cursor->ed == ed) {
			/* The entry already exists in this list. */
			return true;
		}
	}

	if (cursor->ed == ed) {
		/* The entry already exists in this list. */
		return true;
	}

	el_new = nwrap_entlist_init(ed);
	if (el_new == NULL) {
		return false;
	}

	cursor->next = el_new;
	return true;
}

static bool nwrap_ed_inventarize(char *const name,
				 struct nwrap_entdata *const ed)
{
	ENTRY e;
	ENTRY *p;
	bool ok;

	e.key = name;
	e.data = NULL;

	NWRAP_LOG(NWRAP_LOG_DEBUG, "Searching name: %s", e.key);

	p = hsearch(e, FIND);
	if (p == NULL) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Name %s not found. Adding...", name);
		ok = nwrap_ed_inventarize_add_new(name, ed);
	} else {
		struct nwrap_entlist *el = (struct nwrap_entlist *)p->data;

		NWRAP_LOG(NWRAP_LOG_DEBUG, "Name %s found. Add record to list.", name);
		ok = nwrap_ed_inventarize_add_to_existing(ed, el);
	}

	return ok;
}

static bool nwrap_add_hname(struct nwrap_entdata *const ed)
{
	char *const h_name = (char *const)(ed->ht.h_name);
	unsigned i;
	bool ok;

	ok = nwrap_ed_inventarize(h_name, ed);
	if (!ok) {
		return false;
	}

	if (ed->ht.h_aliases == NULL) {
		return true;
	}

	/* Itemize aliases */
	for (i = 0; ed->ht.h_aliases[i] != NULL; ++i) {
		char *h_name_alias;

		h_name_alias = ed->ht.h_aliases[i];

		NWRAP_LOG(NWRAP_LOG_DEBUG, "Add alias: %s", h_name_alias);

		if (!nwrap_ed_inventarize(h_name_alias, ed)) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to add alias: %s", h_name_alias);
			return false;
		}
	}

	return true;
}

static bool nwrap_he_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_he *nwrap_he = (struct nwrap_he *)nwrap->private_data;
	bool do_aliases = true;
	ssize_t aliases_count = 0;
	char *p;
	char *i;
	char *n;

	char *ip;
	bool ok;

	struct nwrap_entdata *ed = (struct nwrap_entdata *)
				   malloc(sizeof(struct nwrap_entdata));
	if (ed == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Unable to allocate memory for nwrap_entdata");
		return false;
	}
	ZERO_STRUCTP(ed);

	i = line;

	/*
	 * IP
	 */

	/* Walk to first char */
	for (p = i; *p != '.' && *p != ':' && !isxdigit((int) *p); p++) {
		if (*p == '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Invalid line[%s]: '%s'",
				  line, i);
			free(ed);
			return false;
		}
	}

	for (i = p; !isspace((int)*p); p++) {
		if (*p == '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Invalid line[%s]: '%s'",
				  line, i);
			free(ed);
			return false;
		}
	}

	*p = '\0';

	if (inet_pton(AF_INET, i, ed->addr.host_addr)) {
		ed->ht.h_addrtype = AF_INET;
		ed->ht.h_length = 4;
#ifdef HAVE_IPV6
	} else if (inet_pton(AF_INET6, i, ed->addr.host_addr)) {
		ed->ht.h_addrtype = AF_INET6;
		ed->ht.h_length = 16;
#endif
	} else {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s'",
			  line, i);

		free(ed);
		return false;
	}
	ip = i;

	ok = nwrap_vector_add_item(&(ed->nwrap_addrdata),
				   (void *const)ed->addr.host_addr);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Unable to add addrdata to vector");
		free(ed);
		return false;
	}
	ed->ht.h_addr_list = nwrap_vector_head(&ed->nwrap_addrdata);

	p++;

	/*
	 * FQDN
	 */

	/* Walk to first char */
	for (n = p; *p != '_' && !isalnum((int) *p); p++) {
		if (*p == '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Invalid line[%s]: '%s'",
				  line, n);

			free(ed);
			return false;
		}
	}

	for (n = p; !isspace((int)*p); p++) {
		if (*p == '\0') {
			do_aliases = false;
			break;
		}
	}

	*p = '\0';

	/* Convert to lowercase. This operate on same memory region */
	str_tolower(n, n);
	ed->ht.h_name = n;

	/* glib's getent always dereferences he->h_aliases */
	ed->ht.h_aliases = malloc(sizeof(char *));
	if (ed->ht.h_aliases == NULL) {
		free(ed);
		return false;
	}
	ed->ht.h_aliases[0] = NULL;

	/*
	 * Aliases
	 */
	while (do_aliases) {
		char **aliases;
		char *a;

		p++;

		/* Walk to first char */
		for (a = p; *p != '_' && !isalnum((int) *p); p++) {
			if (*p == '\0') {
				do_aliases = false;
				break;
			}
		}
		/* Only trailing spaces are left */
		if (!do_aliases) {
			break;
		}

		for (a = p; !isspace((int)*p); p++) {
			if (*p == '\0') {
				do_aliases = false;
				break;
			}
		}

		*p = '\0';

		aliases = realloc(ed->ht.h_aliases, sizeof(char *) * (aliases_count + 2));
		if (aliases == NULL) {
			free(ed);
			return false;
		}
		ed->ht.h_aliases = aliases;

		str_tolower(a, a);
		aliases[aliases_count] = a;
		aliases[aliases_count + 1] = NULL;

		aliases_count += 1;
	}

	ok = nwrap_vector_add_item(&(nwrap_he->entries), (void *const)ed);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Unable to add entry to vector");
		free(ed);
		return false;
	}

	ed->aliases_count = aliases_count;
	/* Inventarize item */
	ok = nwrap_add_hname(ed);
	if (!ok) {
		return false;
	}

	ok = nwrap_ed_inventarize(ip, ed);
	if (!ok) {
		return false;
	}

	nwrap_he->num++;
	return true;
}

static void nwrap_he_unload(struct nwrap_cache *nwrap)
{
	struct nwrap_he *nwrap_he =
		(struct nwrap_he *)nwrap->private_data;
	struct nwrap_entdata *ed;
	struct nwrap_entlist *el;
	size_t i;
	int rc;

	nwrap_vector_foreach (ed, nwrap_he->entries, i)
	{
		SAFE_FREE(ed->nwrap_addrdata.items);
		SAFE_FREE(ed->ht.h_aliases);
		SAFE_FREE(ed);
	}
	SAFE_FREE(nwrap_he->entries.items);
	nwrap_he->entries.count = nwrap_he->entries.capacity = 0;

	nwrap_vector_foreach(el, nwrap_he->lists, i)
	{
		while (el != NULL) {
			struct nwrap_entlist *el_next;

			el_next = el->next;
			SAFE_FREE(el);
			el = el_next;
		}
	}
	SAFE_FREE(nwrap_he->lists.items);
	nwrap_he->lists.count = nwrap_he->lists.capacity = 0;

	nwrap_he->num = 0;
	nwrap_he->idx = 0;

	/*
	 * If we unload the file, the pointers in the hash table point to
	 * invalid memory. So we need to destroy the hash table and recreate
	 * it.
	 */
	hdestroy();
	rc = hcreate(max_hostents);
	if (rc == 0) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Failed to initialize hash table");
		exit(-1);
	}
}


/* user functions */
static struct passwd *nwrap_files_getpwnam(struct nwrap_backend *b,
					   const char *name)
{
	int i;
	bool ok;

	(void) b; /* unused */

	NWRAP_LOG(NWRAP_LOG_DEBUG, "Lookup user %s in files", name);

	ok = nwrap_files_cache_reload(nwrap_pw_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading passwd file");
		return NULL;
	}

	for (i=0; i<nwrap_pw_global.num; i++) {
		if (strcmp(nwrap_pw_global.list[i].pw_name, name) == 0) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "user[%s] found", name);
			return &nwrap_pw_global.list[i];
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "user[%s] does not match [%s]",
			  name,
			  nwrap_pw_global.list[i].pw_name);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "user[%s] not found\n", name);

	errno = ENOENT;
	return NULL;
}

static int nwrap_files_getpwnam_r(struct nwrap_backend *b,
				  const char *name, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_files_getpwnam(b, name);
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

static struct passwd *nwrap_files_getpwuid(struct nwrap_backend *b,
					   uid_t uid)
{
	int i;
	bool ok;

	(void) b; /* unused */

	ok = nwrap_files_cache_reload(nwrap_pw_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading passwd file");
		return NULL;
	}

	for (i=0; i<nwrap_pw_global.num; i++) {
		if (nwrap_pw_global.list[i].pw_uid == uid) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "uid[%u] found", uid);
			return &nwrap_pw_global.list[i];
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "uid[%u] does not match [%u]",
			  uid,
			  nwrap_pw_global.list[i].pw_uid);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "uid[%u] not found\n", uid);

	errno = ENOENT;
	return NULL;
}

static int nwrap_files_getpwuid_r(struct nwrap_backend *b,
				  uid_t uid, struct passwd *pwdst,
				  char *buf, size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_files_getpwuid(b, uid);
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

/* user enum functions */
static void nwrap_files_setpwent(struct nwrap_backend *b)
{
	(void) b; /* unused */

	nwrap_pw_global.idx = 0;
}

static struct passwd *nwrap_files_getpwent(struct nwrap_backend *b)
{
	struct passwd *pw;

	(void) b; /* unused */

	if (nwrap_pw_global.idx == 0) {
		bool ok;
		ok = nwrap_files_cache_reload(nwrap_pw_global.cache);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading passwd file");
			return NULL;
		}
	}

	if (nwrap_pw_global.idx >= nwrap_pw_global.num) {
		errno = ENOENT;
		return NULL;
	}

	pw = &nwrap_pw_global.list[nwrap_pw_global.idx++];

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "return user[%s] uid[%u]",
		  pw->pw_name, pw->pw_uid);

	return pw;
}

static int nwrap_files_getpwent_r(struct nwrap_backend *b,
				  struct passwd *pwdst, char *buf,
				  size_t buflen, struct passwd **pwdstp)
{
	struct passwd *pw;

	pw = nwrap_files_getpwent(b);
	if (!pw) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_pw_copy_r(pw, pwdst, buf, buflen, pwdstp);
}

static void nwrap_files_endpwent(struct nwrap_backend *b)
{
	(void) b; /* unused */

	nwrap_pw_global.idx = 0;
}

/* shadow */

#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)

#ifdef HAVE_SETSPENT
static void nwrap_files_setspent(void)
{
	nwrap_sp_global.idx = 0;
}

static struct spwd *nwrap_files_getspent(void)
{
	struct spwd *sp;

	if (nwrap_sp_global.idx == 0) {
		bool ok;

		ok = nwrap_files_cache_reload(nwrap_sp_global.cache);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading shadow file");
			return NULL;
		}
	}

	if (nwrap_sp_global.idx >= nwrap_sp_global.num) {
		errno = ENOENT;
		return NULL;
	}

	sp = &nwrap_sp_global.list[nwrap_sp_global.idx++];

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "return user[%s]",
		  sp->sp_namp);

	return sp;
}

static void nwrap_files_endspent(void)
{
	nwrap_sp_global.idx = 0;
}
#endif /* HAVE_SETSPENT */

static struct spwd *nwrap_files_getspnam(const char *name)
{
	int i;
	bool ok;

	NWRAP_LOG(NWRAP_LOG_DEBUG, "Lookup user %s in files", name);

	ok = nwrap_files_cache_reload(nwrap_sp_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading shadow file");
		return NULL;
	}

	for (i=0; i<nwrap_sp_global.num; i++) {
		if (strcmp(nwrap_sp_global.list[i].sp_namp, name) == 0) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "user[%s] found", name);
			return &nwrap_sp_global.list[i];
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "user[%s] does not match [%s]",
			  name,
			  nwrap_sp_global.list[i].sp_namp);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "user[%s] not found\n", name);

	errno = ENOENT;
	return NULL;
}
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

/* misc functions */
static int nwrap_files_initgroups(struct nwrap_backend *b,
				  const char *user,
				  gid_t group)
{
	struct group *grp;
	gid_t *groups;
	int size = 1;
	int rc;

	groups = (gid_t *)malloc(size * sizeof(gid_t));
	if (groups == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		errno = ENOMEM;
		return -1;
	}
	groups[0] = group;

	nwrap_files_setgrent(b);
	while ((grp = nwrap_files_getgrent(b)) != NULL) {
		int i = 0;

		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "Inspecting %s for group membership",
			  grp->gr_name);

		for (i=0; grp->gr_mem && grp->gr_mem[i] != NULL; i++) {
			if (group != grp->gr_gid &&
			    (strcmp(user, grp->gr_mem[i]) == 0)) {
				NWRAP_LOG(NWRAP_LOG_DEBUG,
					  "%s is member of %s",
					  user,
					  grp->gr_name);

				groups = (gid_t *)realloc(groups,
							  (size + 1) * sizeof(gid_t));
				if (groups == NULL) {
					NWRAP_LOG(NWRAP_LOG_ERROR,
						  "Out of memory");
					errno = ENOMEM;
					return -1;
				}

				groups[size] = grp->gr_gid;
				size++;
			}
		}
	}

	nwrap_files_endgrent(b);

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "%s is member of %d groups",
		  user, size);

	/* This really only works if uid_wrapper is loaded */
	rc = setgroups(size, groups);

	free(groups);

	return rc;
}

/* group functions */
static struct group *nwrap_files_getgrnam(struct nwrap_backend *b,
					  const char *name)
{
	int i;
	bool ok;

	(void) b; /* unused */

	ok = nwrap_files_cache_reload(nwrap_gr_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading group file");
		return NULL;
	}

	for (i=0; i<nwrap_gr_global.num; i++) {
		if (strcmp(nwrap_gr_global.list[i].gr_name, name) == 0) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "group[%s] found", name);
			return &nwrap_gr_global.list[i];
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "group[%s] does not match [%s]",
			  name,
			  nwrap_gr_global.list[i].gr_name);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "group[%s] not found", name);

	errno = ENOENT;
	return NULL;
}

static int nwrap_files_getgrnam_r(struct nwrap_backend *b,
				  const char *name, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_files_getgrnam(b, name);
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);
}

static struct group *nwrap_files_getgrgid(struct nwrap_backend *b,
					  gid_t gid)
{
	int i;
	bool ok;

	(void) b; /* unused */

	ok = nwrap_files_cache_reload(nwrap_gr_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading group file");
		return NULL;
	}

	for (i=0; i<nwrap_gr_global.num; i++) {
		if (nwrap_gr_global.list[i].gr_gid == gid) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "gid[%u] found", gid);
			return &nwrap_gr_global.list[i];
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "gid[%u] does not match [%u]",
			  gid,
			  nwrap_gr_global.list[i].gr_gid);
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "gid[%u] not found", gid);

	errno = ENOENT;
	return NULL;
}

static int nwrap_files_getgrgid_r(struct nwrap_backend *b,
				  gid_t gid, struct group *grdst,
				  char *buf, size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_files_getgrgid(b, gid);
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);
}

/* group enum functions */
static void nwrap_files_setgrent(struct nwrap_backend *b)
{
	(void) b; /* unused */

	nwrap_gr_global.idx = 0;
}

static struct group *nwrap_files_getgrent(struct nwrap_backend *b)
{
	struct group *gr;

	(void) b; /* unused */

	if (nwrap_gr_global.idx == 0) {
		bool ok;

		ok = nwrap_files_cache_reload(nwrap_gr_global.cache);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading group file");
			return NULL;
		}
	}

	if (nwrap_gr_global.idx >= nwrap_gr_global.num) {
		errno = ENOENT;
		return NULL;
	}

	gr = &nwrap_gr_global.list[nwrap_gr_global.idx++];

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "return group[%s] gid[%u]",
		  gr->gr_name, gr->gr_gid);

	return gr;
}

static int nwrap_files_getgrent_r(struct nwrap_backend *b,
				  struct group *grdst, char *buf,
				  size_t buflen, struct group **grdstp)
{
	struct group *gr;

	gr = nwrap_files_getgrent(b);
	if (!gr) {
		if (errno == 0) {
			return ENOENT;
		}
		return errno;
	}

	return nwrap_gr_copy_r(gr, grdst, buf, buflen, grdstp);
}

static void nwrap_files_endgrent(struct nwrap_backend *b)
{
	(void) b; /* unused */

	nwrap_gr_global.idx = 0;
}

/* hosts functions */
static int nwrap_files_internal_gethostbyname(const char *name, int af,
					      struct hostent *result,
					      struct nwrap_vector *addr_list)
{
	struct nwrap_entlist *el;
	struct hostent *he;
	char *h_name_lower;
	ENTRY e;
	ENTRY *e_p;
	char canon_name[DNS_NAME_MAX] = { 0 };
	size_t name_len;
	bool he_found = false;
	bool ok;

	/*
	 * We need to make sure we have zeroed return pointer for consumers
	 * which don't check return values, e.g. OpenLDAP.
	 */
	ZERO_STRUCTP(result);

	ok = nwrap_files_cache_reload(nwrap_he_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "error loading hosts file");
		goto no_ent;
	}

	name_len = strlen(name);
	if (name_len < sizeof(canon_name) && name[name_len - 1] == '.') {
		memcpy(canon_name, name, name_len - 1);
		canon_name[name_len] = '\0';
		name = canon_name;
	}

	if (!str_tolower_copy(&h_name_lower, name)) {
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "Out of memory while converting to lower case");
		goto no_ent;
	}

	/* Look at hash table for element */
	NWRAP_LOG(NWRAP_LOG_DEBUG, "Searching for name: %s", h_name_lower);
	e.key = h_name_lower;
	e.data = NULL;
	e_p = hsearch(e, FIND);
	if (e_p == NULL) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Name %s not found.", h_name_lower);
		SAFE_FREE(h_name_lower);
		goto no_ent;
	}
	SAFE_FREE(h_name_lower);

	/* Always cleanup vector and results */
	if (!nwrap_vector_is_initialized(addr_list)) {
		if (!nwrap_vector_init(addr_list)) {
			NWRAP_LOG(NWRAP_LOG_DEBUG,
				  "Unable to initialize memory for addr_list vector");
			goto no_ent;
		}
	} else {
		/* When vector is initialized data are valid no more.
		 * Quick way how to free vector is: */
		addr_list->count = 0;
	}

	/* Iterate through results */
	for (el = (struct nwrap_entlist *)e_p->data; el != NULL; el = el->next)
	{
		he = &(el->ed->ht);

		/* Filter by address familiy if provided */
		if (af != AF_UNSPEC && he->h_addrtype != af) {
			continue;
		}

		/*
		 * GLIBC HACK?
		 * glibc doesn't return ipv6 addresses when AF_UNSPEC is used
		 */
		if (af == AF_UNSPEC && he->h_addrtype != AF_INET) {
			continue;
		}

		if (!he_found) {
			memcpy(result, he, sizeof(struct hostent));
			NWRAP_LOG(NWRAP_LOG_DEBUG,
				  "Name found. Returning record for %s",
				  he->h_name);
			he_found = true;
		}
		nwrap_vector_merge(addr_list, &el->ed->nwrap_addrdata);
		result->h_addr_list = nwrap_vector_head(addr_list);
	}

	if (he_found) {
		return 0;
	}
	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "Name found in database. No records matches type.");

no_ent:
	errno = ENOENT;
	return -1;
}

static int nwrap_files_gethostbyname2_r(struct nwrap_backend *b,
					const char *name, int af,
					struct hostent *hedst,
					char *buf, size_t buflen,
					struct hostent **hedstp)
{
	struct nwrap_vector *addr_list = NULL;
	union {
		char *ptr;
		char **list;
	} g;
	int rc;

	(void) b; /* unused */
	(void) af; /* unused */

	if (name == NULL || hedst == NULL || buf == NULL || buflen == 0) {
		errno = EINVAL;
		return -1;
	}
	*hedstp = NULL;
	buf[0] = '\0';

	addr_list = calloc(1, sizeof(struct nwrap_vector));
	if (addr_list == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Unable to allocate memory for address list");
		errno = ENOENT;
		return -1;
	}

	rc = nwrap_files_internal_gethostbyname(name, af, hedst,
						addr_list);
	if (rc == -1) {
		SAFE_FREE(addr_list->items);
		SAFE_FREE(addr_list);
		errno = ENOENT;
		return -1;
	}

	/* +1 i for ending NULL pointer */
	if (buflen < ((addr_list->count + 1) * sizeof(void *))) {
		SAFE_FREE(addr_list->items);
		SAFE_FREE(addr_list);
		return ERANGE;
	}

	/* Copy all to user provided buffer and change
	 * pointers in returned structure.
	 * +1 is for ending NULL pointer. */
	memcpy(buf, addr_list->items, (addr_list->count + 1) * sizeof(void *));

	SAFE_FREE(addr_list->items);
	SAFE_FREE(addr_list);

	g.ptr = buf;
	hedst->h_addr_list = g.list;
	*hedstp = hedst;
	return 0;
}

#ifdef HAVE_GETHOSTBYNAME_R
static int nwrap_gethostbyname_r(const char *name,
				 struct hostent *ret,
				 char *buf, size_t buflen,
				 struct hostent **result, int *h_errnop)
{
	int rc;
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		rc = b->ops->nw_gethostbyname2_r(b, name, AF_UNSPEC, ret,
						 buf, buflen, result);
		if (rc == 0) {
			return 0;
		} else if (rc == ERANGE) {
			return ERANGE;
		}
	}
	*h_errnop = h_errno;
	return ENOENT;
}

int gethostbyname_r(const char *name,
		    struct hostent *ret,
		    char *buf, size_t buflen,
		    struct hostent **result, int *h_errnop)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyname_r(name,
					    ret,
					    buf,
					    buflen,
					    result,
					    h_errnop);
	}

	return nwrap_gethostbyname_r(name, ret, buf, buflen, result, h_errnop);
}
#endif

#ifdef HAVE_GETHOSTBYNAME2_R
static int nwrap_gethostbyname2_r(const char *name, int af,
				 struct hostent *ret,
				 char *buf, size_t buflen,
				 struct hostent **result, int *h_errnop)
{
	int rc;
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		rc = b->ops->nw_gethostbyname2_r(b, name, af, ret,
						 buf, buflen, result);
		if (rc == 0) {
			return 0;
		} else if (rc == ERANGE) {
			return ERANGE;
		}
	}
	*h_errnop = h_errno;
	return ENOENT;
}

int gethostbyname2_r(const char *name, int af,
		     struct hostent *ret,
		     char *buf, size_t buflen,
		     struct hostent **result, int *h_errnop)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyname2_r(name, af, ret, buf, buflen,
					     result, h_errnop);
	}

	return nwrap_gethostbyname2_r(name, af, ret, buf, buflen, result,
				      h_errnop);
}
#endif

static int nwrap_files_getaddrinfo(const char *name,
				   unsigned short port,
				   const struct addrinfo *hints,
				   struct addrinfo **ai)
{
	struct nwrap_entlist *el;
	struct hostent *he;
	struct addrinfo *ai_head = NULL;
	struct addrinfo *ai_cur = NULL;
	char *h_name_lower;
	size_t name_len;
	char canon_name[DNS_NAME_MAX] = { 0 };
	bool skip_canonname = false;
	ENTRY e = {
		.key = NULL,
	};
	ENTRY *e_p = NULL;
	int rc;
	bool ok;

	ok = nwrap_files_cache_reload(nwrap_he_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "error loading hosts file");
		return EAI_SYSTEM;
	}

	name_len = strlen(name);
	if (name_len < sizeof(canon_name) && name[name_len - 1] == '.') {
		memcpy(canon_name, name, name_len - 1);
		canon_name[name_len] = '\0';
		name = canon_name;
	}

	if (!str_tolower_copy(&h_name_lower, name)) {
		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "Out of memory while converting to lower case");
		return EAI_MEMORY;
	}

	NWRAP_LOG(NWRAP_LOG_DEBUG, "Searching for name: %s", h_name_lower);
	e.key = h_name_lower;
	e.data = NULL;
	e_p = hsearch(e, FIND);
	if (e_p == NULL) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Name %s not found.", h_name_lower);
		SAFE_FREE(h_name_lower);
		errno = ENOENT;
		return EAI_NONAME;
	}
	NWRAP_LOG(NWRAP_LOG_DEBUG, "Name: %s found.", h_name_lower);
	SAFE_FREE(h_name_lower);

	rc = EAI_NONAME;
	for (el = (struct nwrap_entlist *)e_p->data; el != NULL; el = el->next)
	{
		int rc2;
		struct addrinfo *ai_new = NULL;

		he = &(el->ed->ht);

		if (hints->ai_family != AF_UNSPEC &&
		    he->h_addrtype != hints->ai_family)
		{
			NWRAP_LOG(NWRAP_LOG_DEBUG,
				  "Entry found but with wrong AF - "
				  "remembering EAI_ADDRINFO.");
			rc = EAI_ADDRFAMILY;
			continue;
		}

		/* Function allocates memory and returns it in ai. */
		rc2 = nwrap_convert_he_ai(he,
					 port,
					 hints,
					 &ai_new,
					 skip_canonname);
		if (rc2 != 0) {
			NWRAP_LOG(NWRAP_LOG_ERROR, "Error converting he to ai");
			if (ai_head != NULL) {
				freeaddrinfo(ai_head);
			}
			return rc2;
		}
		skip_canonname = true;

		if (ai_head == NULL) {
			ai_head = ai_new;
		}
		if (ai_cur != NULL) {
			ai_cur->ai_next = ai_new;
		}
		ai_cur = ai_new;
	}

	if (ai_head != NULL) {
		rc = 0;
	}

	*ai = ai_head;

	return rc;
}

static struct hostent *nwrap_files_gethostbyaddr(struct nwrap_backend *b,
						 const void *addr,
						 socklen_t len, int type)
{
	struct hostent *he;
	char ip[NWRAP_INET_ADDRSTRLEN] = {0};
	struct nwrap_entdata *ed;
	const char *a;
	size_t i;
	bool ok;

	(void) b; /* unused */
	(void) len; /* unused */

	ok = nwrap_files_cache_reload(nwrap_he_global.cache);
	if (!ok) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "error loading hosts file");
		return NULL;
	}

	a = inet_ntop(type, addr, ip, sizeof(ip));
	if (a == NULL) {
		errno = EINVAL;
		return NULL;
	}

	nwrap_vector_foreach(ed, nwrap_he_global.entries, i)
	{
		he = &(ed->ht);
		if (he->h_addrtype != type) {
			continue;
		}

		if (memcmp(addr, he->h_addr_list[0], he->h_length) == 0) {
			return he;
		}
	}

	errno = ENOENT;
	return NULL;
}

#ifdef HAVE_GETHOSTBYADDR_R
static int nwrap_gethostbyaddr_r(const void *addr, socklen_t len, int type,
				 struct hostent *ret,
				 char *buf, size_t buflen,
				 struct hostent **result, int *h_errnop)
{
	size_t i;
	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		*result = b->ops->nw_gethostbyaddr(b, addr, len, type);
		if (*result != NULL) {
			break;
		}
	}

	if (*result != NULL) {
		memset(buf, '\0', buflen);
		*ret = **result;
		return 0;
	}

	*h_errnop = h_errno;
	return -1;
}

int gethostbyaddr_r(const void *addr, socklen_t len, int type,
		    struct hostent *ret,
		    char *buf, size_t buflen,
		    struct hostent **result, int *h_errnop)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyaddr_r(addr,
					    len,
					    type,
					    ret,
					    buf,
					    buflen,
					    result,
					    h_errnop);
	}

	return nwrap_gethostbyaddr_r(addr, len, type, ret, buf, buflen, result, h_errnop);
}
#endif

/* hosts enum functions */
static void nwrap_files_sethostent(void)
{
	nwrap_he_global.idx = 0;
}

static struct hostent *nwrap_files_gethostent(void)
{
	struct hostent *he;

	if (nwrap_he_global.idx == 0) {
		bool ok;

		ok = nwrap_files_cache_reload(nwrap_he_global.cache);
		if (!ok) {
			NWRAP_LOG(NWRAP_LOG_ERROR, "Error loading hosts file");
			return NULL;
		}
	}

	if (nwrap_he_global.idx >= nwrap_he_global.num) {
		errno = ENOENT;
		return NULL;
	}

	he = &((struct nwrap_entdata *)nwrap_he_global.entries.items[nwrap_he_global.idx++])->ht;

	NWRAP_LOG(NWRAP_LOG_DEBUG, "return hosts[%s]", he->h_name);

	return he;
}

static void nwrap_files_endhostent(void)
{
	nwrap_he_global.idx = 0;
}

/*
 * module backend
 */


static struct passwd *nwrap_module_getpwnam(struct nwrap_backend *b,
					    const char *name)
{
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;

	if (b->symbols->_nss_getpwnam_r.f == NULL) {
		return NULL;
	}

	status = b->symbols->_nss_getpwnam_r.f(name,
					       &pwd,
					       buf,
					       sizeof(buf),
					       &errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		return NULL;
	}

	return &pwd;
}

static int nwrap_module_getpwnam_r(struct nwrap_backend *b,
				   const char *name, struct passwd *pwdst,
				   char *buf, size_t buflen, struct passwd **pwdstp)
{
	int ret;

	*pwdstp = NULL;

	if (b->symbols->_nss_getpwnam_r.f == NULL) {
		return NSS_STATUS_NOTFOUND;
	}

	ret = b->symbols->_nss_getpwnam_r.f(name, pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*pwdstp = pwdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static struct passwd *nwrap_module_getpwuid(struct nwrap_backend *b,
					    uid_t uid)
{
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;

	if (b->symbols->_nss_getpwuid_r.f == NULL) {
		return NULL;
	}

	status = b->symbols->_nss_getpwuid_r.f(uid,
					       &pwd,
					       buf,
					       sizeof(buf),
					       &errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		return NULL;
	}
	return &pwd;
}

static int nwrap_module_getpwuid_r(struct nwrap_backend *b,
				   uid_t uid, struct passwd *pwdst,
				   char *buf, size_t buflen, struct passwd **pwdstp)
{
	int ret;

	*pwdstp = NULL;

	if (b->symbols->_nss_getpwuid_r.f == NULL) {
		return ENOENT;
	}

	ret = b->symbols->_nss_getpwuid_r.f(uid, pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*pwdstp = pwdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static void nwrap_module_setpwent(struct nwrap_backend *b)
{
	if (b->symbols->_nss_setpwent.f == NULL) {
		return;
	}

	b->symbols->_nss_setpwent.f();
}

static struct passwd *nwrap_module_getpwent(struct nwrap_backend *b)
{
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;

	if (b->symbols->_nss_getpwent_r.f == NULL) {
		return NULL;
	}

	status = b->symbols->_nss_getpwent_r.f(&pwd, buf, sizeof(buf), &errno);
	if (status == NSS_STATUS_NOTFOUND) {
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		return NULL;
	}
	return &pwd;
}

static int nwrap_module_getpwent_r(struct nwrap_backend *b,
				   struct passwd *pwdst, char *buf,
				   size_t buflen, struct passwd **pwdstp)
{
	int ret;

	*pwdstp = NULL;

	if (b->symbols->_nss_getpwent_r.f == NULL) {
		return ENOENT;
	}

	ret = b->symbols->_nss_getpwent_r.f(pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*pwdstp = pwdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static void nwrap_module_endpwent(struct nwrap_backend *b)
{
	if (b->symbols->_nss_endpwent.f) {
		return;
	}

	b->symbols->_nss_endpwent.f();
}

static int nwrap_module_initgroups(struct nwrap_backend *b,
				   const char *user, gid_t group)
{
	gid_t *groups;
	long int start;
	long int size;

	if (b->symbols->_nss_initgroups.f == NULL) {
		return NSS_STATUS_UNAVAIL;
	}

	return b->symbols->_nss_initgroups.f(user,
					     group,
					     &start,
					     &size,
					     &groups,
					     0,
					     &errno);
}

static struct group *nwrap_module_getgrnam(struct nwrap_backend *b,
					   const char *name)
{
	static struct group grp;
	static char *buf;
	static int buflen = 1000;
	NSS_STATUS status;

	if (b->symbols->_nss_getgrnam_r.f == NULL) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}
again:
	status = b->symbols->_nss_getgrnam_r.f(name, &grp, buf, buflen, &errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		buflen *= 2;
		buf = (char *)realloc(buf, buflen);
		if (!buf) {
			return NULL;
		}
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}
	return &grp;
}

static int nwrap_module_getgrnam_r(struct nwrap_backend *b,
				   const char *name, struct group *grdst,
				   char *buf, size_t buflen, struct group **grdstp)
{
	int ret;

	*grdstp = NULL;

	if (b->symbols->_nss_getgrnam_r.f == NULL) {
		return ENOENT;
	}

	ret = b->symbols->_nss_getgrnam_r.f(name, grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*grdstp = grdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static struct group *nwrap_module_getgrgid(struct nwrap_backend *b,
					   gid_t gid)
{
	static struct group grp;
	static char *buf;
	static int buflen = 1000;
	NSS_STATUS status;

	if (b->symbols->_nss_getgrgid_r.f == NULL) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}

again:
	status = b->symbols->_nss_getgrgid_r.f(gid, &grp, buf, buflen, &errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		buflen *= 2;
		buf = (char *)realloc(buf, buflen);
		if (!buf) {
			return NULL;
		}
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}
	return &grp;
}

static int nwrap_module_getgrgid_r(struct nwrap_backend *b,
				   gid_t gid, struct group *grdst,
				   char *buf, size_t buflen, struct group **grdstp)
{
	int ret;

	*grdstp = NULL;

	if (b->symbols->_nss_getgrgid_r.f == NULL) {
		return ENOENT;
	}

	ret = b->symbols->_nss_getgrgid_r.f(gid, grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*grdstp = grdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static void nwrap_module_setgrent(struct nwrap_backend *b)
{
	if (b->symbols->_nss_setgrent.f) {
		return;
	}

	b->symbols->_nss_setgrent.f();
}

static struct group *nwrap_module_getgrent(struct nwrap_backend *b)
{
	static struct group grp;
	static char *buf;
	static int buflen = 1024;
	NSS_STATUS status;

	if (b->symbols->_nss_getgrent_r.f == NULL) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}

again:
	status = b->symbols->_nss_getgrent_r.f(&grp, buf, buflen, &errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		buflen *= 2;
		buf = (char *)realloc(buf, buflen);
		if (!buf) {
			return NULL;
		}
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}
	return &grp;
}

static int nwrap_module_getgrent_r(struct nwrap_backend *b,
				   struct group *grdst, char *buf,
				   size_t buflen, struct group **grdstp)
{
	int ret;

	*grdstp = NULL;

	if (b->symbols->_nss_getgrent_r.f == NULL) {
		return ENOENT;
	}

	ret = b->symbols->_nss_getgrent_r.f(grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
		*grdstp = grdst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return ret;
	}
}

static void nwrap_module_endgrent(struct nwrap_backend *b)
{
	if (b->symbols->_nss_endgrent.f == NULL) {
		return;
	}

	b->symbols->_nss_endgrent.f();
}

static struct hostent *nwrap_module_gethostbyaddr(struct nwrap_backend *b,
						  const void *addr,
						  socklen_t len, int type)
{
	static struct hostent he;
	static char *buf = NULL;
	static size_t buflen = 1000;
	NSS_STATUS status;

	if (b->symbols->_nss_gethostbyaddr_r.f == NULL) {
		return NULL;
	}

	if (buf == NULL) {
		buf = (char *)malloc(buflen);
		if (buf == NULL) {
			return NULL;
		}
	}
again:
	status = b->symbols->_nss_gethostbyaddr_r.f(addr,
						    len,
						    type,
						    &he,
						    buf,
						    buflen,
						    &errno,
						    &h_errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		char *p = NULL;

		buflen *= 2;
		p = (char *)realloc(buf, buflen);
		if (p == NULL) {
			SAFE_FREE(buf);
			return NULL;
		}
		buf = p;
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}

	return &he;
}

static int nwrap_module_gethostbyname2_r(struct nwrap_backend *b,
					 const char *name, int af,
					 struct hostent *hedst,
					 char *buf, size_t buflen,
					 struct hostent **hedstp)
{
	NSS_STATUS status;

	*hedstp = NULL;

	if (b->symbols->_nss_gethostbyname2_r.f == NULL) {
		return ENOENT;
	}

	status = b->symbols->_nss_gethostbyname2_r.f(name,
						     af,
						     hedst,
						     buf,
						     buflen,
						     &errno,
						     &h_errno);
	switch (status) {
	case NSS_STATUS_SUCCESS:
		*hedstp = hedst;
		return 0;
	case NSS_STATUS_NOTFOUND:
		if (errno != 0) {
			return errno;
		}
		return ENOENT;
	case NSS_STATUS_TRYAGAIN:
		if (errno != 0) {
			return errno;
		}
		return ERANGE;
	default:
		if (errno != 0) {
			return errno;
		}
		return status;
	}
}

static struct hostent *nwrap_module_gethostbyname(struct nwrap_backend *b,
						  const char *name)
{
	static struct hostent he;
	static char *buf = NULL;
	static size_t buflen = 1000;
	NSS_STATUS status;

	if (b->symbols->_nss_gethostbyname2_r.f == NULL) {
		return NULL;
	}

	if (buf == NULL) {
		buf = (char *)malloc(buflen);
		if (buf == NULL) {
			return NULL;
		}
	}

again:
	status = b->symbols->_nss_gethostbyname2_r.f(name,
						     AF_UNSPEC,
						     &he,
						     buf,
						     buflen,
						     &errno,
						     &h_errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		char *p = NULL;

		buflen *= 2;
		p = (char *)realloc(buf, buflen);
		if (p == NULL) {
			SAFE_FREE(buf);
			return NULL;
		}
		buf = p;
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}

	return &he;
}

static struct hostent *nwrap_module_gethostbyname2(struct nwrap_backend *b,
						   const char *name, int af)
{
	static struct hostent he;
	static char *buf = NULL;
	static size_t buflen = 1000;
	NSS_STATUS status;

	if (b->symbols->_nss_gethostbyname2_r.f == NULL) {
		return NULL;
	}

	if (buf == NULL) {
		buf = (char *)malloc(buflen);
		if (buf == NULL) {
			return NULL;
		}
	}

again:
	status = b->symbols->_nss_gethostbyname2_r.f(name,
						     af,
						     &he,
						     buf,
						     buflen,
						     &errno,
						     &h_errno);
	if (status == NSS_STATUS_TRYAGAIN) {
		char *p = NULL;

		buflen *= 2;
		p = (char *)realloc(buf, buflen);
		if (p == NULL) {
			SAFE_FREE(buf);
			return NULL;
		}
		buf = p;
		goto again;
	}
	if (status == NSS_STATUS_NOTFOUND) {
		SAFE_FREE(buf);
		return NULL;
	}
	if (status != NSS_STATUS_SUCCESS) {
		SAFE_FREE(buf);
		return NULL;
	}

	return &he;
}

/****************************************************************************
 *   GETPWNAM
 ***************************************************************************/

static struct passwd *nwrap_getpwnam(const char *name)
{
	size_t i;
	struct passwd *pwd;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		pwd = b->ops->nw_getpwnam(b, name);
		if (pwd) {
			return pwd;
		}
	}

	return NULL;
}

struct passwd *getpwnam(const char *name)
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwnam(name);
	}

	return nwrap_getpwnam(name);
}

/****************************************************************************
 *   GETPWNAM_R
 ***************************************************************************/

static int nwrap_getpwnam_r(const char *name, struct passwd *pwdst,
			    char *buf, size_t buflen, struct passwd **pwdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getpwnam_r(b, name, pwdst, buf, buflen, pwdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#ifdef HAVE_GETPWNAM_R
# ifdef HAVE_SOLARIS_GETPWNAM_R
int getpwnam_r(const char *name, struct passwd *pwdst,
	       char *buf, int buflen, struct passwd **pwdstp)
# else /* HAVE_SOLARIS_GETPWNAM_R */
int getpwnam_r(const char *name, struct passwd *pwdst,
	       char *buf, size_t buflen, struct passwd **pwdstp)
# endif /* HAVE_SOLARIS_GETPWNAM_R */
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwnam_r(name, pwdst, buf, buflen, pwdstp);
	}

	return nwrap_getpwnam_r(name, pwdst, buf, buflen, pwdstp);
}
#endif

/****************************************************************************
 *   GETPWUID
 ***************************************************************************/

static struct passwd *nwrap_getpwuid(uid_t uid)
{
	size_t i;
	struct passwd *pwd;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		pwd = b->ops->nw_getpwuid(b, uid);
		if (pwd) {
			return pwd;
		}
	}

	return NULL;
}

struct passwd *getpwuid(uid_t uid)
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwuid(uid);
	}

	return nwrap_getpwuid(uid);
}

/****************************************************************************
 *   GETPWUID_R
 ***************************************************************************/

static int nwrap_getpwuid_r(uid_t uid, struct passwd *pwdst,
			    char *buf, size_t buflen, struct passwd **pwdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getpwuid_r(b, uid, pwdst, buf, buflen, pwdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#ifdef HAVE_SOLARIS_GETPWUID_R
int getpwuid_r(uid_t uid, struct passwd *pwdst,
	       char *buf, int buflen, struct passwd **pwdstp)
#else
int getpwuid_r(uid_t uid, struct passwd *pwdst,
	       char *buf, size_t buflen, struct passwd **pwdstp)
#endif
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwuid_r(uid, pwdst, buf, buflen, pwdstp);
	}

	return nwrap_getpwuid_r(uid, pwdst, buf, buflen, pwdstp);
}

/****************************************************************************
 *   SETPWENT
 ***************************************************************************/

static void nwrap_setpwent(void)
{
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		b->ops->nw_setpwent(b);
	}
}

void setpwent(void)
{
	if (!nss_wrapper_enabled()) {
		libc_setpwent();
		return;
	}

	nwrap_setpwent();
}

/****************************************************************************
 *   GETPWENT
 ***************************************************************************/

static struct passwd *nwrap_getpwent(void)
{
	size_t i;
	struct passwd *pwd;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		pwd = b->ops->nw_getpwent(b);
		if (pwd) {
			return pwd;
		}
	}

	return NULL;
}

struct passwd *getpwent(void)
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwent();
	}

	return nwrap_getpwent();
}

/****************************************************************************
 *   GETPWENT_R
 ***************************************************************************/

#ifdef HAVE_GETPWENT_R
static int nwrap_getpwent_r(struct passwd *pwdst, char *buf,
			    size_t buflen, struct passwd **pwdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getpwent_r(b, pwdst, buf, buflen, pwdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#  ifdef HAVE_SOLARIS_GETPWENT_R
struct passwd *getpwent_r(struct passwd *pwdst, char *buf, int buflen)
{
	struct passwd *pwdstp = NULL;
	int rc;

	if (!nss_wrapper_enabled()) {
		return libc_getpwent_r(pwdst, buf, buflen);
	}
	rc = nwrap_getpwent_r(pwdst, buf, buflen, &pwdstp);
	if (rc < 0) {
		return NULL;
	}

	return pwdstp;
}
#  else /* HAVE_SOLARIS_GETPWENT_R */
int getpwent_r(struct passwd *pwdst, char *buf,
	       size_t buflen, struct passwd **pwdstp)
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwent_r(pwdst, buf, buflen, pwdstp);
	}

	return nwrap_getpwent_r(pwdst, buf, buflen, pwdstp);
}
#  endif /* HAVE_SOLARIS_GETPWENT_R */
#endif /* HAVE_GETPWENT_R */

/****************************************************************************
 *   ENDPWENT
 ***************************************************************************/

static void nwrap_endpwent(void)
{
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		b->ops->nw_endpwent(b);
	}
}

void endpwent(void)
{
	if (!nss_wrapper_enabled()) {
		libc_endpwent();
		return;
	}

	nwrap_endpwent();
}

/****************************************************************************
 *   INITGROUPS
 ***************************************************************************/

static int nwrap_initgroups(const char *user, gid_t group)
{
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		int rc;

		rc = b->ops->nw_initgroups(b, user, group);
		if (rc == 0) {
			return 0;
		}
	}

	errno = ENOENT;
	return -1;
}

int initgroups(const char *user, gid_t group)
{
	if (!nss_wrapper_enabled()) {
		return libc_initgroups(user, group);
	}

	return nwrap_initgroups(user, group);
}

/****************************************************************************
 *   GETGRNAM
 ***************************************************************************/

static struct group *nwrap_getgrnam(const char *name)
{
	size_t i;
	struct group *grp;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		grp = b->ops->nw_getgrnam(b, name);
		if (grp) {
			return grp;
		}
	}

	return NULL;
}

struct group *getgrnam(const char *name)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrnam(name);
	}

	return nwrap_getgrnam(name);
}

/****************************************************************************
 *   GETGRNAM_R
 ***************************************************************************/

static int nwrap_getgrnam_r(const char *name, struct group *grdst,
			    char *buf, size_t buflen, struct group **grdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getgrnam_r(b, name, grdst, buf, buflen, grdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#ifdef HAVE_GETGRNAM_R
# ifdef HAVE_SOLARIS_GETGRNAM_R
int getgrnam_r(const char *name, struct group *grp,
		char *buf, int buflen, struct group **pgrp)
# else /* HAVE_SOLARIS_GETGRNAM_R */
int getgrnam_r(const char *name, struct group *grp,
	       char *buf, size_t buflen, struct group **pgrp)
# endif /* HAVE_SOLARIS_GETGRNAM_R */
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrnam_r(name,
				       grp,
				       buf,
				       buflen,
				       pgrp);
	}

	return nwrap_getgrnam_r(name, grp, buf, buflen, pgrp);
}
#endif /* HAVE_GETGRNAM_R */

/****************************************************************************
 *   GETGRGID
 ***************************************************************************/

static struct group *nwrap_getgrgid(gid_t gid)
{
	size_t i;
	struct group *grp;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		grp = b->ops->nw_getgrgid(b, gid);
		if (grp) {
			return grp;
		}
	}

	return NULL;
}

struct group *getgrgid(gid_t gid)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrgid(gid);
	}

	return nwrap_getgrgid(gid);
}

/****************************************************************************
 *   GETGRGID_R
 ***************************************************************************/

static int nwrap_getgrgid_r(gid_t gid, struct group *grdst,
			    char *buf, size_t buflen, struct group **grdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getgrgid_r(b, gid, grdst, buf, buflen, grdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#ifdef HAVE_GETGRGID_R
# ifdef HAVE_SOLARIS_GETGRGID_R
int getgrgid_r(gid_t gid, struct group *grdst,
	       char *buf, int buflen, struct group **grdstp)
# else /* HAVE_SOLARIS_GETGRGID_R */
int getgrgid_r(gid_t gid, struct group *grdst,
	       char *buf, size_t buflen, struct group **grdstp)
# endif /* HAVE_SOLARIS_GETGRGID_R */
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrgid_r(gid, grdst, buf, buflen, grdstp);
	}

	return nwrap_getgrgid_r(gid, grdst, buf, buflen, grdstp);
}
#endif

/****************************************************************************
 *   SETGRENT
 ***************************************************************************/

static void nwrap_setgrent(void)
{
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		b->ops->nw_setgrent(b);
	}
}

#ifdef HAVE_BSD_SETGRENT
int setgrent(void)
#else
void setgrent(void)
#endif
{
	if (!nss_wrapper_enabled()) {
		libc_setgrent();
		goto out;
	}

	nwrap_setgrent();

out:
#ifdef HAVE_BSD_SETGRENT
	return 0;
#else
	return;
#endif
}

/****************************************************************************
 *   GETGRENT
 ***************************************************************************/

static struct group *nwrap_getgrent(void)
{
	size_t i;
	struct group *grp;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		grp = b->ops->nw_getgrent(b);
		if (grp) {
			return grp;
		}
	}

	return NULL;
}

struct group *getgrent(void)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrent();
	}

	return nwrap_getgrent();
}

/****************************************************************************
 *   GETGRENT_R
 ***************************************************************************/

#ifdef HAVE_GETGRENT_R
static int nwrap_getgrent_r(struct group *grdst, char *buf,
			    size_t buflen, struct group **grdstp)
{
	size_t i;
	int ret;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		ret = b->ops->nw_getgrent_r(b, grdst, buf, buflen, grdstp);
		if (ret == ENOENT) {
			continue;
		}
		return ret;
	}

	return ENOENT;
}

#  ifdef HAVE_SOLARIS_GETGRENT_R
struct group *getgrent_r(struct group *src, char *buf, int buflen)
{
	struct group *grdstp = NULL;
	int rc;

	if (!nss_wrapper_enabled()) {
		return libc_getgrent_r(src, buf, buflen);
	}

	rc = nwrap_getgrent_r(src, buf, buflen, &grdstp);
	if (rc < 0) {
		return NULL;
	}

	return grdstp;
}
#  else /* HAVE_SOLARIS_GETGRENT_R */
int getgrent_r(struct group *src, char *buf,
	       size_t buflen, struct group **grdstp)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrent_r(src, buf, buflen, grdstp);
	}

	return nwrap_getgrent_r(src, buf, buflen, grdstp);
}
#  endif /* HAVE_SOLARIS_GETGRENT_R */
#endif /* HAVE_GETGRENT_R */

/****************************************************************************
 *   ENDGRENT
 ***************************************************************************/

static void nwrap_endgrent(void)
{
	size_t i;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		b->ops->nw_endgrent(b);
	}
}

void endgrent(void)
{
	if (!nss_wrapper_enabled()) {
		libc_endgrent();
		return;
	}

	nwrap_endgrent();
}

/****************************************************************************
 *   GETGROUPLIST
 ***************************************************************************/

#ifdef HAVE_GETGROUPLIST
static int nwrap_getgrouplist(const char *user, gid_t group,
			      gid_t *groups, int *ngroups)
{
	struct group *grp;
	gid_t *groups_tmp;
	int count = 1;

	NWRAP_LOG(NWRAP_LOG_DEBUG, "getgrouplist called for %s", user);

	groups_tmp = (gid_t *)malloc(count * sizeof(gid_t));
	if (!groups_tmp) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		errno = ENOMEM;
		return -1;
	}
	groups_tmp[0] = group;

	nwrap_setgrent();
	while ((grp = nwrap_getgrent()) != NULL) {
		int i = 0;

		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "Inspecting %s for group membership",
			  grp->gr_name);

		for (i=0; grp->gr_mem && grp->gr_mem[i] != NULL; i++) {

			if (group != grp->gr_gid &&
			    (strcmp(user, grp->gr_mem[i]) == 0)) {

				NWRAP_LOG(NWRAP_LOG_DEBUG,
					  "%s is member of %s",
					  user,
					  grp->gr_name);

				groups_tmp = (gid_t *)realloc(groups_tmp, (count + 1) * sizeof(gid_t));
				if (!groups_tmp) {
					NWRAP_LOG(NWRAP_LOG_ERROR,
						  "Out of memory");
					errno = ENOMEM;
					return -1;
				}
				groups_tmp[count] = grp->gr_gid;

				count++;
			}
		}
	}

	nwrap_endgrent();

	NWRAP_LOG(NWRAP_LOG_DEBUG,
		  "%s is member of %d groups",
		  user, *ngroups);

	if (*ngroups < count) {
		*ngroups = count;
		free(groups_tmp);
		return -1;
	}

	*ngroups = count;
	memcpy(groups, groups_tmp, count * sizeof(gid_t));
	free(groups_tmp);

	return count;
}

int getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrouplist(user, group, groups, ngroups);
	}

	return nwrap_getgrouplist(user, group, groups, ngroups);
}
#endif

/**********************************************************
 * SHADOW
 **********************************************************/

#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)

#ifdef HAVE_SETSPENT
static void nwrap_setspent(void)
{
	nwrap_files_setspent();
}

void setspent(void)
{
	if (!nss_wrapper_shadow_enabled()) {
		return;
	}

	nwrap_setspent();
}

static struct spwd *nwrap_getspent(void)
{
	return nwrap_files_getspent();
}

struct spwd *getspent(void)
{
	if (!nss_wrapper_shadow_enabled()) {
		return NULL;
	}

	return nwrap_getspent();
}

static void nwrap_endspent(void)
{
	nwrap_files_endspent();
}

void endspent(void)
{
	if (!nss_wrapper_shadow_enabled()) {
		return;
	}

	nwrap_endspent();
}
#endif /* HAVE_SETSPENT */

static struct spwd *nwrap_getspnam(const char *name)
{
	return nwrap_files_getspnam(name);
}

struct spwd *getspnam(const char *name)
{
	if (!nss_wrapper_shadow_enabled()) {
		return NULL;
	}

	return nwrap_getspnam(name);
}

#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

/**********************************************************
 * NETDB
 **********************************************************/

static void nwrap_sethostent(int stayopen) {
	(void) stayopen; /* ignored */

	nwrap_files_sethostent();
}

#ifdef HAVE_SOLARIS_SETHOSTENT
int sethostent(int stayopen)
{
	if (!nss_wrapper_hosts_enabled()) {
		libc_sethostent(stayopen);
		return 0;
	}

	nwrap_sethostent(stayopen);

	return 0;
}
#else /* HAVE_SOLARIS_SETHOSTENT */
void sethostent(int stayopen)
{
	if (!nss_wrapper_hosts_enabled()) {
		libc_sethostent(stayopen);
		return;
	}

	nwrap_sethostent(stayopen);
}
#endif /* HAVE_SOLARIS_SETHOSTENT */

static struct hostent *nwrap_gethostent(void)
{
	return nwrap_files_gethostent();
}

struct hostent *gethostent(void) {
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostent();
	}

	return nwrap_gethostent();
}

static void nwrap_endhostent(void) {
	nwrap_files_endhostent();
}

#ifdef HAVE_SOLARIS_ENDHOSTENT
int endhostent(void)
{
	if (!nss_wrapper_hosts_enabled()) {
		libc_endhostent();
		return 0;
	}

	nwrap_endhostent();

	return 0;
}
#else /* HAVE_SOLARIS_ENDHOSTENT */
void endhostent(void)
{
	if (!nss_wrapper_hosts_enabled()) {
		libc_endhostent();
		return;
	}

	nwrap_endhostent();
}
#endif /* HAVE_SOLARIS_ENDHOSTENT */


#ifdef BSD
/* BSD implementation stores data in thread local storage but GLIBC does not */
static __thread struct hostent user_he;
static __thread struct nwrap_vector user_addrlist;
#else
static struct hostent user_he;
static struct nwrap_vector user_addrlist;
#endif /* BSD */

static struct hostent *nwrap_files_gethostbyname(struct nwrap_backend *b,
						 const char *name)
{
	int ret;

	(void) b; /* unused */

	ret = nwrap_files_internal_gethostbyname(name, AF_UNSPEC, &user_he,
						 &user_addrlist);
	if (ret == 0) {
		return &user_he;
	}

	return NULL;
}

static struct hostent *nwrap_gethostbyname(const char *name)
{
	size_t i;
	struct hostent *he = NULL;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		he = b->ops->nw_gethostbyname(b, name);
		if (he != NULL) {
			return he;
		}
	}

	return NULL;
}

struct hostent *gethostbyname(const char *name)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyname(name);
	}

	return nwrap_gethostbyname(name);
}

/* This is a GNU extension - Also can be found on BSD systems */
#ifdef HAVE_GETHOSTBYNAME2
#ifdef BSD
/* BSD implementation stores data in  thread local storage but GLIBC not */
static __thread struct hostent user_he2;
static __thread struct nwrap_vector user_addrlist2;
#else
static struct hostent user_he2;
static struct nwrap_vector user_addrlist2;
#endif /* BSD */

static struct hostent *nwrap_files_gethostbyname2(struct nwrap_backend *b,
						  const char *name, int af)
{
	int ret;

	(void) b; /* unused */

	ret = nwrap_files_internal_gethostbyname(name, af, &user_he2,
						 &user_addrlist2);
	if (ret == 0) {
		return &user_he2;
	}

	return NULL;
}

static struct hostent *nwrap_gethostbyname2(const char *name, int af)
{
	size_t i;
	struct hostent *he = NULL;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		he = b->ops->nw_gethostbyname2(b, name, af);
		if (he != NULL) {
			return he;
		}
	}

	return NULL;
}

struct hostent *gethostbyname2(const char *name, int af)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyname2(name, af);
	}

	return nwrap_gethostbyname2(name, af);
}
#endif

static struct hostent *nwrap_gethostbyaddr(const void *addr,
					   socklen_t len, int type)
{
	size_t i;
	struct hostent *he = NULL;

	for (i=0; i < nwrap_main_global->num_backends; i++) {
		struct nwrap_backend *b = &nwrap_main_global->backends[i];
		he = b->ops->nw_gethostbyaddr(b, addr, len, type);
		if (he != NULL) {
			return he;
		}
	}

	return NULL;
}

struct hostent *gethostbyaddr(const void *addr,
			      socklen_t len, int type)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyaddr(addr, len, type);
	}

	return nwrap_gethostbyaddr(addr, len, type);
}

static const struct addrinfo default_hints =
{
	.ai_flags = AI_ADDRCONFIG|AI_V4MAPPED,
	.ai_family = AF_UNSPEC,
	.ai_socktype = 0,
	.ai_protocol = 0,
	.ai_addrlen = 0,
	.ai_addr = NULL,
	.ai_canonname = NULL,
	.ai_next = NULL
};

static int nwrap_convert_he_ai(const struct hostent *he,
			       unsigned short port,
			       const struct addrinfo *hints,
			       struct addrinfo **pai,
			       bool skip_canonname)
{
	struct addrinfo *ai;
	socklen_t socklen;

	if (he == NULL) {
		return EAI_MEMORY;
	}

	switch (he->h_addrtype) {
		case AF_INET:
			socklen = sizeof(struct sockaddr_in);
			break;
#ifdef HAVE_IPV6
		case AF_INET6:
			socklen = sizeof(struct sockaddr_in6);
			break;
#endif
		default:
			return EAI_FAMILY;
	}

	ai = (struct addrinfo *)malloc(sizeof(struct addrinfo) + socklen);
	if (ai == NULL) {
		return EAI_MEMORY;
	}

	ai->ai_flags = hints->ai_flags;
	ai->ai_family = he->h_addrtype;
	ai->ai_socktype = hints->ai_socktype;
	ai->ai_protocol = hints->ai_protocol;
	ai->ai_canonname = NULL;

	if (ai->ai_socktype == 0) {
		ai->ai_socktype = SOCK_DGRAM;
	}
	if (ai->ai_protocol == 0) {
		if (ai->ai_socktype == SOCK_DGRAM) {
			ai->ai_protocol = IPPROTO_UDP;
		} else if (ai->ai_socktype == SOCK_STREAM) {
			ai->ai_protocol = IPPROTO_TCP;
		}
	}

	ai->ai_addrlen = socklen;
	ai->ai_addr = (void *)(ai + 1);

#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	ai->ai_addr->sa_len = socklen;
#endif
	ai->ai_addr->sa_family = he->h_addrtype;

	switch (he->h_addrtype) {
		case AF_INET:
		{
			union {
				struct sockaddr *sa;
				struct sockaddr_in *in;
			} addr;

			addr.sa = ai->ai_addr;

			memset(addr.in, 0, sizeof(struct sockaddr_in));

			addr.in->sin_port = htons(port);
			addr.in->sin_family = AF_INET;

			memset(addr.in->sin_zero,
			       '\0',
			       sizeof (addr.in->sin_zero));
			memcpy(&(addr.in->sin_addr),
			       he->h_addr_list[0],
			       he->h_length);

		}
		break;
#ifdef HAVE_IPV6
		case AF_INET6:
		{
			union {
				struct sockaddr *sa;
				struct sockaddr_in6 *in6;
			} addr;

			addr.sa = ai->ai_addr;

			memset(addr.in6, 0, sizeof(struct sockaddr_in6));

			addr.in6->sin6_port = htons(port);
			addr.in6->sin6_family = AF_INET6;

			memcpy(&addr.in6->sin6_addr,
			       he->h_addr_list[0],
			       he->h_length);
		}
		break;
#endif
	}

	ai->ai_next = NULL;

	if (he->h_name && !skip_canonname) {
		ai->ai_canonname = strdup(he->h_name);
		if (ai->ai_canonname == NULL) {
			freeaddrinfo(ai);
			return EAI_MEMORY;
		}
	}

	*pai = ai;
	return 0;
}

static int nwrap_getaddrinfo(const char *node,
			     const char *service,
			     const struct addrinfo *hints,
			     struct addrinfo **res)
{
	struct addrinfo *ai = NULL;
	unsigned short port = 0;
	struct {
		int family;
		union {
			struct in_addr v4;
#ifdef HAVE_IPV6
			struct in6_addr v6;
		} in;
#endif
	} addr = {
		.family = AF_UNSPEC,
	};
	int rc;

	if (node == NULL && service == NULL) {
		return EAI_NONAME;
	}

	if (hints == NULL) {
		hints = &default_hints;
	}

        /* EAI_BADFLAGS
              hints.ai_flags   contains   invalid  flags;  or,  hints.ai_flags
              included AI_CANONNAME and name was NULL.
	*/
	if ((hints->ai_flags & AI_CANONNAME) && (node == NULL)) {
		return EAI_BADFLAGS;
	}

	/* If no node has been specified, let glibc deal with it */
	if (node == NULL) {
		int ret;
		struct addrinfo *p = NULL;

		ret = libc_getaddrinfo(node, service, hints, &p);

		if (ret == 0) {
			*res = p;
		}
		return ret;
	}

	if (service != NULL && service[0] != '\0') {
		const char *proto = NULL;
		struct servent *s;
		char *end_ptr;
		long sl;

		errno = 0;
		sl = strtol(service, &end_ptr, 10);

		if (*end_ptr == '\0') {
			port = sl;
			goto valid_port;
		} else if (hints->ai_flags & AI_NUMERICSERV) {
			return EAI_NONAME;
		}

		if (hints->ai_protocol != 0) {
			struct protoent *pent;

			pent = getprotobynumber(hints->ai_protocol);
			if (pent != NULL) {
				proto = pent->p_name;
			}
		}

		s = getservbyname(service, proto);
		if (s == NULL) {
			return EAI_NONAME;
		}
		port = ntohs(s->s_port);
	}

valid_port:

	rc = inet_pton(AF_INET, node, &addr.in.v4);
	if (rc == 1) {
		addr.family = AF_INET;
	}
#ifdef HAVE_IPV6
	if (addr.family == AF_UNSPEC) {
		rc = inet_pton(AF_INET6, node, &addr.in.v6);
		if (rc == 1) {
			addr.family = AF_INET6;
		}
	}
#endif

	if (addr.family == AF_UNSPEC) {
	       if (hints->ai_flags & AI_NUMERICHOST) {
			return EAI_NONAME;
		}
	} else if ((hints->ai_family != AF_UNSPEC) &&
		   (hints->ai_family != addr.family))
	{
		return EAI_ADDRFAMILY;
	}

	rc = nwrap_files_getaddrinfo(node, port, hints, &ai);
	if (rc != 0) {
		int ret;
		struct addrinfo *p = NULL;

		ret = libc_getaddrinfo(node, service, hints, &p);

		if (ret == 0) {
			/*
			 * nwrap_files_getaddrinfo failed, but libc was
			 * successful -- use the result from libc.
			 */
			*res = p;
			return 0;
		}

		return rc;
	}

	/*
	 * If the socktype was not specified, duplicate
	 * each ai returned, so that we have variants for
	 * both UDP and TCP.
	 */
	if (hints->ai_socktype == 0) {
		struct addrinfo *ai_cur;

		/* freeaddrinfo() frees ai_canonname and ai so allocate them */
		for (ai_cur = ai; ai_cur != NULL; ai_cur = ai_cur->ai_next) {
			struct addrinfo *ai_new;

			/* duplicate the current entry */

			ai_new = malloc(sizeof(struct addrinfo));
			if (ai_new == NULL) {
				freeaddrinfo(ai);
				return EAI_MEMORY;
			}

			memcpy(ai_new, ai_cur, sizeof(struct addrinfo));
			ai_new->ai_next = NULL;

			/* We need a deep copy or freeaddrinfo() will blow up */
			if (ai_cur->ai_canonname != NULL) {
				ai_new->ai_canonname =
					strdup(ai_cur->ai_canonname);
			}

			if (ai_cur->ai_socktype == SOCK_DGRAM) {
				ai_new->ai_socktype = SOCK_STREAM;
			} else if (ai_cur->ai_socktype == SOCK_STREAM) {
				ai_new->ai_socktype = SOCK_DGRAM;
			}
			if (ai_cur->ai_protocol == IPPROTO_TCP) {
				ai_new->ai_protocol = IPPROTO_UDP;
			} else if (ai_cur->ai_protocol == IPPROTO_UDP) {
				ai_new->ai_protocol = IPPROTO_TCP;
			}

			/* now insert the new entry */

			ai_new->ai_next = ai_cur->ai_next;
			ai_cur->ai_next = ai_new;

			/* and move on (don't duplicate the new entry) */

			ai_cur = ai_new;
		}
	}

	*res = ai;

	return 0;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_getaddrinfo(node, service, hints, res);
	}

	return nwrap_getaddrinfo(node, service, hints, res);
}

static int nwrap_getnameinfo(const struct sockaddr *sa, socklen_t salen,
			     char *host, size_t hostlen,
			     char *serv, size_t servlen,
			     int flags)
{
	struct hostent *he;
	struct servent *service;
	const char *proto;
	const void *addr;
	socklen_t addrlen;
	uint16_t port;
	sa_family_t type;
	size_t i;

	if (sa == NULL || salen < sizeof(sa_family_t)) {
		return EAI_FAMILY;
	}

	if ((flags & NI_NAMEREQD) && host == NULL && serv == NULL) {
		return EAI_NONAME;
	}

	type = sa->sa_family;
	switch (type) {
	case AF_INET: {
		union {
			const struct sockaddr *sa;
			const struct sockaddr_in *in;
		} a;

		if (salen < sizeof(struct sockaddr_in)) {
			return EAI_FAMILY;
		}

		a.sa = sa;

		addr = &(a.in->sin_addr);
		addrlen = sizeof(a.in->sin_addr);
		port = ntohs(a.in->sin_port);
		break;
	}
#ifdef HAVE_IPV6
	case AF_INET6: {
		union {
			const struct sockaddr *sa;
			const struct sockaddr_in6 *in6;
		} a;

		if (salen < sizeof(struct sockaddr_in6)) {
			return EAI_FAMILY;
		}

		a.sa = sa;

		addr = &(a.in6->sin6_addr);
		addrlen = sizeof(a.in6->sin6_addr);
		port = ntohs(a.in6->sin6_port);
		break;
	}
#endif
	default:
		return EAI_FAMILY;
	}

	if (host != NULL) {
		he = NULL;
		if ((flags & NI_NUMERICHOST) == 0) {
			for (i=0; i < nwrap_main_global->num_backends; i++) {
				struct nwrap_backend *b = &nwrap_main_global->backends[i];
				he = b->ops->nw_gethostbyaddr(b, addr, addrlen, type);
				if (he != NULL) {
					break;
				}
			}
			if ((flags & NI_NAMEREQD) && (he == NULL || he->h_name == NULL))
				return EAI_NONAME;
		}
		if (he != NULL && he->h_name != NULL) {
			if (strlen(he->h_name) >= hostlen)
				return EAI_OVERFLOW;
			snprintf(host, hostlen, "%s", he->h_name);
			if (flags & NI_NOFQDN)
				host[strcspn(host, ".")] = '\0';
		} else {
			if (inet_ntop(type, addr, host, hostlen) == NULL)
				return (errno == ENOSPC) ? EAI_OVERFLOW : EAI_FAIL;
		}
	}

	if (serv != NULL) {
		service = NULL;
		if ((flags & NI_NUMERICSERV) == 0) {
			proto = (flags & NI_DGRAM) ? "udp" : "tcp";
			service = getservbyport(htons(port), proto);
		}
		if (service != NULL) {
			if (strlen(service->s_name) >= servlen)
				return EAI_OVERFLOW;
			snprintf(serv, servlen, "%s", service->s_name);
		} else {
			if (snprintf(serv, servlen, "%u", port) >= (int) servlen)
				return EAI_OVERFLOW;
		}
	}

	return 0;
}

#ifdef HAVE_LINUX_GETNAMEINFO
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen,
		int flags)
#elif defined(HAVE_LINUX_GETNAMEINFO_UNSIGNED)
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen,
		unsigned int flags)
#else
int getnameinfo(const struct sockaddr *sa, socklen_t salen,
		char *host, size_t hostlen,
		char *serv, size_t servlen,
		int flags)
#endif
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
	}

	return nwrap_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

static int nwrap_gethostname(char *name, size_t len)
{
	const char *hostname = getenv("NSS_WRAPPER_HOSTNAME");

	if (strlen(hostname) >= len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	snprintf(name, len, "%s", hostname);

	return 0;
}

#ifdef HAVE_SOLARIS_GETHOSTNAME
int gethostname(char *name, int len)
#else /* HAVE_SOLARIS_GETHOSTNAME */
int gethostname(char *name, size_t len)
#endif /* HAVE_SOLARIS_GETHOSTNAME */
{
	if (!nwrap_hostname_enabled()) {
		return libc_gethostname(name, len);
	}

	return nwrap_gethostname(name, len);
}

/****************************
 * CONSTRUCTOR
 ***************************/
void nwrap_constructor(void)
{
	/*
	 * If we hold a lock and the application forks, then the child
	 * is not able to unlock the mutex and we are in a deadlock.
	 *
	 * Setting these handlers should prevent such deadlocks.
	 */
	pthread_atfork(&nwrap_thread_prepare,
		       &nwrap_thread_parent,
		       &nwrap_thread_child);

	/* Do not call nwrap_init() here. */
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
void nwrap_destructor(void)
{
	size_t i;

	NWRAP_LOCK_ALL;
	if (nwrap_main_global != NULL) {
		struct nwrap_main *m = nwrap_main_global;

		/* libc */
		if (m->libc != NULL) {
			if (m->libc->handle != NULL) {
				dlclose(m->libc->handle);
			}
			if (m->libc->nsl_handle != NULL) {
				dlclose(m->libc->nsl_handle);
			}
			if (m->libc->sock_handle != NULL) {
				dlclose(m->libc->sock_handle);
			}
			SAFE_FREE(m->libc);
		}

		/* backends */
		if (m->backends != NULL) {
			for (i = 0; i < m->num_backends; i++) {
				struct nwrap_backend *b = &(m->backends[i]);

				if (b->so_handle != NULL) {
					dlclose(b->so_handle);
				}
				SAFE_FREE(b->symbols);
			}
			SAFE_FREE(m->backends);
		}
	}

	if (nwrap_pw_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_pw_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			fclose(c->fp);
			c->fd = -1;
		}

		SAFE_FREE(nwrap_pw_global.list);
		nwrap_pw_global.num = 0;
	}

	if (nwrap_gr_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_gr_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			fclose(c->fp);
			c->fd = -1;
		}

		SAFE_FREE(nwrap_gr_global.list);
		nwrap_pw_global.num = 0;
	}

#if defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM)
	if (nwrap_sp_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_sp_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			fclose(c->fp);
			c->fd = -1;
		}

		nwrap_sp_global.num = 0;
	}
#endif /* defined(HAVE_SHADOW_H) && defined(HAVE_GETSPNAM) */

	if (nwrap_he_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_he_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			fclose(c->fp);
			c->fd = -1;
		}

		nwrap_he_global.num = 0;
	}

	free(user_addrlist.items);
#ifdef HAVE_GETHOSTBYNAME2
	free(user_addrlist2.items);
#endif

	hdestroy();
	NWRAP_UNLOCK_ALL;
}
