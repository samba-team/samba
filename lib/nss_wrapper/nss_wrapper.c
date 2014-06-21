/*
 * Copyright (C) Stefan Metzmacher 2007 <metze@samba.org>
 * Copyright (C) Guenther Deschner 2009 <gd@samba.org>
 * Copyright (C) Andreas Schneider 2013 <asn@samba.org>
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
 */

#include "config.h"

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

/* GCC have printf type attribute check. */
#ifdef HAVE_ATTRIBUTE_PRINTF_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_ATTRIBUTE_PRINTF_FORMAT */

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

enum nwrap_dbglvl_e {
	NWRAP_LOG_ERROR = 0,
	NWRAP_LOG_WARN,
	NWRAP_LOG_DEBUG,
	NWRAP_LOG_TRACE
};

#ifdef NDEBUG
# define NWRAP_LOG(...)
#else

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
	int pid = getpid();

	d = getenv("NSS_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		switch (dbglvl) {
			case NWRAP_LOG_ERROR:
				fprintf(stderr,
					"NWRAP_ERROR(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case NWRAP_LOG_WARN:
				fprintf(stderr,
					"NWRAP_WARN(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case NWRAP_LOG_DEBUG:
				fprintf(stderr,
					"NWRAP_DEBUG(%d) - %s: %s\n",
					pid, func, buffer);
				break;
			case NWRAP_LOG_TRACE:
				fprintf(stderr,
					"NWRAP_TRACE(%d) - %s: %s\n",
					pid, func, buffer);
				break;
		}
	}
}
#endif /* NDEBUG NWRAP_LOG */

struct nwrap_libc_fns {
	struct passwd *(*_libc_getpwnam)(const char *name);
	int (*_libc_getpwnam_r)(const char *name, struct passwd *pwd,
		       char *buf, size_t buflen, struct passwd **result);
	struct passwd *(*_libc_getpwuid)(uid_t uid);
	int (*_libc_getpwuid_r)(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result);
	void (*_libc_setpwent)(void);
	struct passwd *(*_libc_getpwent)(void);
#ifdef HAVE_SOLARIS_GETPWENT_R
	struct passwd *(*_libc_getpwent_r)(struct passwd *pwbuf, char *buf, size_t buflen);
#else
	int (*_libc_getpwent_r)(struct passwd *pwbuf, char *buf, size_t buflen, struct passwd **pwbufp);
#endif
	void (*_libc_endpwent)(void);
	int (*_libc_initgroups)(const char *user, gid_t gid);
	struct group *(*_libc_getgrnam)(const char *name);
	int (*_libc_getgrnam_r)(const char *name, struct group *grp, char *buf, size_t buflen, struct group **result);
	struct group *(*_libc_getgrgid)(gid_t gid);
	int (*_libc_getgrgid_r)(gid_t gid, struct group *grp, char *buf, size_t buflen, struct group **result);
	void (*_libc_setgrent)(void);
	struct group *(*_libc_getgrent)(void);
#ifdef HAVE_SOLARIS_GETGRENT_R
	struct group *(*_libc_getgrent_r)(struct group *group, char *buf, size_t buflen);
#else
	int (*_libc_getgrent_r)(struct group *group, char *buf, size_t buflen, struct group **result);
#endif
	void (*_libc_endgrent)(void);
	int (*_libc_getgrouplist)(const char *user, gid_t group, gid_t *groups, int *ngroups);

	void (*_libc_sethostent)(int stayopen);
	struct hostent *(*_libc_gethostent)(void);
	void (*_libc_endhostent)(void);

	struct hostent *(*_libc_gethostbyname)(const char *name);
#ifdef HAVE_GETHOSTBYNAME2 /* GNU extension */
	struct hostent *(*_libc_gethostbyname2)(const char *name, int af);
#endif
	struct hostent *(*_libc_gethostbyaddr)(const void *addr, socklen_t len, int type);

	int (*_libc_getaddrinfo)(const char *node, const char *service,
				 const struct addrinfo *hints,
				 struct addrinfo **res);
	int (*_libc_getnameinfo)(const struct sockaddr *sa, socklen_t salen,
				 char *host, size_t hostlen,
				 char *serv, size_t servlen,
				 int flags);
	int (*_libc_gethostname)(char *name, size_t len);
#ifdef HAVE_GETHOSTBYNAME_R
	int (*_libc_gethostbyname_r)(const char *name,
				     struct hostent *ret,
				     char *buf, size_t buflen,
				     struct hostent **result, int *h_errnop);
#endif
#ifdef HAVE_GETHOSTBYADDR_R
	int (*_libc_gethostbyaddr_r)(const void *addr, socklen_t len, int type,
				     struct hostent *ret,
				     char *buf, size_t buflen,
				     struct hostent **result, int *h_errnop);
#endif
};

struct nwrap_module_nss_fns {
	NSS_STATUS (*_nss_getpwnam_r)(const char *name, struct passwd *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_getpwuid_r)(uid_t uid, struct passwd *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_setpwent)(void);
	NSS_STATUS (*_nss_getpwent_r)(struct passwd *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_endpwent)(void);
	NSS_STATUS (*_nss_initgroups)(const char *user, gid_t group, long int *start,
				      long int *size, gid_t **groups, long int limit, int *errnop);
	NSS_STATUS (*_nss_getgrnam_r)(const char *name, struct group *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_getgrgid_r)(gid_t gid, struct group *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_setgrent)(void);
	NSS_STATUS (*_nss_getgrent_r)(struct group *result, char *buffer,
				      size_t buflen, int *errnop);
	NSS_STATUS (*_nss_endgrent)(void);
};

struct nwrap_backend {
	const char *name;
	const char *so_path;
	void *so_handle;
	struct nwrap_ops *ops;
	struct nwrap_module_nss_fns *fns;
};

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
};

/* Public prototypes */

bool nss_wrapper_enabled(void);
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
};

struct nwrap_libc {
	void *handle;
	void *nsl_handle;
	void *sock_handle;
	struct nwrap_libc_fns *fns;
};

struct nwrap_main {
	const char *nwrap_switch;
	int num_backends;
	struct nwrap_backend *backends;
	struct nwrap_libc *libc;
};

struct nwrap_main *nwrap_main_global;
struct nwrap_main __nwrap_main_global;

struct nwrap_cache {
	const char *path;
	int fd;
	struct stat st;
	uint8_t *buf;
	void *private_data;
	bool (*parse_line)(struct nwrap_cache *, char *line);
	void (*unload)(struct nwrap_cache *);
};

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

struct nwrap_gr {
	struct nwrap_cache *cache;

	struct group *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_gr;
struct nwrap_gr nwrap_gr_global;

static bool nwrap_he_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_he_unload(struct nwrap_cache *nwrap);

struct nwrap_addrdata {
	unsigned char host_addr[16]; /* IPv4 or IPv6 address */
	char *h_addr_ptrs[2]; /* host_addr pointer + NULL */
};

struct nwrap_entdata {
	struct nwrap_addrdata *addr;
	struct hostent ht;
};

struct nwrap_he {
	struct nwrap_cache *cache;

	struct nwrap_entdata *list;
	int num;
	int idx;
};

struct nwrap_cache __nwrap_cache_he;
struct nwrap_he nwrap_he_global;


/*********************************************************
 * NWRAP PROTOTYPES
 *********************************************************/

static void nwrap_init(void);
static bool nwrap_gr_parse_line(struct nwrap_cache *nwrap, char *line);
static void nwrap_gr_unload(struct nwrap_cache *nwrap);
void nwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * NWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum nwrap_lib {
    NWRAP_LIBC,
    NWRAP_LIBNSL,
    NWRAP_LIBSOCKET,
};

#ifndef NDEBUG
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
#endif

static void *nwrap_load_lib_handle(enum nwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef HAVE_APPLE
	return RTLD_NEXT;
#endif

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case NWRAP_LIBNSL:
#ifdef HAVE_LIBNSL
		handle = nwrap_main_global->libc->nsl_handle;
		if (handle == NULL) {
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libnsl.so.%d", i);
				handle = dlopen(soname, flags);
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
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libsocket.so.%d", i);
				handle = dlopen(soname, flags);
			}

			nwrap_main_global->libc->sock_handle = handle;
		}
		break;
#endif
		/* FALL TROUGH */
	case NWRAP_LIBC:
		handle = nwrap_main_global->libc->handle;
		if (handle == NULL) {
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
			}

			nwrap_main_global->libc->handle = handle;
		}
		break;
	}

	if (handle == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
	}

	return handle;
}

static void *_nwrap_load_lib_function(enum nwrap_lib lib, const char *fn_name)
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

#define nwrap_load_lib_function(lib, fn_name) \
	if (nwrap_main_global->libc->fns->_libc_##fn_name == NULL) { \
		*(void **) (&nwrap_main_global->libc->fns->_libc_##fn_name) = \
			_nwrap_load_lib_function(lib, #fn_name); \
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
	nwrap_load_lib_function(NWRAP_LIBC, getpwnam);

	return nwrap_main_global->libc->fns->_libc_getpwnam(name);
}

#ifdef HAVE_GETPWNAM_R
static int libc_getpwnam_r(const char *name,
			   struct passwd *pwd,
			   char *buf,
			   size_t buflen,
			   struct passwd **result)
{
#ifdef HAVE___POSIX_GETPWNAM_R
	if (nwrap_main_global->libc->fns->_libc_getpwnam_r == NULL) {
		*(void **) (&nwrap_main_global->libc->fns->_libc_getpwnam_r) =
			_nwrap_load_lib_function(NWRAP_LIBC, "__posix_getpwnam_r");
	}
#else
	nwrap_load_lib_function(NWRAP_LIBC, getpwnam_r);
#endif

	return nwrap_main_global->libc->fns->_libc_getpwnam_r(name,
							      pwd,
							      buf,
							      buflen,
							      result);
}
#endif

static struct passwd *libc_getpwuid(uid_t uid)
{
	nwrap_load_lib_function(NWRAP_LIBC, getpwuid);

	return nwrap_main_global->libc->fns->_libc_getpwuid(uid);
}

#ifdef HAVE_GETPWUID_R
static int libc_getpwuid_r(uid_t uid,
			   struct passwd *pwd,
			   char *buf,
			   size_t buflen,
			   struct passwd **result)
{
#ifdef HAVE___POSIX_GETPWUID_R
	if (nwrap_main_global->libc->fns->_libc_getpwuid_r == NULL) {
		*(void **) (&nwrap_main_global->libc->fns->_libc_getpwuid_r) =
			_nwrap_load_lib_function(NWRAP_LIBC, "__posix_getpwuid_r");
	}
#else
	nwrap_load_lib_function(NWRAP_LIBC, getpwuid_r);
#endif

	return nwrap_main_global->libc->fns->_libc_getpwuid_r(uid,
							      pwd,
							      buf,
							      buflen,
							      result);
}
#endif

static void libc_setpwent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, setpwent);

	nwrap_main_global->libc->fns->_libc_setpwent();
}

static struct passwd *libc_getpwent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, getpwent);

	return nwrap_main_global->libc->fns->_libc_getpwent();
}

#ifdef HAVE_SOLARIS_GETPWENT_R
static struct passwd *libc_getpwent_r(struct passwd *pwdst,
				      char *buf,
				      int buflen)
{
	nwrap_load_lib_function(NWRAP_LIBC, getpwent_r);

	return nwrap_main_global->libc->fns->_libc_getpwent_r(pwdst,
							      buf,
							      buflen);
}
#else /* HAVE_SOLARIS_GETPWENT_R */
static int libc_getpwent_r(struct passwd *pwdst,
			   char *buf,
			   size_t buflen,
			   struct passwd **pwdstp)
{
	nwrap_load_lib_function(NWRAP_LIBC, getpwent_r);

	return nwrap_main_global->libc->fns->_libc_getpwent_r(pwdst,
							      buf,
							      buflen,
							      pwdstp);
}
#endif /* HAVE_SOLARIS_GETPWENT_R */

static void libc_endpwent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, endpwent);

	nwrap_main_global->libc->fns->_libc_endpwent();
}

static int libc_initgroups(const char *user, gid_t gid)
{
	nwrap_load_lib_function(NWRAP_LIBC, initgroups);

	return nwrap_main_global->libc->fns->_libc_initgroups(user, gid);
}

static struct group *libc_getgrnam(const char *name)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrnam);

	return nwrap_main_global->libc->fns->_libc_getgrnam(name);
}

#ifdef HAVE_GETGRNAM_R
static int libc_getgrnam_r(const char *name,
			   struct group *grp,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
#ifdef HAVE___POSIX_GETGRNAM_R
	if (nwrap_main_global->libc->fns->_libc_getgrnam_r == NULL) {
		*(void **) (&nwrap_main_global->libc->fns->_libc_getgrnam_r) =
			_nwrap_load_lib_function(NWRAP_LIBC, "__posix_getgrnam_r");
	}
#else
	nwrap_load_lib_function(NWRAP_LIBC, getgrnam_r);
#endif

	return nwrap_main_global->libc->fns->_libc_getgrnam_r(name,
							      grp,
							      buf,
							      buflen,
							      result);
}
#endif

static struct group *libc_getgrgid(gid_t gid)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrgid);

	return nwrap_main_global->libc->fns->_libc_getgrgid(gid);
}

#ifdef HAVE_GETGRGID_R
static int libc_getgrgid_r(gid_t gid,
			   struct group *grp,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
#ifdef HAVE___POSIX_GETGRGID_R
	if (nwrap_main_global->libc->fns->_libc_getgrgid_r == NULL) {
		*(void **) (&nwrap_main_global->libc->fns->_libc_getgrgid_r) =
			_nwrap_load_lib_function(NWRAP_LIBC, "__posix_getgrgid_r");
	}
#else
	nwrap_load_lib_function(NWRAP_LIBC, getgrgid_r);
#endif

	return nwrap_main_global->libc->fns->_libc_getgrgid_r(gid,
							      grp,
							      buf,
							      buflen,
							      result);
}
#endif

static void libc_setgrent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, setgrent);

	nwrap_main_global->libc->fns->_libc_setgrent();
}

static struct group *libc_getgrent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrent);

	return nwrap_main_global->libc->fns->_libc_getgrent();
}

#ifdef HAVE_GETGRENT_R
#ifdef HAVE_SOLARIS_GETGRENT_R
static struct group *libc_getgrent_r(struct group *group,
				     char *buf,
				     size_t buflen)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrent_r);

	return nwrap_main_global->libc->fns->_libc_getgrent_r(group,
							      buf,
							      buflen);
}
#else /* !HAVE_SOLARIS_GETGRENT_R */
static int libc_getgrent_r(struct group *group,
			   char *buf,
			   size_t buflen,
			   struct group **result)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrent_r);

	return nwrap_main_global->libc->fns->_libc_getgrent_r(group,
							      buf,
							      buflen,
							      result);
}
#endif /* HAVE_SOLARIS_GETGRENT_R */
#endif /* HAVE_GETGRENT_R */

static void libc_endgrent(void)
{
	nwrap_load_lib_function(NWRAP_LIBC, endgrent);

	nwrap_main_global->libc->fns->_libc_endgrent();
}

#ifdef HAVE_GETGROUPLIST
static int libc_getgrouplist(const char *user,
			     gid_t group,
			     gid_t *groups,
			     int *ngroups)
{
	nwrap_load_lib_function(NWRAP_LIBC, getgrouplist);

	return nwrap_main_global->libc->fns->_libc_getgrouplist(user,
								group,
								groups,
								ngroups);
}
#endif

static void libc_sethostent(int stayopen)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, sethostent);

	nwrap_main_global->libc->fns->_libc_sethostent(stayopen);
}

static struct hostent *libc_gethostent(void)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostent);

	return nwrap_main_global->libc->fns->_libc_gethostent();
}

static void libc_endhostent(void)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, endhostent);

	nwrap_main_global->libc->fns->_libc_endhostent();
}

static struct hostent *libc_gethostbyname(const char *name)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostbyname);

	return nwrap_main_global->libc->fns->_libc_gethostbyname(name);
}

#ifdef HAVE_GETHOSTBYNAME2 /* GNU extension */
static struct hostent *libc_gethostbyname2(const char *name, int af)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostbyname2);

	return nwrap_main_global->libc->fns->_libc_gethostbyname2(name, af);
}
#endif

static struct hostent *libc_gethostbyaddr(const void *addr,
					  socklen_t len,
					  int type)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostbyaddr);

	return nwrap_main_global->libc->fns->_libc_gethostbyaddr(addr,
								 len,
								 type);
}

static int libc_gethostname(char *name, size_t len)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostname);

	return nwrap_main_global->libc->fns->_libc_gethostname(name, len);
}

#ifdef HAVE_GETHOSTBYNAME_R
static int libc_gethostbyname_r(const char *name,
				struct hostent *ret,
				char *buf,
				size_t buflen,
				struct hostent **result,
				int *h_errnop)
{
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostbyname_r);

	return nwrap_main_global->libc->fns->_libc_gethostbyname_r(name,
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
	nwrap_load_lib_function(NWRAP_LIBNSL, gethostbyaddr_r);

	return nwrap_main_global->libc->fns->_libc_gethostbyaddr_r(addr,
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
	nwrap_load_lib_function(NWRAP_LIBSOCKET, getaddrinfo);

	return nwrap_main_global->libc->fns->_libc_getaddrinfo(node,
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
	nwrap_load_lib_function(NWRAP_LIBSOCKET, getnameinfo);

	return nwrap_main_global->libc->fns->_libc_getnameinfo(sa,
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

static void *nwrap_load_module_fn(struct nwrap_backend *b,
				  const char *fn_name)
{
	void *res;
	char *s;

	if (!b->so_handle) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "No handle");
		return NULL;
	}

	if (asprintf(&s, "_nss_%s_%s", b->name, fn_name) == -1) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		return NULL;
	}

	res = dlsym(b->so_handle, s);
	if (!res) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Cannot find function %s in %s",
			  s, b->so_path);
	}
	free(s);
	s = NULL;
	return res;
}

static struct nwrap_module_nss_fns *nwrap_load_module_fns(struct nwrap_backend *b)
{
	struct nwrap_module_nss_fns *fns;

	if (!b->so_handle) {
		return NULL;
	}

	fns = (struct nwrap_module_nss_fns *)malloc(sizeof(struct nwrap_module_nss_fns));
	if (!fns) {
		return NULL;
	}

	*(void **)(&fns->_nss_getpwnam_r) =
		nwrap_load_module_fn(b, "getpwnam_r");
	*(void **)(&fns->_nss_getpwuid_r) =
		nwrap_load_module_fn(b, "getpwuid_r");
	*(void **)(&fns->_nss_setpwent) =
		nwrap_load_module_fn(b, "setpwent");
	*(void **)(&fns->_nss_getpwent_r) =
		nwrap_load_module_fn(b, "getpwent_r");
	*(void **)(&fns->_nss_endpwent) =
		nwrap_load_module_fn(b, "endpwent");
	*(void **)(&fns->_nss_initgroups) =
		nwrap_load_module_fn(b, "initgroups_dyn");
	*(void **)(&fns->_nss_getgrnam_r) =
		nwrap_load_module_fn(b, "getgrnam_r");
	*(void **)(&fns->_nss_getgrgid_r)=
		nwrap_load_module_fn(b, "getgrgid_r");
	*(void **)(&fns->_nss_setgrent) =
		nwrap_load_module_fn(b, "setgrent");
	*(void **)(&fns->_nss_getgrent_r) =
		nwrap_load_module_fn(b, "getgrent_r");
	*(void **)(&fns->_nss_endgrent) =
		nwrap_load_module_fn(b, "endgrent");

	return fns;
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
			      int *num_backends,
			      struct nwrap_backend **backends)
{
	struct nwrap_backend *b;

	*backends = (struct nwrap_backend *)realloc(*backends,
		sizeof(struct nwrap_backend) * ((*num_backends) + 1));
	if (!*backends) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		return false;
	}

	b = &((*backends)[*num_backends]);

	b->name = name;
	b->ops = ops;
	b->so_path = so_path;

	if (so_path != NULL) {
		b->so_handle = nwrap_load_module(so_path);
		b->fns = nwrap_load_module_fns(b);
		if (b->fns == NULL) {
			return false;
		}
	} else {
		b->so_handle = NULL;
		b->fns = NULL;
	}

	(*num_backends)++;

	return true;
}

static void nwrap_libc_init(struct nwrap_main *r)
{
	r->libc = malloc(sizeof(struct nwrap_libc));
	if (r->libc == NULL) {
		printf("Failed to allocate memory for libc");
		exit(-1);
	}
	ZERO_STRUCTP(r->libc);

	r->libc->fns = malloc(sizeof(struct nwrap_libc_fns));
	if (r->libc->fns == NULL) {
		printf("Failed to allocate memory for libc functions");
		exit(-1);
	}
	ZERO_STRUCTP(r->libc->fns);
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
	static bool initialized;

	if (initialized) return;
	initialized = true;

	nwrap_main_global = &__nwrap_main_global;

	nwrap_libc_init(nwrap_main_global);

	nwrap_backend_init(nwrap_main_global);

	nwrap_pw_global.cache = &__nwrap_cache_pw;

	nwrap_pw_global.cache->path = getenv("NSS_WRAPPER_PASSWD");
	nwrap_pw_global.cache->fd = -1;
	nwrap_pw_global.cache->private_data = &nwrap_pw_global;
	nwrap_pw_global.cache->parse_line = nwrap_pw_parse_line;
	nwrap_pw_global.cache->unload = nwrap_pw_unload;

	nwrap_gr_global.cache = &__nwrap_cache_gr;

	nwrap_gr_global.cache->path = getenv("NSS_WRAPPER_GROUP");
	nwrap_gr_global.cache->fd = -1;
	nwrap_gr_global.cache->private_data = &nwrap_gr_global;
	nwrap_gr_global.cache->parse_line = nwrap_gr_parse_line;
	nwrap_gr_global.cache->unload = nwrap_gr_unload;

	nwrap_he_global.cache = &__nwrap_cache_he;

	nwrap_he_global.cache->path = getenv("NSS_WRAPPER_HOSTS");
	nwrap_he_global.cache->fd = -1;
	nwrap_he_global.cache->private_data = &nwrap_he_global;
	nwrap_he_global.cache->parse_line = nwrap_he_parse_line;
	nwrap_he_global.cache->unload = nwrap_he_unload;
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
	int ret;
	uint8_t *buf = NULL;
	char *nline;

	if (nwrap->st.st_size == 0) {
		NWRAP_LOG(NWRAP_LOG_DEBUG, "size == 0");
		goto done;
	}

	if (nwrap->st.st_size > INT32_MAX) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Size[%u] larger than INT32_MAX",
			  (unsigned)nwrap->st.st_size);
		goto failed;
	}

	ret = lseek(nwrap->fd, 0, SEEK_SET);
	if (ret != 0) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "lseek - rc=%d\n", ret);
		goto failed;
	}

	buf = (uint8_t *)malloc(nwrap->st.st_size + 1);
	if (!buf) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		goto failed;
	}

	ret = read(nwrap->fd, buf, nwrap->st.st_size);
	if (ret != nwrap->st.st_size) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "read(%u) rc=%d\n",
			  (unsigned)nwrap->st.st_size, ret);
		goto failed;
	}

	buf[nwrap->st.st_size] = '\0';

	nline = (char *)buf;
	while (nline != NULL && nline[0] != '\0') {
		char *line;
		char *e;
		bool ok;

		line = nline;
		nline = NULL;

		e = strchr(line, '\n');
		if (e) {
			e[0] = '\0';
			e++;
			if (e[0] == '\r') {
				e[0] = '\0';
				e++;
			}
			nline = e;
		}

		if (strlen(line) == 0) {
			continue;
		}

		ok = nwrap->parse_line(nwrap, line);
		if (!ok) {
			goto failed;
		}
	}

done:
	nwrap->buf = buf;
	return true;

failed:
	if (buf) free(buf);
	return false;
}

static void nwrap_files_cache_unload(struct nwrap_cache *nwrap)
{
	nwrap->unload(nwrap);

	if (nwrap->buf) free(nwrap->buf);

	nwrap->buf = NULL;
}

static void nwrap_files_cache_reload(struct nwrap_cache *nwrap)
{
	struct stat st;
	int ret;
	bool ok;
	bool retried = false;

reopen:
	if (nwrap->fd < 0) {
		nwrap->fd = open(nwrap->path, O_RDONLY);
		if (nwrap->fd < 0) {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Unable to open '%s' readonly %d:%s",
				  nwrap->path, nwrap->fd,
				  strerror(errno));
			return;
		}
		NWRAP_LOG(NWRAP_LOG_DEBUG, "Open '%s'", nwrap->path);
	}

	ret = fstat(nwrap->fd, &st);
	if (ret != 0) {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "fstat(%s) - %d:%s",
			  nwrap->path,
			  ret,
			  strerror(errno));
		return;
	}

	if (retried == false && st.st_nlink == 0) {
		/* maybe someone has replaced the file... */
		NWRAP_LOG(NWRAP_LOG_TRACE,
			  "st_nlink == 0, reopen %s",
			  nwrap->path);
		retried = true;
		memset(&nwrap->st, 0, sizeof(nwrap->st));
		close(nwrap->fd);
		nwrap->fd = -1;
		goto reopen;
	}

	if (st.st_mtime == nwrap->st.st_mtime) {
		NWRAP_LOG(NWRAP_LOG_TRACE,
			  "st_mtime[%u] hasn't changed, skip reload",
			  (unsigned)st.st_mtime);
		return;
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
	}

	NWRAP_LOG(NWRAP_LOG_TRACE, "Reloaded %s", nwrap->path);
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

	if (nwrap_pw->list) free(nwrap_pw->list);

	nwrap_pw->list = NULL;
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

	for(nummem=0; p; nummem++) {
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
			if (nwrap_gr->list[i].gr_mem) {
				free(nwrap_gr->list[i].gr_mem);
			}
		}
		free(nwrap_gr->list);
	}

	nwrap_gr->list = NULL;
	nwrap_gr->num = 0;
	nwrap_gr->idx = 0;
}

static int nwrap_gr_copy_r(const struct group *src, struct group *dst,
			   char *buf, size_t buflen, struct group **dstp)
{
	char *first;
	char **lastm;
	char *last = NULL;
	off_t ofsb;
	off_t ofsm;
	off_t ofs;
	unsigned i;

	first = src->gr_name;

	lastm = src->gr_mem;
	while (*lastm) {
		last = *lastm;
		lastm++;
	}

	if (last == NULL) {
		last = src->gr_passwd;
	}
	while (*last) last++;

	ofsb = PTR_DIFF(last + 1, first);
	ofsm = PTR_DIFF(lastm + 1, src->gr_mem);

	if ((ofsb + ofsm) > (off_t) buflen) {
		return ERANGE;
	}

	memcpy(buf, first, ofsb);
	memcpy(buf + ofsb, src->gr_mem, ofsm);

	ofs = PTR_DIFF(src->gr_name, first);
	dst->gr_name = buf + ofs;
	ofs = PTR_DIFF(src->gr_passwd, first);
	dst->gr_passwd = buf + ofs;
	dst->gr_gid = src->gr_gid;

	dst->gr_mem = (char **)(buf + ofsb);
	for (i=0; src->gr_mem[i]; i++) {
		ofs = PTR_DIFF(src->gr_mem[i], first);
		dst->gr_mem[i] = buf + ofs;
	}

	if (dstp) {
		*dstp = dst;
	}

	return 0;
}

static bool nwrap_he_parse_line(struct nwrap_cache *nwrap, char *line)
{
	struct nwrap_he *nwrap_he = (struct nwrap_he *)nwrap->private_data;
	struct nwrap_entdata *ed;
	size_t list_size;
	bool do_aliases = true;
	int aliases_count = 0;
	char *p;
	char *i;
	char *n;

	list_size = sizeof(struct nwrap_entdata) * (nwrap_he->num + 1);

	ed = (struct nwrap_entdata *)realloc(nwrap_he->list, list_size);
	if (ed == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "realloc[%zd] failed", list_size);
		return false;
	}
	nwrap_he->list = ed;

	/* set it to the last element */
	ed = &(nwrap_he->list[nwrap_he->num]);

	ed->addr = malloc(sizeof(struct nwrap_addrdata));
	if (ed->addr == NULL) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "realloc[%zd] failed", list_size);
		return false;
	}

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
			return false;
		}
	}

	for (i = p; !isspace((int)*p); p++) {
		if (*p == '\0') {
			NWRAP_LOG(NWRAP_LOG_ERROR,
				  "Invalid line[%s]: '%s'",
				  line, i);
			return false;
		}
	}

	*p = '\0';

	if (inet_pton(AF_INET, i, ed->addr->host_addr)) {
		ed->ht.h_addrtype = AF_INET;
		ed->ht.h_length = 4;
#ifdef HAVE_IPV6
	} else if (inet_pton(AF_INET6, i, ed->addr->host_addr)) {
		ed->ht.h_addrtype = AF_INET6;
		ed->ht.h_length = 16;
#endif
	} else {
		NWRAP_LOG(NWRAP_LOG_ERROR,
			  "Invalid line[%s]: '%s'",
			  line, i);

		return false;
	}

	ed->addr->h_addr_ptrs[0] = (char *)ed->addr->host_addr;
	ed->addr->h_addr_ptrs[1] = NULL;

	ed->ht.h_addr_list = ed->addr->h_addr_ptrs;

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

	ed->ht.h_name = n;

	/* glib's getent always dereferences he->h_aliases */
	ed->ht.h_aliases = malloc(sizeof(char *));
	if (ed->ht.h_aliases == NULL) {
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
			return false;
		}
		ed->ht.h_aliases = aliases;

		aliases[aliases_count] = a;
		aliases[aliases_count + 1] = NULL;

		aliases_count++;
	}

	nwrap_he->num++;
	return true;
}

static void nwrap_he_unload(struct nwrap_cache *nwrap)
{
	struct nwrap_he *nwrap_he =
		(struct nwrap_he *)nwrap->private_data;
	int i;

	if (nwrap_he->list != NULL) {
		for (i = 0; i < nwrap_he->num; i++) {
			if (nwrap_he->list[i].ht.h_aliases != NULL) {
				free(nwrap_he->list[i].ht.h_aliases);
			}
			if (nwrap_he->list[i].addr != NULL) {
				free(nwrap_he->list[i].addr);
			}
		}
		free(nwrap_he->list);
	}

	nwrap_he->list = NULL;
	nwrap_he->num = 0;
	nwrap_he->idx = 0;
}


/* user functions */
static struct passwd *nwrap_files_getpwnam(struct nwrap_backend *b,
					   const char *name)
{
	int i;

	(void) b; /* unused */

	NWRAP_LOG(NWRAP_LOG_DEBUG, "Lookup user %s in files", name);

	nwrap_files_cache_reload(nwrap_pw_global.cache);

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

	(void) b; /* unused */

	nwrap_files_cache_reload(nwrap_pw_global.cache);

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
		nwrap_files_cache_reload(nwrap_pw_global.cache);
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

/* misc functions */
static int nwrap_files_initgroups(struct nwrap_backend *b,
				  const char *user, gid_t group)
{
	(void) b; /* unused */
	(void) user; /* unused */
	(void) group; /* used */

	/* TODO: maybe we should also fake this... */
	return EPERM;
}

/* group functions */
static struct group *nwrap_files_getgrnam(struct nwrap_backend *b,
					  const char *name)
{
	int i;

	(void) b; /* unused */

	nwrap_files_cache_reload(nwrap_gr_global.cache);

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

	(void) b; /* unused */

	nwrap_files_cache_reload(nwrap_gr_global.cache);

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
		nwrap_files_cache_reload(nwrap_gr_global.cache);
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
static struct hostent *nwrap_files_gethostbyname(const char *name, int af)
{
	struct hostent *he;
	int i;

	nwrap_files_cache_reload(nwrap_he_global.cache);

	for (i = 0; i < nwrap_he_global.num; i++) {
		int j;

		he = &nwrap_he_global.list[i].ht;

		/* Filter by address familiy if provided */
		if (af != AF_UNSPEC && he->h_addrtype != af) {
			continue;
		}

		if (strcasecmp(he->h_name, name) == 0) {
			NWRAP_LOG(NWRAP_LOG_DEBUG, "name[%s] found", name);
			return he;
		}

		if (he->h_aliases == NULL) {
			continue;
		}

		for (j = 0; he->h_aliases[j] != NULL; j++) {
			if (strcasecmp(he->h_aliases[j], name) == 0) {
				NWRAP_LOG(NWRAP_LOG_DEBUG,
					  "name[%s] found",
					  name);
				return he;
			}
		}
	}

	errno = ENOENT;
	return NULL;
}

#ifdef HAVE_GETHOSTBYNAME_R
static int nwrap_gethostbyname_r(const char *name,
				 struct hostent *ret,
				 char *buf, size_t buflen,
				 struct hostent **result, int *h_errnop)
{
	*result = nwrap_files_gethostbyname(name, AF_UNSPEC);
	if (*result != NULL) {
		memset(buf, '\0', buflen);
		*ret = **result;
		return 0;
	} else {
		*h_errnop = h_errno;
		return -1;
	}
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

static struct hostent *nwrap_files_gethostbyaddr(const void *addr,
						 socklen_t len, int type)
{
	struct hostent *he;
	char ip[INET6_ADDRSTRLEN] = {0};
	const char *a;
	int i;

	(void) len; /* unused */

	nwrap_files_cache_reload(nwrap_he_global.cache);

	a = inet_ntop(type, addr, ip, sizeof(ip));
	if (a == NULL) {
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < nwrap_he_global.num; i++) {
		he = &nwrap_he_global.list[i].ht;

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
	*result = nwrap_files_gethostbyaddr(addr, len, type);
	if (*result != NULL) {
		memset(buf, '\0', buflen);
		*ret = **result;
		return 0;
	} else {
		*h_errnop = h_errno;
		return -1;
	}
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
		nwrap_files_cache_reload(nwrap_he_global.cache);
	}

	if (nwrap_he_global.idx >= nwrap_he_global.num) {
		errno = ENOENT;
		return NULL;
	}

	he = &nwrap_he_global.list[nwrap_he_global.idx++].ht;

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

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

static struct passwd *nwrap_module_getpwnam(struct nwrap_backend *b,
					    const char *name)
{
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;

	if (!b->fns->_nss_getpwnam_r) {
		return NULL;
	}

	status = b->fns->_nss_getpwnam_r(name, &pwd, buf, sizeof(buf), &errno);
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

	(void) b; /* unused */
	(void) pwdst; /* unused */
	(void) pwdstp; /* unused */

	if (!b->fns->_nss_getpwnam_r) {
		return NSS_STATUS_NOTFOUND;
	}

	ret = b->fns->_nss_getpwnam_r(name, pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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

	if (!b->fns->_nss_getpwuid_r) {
		return NULL;
	}

	status = b->fns->_nss_getpwuid_r(uid, &pwd, buf, sizeof(buf), &errno);
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

	(void) pwdstp; /* unused */

	if (!b->fns->_nss_getpwuid_r) {
		return ENOENT;
	}

	ret = b->fns->_nss_getpwuid_r(uid, pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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
	if (!b->fns->_nss_setpwent) {
		return;
	}

	b->fns->_nss_setpwent();
}

static struct passwd *nwrap_module_getpwent(struct nwrap_backend *b)
{
	static struct passwd pwd;
	static char buf[1000];
	NSS_STATUS status;

	if (!b->fns->_nss_getpwent_r) {
		return NULL;
	}

	status = b->fns->_nss_getpwent_r(&pwd, buf, sizeof(buf), &errno);
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

	(void) pwdstp; /* unused */

	if (!b->fns->_nss_getpwent_r) {
		return ENOENT;
	}

	ret = b->fns->_nss_getpwent_r(pwdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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
	if (!b->fns->_nss_endpwent) {
		return;
	}

	b->fns->_nss_endpwent();
}

static int nwrap_module_initgroups(struct nwrap_backend *b,
				   const char *user, gid_t group)
{
	gid_t *groups;
	long int start;
	long int size;

	if (!b->fns->_nss_initgroups) {
		return NSS_STATUS_UNAVAIL;
	}

	return b->fns->_nss_initgroups(user, group, &start, &size, &groups, 0, &errno);
}

static struct group *nwrap_module_getgrnam(struct nwrap_backend *b,
					   const char *name)
{
	static struct group grp;
	static char *buf;
	static int buflen = 1000;
	NSS_STATUS status;

	if (!b->fns->_nss_getgrnam_r) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}
again:
	status = b->fns->_nss_getgrnam_r(name, &grp, buf, buflen, &errno);
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

	(void) grdstp; /* unused */

	if (!b->fns->_nss_getgrnam_r) {
		return ENOENT;
	}

	ret = b->fns->_nss_getgrnam_r(name, grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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

	if (!b->fns->_nss_getgrgid_r) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}

again:
	status = b->fns->_nss_getgrgid_r(gid, &grp, buf, buflen, &errno);
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

	(void) grdstp; /* unused */

	if (!b->fns->_nss_getgrgid_r) {
		return ENOENT;
	}

	ret = b->fns->_nss_getgrgid_r(gid, grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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
	if (!b->fns->_nss_setgrent) {
		return;
	}

	b->fns->_nss_setgrent();
}

static struct group *nwrap_module_getgrent(struct nwrap_backend *b)
{
	static struct group grp;
	static char *buf;
	static int buflen = 1024;
	NSS_STATUS status;

	if (!b->fns->_nss_getgrent_r) {
		return NULL;
	}

	if (!buf) {
		buf = (char *)malloc(buflen);
	}

again:
	status = b->fns->_nss_getgrent_r(&grp, buf, buflen, &errno);
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

	(void) grdstp; /* unused */

	if (!b->fns->_nss_getgrent_r) {
		return ENOENT;
	}

	ret = b->fns->_nss_getgrent_r(grdst, buf, buflen, &errno);
	switch (ret) {
	case NSS_STATUS_SUCCESS:
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
	if (!b->fns->_nss_endgrent) {
		return;
	}

	b->fns->_nss_endgrent();
}

/****************************************************************************
 *   GETPWNAM
 ***************************************************************************/

static struct passwd *nwrap_getpwnam(const char *name)
{
	int i;
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
	int i,ret;

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
	int i;
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
	int i,ret;

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
	int i;

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
	int i;
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

static int nwrap_getpwent_r(struct passwd *pwdst, char *buf,
			    size_t buflen, struct passwd **pwdstp)
{
	int i,ret;

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

#ifdef HAVE_SOLARIS_GETPWENT_R
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
#else /* HAVE_SOLARIS_GETPWENT_R */
int getpwent_r(struct passwd *pwdst, char *buf,
	       size_t buflen, struct passwd **pwdstp)
{
	if (!nss_wrapper_enabled()) {
		return libc_getpwent_r(pwdst, buf, buflen, pwdstp);
	}

	return nwrap_getpwent_r(pwdst, buf, buflen, pwdstp);
}
#endif /* HAVE_SOLARIS_GETPWENT_R */

/****************************************************************************
 *   ENDPWENT
 ***************************************************************************/

static void nwrap_endpwent(void)
{
	int i;

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
	int i;

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
	int i;
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
	int i, ret;

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
	int i;
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
	int i,ret;

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
	int i;

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
	int i;
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

static int nwrap_getgrent_r(struct group *grdst, char *buf,
			    size_t buflen, struct group **grdstp)
{
	int i,ret;

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

#ifdef HAVE_SOLARIS_GETGRENT_R
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
#else /* HAVE_SOLARIS_GETGRENT_R */
int getgrent_r(struct group *src, char *buf,
	       size_t buflen, struct group **grdstp)
{
	if (!nss_wrapper_enabled()) {
		return libc_getgrent_r(src, buf, buflen, grdstp);
	}

	return nwrap_getgrent_r(src, buf, buflen, grdstp);
}
#endif /* HAVE_SOLARIS_GETGRENT_R */

/****************************************************************************
 *   ENDGRENT
 ***************************************************************************/

static void nwrap_endgrent(void)
{
	int i;

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
	const char *name_of_group = "";

	NWRAP_LOG(NWRAP_LOG_DEBUG, "getgrouplist called for %s", user);

	groups_tmp = (gid_t *)malloc(count * sizeof(gid_t));
	if (!groups_tmp) {
		NWRAP_LOG(NWRAP_LOG_ERROR, "Out of memory");
		errno = ENOMEM;
		return -1;
	}

	memcpy(groups_tmp, &group, sizeof(gid_t));

	grp = nwrap_getgrgid(group);
	if (grp) {
		name_of_group = grp->gr_name;
	}

	nwrap_setgrent();
	while ((grp = nwrap_getgrent()) != NULL) {
		int i = 0;

		NWRAP_LOG(NWRAP_LOG_DEBUG,
			  "Inspecting %s for group membership",
			  grp->gr_name);

		for (i=0; grp->gr_mem && grp->gr_mem[i] != NULL; i++) {

			if ((strcmp(user, grp->gr_mem[i]) == 0) &&
			    (strcmp(name_of_group, grp->gr_name) != 0)) {

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

				memcpy(&groups_tmp[count], &grp->gr_gid, sizeof(gid_t));
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

static struct hostent *nwrap_gethostbyname(const char *name)
{
	return nwrap_files_gethostbyname(name, AF_UNSPEC);
}

struct hostent *gethostbyname(const char *name)
{
	if (!nss_wrapper_hosts_enabled()) {
		return libc_gethostbyname(name);
	}

	return nwrap_gethostbyname(name);
}

/* This is a GNU extension */
#ifdef HAVE_GETHOSTBYNAME2
static struct hostent *nwrap_gethostbyname2(const char *name, int af)
{
	return nwrap_files_gethostbyname(name, af);
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
	return nwrap_files_gethostbyaddr(addr, len, type);
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
			       struct addrinfo **pai)
{
	struct addrinfo *ai;
	socklen_t socklen;

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

	ai->ai_flags = 0;
	ai->ai_family = he->h_addrtype;
	ai->ai_socktype = hints->ai_socktype;
	ai->ai_protocol = hints->ai_protocol;

	ai->ai_addrlen = socklen;
	ai->ai_addr = (void *)(ai + 1);

#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	ai->ai_addr->sa_len = socklen;
#endif
	ai->ai_addr->sa_family = he->h_addrtype;

	switch (he->h_addrtype) {
		case AF_INET:
		{
			struct sockaddr_in *sinp =
				(struct sockaddr_in *) ai->ai_addr;

			memset(sinp, 0, sizeof(struct sockaddr_in));

			sinp->sin_port = htons(port);
			sinp->sin_family = AF_INET;

			memset (sinp->sin_zero, '\0', sizeof (sinp->sin_zero));
			memcpy(&sinp->sin_addr, he->h_addr_list[0], he->h_length);

		}
		break;
#ifdef HAVE_IPV6
		case AF_INET6:
		{
			struct sockaddr_in6 *sin6p =
				(struct sockaddr_in6 *) ai->ai_addr;

			memset(sin6p, 0, sizeof(struct sockaddr_in6));

			sin6p->sin6_port = htons(port);
			sin6p->sin6_family = AF_INET6;

			memcpy(&sin6p->sin6_addr, he->h_addr_list[0], he->h_length);
		}
		break;
#endif
	}

	ai->ai_next = NULL;

	if (he->h_name) {
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
	struct addrinfo *p = NULL;
	unsigned short port = 0;
	struct hostent *he;
	struct in_addr in;
	bool is_addr_ipv4 = false;
	bool is_addr_ipv6 = false;
	int eai = EAI_SYSTEM;
	int ret;
	int rc;
	int af;

	if (node == NULL && service == NULL) {
		return EAI_NONAME;
	}

	ret = libc_getaddrinfo(node, service, hints, &p);
	if (ret == 0) {
		*res = p;
	}

	/* If no node has been specified, let glibc deal with it */
	if (node == NULL) {
		return ret;
	}

	if (hints == NULL) {
		hints = &default_hints;
	}

	if ((hints->ai_flags & AI_CANONNAME) && node == NULL) {
		return EAI_BADFLAGS;
	}

	if (service != NULL && service[0] != '\0') {
		if (isdigit((int)service[0])) {
			port = (unsigned short)atoi(service);
		} else {
			const char *proto = NULL;
			struct servent *s;

			if (hints->ai_protocol != 0) {
				struct protoent *pent;

				pent = getprotobynumber(hints->ai_protocol);
				if (pent != NULL) {
					proto = pent->p_name;
				}
			}

			s = getservbyname(service, proto);
			if (s != NULL) {
				port = ntohs(s->s_port);
			} else {
				if (p != NULL) {
					freeaddrinfo(p);
				}
				return EAI_SERVICE;
			}
		}
	}

	af = hints->ai_family;
	if (af == AF_UNSPEC) {
		af = AF_INET;
	}

	rc = inet_pton(af, node, &in);
	if (rc == 1) {
		is_addr_ipv4 = true;
		if (af == AF_UNSPEC) {
			af = AF_INET;
		}
#ifdef HAVE_IPV6
	} else {
		struct in6_addr in6;

		af = AF_INET6;

		rc = inet_pton(af, node, &in6);
		if (rc == 1) {
			is_addr_ipv6 = true;
		}
#endif
	}

	if (is_addr_ipv4) {
		he = nwrap_files_gethostbyaddr(&in, sizeof(struct in_addr), af);
		if (he != NULL) {
			rc = nwrap_convert_he_ai(he, port, hints, &ai);
		} else {
			eai = EAI_NODATA;
			rc = -1;
		}
#ifdef HAVE_IPV6
	} else if (is_addr_ipv6) {
		struct in6_addr in6;

		rc =  inet_pton(af, node, &in6);
		if (rc <= 0) {
			eai = EAI_ADDRFAMILY;
			return ret == 0 ? 0 : eai;
		}

		he = nwrap_files_gethostbyaddr(&in6,
					       sizeof(struct in6_addr),
					       af);
		if (he != NULL) {
			rc = nwrap_convert_he_ai(he, port, hints, &ai);
			eai = rc;
		} else {
			eai = EAI_NODATA;
			rc = -1;
		}
#endif
	} else {
		he = nwrap_files_gethostbyname(node, hints->ai_family);
		if (he != NULL) {
			rc = nwrap_convert_he_ai(he, port, hints, &ai);
			eai = rc;
		} else {
			eai = EAI_NODATA;
			rc = -1;
		}
	}

	if (rc < 0) {
		return ret == 0 ? 0 : eai;
	}

	if (ret == 0) {
		freeaddrinfo(p);
	}

	if (ai->ai_flags == 0) {
		ai->ai_flags = hints->ai_flags;
	}
	if (ai->ai_socktype == 0) {
		ai->ai_socktype = SOCK_DGRAM;
	}
	if (ai->ai_protocol == 0 && ai->ai_socktype == SOCK_DGRAM) {
		ai->ai_protocol = 17; /* UDP */
	} else if (ai->ai_protocol == 0 && ai->ai_socktype == SOCK_STREAM) {
		ai->ai_protocol = 6; /* TCP */
	}

	if (hints->ai_socktype == 0) {
		/* Add second ai */
		rc = nwrap_convert_he_ai(he, port, hints, &ai->ai_next);
		if (rc < 0) {
			freeaddrinfo(ai);
			return rc;
		}

		if (ai->ai_next->ai_flags == 0) {
			ai->ai_next->ai_flags = hints->ai_flags;
		}
		if (ai->ai_socktype == SOCK_DGRAM) {
			ai->ai_next->ai_socktype = SOCK_STREAM;
		} else if (ai->ai_socktype == SOCK_STREAM) {
			ai->ai_next->ai_socktype = SOCK_DGRAM;
		}
		if (ai->ai_next->ai_socktype == SOCK_DGRAM) {
			ai->ai_next->ai_protocol = 17; /* UDP */
		} else if (ai->ai_next->ai_socktype == SOCK_STREAM) {
			ai->ai_next->ai_protocol = 6; /* TCP */
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

	if (sa == NULL || salen < sizeof(sa_family_t)) {
		return EAI_FAMILY;
	}

	if ((flags & NI_NAMEREQD) && host == NULL && serv == NULL) {
		return EAI_NONAME;
	}

	type = sa->sa_family;
	switch (type) {
	case AF_INET:
		if (salen < sizeof(struct sockaddr_in))
			return EAI_FAMILY;
		addr = &((const struct sockaddr_in *)sa)->sin_addr;
		addrlen = sizeof(((const struct sockaddr_in *)sa)->sin_addr);
		port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
		break;
#ifdef HAVE_IPV6
	case AF_INET6:
		if (salen < sizeof(struct sockaddr_in6))
			return EAI_FAMILY;
		addr = &((const struct sockaddr_in6 *)sa)->sin6_addr;
		addrlen = sizeof(((const struct sockaddr_in6 *)sa)->sin6_addr);
		port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
		break;
#endif
	default:
		return EAI_FAMILY;
	}

	if (host != NULL) {
		he = NULL;
		if ((flags & NI_NUMERICHOST) == 0) {
			he = nwrap_files_gethostbyaddr(addr, addrlen, type);
			if ((flags & NI_NAMEREQD) && (he == NULL || he->h_name == NULL))
				return EAI_NONAME;
		}
		if (he != NULL && he->h_name != NULL) {
			if (strlen(he->h_name) >= hostlen)
				return EAI_OVERFLOW;
			strcpy(host, he->h_name);
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
			strcpy(serv, service->s_name);
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
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * sockets get closed and the unix file for the socket are unlinked.
 */
void nwrap_destructor(void)
{
	int i;

	if (nwrap_main_global != NULL) {
		struct nwrap_main *m = nwrap_main_global;

		/* libc */
		SAFE_FREE(m->libc->fns);
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

		/* backends */
		for (i = 0; i < m->num_backends; i++) {
			struct nwrap_backend *b = &(m->backends[i]);

			if (b->so_handle != NULL) {
				dlclose(b->so_handle);
			}
			SAFE_FREE(b->fns);
		}
		SAFE_FREE(m->backends);
	}

	if (nwrap_pw_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_pw_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			close(c->fd);
		}

		SAFE_FREE(nwrap_pw_global.list);
		nwrap_pw_global.num = 0;
	}

	if (nwrap_gr_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_gr_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			close(c->fd);
		}

		SAFE_FREE(nwrap_gr_global.list);
		nwrap_pw_global.num = 0;
	}

	if (nwrap_he_global.cache != NULL) {
		struct nwrap_cache *c = nwrap_he_global.cache;

		nwrap_files_cache_unload(c);
		if (c->fd >= 0) {
			close(c->fd);
		}

		SAFE_FREE(nwrap_he_global.list);
		nwrap_he_global.num = 0;
	}
}
