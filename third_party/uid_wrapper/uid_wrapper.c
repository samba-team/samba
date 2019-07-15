/*
 * Copyright (c) 2009      Andrew Tridgell
 * Copyright (c) 2011-2013 Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#endif
#include <dlfcn.h>
#include <limits.h>

#include <pthread.h>

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define UWRAP_THREAD __thread
#else
# define UWRAP_THREAD
#endif

# define UWRAP_LOCK(m) do { \
	pthread_mutex_lock(&( m ## _mutex)); \
} while(0)

# define UWRAP_UNLOCK(m) do { \
	pthread_mutex_unlock(&( m ## _mutex)); \
} while(0)

/* Add new global locks here please */
# define UWRAP_LOCK_ALL \
	UWRAP_LOCK(uwrap_id); \
	UWRAP_LOCK(libc_symbol_binding); \
	UWRAP_LOCK(libpthread_symbol_binding)

# define UWRAP_UNLOCK_ALL \
	UWRAP_UNLOCK(libpthread_symbol_binding); \
	UWRAP_UNLOCK(libc_symbol_binding); \
	UWRAP_UNLOCK(uwrap_id)

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

#ifdef HAVE_ADDRESS_SANITIZER_ATTRIBUTE
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE __attribute__((no_sanitize_address))
#else /* DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE */
#define DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
#endif /* DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE */

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

#ifndef FALL_THROUGH
# ifdef HAVE_FALLTHROUGH_ATTRIBUTE
#  define FALL_THROUGH __attribute__ ((fallthrough))
# else /* HAVE_FALLTHROUGH_ATTRIBUTE */
#  define FALL_THROUGH
# endif /* HAVE_FALLTHROUGH_ATTRIBUTE */
#endif /* FALL_THROUGH */

#define UWRAP_DLIST_ADD(list,item) do { \
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

#define UWRAP_DLIST_REMOVE(list,item) do { \
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

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

/*****************
 * LOGGING
 *****************/

enum uwrap_dbglvl_e {
	UWRAP_LOG_ERROR = 0,
	UWRAP_LOG_WARN,
	UWRAP_LOG_DEBUG,
	UWRAP_LOG_TRACE
};

static void uwrap_log(enum uwrap_dbglvl_e dbglvl, const char *function, const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define UWRAP_LOG(dbglvl, ...) uwrap_log((dbglvl), __func__, __VA_ARGS__)

static void uwrap_log(enum uwrap_dbglvl_e dbglvl, const char *function, const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = "UWRAP";

	d = getenv("UID_WRAPPER_DEBUGLEVEL");
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
		case UWRAP_LOG_ERROR:
			prefix = "UWRAP_ERROR";
			break;
		case UWRAP_LOG_WARN:
			prefix = "UWRAP_WARN";
			break;
		case UWRAP_LOG_DEBUG:
			prefix = "UWRAP_DEBUG";
			break;
		case UWRAP_LOG_TRACE:
			prefix = "UWRAP_TRACE";
			break;
	}

	fprintf(stderr,
		"%s(%d) - %s: %s\n",
		prefix,
		(int)getpid(),
		function,
		buffer);
}

/*****************
 * LIBC
 *****************/

#define LIBC_NAME "libc.so"

typedef int (*__libc_setuid)(uid_t uid);

typedef	uid_t (*__libc_getuid)(void);

#ifdef HAVE_SETEUID
typedef int (*__libc_seteuid)(uid_t euid);
#endif

#ifdef HAVE_SETREUID
typedef int (*__libc_setreuid)(uid_t ruid, uid_t euid);
#endif

#ifdef HAVE_SETRESUID
typedef int (*__libc_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
#endif

#ifdef HAVE_GETRESUID
typedef int (*__libc_getresuid)(uid_t *ruid, uid_t *euid, uid_t *suid);
#endif

typedef uid_t (*__libc_geteuid)(void);

typedef int (*__libc_setgid)(gid_t gid);

typedef gid_t (*__libc_getgid)(void);

#ifdef HAVE_SETEGID
typedef int (*__libc_setegid)(uid_t egid);
#endif

#ifdef HAVE_SETREGID
typedef int (*__libc_setregid)(uid_t rgid, uid_t egid);
#endif

#ifdef HAVE_SETRESGID
typedef int (*__libc_setresgid)(uid_t rgid, uid_t egid, uid_t sgid);
#endif

#ifdef HAVE_GETRESGID
typedef int (*__libc_getresgid)(gid_t *rgid, gid_t *egid, gid_t *sgid);
#endif

typedef gid_t (*__libc_getegid)(void);

typedef int (*__libc_getgroups)(int size, gid_t list[]);

typedef int (*__libc_setgroups)(size_t size, const gid_t *list);

#ifdef HAVE_SYSCALL
typedef long int (*__libc_syscall)(long int sysno, ...);
#endif

#define UWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libc_##i f; \
		void *obj; \
	} _libc_##i

struct uwrap_libc_symbols {
	UWRAP_SYMBOL_ENTRY(setuid);
	UWRAP_SYMBOL_ENTRY(getuid);
#ifdef HAVE_SETEUID
	UWRAP_SYMBOL_ENTRY(seteuid);
#endif
#ifdef HAVE_SETREUID
	UWRAP_SYMBOL_ENTRY(setreuid);
#endif
#ifdef HAVE_SETRESUID
	UWRAP_SYMBOL_ENTRY(setresuid);
#endif
#ifdef HAVE_GETRESUID
	UWRAP_SYMBOL_ENTRY(getresuid);
#endif
	UWRAP_SYMBOL_ENTRY(geteuid);
	UWRAP_SYMBOL_ENTRY(setgid);
	UWRAP_SYMBOL_ENTRY(getgid);
#ifdef HAVE_SETEGID
	UWRAP_SYMBOL_ENTRY(setegid);
#endif
#ifdef HAVE_SETREGID
	UWRAP_SYMBOL_ENTRY(setregid);
#endif
#ifdef HAVE_SETRESGID
	UWRAP_SYMBOL_ENTRY(setresgid);
#endif
#ifdef HAVE_GETRESGID
	UWRAP_SYMBOL_ENTRY(getresgid);
#endif
	UWRAP_SYMBOL_ENTRY(getegid);
	UWRAP_SYMBOL_ENTRY(getgroups);
	UWRAP_SYMBOL_ENTRY(setgroups);
#ifdef HAVE_SYSCALL
	UWRAP_SYMBOL_ENTRY(syscall);
#endif
};
#undef UWRAP_SYMBOL_ENTRY

/*****************
 * LIBPTHREAD
 *****************/
/* Yeah... I'm pig. I overloading macro here... So what? */
#define UWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libpthread_##i f; \
		void *obj; \
	} _libpthread_##i

typedef int (*__libpthread_pthread_create)(pthread_t *thread,
				    const pthread_attr_t *attr,
				    void *(*start_routine) (void *),
				    void *arg);
typedef void (*__libpthread_pthread_exit)(void *retval);

struct uwrap_libpthread_symbols {
	UWRAP_SYMBOL_ENTRY(pthread_create);
	UWRAP_SYMBOL_ENTRY(pthread_exit);
};
#undef UWRAP_SYMBOL_ENTRY

/*
 * We keep the virtualised euid/egid/groups information here
 */
struct uwrap_thread {
	bool enabled;

	uid_t ruid;
	uid_t euid;
	uid_t suid;

	gid_t rgid;
	gid_t egid;
	gid_t sgid;

	int ngroups;
	gid_t *groups;

	struct uwrap_thread *next;
	struct uwrap_thread *prev;
};

struct uwrap {
	struct {
		void *handle;
		struct uwrap_libc_symbols symbols;
	} libc;

	struct {
		void *handle;
		struct uwrap_libpthread_symbols symbols;
	} libpthread;

	bool initialised;

	/* Real uid and gid of user who run uid wrapper */
	uid_t myuid;
	gid_t mygid;

	struct uwrap_thread *ids;
};

static struct uwrap uwrap;

/* Shortcut to the list item */
static UWRAP_THREAD struct uwrap_thread *uwrap_tls_id;

/* The mutex or accessing the id */
static pthread_mutex_t uwrap_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The mutex for accessing the global libc.symbols */
static pthread_mutex_t libc_symbol_binding_mutex = PTHREAD_MUTEX_INITIALIZER;

/* The mutex for accessing the global libpthread.symbols */
static pthread_mutex_t libpthread_symbol_binding_mutex = PTHREAD_MUTEX_INITIALIZER;

/*********************************************************
 * UWRAP PROTOTYPES
 *********************************************************/

bool uid_wrapper_enabled(void);
void uwrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
void uwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * UWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum uwrap_lib {
    UWRAP_LIBC,
    UWRAP_LIBNSL,
    UWRAP_LIBSOCKET,
    UWRAP_LIBPTHREAD,
};

static void *uwrap_load_lib_handle(enum uwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	const char *env_preload = getenv("LD_PRELOAD");
	const char *env_deepbind = getenv("UID_WRAPPER_DISABLE_DEEPBIND");
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
	case UWRAP_LIBNSL:
	case UWRAP_LIBSOCKET:
	case UWRAP_LIBC:
		handle = uwrap.libc.handle;
		if (handle == NULL) {
			for (i = 10; i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}

				/* glibc on Alpha and IA64 is libc.so.6.1 */
				snprintf(soname, sizeof(soname), "libc.so.%d.1", i);
				handle = dlopen(soname, flags);
				if (handle != NULL) {
					break;
				}
			}

			uwrap.libc.handle = handle;
		}
		break;
	case UWRAP_LIBPTHREAD:
		handle = uwrap.libpthread.handle;
		if (handle == NULL) {
			handle = dlopen("libpthread.so.0", flags);
			if (handle != NULL) {
				break;
			}
		}
		break;
	}

	if (handle == NULL) {
#ifdef RTLD_NEXT
		handle = uwrap.libc.handle = RTLD_NEXT;
#else
		fprintf(stderr,
			"Failed to dlopen library: %s\n",
			dlerror());
		exit(-1);
#endif
	}

	return handle;
}

static void *_uwrap_bind_symbol(enum uwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = uwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		fprintf(stderr,
			"Failed to find %s: %s\n",
			fn_name, dlerror());
		exit(-1);
	}

	return func;
}

#define uwrap_bind_symbol_libc(sym_name) \
	UWRAP_LOCK(libc_symbol_binding); \
	if (uwrap.libc.symbols._libc_##sym_name.obj == NULL) { \
		uwrap.libc.symbols._libc_##sym_name.obj = \
			_uwrap_bind_symbol(UWRAP_LIBC, #sym_name); \
	} \
	UWRAP_UNLOCK(libc_symbol_binding)

#define uwrap_bind_symbol_libpthread(sym_name) \
	UWRAP_LOCK(libpthread_symbol_binding); \
	if (uwrap.libpthread.symbols._libpthread_##sym_name.obj == NULL) { \
		uwrap.libpthread.symbols._libpthread_##sym_name.obj = \
			_uwrap_bind_symbol(UWRAP_LIBPTHREAD, #sym_name); \
	} \
	UWRAP_UNLOCK(libpthread_symbol_binding)

/*
 * IMPORTANT
 *
 * Functions expeciall from libc need to be loaded individually, you can't load
 * all at once or gdb will segfault at startup. The same applies to valgrind and
 * has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
static int libc_setuid(uid_t uid)
{
	uwrap_bind_symbol_libc(setuid);

	return uwrap.libc.symbols._libc_setuid.f(uid);
}

static uid_t libc_getuid(void)
{
	uwrap_bind_symbol_libc(getuid);

	return uwrap.libc.symbols._libc_getuid.f();
}

#ifdef HAVE_SETEUID
static int libc_seteuid(uid_t euid)
{
	uwrap_bind_symbol_libc(seteuid);

	return uwrap.libc.symbols._libc_seteuid.f(euid);
}
#endif

#ifdef HAVE_SETREUID
static int libc_setreuid(uid_t ruid, uid_t euid)
{
	uwrap_bind_symbol_libc(setreuid);

	return uwrap.libc.symbols._libc_setreuid.f(ruid, euid);
}
#endif

#ifdef HAVE_SETRESUID
static int libc_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	uwrap_bind_symbol_libc(setresuid);

	return uwrap.libc.symbols._libc_setresuid.f(ruid, euid, suid);
}
#endif

#ifdef HAVE_GETRESUID
static int libc_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	uwrap_bind_symbol_libc(getresuid);

	return uwrap.libc.symbols._libc_getresuid.f(ruid, euid, suid);
}
#endif

static uid_t libc_geteuid(void)
{
	uwrap_bind_symbol_libc(geteuid);

	return uwrap.libc.symbols._libc_geteuid.f();
}

static int libc_setgid(gid_t gid)
{
	uwrap_bind_symbol_libc(setgid);

	return uwrap.libc.symbols._libc_setgid.f(gid);
}

static gid_t libc_getgid(void)
{
	uwrap_bind_symbol_libc(getgid);

	return uwrap.libc.symbols._libc_getgid.f();
}

#ifdef HAVE_SETEGID
static int libc_setegid(gid_t egid)
{
	uwrap_bind_symbol_libc(setegid);

	return uwrap.libc.symbols._libc_setegid.f(egid);
}
#endif

#ifdef HAVE_SETREGID
static int libc_setregid(gid_t rgid, gid_t egid)
{
	uwrap_bind_symbol_libc(setregid);

	return uwrap.libc.symbols._libc_setregid.f(rgid, egid);
}
#endif

#ifdef HAVE_SETRESGID
static int libc_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	uwrap_bind_symbol_libc(setresgid);

	return uwrap.libc.symbols._libc_setresgid.f(rgid, egid, sgid);
}
#endif

#ifdef HAVE_GETRESGID
static int libc_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	uwrap_bind_symbol_libc(setresgid);

	return uwrap.libc.symbols._libc_getresgid.f(rgid, egid, sgid);
}
#endif

static gid_t libc_getegid(void)
{
	uwrap_bind_symbol_libc(getegid);

	return uwrap.libc.symbols._libc_getegid.f();
}

static int libc_getgroups(int size, gid_t list[])
{
	uwrap_bind_symbol_libc(getgroups);

	return uwrap.libc.symbols._libc_getgroups.f(size, list);
}

static int libc_setgroups(size_t size, const gid_t *list)
{
	uwrap_bind_symbol_libc(setgroups);

	return uwrap.libc.symbols._libc_setgroups.f(size, list);
}

#ifdef HAVE_SYSCALL
DO_NOT_SANITIZE_ADDRESS_ATTRIBUTE
static long int libc_vsyscall(long int sysno, va_list va)
{
	long int args[8];
	long int rc;
	int i;

	uwrap_bind_symbol_libc(syscall);

	for (i = 0; i < 8; i++) {
		args[i] = va_arg(va, long int);
	}

	rc = uwrap.libc.symbols._libc_syscall.f(sysno,
					  args[0],
					  args[1],
					  args[2],
					  args[3],
					  args[4],
					  args[5],
					  args[6],
					  args[7]);

	return rc;
}
#endif

/*
 * This part is "optimistic".
 * Thread can ends without pthread_exit call.
 */
static void libpthread_pthread_exit(void *retval)
{
	uwrap_bind_symbol_libpthread(pthread_exit);

	uwrap.libpthread.symbols._libpthread_pthread_exit.f(retval);
}

static void uwrap_pthread_exit(void *retval)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOG(UWRAP_LOG_DEBUG, "Cleanup thread");

	UWRAP_LOCK(uwrap_id);
	if (id == NULL) {
		UWRAP_UNLOCK(uwrap_id);
		libpthread_pthread_exit(retval);
		return;
	}

	UWRAP_DLIST_REMOVE(uwrap.ids, id);
	SAFE_FREE(id->groups);
	SAFE_FREE(id);
	uwrap_tls_id = NULL;

	UWRAP_UNLOCK(uwrap_id);

	libpthread_pthread_exit(retval);
}

void pthread_exit(void *retval)
{
	if (!uid_wrapper_enabled()) {
		libpthread_pthread_exit(retval);
	};

	uwrap_pthread_exit(retval);

	/* Calm down gcc warning. */
	exit(666);
}

static int libpthread_pthread_create(pthread_t *thread,
				const pthread_attr_t *attr,
				void *(*start_routine) (void *),
				void *arg)
{
	uwrap_bind_symbol_libpthread(pthread_create);
	return uwrap.libpthread.symbols._libpthread_pthread_create.f(thread,
								     attr,
								     start_routine,
								     arg);
}

struct uwrap_pthread_create_args {
	struct uwrap_thread *id;
	void *(*start_routine) (void *);
	void *arg;
};

static void *uwrap_pthread_create_start(void *_a)
{
	struct uwrap_pthread_create_args *a =
		(struct uwrap_pthread_create_args *)_a;
	void *(*start_routine) (void *) = a->start_routine;
	void *arg = a->arg;
	struct uwrap_thread *id = a->id;

	SAFE_FREE(a);

	uwrap_tls_id = id;

	return start_routine(arg);
}

static int uwrap_pthread_create(pthread_t *thread,
				 const pthread_attr_t *attr,
				 void *(*start_routine) (void *),
				 void *arg)
{
	struct uwrap_pthread_create_args *args;
	struct uwrap_thread *src_id = uwrap_tls_id;
	int ret;

	args = malloc(sizeof(struct uwrap_pthread_create_args));
	if (args == NULL) {
		UWRAP_LOG(UWRAP_LOG_ERROR,
			  "uwrap_pthread_create: Unable to allocate memory");
		errno = ENOMEM;
		return -1;
	}
	args->start_routine = start_routine;
	args->arg = arg;

	args->id = calloc(1, sizeof(struct uwrap_thread));
	if (args->id == NULL) {
		SAFE_FREE(args);
		UWRAP_LOG(UWRAP_LOG_ERROR,
			  "uwrap_pthread_create: Unable to allocate memory");
		errno = ENOMEM;
		return -1;
	}

	UWRAP_LOCK(uwrap_id);

	args->id->groups = calloc(src_id->ngroups, sizeof(gid_t));
	if (args->id->groups == NULL) {
		UWRAP_UNLOCK(uwrap_id);
		SAFE_FREE(args->id);
		SAFE_FREE(args);
		UWRAP_LOG(UWRAP_LOG_ERROR,
			  "uwrap_pthread_create: Unable to allocate memory again");
		errno = ENOMEM;
		return -1;
	}

	args->id->ruid = src_id->ruid;
	args->id->euid = src_id->euid;
	args->id->suid = src_id->suid;

	args->id->rgid = src_id->rgid;
	args->id->egid = src_id->egid;
	args->id->sgid = src_id->sgid;

	args->id->enabled = src_id->enabled;

	args->id->ngroups = src_id->ngroups;
	if (src_id->groups != NULL) {
		memcpy(args->id->groups, src_id->groups,
		       sizeof(gid_t) * src_id->ngroups);
	} else {
		SAFE_FREE(args->id->groups);
	}

	UWRAP_DLIST_ADD(uwrap.ids, args->id);
	UWRAP_UNLOCK(uwrap_id);

	ret = libpthread_pthread_create(thread, attr,
					uwrap_pthread_create_start,
					args);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

int pthread_create(pthread_t *thread,
		    const pthread_attr_t *attr,
		    void *(*start_routine) (void *),
		    void *arg)
{
	if (!uid_wrapper_enabled()) {
		return libpthread_pthread_create(thread,
					   attr,
					   start_routine,
					   arg);
	};

	return uwrap_pthread_create(thread,
				    attr,
				    start_routine,
				    arg);
}

/*********************************************************
 * UWRAP ID HANDLING
 *********************************************************/

#define GROUP_STRING_SIZE 16384
#define GROUP_MAX_COUNT (GROUP_STRING_SIZE / (10 + 1))

/**
 * This function exports all the IDs of the current user so if
 * we fork and then exec we can setup uid_wrapper in the new process
 * with those IDs.
 */
static void uwrap_export_ids(struct uwrap_thread *id)
{
	char groups_str[GROUP_STRING_SIZE] = {0};
	size_t groups_str_size = sizeof(groups_str);
	char unsigned_str[16] = {0}; /* We need 10 + 1 (+ 1) */
	int i;

	/* UIDS */
	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->ruid);
	setenv("UID_WRAPPER_INITIAL_RUID", unsigned_str, 1);

	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->euid);
	setenv("UID_WRAPPER_INITIAL_EUID", unsigned_str, 1);

	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->suid);
	setenv("UID_WRAPPER_INITIAL_SUID", unsigned_str, 1);

	/* GIDS */
	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->rgid);
	setenv("UID_WRAPPER_INITIAL_RGID", unsigned_str, 1);

	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->egid);
	setenv("UID_WRAPPER_INITIAL_EGID", unsigned_str, 1);

	snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->sgid);
	setenv("UID_WRAPPER_INITIAL_SGID", unsigned_str, 1);

	if (id->ngroups > GROUP_MAX_COUNT) {
		UWRAP_LOG(UWRAP_LOG_ERROR,
			  "ERROR: Number of groups (%u) exceeds maximum value "
			  "uid_wrapper can handle (%u).",
			  id->ngroups,
			  GROUP_MAX_COUNT);
		exit(-1);
	}

	/* GROUPS */
	for (i = 0; i < id->ngroups; i++) {
		size_t groups_str_len = strlen(groups_str);
		size_t groups_str_avail = groups_str_size - groups_str_len - 1;
		int len;

		len = snprintf(unsigned_str, sizeof(unsigned_str), ",%u", id->groups[i]);
		if (len <= 1) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "snprintf failed for groups[%d]=%u",
				  i,
				  id->groups[i]);
			break;
		}
		if (((size_t)len) >= groups_str_avail) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "groups env string is to small for %d groups",
				  i);
			break;
		}

		len = snprintf(groups_str + groups_str_len,
			       groups_str_size - groups_str_len,
			       "%s",
			       i == 0 ? unsigned_str + 1 : unsigned_str);
		if (len < 1) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "snprintf failed to create groups string at groups[%d]=%u",
				  i,
				  id->groups[i]);
			break;
		}
	}

	if (id->ngroups == i) {
		setenv("UID_WRAPPER_INITIAL_GROUPS", groups_str, 1);

		snprintf(unsigned_str, sizeof(unsigned_str), "%u", id->ngroups);
		setenv("UID_WRAPPER_INITIAL_GROUPS_COUNT", unsigned_str, 1);
	}
}

static void uwrap_thread_prepare(void)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOCK_ALL;

	/* uid_wrapper is loaded but not enabled */
	if (id == NULL) {
		return;
	}

	/*
	 * What happens if another atfork prepare functions calls a uwrap
	 * function? So disable it in case another atfork prepare function
	 * calls a (s)uid function. We disable uid_wrapper only for thread
	 * (process) which called fork.
	 */
	id->enabled = false;
}

static void uwrap_thread_parent(void)
{
	struct uwrap_thread *id = uwrap_tls_id;

	/* uid_wrapper is loaded but not enabled */
	if (id == NULL) {
		UWRAP_UNLOCK_ALL;
		return;
	}

	id->enabled = true;

	UWRAP_UNLOCK_ALL;
}

static void uwrap_thread_child(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	struct uwrap_thread *u = uwrap.ids;

	/* uid_wrapper is loaded but not enabled */
	if (id == NULL) {
		UWRAP_UNLOCK_ALL;
		return;
	}

	/*
	 * "Garbage collector" - Inspired by DESTRUCTOR.
	 * All threads (except one which called fork()) are dead now.. Dave
	 * That's what posix said...
	 */
	while (u != NULL) {
		if (u == id) {
			/* Skip this item. */
			u = uwrap.ids->next;
			continue;
		}

		UWRAP_DLIST_REMOVE(uwrap.ids, u);

		SAFE_FREE(u->groups);
		SAFE_FREE(u);

		u = uwrap.ids;
	}

	uwrap_export_ids(id);

	id->enabled = true;

	UWRAP_UNLOCK_ALL;
}

static unsigned long uwrap_get_xid_from_env(const char *envname)
{
	unsigned long xid;
	const char *env = NULL;
	char *endp = NULL;

	env = getenv(envname);
	if (env == NULL) {
		return ULONG_MAX;
	}

	if (env[0] == '\0') {
		unsetenv(envname);
		return ULONG_MAX;
	}

	xid = strtoul(env, &endp, 10);
	unsetenv(envname);
	if (env == endp) {
		return ULONG_MAX;
	}

	return xid;
}

/*
 * This initializes uid_wrapper with the IDs exported to the environment. Those
 * are normally set after we forked and executed.
 */
static void uwrap_init_env(struct uwrap_thread *id)
{
	const char *env;
	int ngroups = 0;
	unsigned long xid;

	/* UIDs */
	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_RUID");
	if (xid != ULONG_MAX) {
		id->ruid = (uid_t)xid;
	}

	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_EUID");
	if (xid != ULONG_MAX) {
		id->euid = (uid_t)xid;
	}

	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_SUID");
	if (xid != ULONG_MAX) {
		id->suid = (uid_t)xid;
	}

	/* GIDs */
	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_RGID");
	if (xid != ULONG_MAX) {
		id->rgid = (gid_t)xid;
	}

	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_EGID");
	if (xid != ULONG_MAX) {
		id->egid = (gid_t)xid;
	}

	xid = uwrap_get_xid_from_env("UID_WRAPPER_INITIAL_SGID");
	if (xid != ULONG_MAX) {
		id->sgid = (gid_t)xid;
	}

	env = getenv("UID_WRAPPER_INITIAL_GROUPS_COUNT");
	if (env != NULL && env[0] != '\0') {
		char *endp = NULL;
		long n;

		n = strtol(env, &endp, 10);
		if (env == endp) {
			ngroups = 0;
		} else if (n > 0 && n < GROUP_MAX_COUNT) {
			ngroups = (int)n;
		}
		unsetenv("UID_WRAPPER_INITIAL_GROUPS_COUNT");
	}

	if (ngroups > 0) {
		int i = 0;

		id->ngroups = 0;

		free(id->groups);
		id->groups = calloc(ngroups, sizeof(gid_t));
		if (id->groups == NULL) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "Unable to allocate memory");
			exit(-1);
		}

		env = getenv("UID_WRAPPER_INITIAL_GROUPS");
		if (env != NULL && env[0] != '\0') {
			char *groups_str = NULL;
			char *saveptr = NULL;
			const char *p = NULL;

			groups_str = strdup(env);
			if (groups_str == NULL) {
				exit(-1);
			}

			p = strtok_r(groups_str, ",", &saveptr);
			while (p != NULL) {
				id->groups[i] = strtol(p, (char **)NULL, 10);
				i++;

				p = strtok_r(NULL, ",", &saveptr);
			}
			SAFE_FREE(groups_str);
		}

		if (i != ngroups) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "ERROR: The number of groups (%u) passed, "
				  "does not match the number of groups (%u) "
				  "we parsed.",
				  ngroups,
				  i);
			exit(-1);
		}

		UWRAP_LOG(UWRAP_LOG_DEBUG, "Initalize groups with %s", env);
		id->ngroups = ngroups;
	}
}

static void uwrap_init(void)
{
	const char *env;

	UWRAP_LOCK(uwrap_id);

	if (uwrap.initialised) {
		struct uwrap_thread *id = uwrap_tls_id;

		if (uwrap.ids == NULL) {
			UWRAP_UNLOCK(uwrap_id);
			return;
		}

		if (id == NULL) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "Invalid id for thread");
			exit(-1);
		}

		UWRAP_UNLOCK(uwrap_id);
		return;
	}

	UWRAP_LOG(UWRAP_LOG_DEBUG, "Initialize uid_wrapper");

	uwrap.initialised = true;

	env = getenv("UID_WRAPPER");
	if (env != NULL && env[0] == '1') {
		const char *root = getenv("UID_WRAPPER_ROOT");
		struct uwrap_thread *id;

		id = calloc(1, sizeof(struct uwrap_thread));
		if (id == NULL) {
			UWRAP_LOG(UWRAP_LOG_ERROR,
				  "Unable to allocate memory for main id");
			exit(-1);
		}

		UWRAP_DLIST_ADD(uwrap.ids, id);
		uwrap_tls_id = id;

		uwrap.myuid = libc_geteuid();
		uwrap.mygid = libc_getegid();

		/* put us in one group */
		if (root != NULL && root[0] == '1') {
			id->ruid = id->euid = id->suid = 0;
			id->rgid = id->egid = id->sgid = 0;

			id->groups = malloc(sizeof(gid_t) * 1);
			if (id->groups == NULL) {
				UWRAP_LOG(UWRAP_LOG_ERROR,
					  "Unable to allocate memory");
				exit(-1);
			}

			id->ngroups = 1;
			id->groups[0] = 0;

		} else {
			id->ruid = id->euid = id->suid = uwrap.myuid;
			id->rgid = id->egid = id->sgid = uwrap.mygid;

			id->ngroups = libc_getgroups(0, NULL);
			if (id->ngroups == -1) {
				UWRAP_LOG(UWRAP_LOG_ERROR,
					  "Unable to call libc_getgroups in uwrap_init.");
				exit(-1);
			}
			id->groups = malloc(sizeof(gid_t) * id->ngroups);
			if (id->groups == NULL) {
				UWRAP_LOG(UWRAP_LOG_ERROR, "Unable to allocate memory");
				exit(-1);
			}
			if (libc_getgroups(id->ngroups, id->groups) == -1) {
				UWRAP_LOG(UWRAP_LOG_ERROR,
					  "Unable to call libc_getgroups again in uwrap_init.");
				id->groups = 0;
				/*
				 * Deallocation of uwrap.groups is handled by
				 * library destructor.
				 */
				exit(-1);
			}
		}

		uwrap_init_env(id);

		id->enabled = true;

		UWRAP_LOG(UWRAP_LOG_DEBUG,
			  "Enabled uid_wrapper as %s (real uid=%u)",
			  id->ruid == 0 ? "root" : "user",
			  (unsigned int)uwrap.myuid);
	}

	UWRAP_UNLOCK(uwrap_id);

	UWRAP_LOG(UWRAP_LOG_DEBUG, "Successfully initialized uid_wrapper");
}

bool uid_wrapper_enabled(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	bool enabled;

	if (id == NULL) {
		return false;
	}

	UWRAP_LOCK(uwrap_id);
	enabled = id->enabled;
	UWRAP_UNLOCK(uwrap_id);

	return enabled;
}

/*
 * UWRAP_SETxUID FUNCTIONS
 */

static int uwrap_setresuid_args(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d, suid %d -> %d",
		  id->ruid, ruid, id->euid, euid, id->suid, suid);

	if (id->euid != 0) {
		if (ruid != (uid_t)-1 &&
		    ruid != id->ruid &&
		    ruid != id->euid &&
		    ruid != id->suid) {
			errno = EPERM;
			return -1;
		}
		if (euid != (uid_t)-1 &&
		    euid != id->ruid &&
		    euid != id->euid &&
		    euid != id->suid) {
			errno = EPERM;
			return -1;
		}
		if (suid != (uid_t)-1 &&
		    suid != id->ruid &&
		    suid != id->euid &&
		    suid != id->suid) {
			errno = EPERM;
			return -1;
		}
	}

	return 0;
}

static int uwrap_setresuid_thread(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d, suid %d -> %d",
		  id->ruid, ruid, id->euid, euid, id->suid, suid);

	rc = uwrap_setresuid_args(ruid, euid, suid);
	if (rc != 0) {
		return rc;
	}

	UWRAP_LOCK(uwrap_id);

	if (ruid != (uid_t)-1) {
		id->ruid = ruid;
	}

	if (euid != (uid_t)-1) {
		id->euid = euid;
	}

	if (suid != (uid_t)-1) {
		id->suid = suid;
	}

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}

static int uwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d, suid %d -> %d",
		  id->ruid, ruid, id->euid, euid, id->suid, suid);

	rc = uwrap_setresuid_args(ruid, euid, suid);
	if (rc != 0) {
		return rc;
	}

	UWRAP_LOCK(uwrap_id);

	for (id = uwrap.ids; id; id = id->next) {
		if (ruid != (uid_t)-1) {
			id->ruid = ruid;
		}

		if (euid != (uid_t)-1) {
			id->euid = euid;
		}

		if (suid != (uid_t)-1) {
			id->suid = suid;
		}
	}

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}

static int uwrap_setreuid_args(uid_t ruid, uid_t euid,
			       uid_t *_new_ruid,
			       uid_t *_new_euid,
			       uid_t *_new_suid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t new_ruid = -1, new_euid = -1, new_suid = -1;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d",
		  id->ruid, ruid, id->euid, euid);

	if (ruid != (uid_t)-1) {
		new_ruid = ruid;
		if (ruid != id->ruid &&
		    ruid != id->euid &&
		    id->euid != 0) {
			errno = EPERM;
			return -1;
		}
	}

	if (euid != (uid_t)-1) {
		new_euid = euid;
		if (euid != id->ruid &&
		    euid != id->euid &&
		    euid != id->suid &&
		    id->euid != 0) {
			errno = EPERM;
			return -1;
		}
	}

	if (ruid != (uid_t) -1 ||
	    (euid != (uid_t)-1 && id->ruid != euid)) {
		new_suid = new_euid;
	}

	*_new_ruid = new_ruid;
	*_new_euid = new_euid;
	*_new_suid = new_suid;

	return 0;
}

static int uwrap_setreuid_thread(uid_t ruid, uid_t euid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t new_ruid = -1, new_euid = -1, new_suid = -1;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d",
		  id->ruid, ruid, id->euid, euid);

	rc = uwrap_setreuid_args(ruid, euid, &new_ruid, &new_euid, &new_suid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresuid_thread(new_ruid, new_euid, new_suid);
}

#ifdef HAVE_SETREUID
static int uwrap_setreuid(uid_t ruid, uid_t euid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t new_ruid = -1, new_euid = -1, new_suid = -1;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "ruid %d -> %d, euid %d -> %d",
		  id->ruid, ruid, id->euid, euid);

	rc = uwrap_setreuid_args(ruid, euid, &new_ruid, &new_euid, &new_suid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresuid(new_ruid, new_euid, new_suid);
}
#endif

static int uwrap_setuid_args(uid_t uid,
			     uid_t *new_ruid,
			     uid_t *new_euid,
			     uid_t *new_suid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "uid %d -> %d",
		  id->ruid, uid);

	if (uid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (id->euid == 0) {
		*new_suid = *new_ruid = uid;
	} else if (uid != id->ruid &&
		   uid != id->suid) {
		errno = EPERM;
		return -1;
	}

	*new_euid = uid;

	return 0;
}

static int uwrap_setuid_thread(uid_t uid)
{
	uid_t new_ruid = -1, new_euid = -1, new_suid = -1;
	int rc;

	rc = uwrap_setuid_args(uid, &new_ruid, &new_euid, &new_suid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresuid_thread(new_ruid, new_euid, new_suid);
}

static int uwrap_setuid(uid_t uid)
{
	uid_t new_ruid = -1, new_euid = -1, new_suid = -1;
	int rc;

	rc = uwrap_setuid_args(uid, &new_ruid, &new_euid, &new_suid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresuid(new_ruid, new_euid, new_suid);
}

/*
 * UWRAP_GETxUID FUNCTIONS
 */

#ifdef HAVE_GETRESUID
static int uwrap_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOCK(uwrap_id);

	*ruid = id->ruid;
	*euid = id->euid;
	*suid = id->suid;

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}
#endif

#ifdef HAVE_GETRESGID
static int uwrap_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOCK(uwrap_id);

	*rgid = id->rgid;
	*egid = id->egid;
	*sgid = id->sgid;

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}
#endif

/*
 * UWRAP_SETxGID FUNCTIONS
 */

static int uwrap_setresgid_args(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d, sgid %d -> %d",
		  id->rgid, rgid, id->egid, egid, id->sgid, sgid);

	if (id->euid != 0) {
		if (rgid != (gid_t)-1 &&
		    rgid != id->rgid &&
		    rgid != id->egid &&
		    rgid != id->sgid) {
			errno = EPERM;
			return -1;
		}
		if (egid != (gid_t)-1 &&
		    egid != id->rgid &&
		    egid != id->egid &&
		    egid != id->sgid) {
			errno = EPERM;
			return -1;
		}
		if (sgid != (gid_t)-1 &&
		    sgid != id->rgid &&
		    sgid != id->egid &&
		    sgid != id->sgid) {
			errno = EPERM;
			return -1;
		}
	}

	return 0;
}

static int uwrap_setresgid_thread(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d, sgid %d -> %d",
		  id->rgid, rgid, id->egid, egid, id->sgid, sgid);

	rc = uwrap_setresgid_args(rgid, egid, sgid);
	if (rc != 0) {
		return rc;
	}

	UWRAP_LOCK(uwrap_id);

	if (rgid != (gid_t)-1) {
		id->rgid = rgid;
	}

	if (egid != (gid_t)-1) {
		id->egid = egid;
	}

	if (sgid != (gid_t)-1) {
		id->sgid = sgid;
	}

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}

static int uwrap_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d, sgid %d -> %d",
		  id->rgid, rgid, id->egid, egid, id->sgid, sgid);

	rc = uwrap_setresgid_args(rgid, egid, sgid);
	if (rc != 0) {
		return rc;
	}

	UWRAP_LOCK(uwrap_id);

	for (id = uwrap.ids; id; id = id->next) {
		if (rgid != (gid_t)-1) {
			id->rgid = rgid;
		}

		if (egid != (gid_t)-1) {
			id->egid = egid;
		}

		if (sgid != (gid_t)-1) {
			id->sgid = sgid;
		}
	}

	UWRAP_UNLOCK(uwrap_id);

	return 0;
}

static int uwrap_setregid_args(gid_t rgid, gid_t egid,
			       gid_t *_new_rgid,
			       gid_t *_new_egid,
			       gid_t *_new_sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t new_rgid = -1, new_egid = -1, new_sgid = -1;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d",
		  id->rgid, rgid, id->egid, egid);

	if (rgid != (gid_t)-1) {
		new_rgid = rgid;
		if (rgid != id->rgid &&
		    rgid != id->egid &&
		    id->euid != 0) {
			errno = EPERM;
			return -1;
		}
	}

	if (egid != (gid_t)-1) {
		new_egid = egid;
		if (egid != id->rgid &&
		    egid != id->egid &&
		    egid != id->sgid &&
		    id->euid != 0) {
			errno = EPERM;
			return -1;
		}
	}

	if (rgid != (gid_t) -1 ||
	    (egid != (gid_t)-1 && id->rgid != egid)) {
		new_sgid = new_egid;
	}

	*_new_rgid = new_rgid;
	*_new_egid = new_egid;
	*_new_sgid = new_sgid;

	return 0;
}

static int uwrap_setregid_thread(gid_t rgid, gid_t egid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t new_rgid = -1, new_egid = -1, new_sgid = -1;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d",
		  id->rgid, rgid, id->egid, egid);

	rc = uwrap_setregid_args(rgid, egid, &new_rgid, &new_egid, &new_sgid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresgid_thread(new_rgid, new_egid, new_sgid);
}

#ifdef HAVE_SETREGID
static int uwrap_setregid(gid_t rgid, gid_t egid)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t new_rgid = -1, new_egid = -1, new_sgid = -1;
	int rc;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "rgid %d -> %d, egid %d -> %d",
		  id->rgid, rgid, id->egid, egid);

	rc = uwrap_setregid_args(rgid, egid, &new_rgid, &new_egid, &new_sgid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresgid(new_rgid, new_egid, new_sgid);
}
#endif

static int uwrap_setgid_args(gid_t gid,
			     gid_t *new_rgid,
			     gid_t *new_egid,
			     gid_t *new_sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	UWRAP_LOG(UWRAP_LOG_TRACE,
		  "gid %d -> %d",
		  id->rgid, gid);

	if (gid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (id->euid == 0) {
		*new_sgid = *new_rgid = gid;
	} else if (gid != id->rgid &&
		   gid != id->sgid) {
		errno = EPERM;
		return -1;
	}

	*new_egid = gid;

	return 0;
}

static int uwrap_setgid_thread(gid_t gid)
{
	gid_t new_rgid = -1, new_egid = -1, new_sgid = -1;
	int rc;

	rc = uwrap_setgid_args(gid, &new_rgid, &new_egid, &new_sgid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresgid_thread(new_rgid, new_egid, new_sgid);
}

static int uwrap_setgid(gid_t gid)
{
	gid_t new_rgid = -1, new_egid = -1, new_sgid = -1;
	int rc;

	rc = uwrap_setgid_args(gid, &new_rgid, &new_egid, &new_sgid);
	if (rc != 0) {
		return rc;
	}

	return uwrap_setresgid(new_rgid, new_egid, new_sgid);
}

/*
 * SETUID
 */
int setuid(uid_t uid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setuid(uid);
	}

	uwrap_init();
	return uwrap_setuid(uid);
}

#ifdef HAVE_SETEUID
int seteuid(uid_t euid)
{
	if (!uid_wrapper_enabled()) {
		return libc_seteuid(euid);
	}

	/* On FreeBSD the uid_t -1 is set and doesn't produce and error */
	if (euid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	uwrap_init();
	return uwrap_setresuid(-1, euid, -1);
}
#endif

#ifdef HAVE_SETREUID
int setreuid(uid_t ruid, uid_t euid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setreuid(ruid, euid);
	}

	uwrap_init();
	return uwrap_setreuid(ruid, euid);
}
#endif

#ifdef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setresuid(ruid, euid, suid);
	}

	uwrap_init();
	return uwrap_setresuid(ruid, euid, suid);
}
#endif

#ifdef HAVE_GETRESUID
int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	if (!uid_wrapper_enabled()) {
		return libc_getresuid(ruid, euid, suid);
	}

	uwrap_init();
	return uwrap_getresuid(ruid, euid, suid);
}
#endif

/*
 * GETUID
 */
static uid_t uwrap_getuid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t uid;

	UWRAP_LOCK(uwrap_id);
	uid = id->ruid;
	UWRAP_UNLOCK(uwrap_id);

	return uid;
}

uid_t getuid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getuid();
	}

	uwrap_init();
	return uwrap_getuid();
}

/*
 * GETEUID
 */
static uid_t uwrap_geteuid(void)
{
	const char *env = getenv("UID_WRAPPER_MYUID");
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t uid;

	UWRAP_LOCK(uwrap_id);
	uid = id->euid;
	UWRAP_UNLOCK(uwrap_id);

	/* Disable root and return myuid */
	if (env != NULL && env[0] == '1') {
		uid = uwrap.myuid;
	}

	return uid;
}

uid_t geteuid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_geteuid();
	}

	uwrap_init();
	return uwrap_geteuid();
}

/*
 * SETGID
 */
int setgid(gid_t gid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setgid(gid);
	}

	uwrap_init();
	return uwrap_setgid(gid);
}

#ifdef HAVE_SETEGID
int setegid(gid_t egid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setegid(egid);
	}

	/* On FreeBSD the uid_t -1 is set and doesn't produce and error */
	if (egid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	uwrap_init();
	return uwrap_setresgid(-1, egid, -1);
}
#endif

#ifdef HAVE_SETREGID
int setregid(gid_t rgid, gid_t egid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setregid(rgid, egid);
	}

	uwrap_init();
	return uwrap_setregid(rgid, egid);
}
#endif

#ifdef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setresgid(rgid, egid, sgid);
	}

	uwrap_init();
	return uwrap_setresgid(rgid, egid, sgid);
}
#endif

#ifdef HAVE_GETRESGID
int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
	if (!uid_wrapper_enabled()) {
		return libc_getresgid(rgid, egid, sgid);
	}

	uwrap_init();
	return uwrap_getresgid(rgid, egid, sgid);
}
#endif

/*
 * GETGID
 */
static gid_t uwrap_getgid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	UWRAP_LOCK(uwrap_id);
	gid = id->rgid;
	UWRAP_UNLOCK(uwrap_id);

	return gid;
}

gid_t getgid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getgid();
	}

	uwrap_init();
	return uwrap_getgid();
}

/*
 * GETEGID
 */
static uid_t uwrap_getegid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	UWRAP_LOCK(uwrap_id);
	gid = id->egid;
	UWRAP_UNLOCK(uwrap_id);

	return gid;
}

uid_t getegid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getegid();
	}

	uwrap_init();
	return uwrap_getegid();
}

static int uwrap_setgroups_thread(size_t size, const gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc = -1;

	UWRAP_LOCK(uwrap_id);

	if (size == 0) {
		SAFE_FREE(id->groups);
		id->ngroups = 0;
	} else if (size > 0) {
		gid_t *tmp;

		tmp = realloc(id->groups, sizeof(gid_t) * size);
		if (tmp == NULL) {
			errno = ENOMEM;
			goto out;
		}
		id->groups = tmp;
		id->ngroups = size;
		memcpy(id->groups, list, size * sizeof(gid_t));
	}

	rc = 0;
out:
	UWRAP_UNLOCK(uwrap_id);

	return rc;
}

static int uwrap_setgroups(size_t size, const gid_t *list)
{
	struct uwrap_thread *id;
	int rc = -1;

	UWRAP_LOCK(uwrap_id);

	if (size == 0) {
		for (id = uwrap.ids; id; id = id->next) {
			SAFE_FREE(id->groups);
			id->ngroups = 0;

		}
	} else if (size > 0) {
		gid_t *tmp;

		for (id = uwrap.ids; id; id = id->next) {
			tmp = realloc(id->groups, sizeof(gid_t) * size);
			if (tmp == NULL) {
				errno = ENOMEM;
				goto out;
			}
			id->groups = tmp;

			id->ngroups = size;
			memcpy(id->groups, list, size * sizeof(gid_t));
		}
	}

	rc = 0;
out:
	UWRAP_UNLOCK(uwrap_id);

	return rc;
}

#ifdef HAVE_SETGROUPS_INT
int setgroups(int size, const gid_t *list)
#else
int setgroups(size_t size, const gid_t *list)
#endif
{
	if (!uid_wrapper_enabled()) {
		return libc_setgroups(size, list);
	}

	uwrap_init();
	return uwrap_setgroups(size, list);
}

static int uwrap_getgroups(int size, gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int ngroups;

	UWRAP_LOCK(uwrap_id);
	ngroups = id->ngroups;

	if (size > ngroups) {
		size = ngroups;
	}
	if (size == 0) {
		goto out;
	}
	if (size < ngroups) {
		errno = EINVAL;
		ngroups = -1;
	}
	memcpy(list, id->groups, size * sizeof(gid_t));

out:
	UWRAP_UNLOCK(uwrap_id);

	return ngroups;
}

int getgroups(int size, gid_t *list)
{
	if (!uid_wrapper_enabled()) {
		return libc_getgroups(size, list);
	}

	uwrap_init();
	return uwrap_getgroups(size, list);
}

#if (defined(HAVE_SYS_SYSCALL_H) || defined(HAVE_SYSCALL_H)) \
    && (defined(SYS_setreuid) || defined(SYS_setreuid32))
static long int uwrap_syscall (long int sysno, va_list vp)
{
	long int rc;

	switch (sysno) {
		/* gid */
#ifdef __alpha__
		case SYS_getxgid:
#else
		case SYS_getgid:
#endif
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getgid32:
#endif
			{
				rc = uwrap_getgid();
			}
			break;
#ifdef SYS_getegid
		case SYS_getegid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getegid32:
#endif
			{
				rc = uwrap_getegid();
			}
			break;
#endif /* SYS_getegid */
		case SYS_setgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgid32:
#endif
			{
				gid_t gid = (gid_t) va_arg(vp, gid_t);

				rc = uwrap_setgid_thread(gid);
			}
			break;
		case SYS_setregid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setregid32:
#endif
			{
				gid_t rgid = (gid_t) va_arg(vp, gid_t);
				gid_t egid = (gid_t) va_arg(vp, gid_t);

				rc = uwrap_setregid_thread(rgid, egid);
			}
			break;
#ifdef SYS_setresgid
		case SYS_setresgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresgid32:
#endif
			{
				gid_t rgid = (gid_t) va_arg(vp, gid_t);
				gid_t egid = (gid_t) va_arg(vp, gid_t);
				gid_t sgid = (gid_t) va_arg(vp, gid_t);

				rc = uwrap_setresgid_thread(rgid, egid, sgid);
			}
			break;
#endif /* SYS_setresgid */
#if defined(SYS_getresgid) && defined(HAVE_GETRESGID)
		case SYS_getresgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getresgid32:
#endif
			{
				gid_t *rgid = (gid_t *) va_arg(vp, gid_t *);
				gid_t *egid = (gid_t *) va_arg(vp, gid_t *);
				gid_t *sgid = (gid_t *) va_arg(vp, gid_t *);

				rc = uwrap_getresgid(rgid, egid, sgid);
			}
			break;
#endif /* SYS_getresgid && HAVE_GETRESGID */

		/* uid */
#ifdef __alpha__
		case SYS_getxuid:
#else
		case SYS_getuid:
#endif
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getuid32:
#endif
			{
				rc = uwrap_getuid();
			}
			break;
#ifdef SYS_geteuid
		case SYS_geteuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_geteuid32:
#endif
			{
				rc = uwrap_geteuid();
			}
			break;
#endif /* SYS_geteuid */
		case SYS_setuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setuid32:
#endif
			{
				uid_t uid = (uid_t) va_arg(vp, uid_t);

				rc = uwrap_setuid_thread(uid);
			}
			break;
		case SYS_setreuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setreuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, uid_t);
				uid_t euid = (uid_t) va_arg(vp, uid_t);

				rc = uwrap_setreuid_thread(ruid, euid);
			}
			break;
#ifdef SYS_setresuid
		case SYS_setresuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, uid_t);
				uid_t euid = (uid_t) va_arg(vp, uid_t);
				uid_t suid = (uid_t) va_arg(vp, uid_t);

				rc = uwrap_setresuid_thread(ruid, euid, suid);
			}
			break;
#endif /* SYS_setresuid */
#if defined(SYS_getresuid) && defined(HAVE_GETRESUID)
		case SYS_getresuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_getresuid32:
#endif
			{
				uid_t *ruid = (uid_t *) va_arg(vp, uid_t *);
				uid_t *euid = (uid_t *) va_arg(vp, uid_t *);
				uid_t *suid = (uid_t *) va_arg(vp, uid_t *);

				rc = uwrap_getresuid(ruid, euid, suid);
			}
			break;
#endif /* SYS_getresuid && HAVE_GETRESUID*/
		/* groups */
		case SYS_setgroups:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setgroups32:
#endif
			{
				size_t size = (size_t) va_arg(vp, size_t);
				gid_t *list = (gid_t *) va_arg(vp, int *);

				rc = uwrap_setgroups_thread(size, list);
			}
			break;
		default:
			UWRAP_LOG(UWRAP_LOG_DEBUG,
				  "UID_WRAPPER calling non-wrapped syscall %lu",
				  sysno);

			rc = libc_vsyscall(sysno, vp);
			break;
	}

	return rc;
}

#ifdef HAVE_SYSCALL
#ifdef HAVE_SYSCALL_INT
int syscall (int sysno, ...)
#else
long int syscall (long int sysno, ...)
#endif
{
#ifdef HAVE_SYSCALL_INT
	int rc;
#else
	long int rc;
#endif
	va_list va;

	va_start(va, sysno);

	if (!uid_wrapper_enabled()) {
		rc = libc_vsyscall(sysno, va);
		va_end(va);
		return rc;
	}

	uwrap_init();
	rc = uwrap_syscall(sysno, va);
	va_end(va);

	return rc;
}
#endif /* HAVE_SYSCALL */
#endif /* HAVE_SYS_SYSCALL_H || HAVE_SYSCALL_H */

/****************************
 * CONSTRUCTOR
 ***************************/

void uwrap_constructor(void)
{
	char *glibc_malloc_lock_bug;

	/*
	 * This is a workaround for a bug in glibc < 2.24:
	 *
	 * The child handler for the malloc() function is called and locks the
	 * mutex. Then our child handler is called and we try to call setenv().
	 * setenv() wants to malloc and tries to aquire the lock for malloc and
	 * we end up in a deadlock.
	 *
	 * So as a workaround we need to call malloc once before we setup the
	 * handlers.
	 *
	 * See https://sourceware.org/bugzilla/show_bug.cgi?id=16742
	 */
	glibc_malloc_lock_bug = malloc(1);
	if (glibc_malloc_lock_bug == NULL) {
		exit(-1);
	}
	glibc_malloc_lock_bug[0] = '\0';

	/*
	* If we hold a lock and the application forks, then the child
	* is not able to unlock the mutex and we are in a deadlock.
	* This should prevent such deadlocks.
	*/
	pthread_atfork(&uwrap_thread_prepare,
		       &uwrap_thread_parent,
		       &uwrap_thread_child);

	free(glibc_malloc_lock_bug);

	/* Here is safe place to call uwrap_init() and initialize data
	 * for main process.
	 */
	uwrap_init();
}

/****************************
 * DESTRUCTOR
 ***************************/

/*
 * This function is called when the library is unloaded and makes sure that
 * resources are freed.
 */
void uwrap_destructor(void)
{
	struct uwrap_thread *u = uwrap.ids;

	UWRAP_LOCK_ALL;

	while (u != NULL) {
		UWRAP_DLIST_REMOVE(uwrap.ids, u);

		SAFE_FREE(u->groups);
		SAFE_FREE(u);

		u = uwrap.ids;
	}


	if (uwrap.libc.handle != NULL) {
		dlclose(uwrap.libc.handle);
	}

	if (uwrap.libpthread.handle != NULL) {
		dlclose(uwrap.libpthread.handle);
	}

	UWRAP_UNLOCK_ALL;
}
