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

#include <pthread.h>

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define UWRAP_THREAD __thread
#else
# define UWRAP_THREAD
#endif

#ifdef HAVE_DESTRUCTOR_ATTRIBUTE
#define DESTRUCTOR_ATTRIBUTE __attribute__ ((destructor))
#else
#define DESTRUCTOR_ATTRIBUTE
#endif /* HAVE_DESTRUCTOR_ATTRIBUTE */

/* GCC have printf type attribute check. */
#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* HAVE_FUNCTION_ATTRIBUTE_FORMAT */

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

#ifdef NDEBUG
# define UWRAP_LOG(...)
#else /* NDEBUG */
static void uwrap_log(enum uwrap_dbglvl_e dbglvl, const char *format, ...) PRINTF_ATTRIBUTE(2, 3);
# define UWRAP_LOG(dbglvl, ...) uwrap_log((dbglvl), __VA_ARGS__)

static void uwrap_log(enum uwrap_dbglvl_e dbglvl, const char *format, ...)
{
	char buffer[1024];
	va_list va;
	const char *d;
	unsigned int lvl = 0;

	d = getenv("UID_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	va_start(va, format);
	vsnprintf(buffer, sizeof(buffer), format, va);
	va_end(va);

	if (lvl >= dbglvl) {
		switch (dbglvl) {
			case UWRAP_LOG_ERROR:
				fprintf(stderr,
					"UWRAP_ERROR(%d): %s\n",
					(int)getpid(), buffer);
				break;
			case UWRAP_LOG_WARN:
				fprintf(stderr,
					"UWRAP_WARN(%d): %s\n",
					(int)getpid(), buffer);
				break;
			case UWRAP_LOG_DEBUG:
				fprintf(stderr,
					"UWRAP_DEBUG(%d): %s\n",
					(int)getpid(), buffer);
				break;
			case UWRAP_LOG_TRACE:
				fprintf(stderr,
					"UWRAP_TRACE(%d): %s\n",
					(int)getpid(), buffer);
				break;
		}
	}
}
#endif /* NDEBUG */

/*****************
 * LIBC
 *****************/

#define LIBC_NAME "libc.so"

struct uwrap_libc_fns {
	int (*_libc_setuid)(uid_t uid);
	uid_t (*_libc_getuid)(void);

#ifdef HAVE_SETEUID
	int (*_libc_seteuid)(uid_t euid);
#endif
#ifdef HAVE_SETREUID
	int (*_libc_setreuid)(uid_t ruid, uid_t euid);
#endif
#ifdef HAVE_SETRESUID
	int (*_libc_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
#endif
	uid_t (*_libc_geteuid)(void);

	int (*_libc_setgid)(gid_t gid);
	gid_t (*_libc_getgid)(void);
#ifdef HAVE_SETEGID
	int (*_libc_setegid)(uid_t egid);
#endif
#ifdef HAVE_SETREGID
	int (*_libc_setregid)(uid_t rgid, uid_t egid);
#endif
#ifdef HAVE_SETRESGID
	int (*_libc_setresgid)(uid_t rgid, uid_t egid, uid_t sgid);
#endif
	gid_t (*_libc_getegid)(void);
	int (*_libc_getgroups)(int size, gid_t list[]);
	int (*_libc_setgroups)(size_t size, const gid_t *list);
#ifdef HAVE_SYSCALL
	long int (*_libc_syscall)(long int sysno, ...);
#endif
};

/*
 * We keep the virtualised euid/egid/groups information here
 */
struct uwrap_thread {
	pthread_t tid;
	bool dead;

	uid_t ruid;
	uid_t euid;
	uid_t suid;

	gid_t rgid;
	gid_t egid;
	gid_t sgid;

	gid_t *groups;
	int ngroups;

	struct uwrap_thread *next;
	struct uwrap_thread *prev;
};

struct uwrap {
	struct {
		void *handle;
		struct uwrap_libc_fns fns;
	} libc;

	bool initialised;
	bool enabled;

	uid_t myuid;
	uid_t mygid;

	struct uwrap_thread *ids;
};

static struct uwrap uwrap;

/* Shortcut to the list item */
static UWRAP_THREAD struct uwrap_thread *uwrap_tls_id;

/* The mutex or accessing the id */
static pthread_mutex_t uwrap_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/*********************************************************
 * UWRAP PROTOTYPES
 *********************************************************/

bool uid_wrapper_enabled(void);
void uwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * UWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum uwrap_lib {
    UWRAP_LIBC,
    UWRAP_LIBNSL,
    UWRAP_LIBSOCKET,
};

static void *uwrap_load_lib_handle(enum uwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;
	int i;

#ifdef RTLD_DEEPBIND
	flags |= RTLD_DEEPBIND;
#endif

	switch (lib) {
	case UWRAP_LIBNSL:
		/* FALL TROUGH */
	case UWRAP_LIBSOCKET:
		/* FALL TROUGH */
	case UWRAP_LIBC:
		handle = uwrap.libc.handle;
		if (handle == NULL) {
			for (handle = NULL, i = 10; handle == NULL && i >= 0; i--) {
				char soname[256] = {0};

				snprintf(soname, sizeof(soname), "libc.so.%d", i);
				handle = dlopen(soname, flags);
			}

			uwrap.libc.handle = handle;
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

static void *_uwrap_load_lib_function(enum uwrap_lib lib, const char *fn_name)
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

#define uwrap_load_lib_function(lib, fn_name) \
	if (uwrap.libc.fns._libc_##fn_name == NULL) { \
		*(void **) (&uwrap.libc.fns._libc_##fn_name) = \
			_uwrap_load_lib_function(lib, #fn_name); \
	}

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
	uwrap_load_lib_function(UWRAP_LIBC, setuid);

	return uwrap.libc.fns._libc_setuid(uid);
}

static uid_t libc_getuid(void)
{
	uwrap_load_lib_function(UWRAP_LIBC, getuid);

	return uwrap.libc.fns._libc_getuid();
}

#ifdef HAVE_SETEUID
static int libc_seteuid(uid_t euid)
{
	uwrap_load_lib_function(UWRAP_LIBC, seteuid);

	return uwrap.libc.fns._libc_seteuid(euid);
}
#endif

#ifdef HAVE_SETREUID
static int libc_setreuid(uid_t ruid, uid_t euid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setreuid);

	return uwrap.libc.fns._libc_setreuid(ruid, euid);
}
#endif

#ifdef HAVE_SETRESUID
static int libc_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setresuid);

	return uwrap.libc.fns._libc_setresuid(ruid, euid, suid);
}
#endif

static uid_t libc_geteuid(void)
{
	uwrap_load_lib_function(UWRAP_LIBC, geteuid);

	return uwrap.libc.fns._libc_geteuid();
}

static int libc_setgid(gid_t gid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setgid);

	return uwrap.libc.fns._libc_setgid(gid);
}

static gid_t libc_getgid(void)
{
	uwrap_load_lib_function(UWRAP_LIBC, getgid);

	return uwrap.libc.fns._libc_getgid();
}

#ifdef HAVE_SETEGID
static int libc_setegid(gid_t egid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setegid);

	return uwrap.libc.fns._libc_setegid(egid);
}
#endif

#ifdef HAVE_SETREGID
static int libc_setregid(gid_t rgid, gid_t egid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setregid);

	return uwrap.libc.fns._libc_setregid(rgid, egid);
}
#endif

#ifdef HAVE_SETRESGID
static int libc_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	uwrap_load_lib_function(UWRAP_LIBC, setresgid);

	return uwrap.libc.fns._libc_setresgid(rgid, egid, sgid);
}
#endif

static gid_t libc_getegid(void)
{
	uwrap_load_lib_function(UWRAP_LIBC, getegid);

	return uwrap.libc.fns._libc_getegid();
}

static int libc_getgroups(int size, gid_t list[])
{
	uwrap_load_lib_function(UWRAP_LIBC, getgroups);

	return uwrap.libc.fns._libc_getgroups(size, list);
}

static int libc_setgroups(size_t size, const gid_t *list)
{
	uwrap_load_lib_function(UWRAP_LIBC, setgroups);

	return uwrap.libc.fns._libc_setgroups(size, list);
}

#ifdef HAVE_SYSCALL
static long int libc_vsyscall(long int sysno, va_list va)
{
	long int args[8];
	long int rc;
	int i;

	uwrap_load_lib_function(UWRAP_LIBC, syscall);

	for (i = 0; i < 8; i++) {
		args[i] = va_arg(va, long int);
	}

	rc = uwrap.libc.fns._libc_syscall(sysno,
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

/*********************************************************
 * UWRAP ID HANDLING
 *********************************************************/

static struct uwrap_thread *find_uwrap_id(pthread_t tid)
{
	struct uwrap_thread *id;

	for (id = uwrap.ids; id; id = id->next) {
		if (pthread_equal(id->tid, tid)) {
			return id;
		}
	}

	return NULL;
}

static int uwrap_new_id(pthread_t tid, bool do_alloc)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (do_alloc) {
		id = malloc(sizeof(struct uwrap_thread));
		if (id == NULL) {
			UWRAP_LOG(UWRAP_LOG_ERROR, "Unable to allocate memory");
			errno = ENOMEM;
			return -1;
		}

		id->groups = malloc(sizeof(gid_t) * 1);
		if (id->groups == NULL) {
			UWRAP_LOG(UWRAP_LOG_ERROR, "Unable to allocate memory");
			SAFE_FREE(id);
			errno = ENOMEM;
			return -1;
		}

		UWRAP_DLIST_ADD(uwrap.ids, id);
		uwrap_tls_id = id;
	}

	id->tid = tid;
	id->dead = false;

	id->ruid = id->euid = id->suid = uwrap.myuid;
	id->rgid = id->egid = id->sgid = uwrap.mygid;

	id->ngroups = 1;
	id->groups[0] = uwrap.mygid;

	return 0;
}

static void uwrap_thread_prepare(void)
{
	pthread_mutex_lock(&uwrap_id_mutex);

	/*
	 * What happens if another atfork prepare functions calls a uwrap
	 * function? So disable it in case another atfork prepare function
	 * calls a (s)uid function.
	 */
	uwrap.enabled = false;
}

static void uwrap_thread_parent(void)
{
	uwrap.enabled = true;

	pthread_mutex_unlock(&uwrap_id_mutex);
}

static void uwrap_thread_child(void)
{
	uwrap.enabled = true;

	pthread_mutex_unlock(&uwrap_id_mutex);
}

static void uwrap_init(void)
{
	const char *env = getenv("UID_WRAPPER");
	pthread_t tid = pthread_self();



	if (uwrap.initialised) {
		struct uwrap_thread *id = uwrap_tls_id;
		int rc;

		if (id != NULL) {
			return;
		}

		pthread_mutex_lock(&uwrap_id_mutex);
		id = find_uwrap_id(tid);
		if (id == NULL) {
			rc = uwrap_new_id(tid, true);
			if (rc < 0) {
				exit(-1);
			}
		} else {
			/* We reuse an old thread id */
			uwrap_tls_id = id;

			uwrap_new_id(tid, false);
		}
		pthread_mutex_unlock(&uwrap_id_mutex);

		return;
	}

	UWRAP_LOG(UWRAP_LOG_DEBUG, "Initialize uid_wrapper");

	/*
	 * If we hold a lock and the application forks, then the child
	 * is not able to unlock the mutex and we are in a deadlock.
	 * This should prevent such deadlocks.
	 */
	pthread_atfork(&uwrap_thread_prepare,
		       &uwrap_thread_parent,
		       &uwrap_thread_child);

	pthread_mutex_lock(&uwrap_id_mutex);

	uwrap.initialised = true;
	uwrap.enabled = false;

	if (env != NULL && env[0] == '1') {
		const char *root = getenv("UID_WRAPPER_ROOT");
		int rc;

		/* put us in one group */
		if (root != NULL && root[0] == '1') {
			uwrap.myuid = 0;
			uwrap.mygid = 0;
		} else {
			uwrap.myuid = libc_geteuid();
			uwrap.mygid = libc_getegid();
		}

		rc = uwrap_new_id(tid, true);
		if (rc < 0) {
			exit(-1);
		}

		uwrap.enabled = true;

		UWRAP_LOG(UWRAP_LOG_DEBUG,
			  "Enabled uid_wrapper as %s",
			  uwrap.myuid == 0 ? "root" : "user");
	}

	pthread_mutex_unlock(&uwrap_id_mutex);

	UWRAP_LOG(UWRAP_LOG_DEBUG, "Succeccfully initialized uid_wrapper");
}

bool uid_wrapper_enabled(void)
{
	uwrap_init();

	return uwrap.enabled ? true : false;
}

static int uwrap_setresuid_thread(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (ruid == (uid_t)-1 && euid == (uid_t)-1 && suid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	if (ruid != (uid_t)-1) {
		id->ruid = ruid;
	}

	if (euid != (uid_t)-1) {
		id->euid = euid;
	}

	if (suid != (uid_t)-1) {
		id->suid = suid;
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

static int uwrap_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	struct uwrap_thread *id;

	if (ruid == (uid_t)-1 && euid == (uid_t)-1 && suid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	for (id = uwrap.ids; id; id = id->next) {
		if (id->dead) {
			continue;
		}

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
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

/*
 * SETUID
 */
int setuid(uid_t uid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setuid(uid);
	}

	return uwrap_setresuid(uid, -1, -1);
}

#ifdef HAVE_SETEUID
int seteuid(uid_t euid)
{
	if (euid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (!uid_wrapper_enabled()) {
		return libc_seteuid(euid);
	}

	return uwrap_setresuid(-1, euid, -1);
}
#endif

#ifdef HAVE_SETREUID
int setreuid(uid_t ruid, uid_t euid)
{
	if (ruid == (uid_t)-1 && euid == (uid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	if (!uid_wrapper_enabled()) {
		return libc_setreuid(ruid, euid);
	}

	return uwrap_setresuid(ruid, euid, -1);
}
#endif

#ifdef HAVE_SETRESUID
int setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setresuid(ruid, euid, suid);
	}

	return uwrap_setresuid(ruid, euid, suid);
}
#endif

/*
 * GETUID
 */
static uid_t uwrap_getuid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	uid_t uid;

	pthread_mutex_lock(&uwrap_id_mutex);
	uid = id->ruid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return uid;
}

uid_t getuid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getuid();
	}

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

	pthread_mutex_lock(&uwrap_id_mutex);
	uid = id->euid;
	pthread_mutex_unlock(&uwrap_id_mutex);

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

	return uwrap_geteuid();
}

static int uwrap_setresgid_thread(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id = uwrap_tls_id;

	if (rgid == (gid_t)-1 && egid == (gid_t)-1 && sgid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	if (rgid != (gid_t)-1) {
		id->rgid = rgid;
	}

	if (egid != (gid_t)-1) {
		id->egid = egid;
	}

	if (sgid != (gid_t)-1) {
		id->sgid = sgid;
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

static int uwrap_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	struct uwrap_thread *id;

	if (rgid == (gid_t)-1 && egid == (gid_t)-1 && sgid == (gid_t)-1) {
		errno = EINVAL;
		return -1;
	}

	pthread_mutex_lock(&uwrap_id_mutex);
	for (id = uwrap.ids; id; id = id->next) {
		if (id->dead) {
			continue;
		}

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
	pthread_mutex_unlock(&uwrap_id_mutex);

	return 0;
}

/*
 * SETGID
 */
int setgid(gid_t gid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setgid(gid);
	}

	return uwrap_setresgid(gid, -1, -1);
}

#ifdef HAVE_SETEGID
int setegid(gid_t egid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setegid(egid);
	}

	return uwrap_setresgid(-1, egid, -1);
}
#endif

#ifdef HAVE_SETREGID
int setregid(gid_t rgid, gid_t egid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setregid(rgid, egid);
	}

	return uwrap_setresgid(rgid, egid, -1);
}
#endif

#ifdef HAVE_SETRESGID
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (!uid_wrapper_enabled()) {
		return libc_setresgid(rgid, egid, sgid);
	}

	return uwrap_setresgid(rgid, egid, sgid);
}
#endif

/*
 * GETGID
 */
static gid_t uwrap_getgid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	pthread_mutex_lock(&uwrap_id_mutex);
	gid = id->rgid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return gid;
}

gid_t getgid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getgid();
	}

	return uwrap_getgid();
}

/*
 * GETEGID
 */
static uid_t uwrap_getegid(void)
{
	struct uwrap_thread *id = uwrap_tls_id;
	gid_t gid;

	pthread_mutex_lock(&uwrap_id_mutex);
	gid = id->egid;
	pthread_mutex_unlock(&uwrap_id_mutex);

	return gid;
}

uid_t getegid(void)
{
	if (!uid_wrapper_enabled()) {
		return libc_getegid();
	}

	return uwrap_getegid();
}

static int uwrap_setgroups_thread(size_t size, const gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int rc = -1;

	pthread_mutex_lock(&uwrap_id_mutex);

	if (size == 0) {
		free(id->groups);
		id->groups = NULL;
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
	pthread_mutex_unlock(&uwrap_id_mutex);

	return rc;
}

static int uwrap_setgroups(size_t size, const gid_t *list)
{
	struct uwrap_thread *id;
	int rc = -1;

	pthread_mutex_lock(&uwrap_id_mutex);

	if (size == 0) {
		for (id = uwrap.ids; id; id = id->next) {
			free(id->groups);
			id->groups = NULL;
			id->ngroups = 0;
		}
	} else if (size > 0) {
		for (id = uwrap.ids; id; id = id->next) {
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
	}

	rc = 0;
out:
	pthread_mutex_unlock(&uwrap_id_mutex);

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

	return uwrap_setgroups(size, list);
}

static int uwrap_getgroups(int size, gid_t *list)
{
	struct uwrap_thread *id = uwrap_tls_id;
	int ngroups;

	pthread_mutex_lock(&uwrap_id_mutex);
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
	pthread_mutex_unlock(&uwrap_id_mutex);

	return ngroups;
}

int getgroups(int size, gid_t *list)
{
	if (!uid_wrapper_enabled()) {
		return libc_getgroups(size, list);
	}

	return uwrap_getgroups(size, list);
}

#if (defined(HAVE_SYS_SYSCALL_H) || defined(HAVE_SYSCALL_H)) \
    && (defined(SYS_setreuid) || defined(SYS_setreuid32))
static long int uwrap_syscall (long int sysno, va_list vp)
{
	long int rc;

	switch (sysno) {
		/* gid */
		case SYS_getgid:
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
				gid_t gid = (gid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(gid, -1, -1);
			}
			break;
		case SYS_setregid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setregid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(rgid, egid, -1);
			}
			break;
#ifdef SYS_setresgid
		case SYS_setresgid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresgid32:
#endif
			{
				uid_t rgid = (uid_t) va_arg(vp, int);
				uid_t egid = (uid_t) va_arg(vp, int);
				uid_t sgid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresgid_thread(rgid, egid, sgid);
			}
			break;
#endif /* SYS_setresgid */

		/* uid */
		case SYS_getuid:
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
				uid_t uid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(uid, -1, -1);
			}
			break;
		case SYS_setreuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setreuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(ruid, euid, -1);
			}
			break;
#ifdef SYS_setresuid
		case SYS_setresuid:
#ifdef HAVE_LINUX_32BIT_SYSCALLS
		case SYS_setresuid32:
#endif
			{
				uid_t ruid = (uid_t) va_arg(vp, int);
				uid_t euid = (uid_t) va_arg(vp, int);
				uid_t suid = (uid_t) va_arg(vp, int);

				rc = uwrap_setresuid_thread(ruid, euid, suid);
			}
			break;
#endif /* SYS_setresuid */

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
				  "UID_WRAPPER calling non-wrapped syscall %lu\n",
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

	rc = uwrap_syscall(sysno, va);
	va_end(va);

	return rc;
}
#endif /* HAVE_SYSCALL */
#endif /* HAVE_SYS_SYSCALL_H || HAVE_SYSCALL_H */

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

	pthread_mutex_lock(&uwrap_id_mutex);
	while (u != NULL) {
		UWRAP_DLIST_REMOVE(uwrap.ids, u);

		SAFE_FREE(u->groups);
		SAFE_FREE(u);

		u = uwrap.ids;
	}
	pthread_mutex_unlock(&uwrap_id_mutex);

	if (uwrap.libc.handle != NULL) {
		dlclose(uwrap.libc.handle);
	}
}
