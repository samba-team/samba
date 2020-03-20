/*
 * Copyright (c) 2015 Andreas Schneider <asn@samba.org>
 * Copyright (c) 2015 Jakub Hrozek <jakub.hrozek@posteo.se>
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
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libgen.h>
#include <signal.h>
#include <limits.h>
#include <ctype.h>

#include <pthread.h>

#include <ftw.h>

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif
#ifdef HAVE_SECURITY_PAM_EXT_H
#include <security/pam_ext.h>
#endif

#include "pwrap_compat.h"

#ifdef HAVE_GCC_THREAD_LOCAL_STORAGE
# define PWRAP_THREAD __thread
#else
# define PWRAP_THREAD
#endif

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

#ifndef SAFE_FREE
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

/*****************
 * LOGGING
 *****************/

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

enum pwrap_dbglvl_e {
	PWRAP_LOG_ERROR = 0,
	PWRAP_LOG_WARN,
	PWRAP_LOG_DEBUG,
	PWRAP_LOG_TRACE
};

static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...) PRINTF_ATTRIBUTE(3, 4);
# define PWRAP_LOG(dbglvl, ...) pwrap_log((dbglvl), __func__, __VA_ARGS__)

static void pwrap_vlog(enum pwrap_dbglvl_e dbglvl,
		       const char *function,
		       const char *format,
		       va_list args) PRINTF_ATTRIBUTE(3, 0);

static void pwrap_vlog(enum pwrap_dbglvl_e dbglvl,
		       const char *function,
		       const char *format,
		       va_list args)
{
	char buffer[1024];
	const char *d;
	unsigned int lvl = 0;
	const char *prefix = "PWRAP";
	const char *progname = getprogname();

	d = getenv("PAM_WRAPPER_DEBUGLEVEL");
	if (d != NULL) {
		lvl = atoi(d);
	}

	if (lvl < dbglvl) {
		return;
	}

	vsnprintf(buffer, sizeof(buffer), format, args);

	switch (dbglvl) {
		case PWRAP_LOG_ERROR:
			prefix = "PWRAP_ERROR";
			break;
		case PWRAP_LOG_WARN:
			prefix = "PWRAP_WARN";
			break;
		case PWRAP_LOG_DEBUG:
			prefix = "PWRAP_DEBUG";
			break;
		case PWRAP_LOG_TRACE:
			prefix = "PWRAP_TRACE";
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
		function,
		buffer);
}

static void pwrap_log(enum pwrap_dbglvl_e dbglvl,
		      const char *function,
		      const char *format, ...)
{
	va_list va;

	va_start(va, format);
	pwrap_vlog(dbglvl, function, format, va);
	va_end(va);
}

/*****************
 * LIBC
 *****************/

#define LIBPAM_NAME "libpam.so.0"

typedef int (*__libpam_pam_start)(const char *service_name,
				  const char *user,
				  const struct pam_conv *pam_conversation,
				  pam_handle_t **pamh);

typedef int (*__libpam_pam_start_confdir)(const char *service_name,
					  const char *user,
					  const struct pam_conv *pam_conversation,
					  const char *confdir,
					  pam_handle_t **pamh);

typedef int (*__libpam_pam_end)(pam_handle_t *pamh, int pam_status);

typedef int (*__libpam_pam_authenticate)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_chauthtok)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_acct_mgmt)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_putenv)(pam_handle_t *pamh, const char *name_value);

typedef const char * (*__libpam_pam_getenv)(pam_handle_t *pamh, const char *name);

typedef char ** (*__libpam_pam_getenvlist)(pam_handle_t *pamh);

typedef int (*__libpam_pam_open_session)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_close_session)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_setcred)(pam_handle_t *pamh, int flags);

typedef int (*__libpam_pam_get_item)(const pam_handle_t *pamh,
				     int item_type,
				     const void **item);

typedef int (*__libpam_pam_set_item)(pam_handle_t *pamh,
				     int item_type,
				     const void *item);

typedef int (*__libpam_pam_get_data)(const pam_handle_t *pamh,
				     const char *module_data_name,
				     const void **data);

typedef int (*__libpam_pam_set_data)(pam_handle_t *pamh,
				     const char *module_data_name,
				     void *data,
				     void (*cleanup)(pam_handle_t *pamh,
						     void *data,
						     int error_status));

typedef int (*__libpam_pam_vprompt)(pam_handle_t *pamh,
				    int style,
				    char **response,
				    const char *fmt,
				    va_list args);

typedef const char * (*__libpam_pam_strerror)(pam_handle_t *pamh,
                                              int errnum);

#ifdef HAVE_PAM_VSYSLOG
typedef void (*__libpam_pam_vsyslog)(const pam_handle_t *pamh,
				     int priority,
				     const char *fmt,
				     va_list args);
#endif

#define PWRAP_SYMBOL_ENTRY(i) \
	union { \
		__libpam_##i f; \
		void *obj; \
	} _libpam_##i

struct pwrap_libpam_symbols {
	PWRAP_SYMBOL_ENTRY(pam_start);
	PWRAP_SYMBOL_ENTRY(pam_start_confdir);
	PWRAP_SYMBOL_ENTRY(pam_end);
	PWRAP_SYMBOL_ENTRY(pam_authenticate);
	PWRAP_SYMBOL_ENTRY(pam_chauthtok);
	PWRAP_SYMBOL_ENTRY(pam_acct_mgmt);
	PWRAP_SYMBOL_ENTRY(pam_putenv);
	PWRAP_SYMBOL_ENTRY(pam_getenv);
	PWRAP_SYMBOL_ENTRY(pam_getenvlist);
	PWRAP_SYMBOL_ENTRY(pam_open_session);
	PWRAP_SYMBOL_ENTRY(pam_close_session);
	PWRAP_SYMBOL_ENTRY(pam_setcred);
	PWRAP_SYMBOL_ENTRY(pam_get_item);
	PWRAP_SYMBOL_ENTRY(pam_set_item);
	PWRAP_SYMBOL_ENTRY(pam_get_data);
	PWRAP_SYMBOL_ENTRY(pam_set_data);
	PWRAP_SYMBOL_ENTRY(pam_vprompt);
	PWRAP_SYMBOL_ENTRY(pam_strerror);
#ifdef HAVE_PAM_VSYSLOG
	PWRAP_SYMBOL_ENTRY(pam_vsyslog);
#endif
};

struct pwrap {
	struct {
		void *handle;
		struct pwrap_libpam_symbols symbols;
	} libpam;

	bool enabled;
	bool initialised;
	char *config_dir;
	char *libpam_so;
};

static struct pwrap pwrap;

/*********************************************************
 * PWRAP PROTOTYPES
 *********************************************************/

bool pam_wrapper_enabled(void);
void pwrap_constructor(void) CONSTRUCTOR_ATTRIBUTE;
void pwrap_destructor(void) DESTRUCTOR_ATTRIBUTE;

/*********************************************************
 * PWRAP LIBC LOADER FUNCTIONS
 *********************************************************/

enum pwrap_lib {
    PWRAP_LIBPAM,
};

static void *pwrap_load_lib_handle(enum pwrap_lib lib)
{
	int flags = RTLD_LAZY;
	void *handle = NULL;

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
	case PWRAP_LIBPAM:
		handle = pwrap.libpam.handle;
		if (handle == NULL) {
			handle = dlopen(pwrap.libpam_so, flags);
			if (handle != NULL) {
				PWRAP_LOG(PWRAP_LOG_DEBUG,
					  "Opened %s\n", pwrap.libpam_so);
				pwrap.libpam.handle = handle;
				break;
			}
		}
		break;
	}

	if (handle == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to dlopen library: %s\n",
			  dlerror());
		exit(-1);
	}

	return handle;
}

static void *_pwrap_bind_symbol(enum pwrap_lib lib, const char *fn_name)
{
	void *handle;
	void *func;

	handle = pwrap_load_lib_handle(lib);

	func = dlsym(handle, fn_name);
	if (func == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to find %s: %s\n",
			  fn_name, dlerror());
		exit(-1);
	}

	return func;
}

#define pwrap_bind_symbol_libpam(sym_name) \
	if (pwrap.libpam.symbols._libpam_##sym_name.obj == NULL) { \
		pwrap.libpam.symbols._libpam_##sym_name.obj = \
			_pwrap_bind_symbol(PWRAP_LIBPAM, #sym_name); \
	} \

/*
 * IMPORTANT
 *
 * Functions especially from libpam need to be loaded individually, you can't
 * load all at once or gdb will segfault at startup. The same applies to
 * valgrind and has probably something todo with with the linker.
 * So we need load each function at the point it is called the first time.
 */
#ifdef HAVE_PAM_START_CONFDIR
static int libpam_pam_start_confdir(const char *service_name,
				    const char *user,
				    const struct pam_conv *pam_conversation,
				    const char *confdir,
				    pam_handle_t **pamh)
{
	pwrap_bind_symbol_libpam(pam_start_confdir);

	return pwrap.libpam.symbols._libpam_pam_start_confdir.f(service_name,
								user,
								pam_conversation,
								confdir,
								pamh);
}
#else
static int libpam_pam_start(const char *service_name,
			    const char *user,
			    const struct pam_conv *pam_conversation,
			    pam_handle_t **pamh)
{
	pwrap_bind_symbol_libpam(pam_start);

	return pwrap.libpam.symbols._libpam_pam_start.f(service_name,
							user,
							pam_conversation,
							pamh);
}

#endif

static int libpam_pam_end(pam_handle_t *pamh, int pam_status)
{
	pwrap_bind_symbol_libpam(pam_end);

	return pwrap.libpam.symbols._libpam_pam_end.f(pamh, pam_status);
}

static int libpam_pam_authenticate(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_authenticate);

	return pwrap.libpam.symbols._libpam_pam_authenticate.f(pamh, flags);
}

static int libpam_pam_chauthtok(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_chauthtok);

	return pwrap.libpam.symbols._libpam_pam_chauthtok.f(pamh, flags);
}

static int libpam_pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_acct_mgmt);

	return pwrap.libpam.symbols._libpam_pam_acct_mgmt.f(pamh, flags);
}

static int libpam_pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	pwrap_bind_symbol_libpam(pam_putenv);

	return pwrap.libpam.symbols._libpam_pam_putenv.f(pamh, name_value);
}

static const char *libpam_pam_getenv(pam_handle_t *pamh, const char *name)
{
	pwrap_bind_symbol_libpam(pam_getenv);

	return pwrap.libpam.symbols._libpam_pam_getenv.f(pamh, name);
}

static char **libpam_pam_getenvlist(pam_handle_t *pamh)
{
	pwrap_bind_symbol_libpam(pam_getenvlist);

	return pwrap.libpam.symbols._libpam_pam_getenvlist.f(pamh);
}

static int libpam_pam_open_session(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_open_session);

	return pwrap.libpam.symbols._libpam_pam_open_session.f(pamh, flags);
}

static int libpam_pam_close_session(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_close_session);

	return pwrap.libpam.symbols._libpam_pam_close_session.f(pamh, flags);
}

static int libpam_pam_setcred(pam_handle_t *pamh, int flags)
{
	pwrap_bind_symbol_libpam(pam_setcred);

	return pwrap.libpam.symbols._libpam_pam_setcred.f(pamh, flags);
}

static int libpam_pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	pwrap_bind_symbol_libpam(pam_get_item);

	return pwrap.libpam.symbols._libpam_pam_get_item.f(pamh, item_type, item);
}

static int libpam_pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	pwrap_bind_symbol_libpam(pam_set_item);

	return pwrap.libpam.symbols._libpam_pam_set_item.f(pamh, item_type, item);
}

static int libpam_pam_get_data(const pam_handle_t *pamh,
			       const char *module_data_name,
			       const void **data)
{
	pwrap_bind_symbol_libpam(pam_get_data);

	return pwrap.libpam.symbols._libpam_pam_get_data.f(pamh,
							   module_data_name,
							   data);
}

static int libpam_pam_set_data(pam_handle_t *pamh,
			       const char *module_data_name,
			       void *data,
			       void (*cleanup)(pam_handle_t *pamh,
					       void *data,
					       int error_status))
{
	pwrap_bind_symbol_libpam(pam_set_data);

	return pwrap.libpam.symbols._libpam_pam_set_data.f(pamh,
							   module_data_name,
							   data,
							   cleanup);
}

static int libpam_pam_vprompt(pam_handle_t *pamh,
			      int style,
			      char **response,
			      const char *fmt,
			      va_list args)
{
	pwrap_bind_symbol_libpam(pam_vprompt);

	return pwrap.libpam.symbols._libpam_pam_vprompt.f(pamh,
							  style,
							  response,
							  fmt,
							  args);
}

#ifdef HAVE_PAM_STRERROR_CONST
static const char *libpam_pam_strerror(const pam_handle_t *pamh, int errnum)
#else
static const char *libpam_pam_strerror(pam_handle_t *pamh, int errnum)
#endif
{
	pwrap_bind_symbol_libpam(pam_strerror);

	return pwrap.libpam.symbols._libpam_pam_strerror.f(discard_const_p(pam_handle_t, pamh), errnum);
}

#ifdef HAVE_PAM_VSYSLOG
static void libpam_pam_vsyslog(const pam_handle_t *pamh,
			       int priority,
			       const char *fmt,
			       va_list args)
{
	pwrap_bind_symbol_libpam(pam_vsyslog);

	pwrap.libpam.symbols._libpam_pam_vsyslog.f(pamh,
						   priority,
						   fmt,
						   args);
}
#endif /* HAVE_PAM_VSYSLOG */

/*********************************************************
 * PWRAP INIT
 *********************************************************/

#define BUFFER_SIZE 32768

/* copy file from src to dst, overwrites dst */
static int p_copy(const char *src, const char *dst, mode_t mode)
{
	int srcfd = -1;
	int dstfd = -1;
	int rc = -1;
	ssize_t bread, bwritten;
	struct stat sb;
	char buf[BUFFER_SIZE];
	int cmp;

	cmp = strcmp(src, dst);
	if (cmp == 0) {
		return -1;
	}

	srcfd = open(src, O_RDONLY, 0);
	if (srcfd < 0) {
		return -1;
	}

	if (mode == 0) {
		rc = fstat(srcfd, &sb);
		if (rc != 0) {
			rc = -1;
			goto out;
		}
		mode = sb.st_mode;
	}

	dstfd = open(dst, O_CREAT|O_WRONLY|O_TRUNC, mode);
	if (dstfd < 0) {
		rc = -1;
		goto out;
	}

	for (;;) {
		bread = read(srcfd, buf, BUFFER_SIZE);
		if (bread == 0) {
			/* done */
			break;
		} else if (bread < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		bwritten = write(dstfd, buf, bread);
		if (bwritten < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		if (bread != bwritten) {
			errno = EFAULT;
			rc = -1;
			goto out;
		}
	}

	rc = 0;
out:
	if (srcfd != -1) {
		close(srcfd);
	}
	if (dstfd != -1) {
		close(dstfd);
	}
	if (rc < 0) {
		unlink(dst);
	}

	return rc;
}

/* Do not pass any flag if not defined */
#ifndef FTW_ACTIONRETVAL
#define FTW_ACTIONRETVAL 0
#endif

/* Action return values */
#ifndef FTW_STOP
#define FTW_STOP -1
#endif

#ifndef FTW_CONTINUE
#define FTW_CONTINUE 0
#endif

#ifndef FTW_SKIP_SUBTREE
#define FTW_SKIP_SUBTREE 0
#endif

static int copy_ftw(const char *fpath,
		    const struct stat *sb,
		    int typeflag,
		    struct FTW *ftwbuf)
{
	int rc;
	char buf[BUFFER_SIZE];

	switch (typeflag) {
	case FTW_D:
	case FTW_DNR:
		/* We want to copy the directories from this directory */
		if (ftwbuf->level == 0) {
			return FTW_CONTINUE;
		}
		return FTW_SKIP_SUBTREE;
	case FTW_F:
		break;
	default:
		return FTW_CONTINUE;
	}

	rc = snprintf(buf, BUFFER_SIZE, "%s/%s", pwrap.config_dir, fpath + ftwbuf->base);
	if (rc >= BUFFER_SIZE) {
		return FTW_STOP;
	}

	PWRAP_LOG(PWRAP_LOG_TRACE, "Copying %s", fpath);
	rc = p_copy(fpath, buf, sb->st_mode);
	if (rc != 0) {
		return FTW_STOP;
	}

	return FTW_CONTINUE;
}

static int copy_confdir(const char *src)
{
	int rc;

	PWRAP_LOG(PWRAP_LOG_DEBUG,
		  "Copy config files from %s to %s",
		  src,
		  pwrap.config_dir);
	rc = nftw(src, copy_ftw, 1, FTW_ACTIONRETVAL);
	if (rc != 0) {
		return -1;
	}

	return 0;
}

static int p_rmdirs(const char *path);

static void pwrap_clean_stale_dirs(const char *dir)
{
	size_t len = strlen(dir);
	char pidfile[len + 5];
	ssize_t rc;
	char buf[8] = {0};
	long int tmp;
	pid_t pid;
	int fd;

	snprintf(pidfile,
		 sizeof(pidfile),
		 "%s/pid",
		 dir);

	/* read the pidfile */
	fd = open(pidfile, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pidfile %s missing, nothing to do\n",
				  pidfile);
		} else {
			PWRAP_LOG(PWRAP_LOG_ERROR,
				  "Failed to open pidfile %s - error: %s",
				  pidfile, strerror(errno));
		}
		return;
	}

	rc = read(fd, buf, sizeof(buf));
	close(fd);
	if (rc < 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to read pidfile %s - error: %s",
			  pidfile, strerror(errno));
		return;
	}

	buf[sizeof(buf) - 1] = '\0';

	tmp = strtol(buf, NULL, 10);
	if (tmp == 0 || tmp > 0xFFFF || errno == ERANGE) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to parse pid, buf=%s",
			  buf);
		return;
	}

	pid = (pid_t)(tmp & 0xFFFF);

	rc = kill(pid, 0);
	if (rc == -1) {
		PWRAP_LOG(PWRAP_LOG_TRACE,
			  "Remove stale pam_wrapper dir: %s",
			  dir);
		p_rmdirs(dir);
	}

	return;
}

#ifdef HAVE_PAM_START_CONFDIR
static void pwrap_init(void)
{
	char tmp_config_dir[] = "/tmp/pam.X";
	size_t len = strlen(tmp_config_dir);
	const char *env;
	struct stat sb;
	int rc;
	unsigned i;
	ssize_t ret;
	FILE *pidfile;
	char pidfile_path[1024] = { 0 };
	char letter;

	if (!pam_wrapper_enabled()) {
		return;
	}

	if (pwrap.initialised) {
		return;
	}

	/*
	 * The name is selected to match/replace /etc/pam.d
	 * We start from a random alphanum trying letters until
	 * an available directory is found.
	 */
	letter = 48 + (getpid() % 70);
	for (i = 0; i < 127; i++) {
		if (isalpha(letter) || isdigit(letter)) {
			tmp_config_dir[len - 1] = letter;

			rc = lstat(tmp_config_dir, &sb);
			if (rc == 0) {
				PWRAP_LOG(PWRAP_LOG_TRACE,
					  "Check if pam_wrapper dir %s is a "
					  "stale directory",
					  tmp_config_dir);
				pwrap_clean_stale_dirs(tmp_config_dir);
			} else if (rc < 0) {
				if (errno != ENOENT) {
					continue;
				}
				break; /* found */
			}
		}

		letter++;
		letter %= 127;
	}

	if (i == 127) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to find a possible path to create "
			  "pam_wrapper config dir: %s",
			  tmp_config_dir);
		exit(1);
	}

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Initialize pam_wrapper");

	pwrap.config_dir = strdup(tmp_config_dir);
	if (pwrap.config_dir == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "No memory");
		exit(1);
	}
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pam_wrapper config dir: %s",
		  tmp_config_dir);

	rc = mkdir(pwrap.config_dir, 0755);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to create pam_wrapper config dir: %s - %s",
			  tmp_config_dir, strerror(errno));
	}

	/* Create file with the PID of the the process */
	ret = snprintf(pidfile_path, sizeof(pidfile_path),
		       "%s/pid", pwrap.config_dir);
	if (ret < 0) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	pidfile = fopen(pidfile_path, "w");
	if (pidfile == NULL) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	rc = fprintf(pidfile, "%d", getpid());
	fclose(pidfile);
	if (rc <= 0) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	pwrap.libpam_so = strdup(PAM_LIBRARY);
	if (pwrap.libpam_so == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No memory");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	PWRAP_LOG(PWRAP_LOG_TRACE, "Using libpam path: %s", pwrap.libpam_so);

	pwrap.initialised = true;

	env = getenv("PAM_WRAPPER_SERVICE_DIR");
	if (env == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No config file");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	rc = copy_confdir(env);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to copy config files");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	setenv("PAM_WRAPPER_RUNTIME_DIR", pwrap.config_dir, 1);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Successfully initialized pam_wrapper");
}

#else /* HAVE_PAM_START_CONFDIR */

#ifdef HAVE_PAM_MODUTIL_SEARCH_KEY
/*
 * This is needed to workaround Tumbleweed which packages a libpam git version.
 */
static int pso_copy(const char *src, const char *dst, const char *pdir, mode_t mode)
{
#define PSO_COPY_READ_SIZE 16
	int srcfd = -1;
	int dstfd = -1;
	int rc = -1;
	ssize_t bread, bwritten;
	struct stat sb;
	char buf[PSO_COPY_READ_SIZE + 1];
	size_t pso_copy_read_size = PSO_COPY_READ_SIZE;
	int cmp;
	size_t to_read;
	bool found_slash;

	cmp = strcmp(src, dst);
	if (cmp == 0) {
		return -1;
	}

	srcfd = open(src, O_RDONLY, 0);
	if (srcfd < 0) {
		return -1;
	}

	if (mode == 0) {
		rc = fstat(srcfd, &sb);
		if (rc != 0) {
			rc = -1;
			goto out;
		}
		mode = sb.st_mode;
	}

	dstfd = open(dst, O_CREAT|O_WRONLY|O_TRUNC, mode);
	if (dstfd < 0) {
		rc = -1;
		goto out;
	}

	found_slash = false;
	to_read = 1;

	for (;;) {
		bread = read(srcfd, buf, to_read);
		if (bread == 0) {
			/* done */
			break;
		} else if (bread < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		to_read = 1;
		if (!found_slash && buf[0] == '/') {
			found_slash = true;
			to_read = pso_copy_read_size;
		}

		if (found_slash && bread == PSO_COPY_READ_SIZE) {
			cmp = memcmp(buf, "usr/etc/pam.d/%s", 16);
			if (cmp == 0) {
				char tmp[16] = {0};

				snprintf(tmp, sizeof(tmp), "%s/%%s", pdir + 1);

				memcpy(buf, tmp, 12);
				memset(&buf[12], '\0', 4);

				/*
				 * If we found this string, we need to reduce
				 * the read size to not miss, the next one.
				 */
				pso_copy_read_size = 13;
			} else {
				cmp = memcmp(buf, "usr/etc/pam.d", 13);
				if (cmp == 0) {
					memcpy(buf, pdir + 1, 9);
					memset(&buf[9], '\0', 4);
				} else {
					cmp = memcmp(buf, "etc/pam.d", 9);
					if (cmp == 0) {
						memcpy(buf, pdir + 1, 9);
					}
				}
			}
			found_slash = false;
		}

		bwritten = write(dstfd, buf, bread);
		if (bwritten < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		if (bread != bwritten) {
			errno = EFAULT;
			rc = -1;
			goto out;
		}
	}

	rc = 0;
out:
	if (srcfd != -1) {
		close(srcfd);
	}
	if (dstfd != -1) {
		close(dstfd);
	}
	if (rc < 0) {
		unlink(dst);
	}

	return rc;
#undef PSO_COPY_READ_SIZE
}
#else /* HAVE_PAM_MODUTIL_SEARCH_KEY */

static int pso_copy(const char *src, const char *dst, const char *pdir, mode_t mode)
{
#define PSO_COPY_READ_SIZE 9
	int srcfd = -1;
	int dstfd = -1;
	int rc = -1;
	ssize_t bread, bwritten;
	struct stat sb;
	char buf[PSO_COPY_READ_SIZE + 1];
	int cmp;
	size_t to_read;
	bool found_slash;

	cmp = strcmp(src, dst);
	if (cmp == 0) {
		return -1;
	}

	srcfd = open(src, O_RDONLY, 0);
	if (srcfd < 0) {
		return -1;
	}

	if (mode == 0) {
		rc = fstat(srcfd, &sb);
		if (rc != 0) {
			rc = -1;
			goto out;
		}
		mode = sb.st_mode;
	}

	dstfd = open(dst, O_CREAT|O_WRONLY|O_TRUNC, mode);
	if (dstfd < 0) {
		rc = -1;
		goto out;
	}

	found_slash = false;
	to_read = 1;

	for (;;) {
		bread = read(srcfd, buf, to_read);
		if (bread == 0) {
			/* done */
			break;
		} else if (bread < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		to_read = 1;
		if (!found_slash && buf[0] == '/') {
			found_slash = true;
			to_read = PSO_COPY_READ_SIZE;
		}

		if (found_slash && bread == PSO_COPY_READ_SIZE) {
			cmp = memcmp(buf, "etc/pam.d", PSO_COPY_READ_SIZE);
			if (cmp == 0) {
				memcpy(buf, pdir + 1, PSO_COPY_READ_SIZE);
			}
			found_slash = false;
		}

		bwritten = write(dstfd, buf, bread);
		if (bwritten < 0) {
			errno = EIO;
			rc = -1;
			goto out;
		}

		if (bread != bwritten) {
			errno = EFAULT;
			rc = -1;
			goto out;
		}
	}

	rc = 0;
out:
	if (srcfd != -1) {
		close(srcfd);
	}
	if (dstfd != -1) {
		close(dstfd);
	}
	if (rc < 0) {
		unlink(dst);
	}

	return rc;
#undef PSO_COPY_READ_SIZE
}
#endif /* HAVE_PAM_MODUTIL_SEARCH_KEY */

static void pwrap_init(void)
{
	char tmp_config_dir[] = "/tmp/pam.X";
	size_t len = strlen(tmp_config_dir);
	const char *env;
	struct stat sb;
	int rc;
	unsigned i;
	char pam_library[128] = { 0 };
	char libpam_path[1024] = { 0 };
	ssize_t ret;
	FILE *pidfile;
	char pidfile_path[1024] = { 0 };
	char letter;

	if (!pam_wrapper_enabled()) {
		return;
	}

	if (pwrap.initialised) {
		return;
	}

	/*
	 * The name is selected to match/replace /etc/pam.d
	 * We start from a random alphanum trying letters until
	 * an available directory is found.
	 */
	letter = 48 + (getpid() % 70);
	for (i = 0; i < 127; i++) {
		if (isalpha(letter) || isdigit(letter)) {
			tmp_config_dir[len - 1] = letter;

			rc = lstat(tmp_config_dir, &sb);
			if (rc == 0) {
				PWRAP_LOG(PWRAP_LOG_TRACE,
					  "Check if pam_wrapper dir %s is a "
					  "stale directory",
					  tmp_config_dir);
				pwrap_clean_stale_dirs(tmp_config_dir);
			} else if (rc < 0) {
				if (errno != ENOENT) {
					continue;
				}
				break; /* found */
			}
		}

		letter++;
		letter %= 127;
	}

	if (i == 127) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to find a possible path to create "
			  "pam_wrapper config dir: %s",
			  tmp_config_dir);
		exit(1);
	}

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Initialize pam_wrapper");

	pwrap.config_dir = strdup(tmp_config_dir);
	if (pwrap.config_dir == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "No memory");
		exit(1);
	}
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pam_wrapper config dir: %s",
		  tmp_config_dir);

	rc = mkdir(pwrap.config_dir, 0755);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to create pam_wrapper config dir: %s - %s",
			  tmp_config_dir, strerror(errno));
	}

	/* Create file with the PID of the the process */
	ret = snprintf(pidfile_path, sizeof(pidfile_path),
		       "%s/pid", pwrap.config_dir);
	if (ret < 0) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	pidfile = fopen(pidfile_path, "w");
	if (pidfile == NULL) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	rc = fprintf(pidfile, "%d", getpid());
	fclose(pidfile);
	if (rc <= 0) {
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	/* create lib subdirectory */
	snprintf(libpam_path,
		 sizeof(libpam_path),
		 "%s/lib",
		 pwrap.config_dir);

	rc = mkdir(libpam_path, 0755);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to create path for libpam: %s - %s",
			  tmp_config_dir, strerror(errno));
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	snprintf(libpam_path,
		 sizeof(libpam_path),
		 "%s/lib/%s",
		 pwrap.config_dir,
		 LIBPAM_NAME);

	pwrap.libpam_so = strdup(libpam_path);
	if (pwrap.libpam_so == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No memory");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	/* copy libpam.so.0 */
	snprintf(libpam_path, sizeof(libpam_path), "%s", PAM_LIBRARY);
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "PAM path: %s",
		  libpam_path);

	ret = readlink(libpam_path, pam_library, sizeof(pam_library) - 1);
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "PAM library: %s",
		  pam_library);
	if (ret <= 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to read %s link", LIBPAM_NAME);
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	if (pam_library[0] == '/') {
		snprintf(libpam_path,
			 sizeof(libpam_path),
			 "%s",
			 pam_library);
	} else {
		char libpam_path_cp[1024] = {0};
		char *dname = NULL;

		snprintf(libpam_path_cp,
			 sizeof(libpam_path_cp),
			 "%s",
			 libpam_path);

		dname = dirname(libpam_path_cp);
		if (dname == NULL) {
			PWRAP_LOG(PWRAP_LOG_ERROR,
				  "No directory component in %s", libpam_path);
			p_rmdirs(pwrap.config_dir);
			exit(1);
		}

		snprintf(libpam_path,
			 sizeof(libpam_path),
			 "%s/%s",
			 dname,
			 pam_library);
	}
	PWRAP_LOG(PWRAP_LOG_TRACE, "Reconstructed PAM path: %s", libpam_path);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Copy %s to %s", libpam_path, pwrap.libpam_so);
	rc = pso_copy(libpam_path, pwrap.libpam_so, pwrap.config_dir, 0644);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Failed to copy %s - error: %s",
			  LIBPAM_NAME,
			  strerror(errno));
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	PWRAP_LOG(PWRAP_LOG_TRACE, "Using libpam path: %s", pwrap.libpam_so);

	pwrap.initialised = true;

	env = getenv("PAM_WRAPPER_SERVICE_DIR");
	if (env == NULL) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "No config file");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	rc = copy_confdir(env);
	if (rc != 0) {
		PWRAP_LOG(PWRAP_LOG_ERROR, "Failed to copy config files");
		p_rmdirs(pwrap.config_dir);
		exit(1);
	}

	setenv("PAM_WRAPPER_RUNTIME_DIR", pwrap.config_dir, 1);

	PWRAP_LOG(PWRAP_LOG_DEBUG, "Successfully initialized pam_wrapper");
}
#endif /* HAVE_PAM_START_CONFDIR */

bool pam_wrapper_enabled(void)
{
	const char *env;

	pwrap.enabled = false;

	env = getenv("PAM_WRAPPER");
	if (env != NULL && env[0] == '1') {
		pwrap.enabled = true;
	}

	if (pwrap.enabled) {
		pwrap.enabled = false;

		env = getenv("PAM_WRAPPER_SERVICE_DIR");
		if (env != NULL && env[0] != '\0') {
			pwrap.enabled = true;
		}
	}

	return pwrap.enabled;
}

#ifdef HAVE_OPENPAM
static int pwrap_openpam_start(const char *service_name,
			       const char *user,
			       const struct pam_conv *pam_conversation,
			       pam_handle_t **pamh)
{
	int rv;
	char fullpath[1024];

	rv = openpam_set_feature(OPENPAM_RESTRICT_SERVICE_NAME, 0);
	if (rv != PAM_SUCCESS) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Cannot disable OPENPAM_RESTRICT_SERVICE_NAME");
		return rv;
	}

	rv = openpam_set_feature(OPENPAM_RESTRICT_MODULE_NAME, 0);
	if (rv != PAM_SUCCESS) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Cannot disable OPENPAM_RESTRICT_MODULE_NAME");
		return rv;
	}

	rv = openpam_set_feature(OPENPAM_VERIFY_MODULE_FILE, 0);
	if (rv != PAM_SUCCESS) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Cannot disable OPENPAM_VERIFY_MODULE_FILE");
		return rv;
	}

	rv = openpam_set_feature(OPENPAM_VERIFY_POLICY_FILE, 0);
	if (rv != PAM_SUCCESS) {
		PWRAP_LOG(PWRAP_LOG_ERROR,
			  "Cannot disable OPENPAM_VERIFY_POLICY_FILE");
		return rv;
	}

	snprintf(fullpath,
		 sizeof(fullpath),
		 "%s/%s",
		 pwrap.config_dir,
		 service_name);

	return libpam_pam_start(fullpath,
				user,
				pam_conversation,
				pamh);
}
#endif

static int pwrap_pam_start(const char *service_name,
			   const char *user,
			   const struct pam_conv *pam_conversation,
			   pam_handle_t **pamh)
{
	int rc;

	pwrap_init();

	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pam_start service=%s, user=%s",
		  service_name,
		  user);

#if defined(HAVE_OPENPAM)
	rc = pwrap_openpam_start(service_name,
				 user,
				 pam_conversation,
				 pamh);
#elif defined (HAVE_PAM_START_CONFDIR)
	rc = libpam_pam_start_confdir(service_name,
				      user,
				      pam_conversation,
				      pwrap.config_dir,
				      pamh);
#else
	rc = libpam_pam_start(service_name,
			      user,
			      pam_conversation,
			      pamh);
#endif
	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_start rc=%d", rc);

	return rc;
}


int pam_start(const char *service_name,
	      const char *user,
	      const struct pam_conv *pam_conversation,
	      pam_handle_t **pamh)
{
	return pwrap_pam_start(service_name, user, pam_conversation, pamh);
}

static int pwrap_pam_end(pam_handle_t *pamh, int pam_status)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_end status=%d", pam_status);
	return libpam_pam_end(pamh, pam_status);
}


int pam_end(pam_handle_t *pamh, int pam_status)
{
	return pwrap_pam_end(pamh, pam_status);
}

static int pwrap_pam_authenticate(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_authenticate flags=%d", flags);
	return libpam_pam_authenticate(pamh, flags);
}

int pam_authenticate(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_authenticate(pamh, flags);
}

static int pwrap_pam_chauthtok(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_chauthtok flags=%d", flags);
	return libpam_pam_chauthtok(pamh, flags);
}

int pam_chauthtok(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_chauthtok(pamh, flags);
}

static int pwrap_pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_acct_mgmt flags=%d", flags);
	return libpam_pam_acct_mgmt(pamh, flags);
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_acct_mgmt(pamh, flags);
}

static int pwrap_pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_putenv name_value=%s", name_value);
	return libpam_pam_putenv(pamh, name_value);
}

int pam_putenv(pam_handle_t *pamh, const char *name_value)
{
	return pwrap_pam_putenv(pamh, name_value);
}

static const char *pwrap_pam_getenv(pam_handle_t *pamh, const char *name)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_getenv name=%s", name);
	return libpam_pam_getenv(pamh, name);
}

const char *pam_getenv(pam_handle_t *pamh, const char *name)
{
	return pwrap_pam_getenv(pamh, name);
}

static char **pwrap_pam_getenvlist(pam_handle_t *pamh)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_getenvlist called");
	return libpam_pam_getenvlist(pamh);
}

char **pam_getenvlist(pam_handle_t *pamh)
{
	return pwrap_pam_getenvlist(pamh);
}

static int pwrap_pam_open_session(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_open_session flags=%d", flags);
	return libpam_pam_open_session(pamh, flags);
}

int pam_open_session(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_open_session(pamh, flags);
}

static int pwrap_pam_close_session(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_close_session flags=%d", flags);
	return libpam_pam_close_session(pamh, flags);
}

int pam_close_session(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_close_session(pamh, flags);
}

static int pwrap_pam_setcred(pam_handle_t *pamh, int flags)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_setcred flags=%d", flags);
	return libpam_pam_setcred(pamh, flags);
}

int pam_setcred(pam_handle_t *pamh, int flags)
{
	return pwrap_pam_setcred(pamh, flags);
}

static const char *pwrap_get_service(const char *libpam_service)
{
#ifdef HAVE_OPENPAM
	const char *service_name;

	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "internal PAM_SERVICE=%s", libpam_service);
	service_name = strrchr(libpam_service, '/');
	if (service_name != NULL && service_name[0] == '/') {
		service_name++;
	}
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "PAM_SERVICE=%s", service_name);
	return service_name;
#else
	return libpam_service;
#endif
}

static int pwrap_pam_get_item(const pam_handle_t *pamh,
			      int item_type,
			      const void **item)
{
	int rc;
	const char *svc;

	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_get_item called");

	rc = libpam_pam_get_item(pamh, item_type, item);

	if (rc == PAM_SUCCESS) {
		switch(item_type) {
		case PAM_USER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_USER=%s",
				  (const char *)*item);
			break;
		case PAM_SERVICE:
			svc = pwrap_get_service((const char *) *item);

			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_SERVICE=%s",
				  svc);
			*item = svc;
			break;
		case PAM_USER_PROMPT:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_USER_PROMPT=%s",
				  (const char *)*item);
			break;
		case PAM_TTY:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_TTY=%s",
				  (const char *)*item);
			break;
		case PAM_RUSER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_RUSER=%s",
				  (const char *)*item);
			break;
		case PAM_RHOST:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_RHOST=%s",
				  (const char *)*item);
			break;
		case PAM_AUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_AUTHTOK=%s",
				  (const char *)*item);
			break;
		case PAM_OLDAUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_OLDAUTHTOK=%s",
				  (const char *)*item);
			break;
		case PAM_CONV:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item PAM_CONV=%p",
				  (const void *)*item);
			break;
		default:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_get_item item_type=%d item=%p",
				  item_type, (const void *)*item);
			break;
		}
	} else {
		PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_get_item failed rc=%d", rc);
	}

	return rc;
}

int pam_get_item(const pam_handle_t *pamh, int item_type, const void **item)
{
	return pwrap_pam_get_item(pamh, item_type, item);
}

static int pwrap_pam_set_item(pam_handle_t *pamh,
			      int item_type,
			      const void *item)
{
	int rc;

	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_set_item called");

	rc = libpam_pam_set_item(pamh, item_type, item);
	if (rc == PAM_SUCCESS) {
		switch(item_type) {
		case PAM_USER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER=%s",
				  (const char *)item);
			break;
		case PAM_SERVICE:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_SERVICE=%s",
				  (const char *)item);
			break;
		case PAM_USER_PROMPT:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_USER_PROMPT=%s",
				  (const char *)item);
			break;
		case PAM_TTY:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_TTY=%s",
				  (const char *)item);
			break;
		case PAM_RUSER:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RUSER=%s",
				  (const char *)item);
			break;
		case PAM_RHOST:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_RHOST=%s",
				  (const char *)item);
			break;
		case PAM_AUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_AUTHTOK=%s",
				  (const char *)item);
			break;
		case PAM_OLDAUTHTOK:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_OLDAUTHTOK=%s",
				  (const char *)item);
			break;
		case PAM_CONV:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item PAM_CONV=%p",
				  item);
			break;
		default:
			PWRAP_LOG(PWRAP_LOG_TRACE,
				  "pwrap_set_item item_type=%d item=%p",
				  item_type, item);
			break;
		}
	} else {
		PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_set_item failed rc=%d", rc);
	}

	return rc;
}

int pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
	return pwrap_pam_set_item(pamh, item_type, item);
}

static int pwrap_pam_get_data(const pam_handle_t *pamh,
			      const char *module_data_name,
			      const void **data)
{
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pwrap_get_data module_data_name=%s", module_data_name);
	return libpam_pam_get_data(pamh, module_data_name, data);
}

int pam_get_data(const pam_handle_t *pamh,
		 const char *module_data_name,
		 const void **data)
{
	return pwrap_pam_get_data(pamh, module_data_name, data);
}

static int pwrap_pam_set_data(pam_handle_t *pamh,
			      const char *module_data_name,
			      void *data,
			      void (*cleanup)(pam_handle_t *pamh,
					      void *data,
					      int error_status))
{
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "pwrap_set_data module_data_name=%s data=%p",
		  module_data_name, data);
	return libpam_pam_set_data(pamh, module_data_name, data, cleanup);
}

int pam_set_data(pam_handle_t *pamh,
		 const char *module_data_name,
		 void *data,
		 void (*cleanup)(pam_handle_t *pamh,
				 void *data,
				 int error_status))
{
	return pwrap_pam_set_data(pamh, module_data_name, data, cleanup);
}

#ifdef HAVE_PAM_VPROMPT_CONST
static int pwrap_pam_vprompt(const pam_handle_t *pamh,
#else
static int pwrap_pam_vprompt(pam_handle_t *pamh,
#endif
			     int style,
			     char **response,
			     const char *fmt,
			     va_list args)
{
	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_vprompt style=%d", style);
	return libpam_pam_vprompt(discard_const_p(pam_handle_t, pamh),
				  style,
				  response,
				  fmt,
				  args);
}

#ifdef HAVE_PAM_VPROMPT_CONST
int pam_vprompt(const pam_handle_t *pamh,
		int style,
		char **response,
		const char *fmt,
		va_list args)
#else
int pam_vprompt(pam_handle_t *pamh,
		int style,
		char **response,
		const char *fmt,
		va_list args)
#endif
{
	return pwrap_pam_vprompt(discard_const_p(pam_handle_t, pamh),
				 style,
				 response,
				 fmt,
				 args);
}

#ifdef HAVE_PAM_PROMPT_CONST
int pam_prompt(const pam_handle_t *pamh,
	       int style,
	       char **response,
	       const char *fmt, ...)
#else
int pam_prompt(pam_handle_t *pamh,
	       int style,
	       char **response,
	       const char *fmt, ...)
#endif
{
	va_list args;
	int rv;

	va_start(args, fmt);
	rv = pwrap_pam_vprompt(discard_const_p(pam_handle_t, pamh),
			       style,
			       response,
			       fmt,
			       args);
	va_end(args);

	return rv;
}

#ifdef HAVE_PAM_STRERROR_CONST
static const char *pwrap_pam_strerror(const pam_handle_t *pamh, int errnum)
#else
static const char *pwrap_pam_strerror(pam_handle_t *pamh, int errnum)
#endif
{
	const char *str;

	pwrap_init();

	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_strerror errnum=%d", errnum);

	str = libpam_pam_strerror(discard_const_p(pam_handle_t, pamh),
				  errnum);

	PWRAP_LOG(PWRAP_LOG_TRACE, "pam_strerror error=%s", str);

	return str;
}

#ifdef HAVE_PAM_STRERROR_CONST
const char *pam_strerror(const pam_handle_t *pamh, int errnum)
#else
const char *pam_strerror(pam_handle_t *pamh, int errnum)
#endif
{
	return pwrap_pam_strerror(discard_const_p(pam_handle_t, pamh),
				  errnum);
}

#if defined(HAVE_PAM_VSYSLOG) || defined(HAVE_PAM_SYSLOG)
static void pwrap_pam_vsyslog(const pam_handle_t *pamh,
			      int priority,
			      const char *fmt,
			      va_list args) PRINTF_ATTRIBUTE(3, 0);

static void pwrap_pam_vsyslog(const pam_handle_t *pamh,
			      int priority,
			      const char *fmt,
			      va_list args)
{
	const char *d;
	char syslog_str[32] = {0};
	enum pwrap_dbglvl_e dbglvl = PWRAP_LOG_TRACE;

	PWRAP_LOG(PWRAP_LOG_TRACE, "pwrap_pam_vsyslog called");

#ifdef HAVE_PAM_VSYSLOG
	d = getenv("PAM_WRAPPER_USE_SYSLOG");
	if (d != NULL && d[0] == '1') {
		libpam_pam_vsyslog(pamh, priority, fmt, args);
		return;
	}
#endif /* HAVE_PAM_VSYSLOG */

	switch(priority) {
	case 0: /* LOG_EMERG */
	case 1: /* LOG_ALERT */
	case 2: /* LOG_CRIT */
	case 3: /* LOG_ERR */
		dbglvl = PWRAP_LOG_ERROR;
		break;
	case 4: /* LOG_WARN */
		dbglvl = PWRAP_LOG_WARN;
		break;
	case 5: /* LOG_NOTICE */
	case 6: /* LOG_INFO */
	case 7: /* LOG_DEBUG */
		dbglvl = PWRAP_LOG_DEBUG;
		break;
	default:
		dbglvl = PWRAP_LOG_TRACE;
		break;
	}

	snprintf(syslog_str, sizeof(syslog_str), "SYSLOG(%d)", priority);

	pwrap_vlog(dbglvl, syslog_str, fmt, args);
}
#endif /* defined(HAVE_PAM_VSYSLOG) || defined(HAVE_PAM_SYSLOG) */

#ifdef HAVE_PAM_VSYSLOG
void pam_vsyslog(const pam_handle_t *pamh,
		 int priority,
		 const char *fmt,
		 va_list args)
{
	pwrap_pam_vsyslog(pamh, priority, fmt, args);
}
#endif

#ifdef HAVE_PAM_SYSLOG
void pam_syslog(const pam_handle_t *pamh,
	        int priority,
	        const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	pwrap_pam_vsyslog(pamh, priority, fmt, args);
	va_end(args);
}
#endif

/* This might be called by pam_end() running with sshd */
int audit_open(void);
int audit_open(void)
{
	/*
	 * Tell the application that the kernel doesn't
	 * have audit compiled in.
	 */
	errno = EPROTONOSUPPORT;
	return -1;
}

/* Disable BSD auditing */
int cannot_audit(int x);
int cannot_audit(int x)
{
	(void) x;

	return 1;
}

/****************************
 * CONSTRUCTOR
 ***************************/

/*
 * Handler executed before fork(2) processing starts.
 */
static void pwrap_thread_prepare(void)
{
}

/*
 * Handler that is executed in the parent process after fork(2) processing
 * completes.
 */
static void pwrap_thread_parent(void)
{
}

/*
 * Handler that is executed in the child process after fork(2) processing
 * completes.
 */
static void pwrap_thread_child(void)
{
	pwrap.initialised = false;
}

void pwrap_constructor(void)
{
	/*
	* If we hold a lock and the application forks, then the child
	* is not able to unlock the mutex and we are in a deadlock.
	* This should prevent such deadlocks.
	*/
	pthread_atfork(&pwrap_thread_prepare,
		       &pwrap_thread_parent,
		       &pwrap_thread_child);

	/*
	 * Here is safe place to call pwrap_init() and initialize data
	 * for main process.
	 */
	pwrap_init();
}

/****************************
 * DESTRUCTOR
 ***************************/

static int p_rmdirs_at(const char *path, int parent_fd)
{
	DIR *d = NULL;
	struct dirent *dp = NULL;
	struct stat sb;
	char fd_str[64] = { 0 };
	int path_fd;
	int rc;

	switch(parent_fd) {
	case AT_FDCWD:
		snprintf(fd_str, sizeof(fd_str), "CWD");
		break;
	default:
		snprintf(fd_str, sizeof(fd_str), "fd=%d", parent_fd);
		break;
	}

	/* If path is absolute, parent_fd is ignored. */
	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "p_rmdirs_at removing %s at %s\n", path, fd_str);

	path_fd = openat(parent_fd,
			 path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (path_fd == -1) {
		return -1;
	}

	d = fdopendir(path_fd);
	if (d == NULL) {
		close(path_fd);
		return -1;
	}

	while ((dp = readdir(d)) != NULL) {
		/* skip '.' and '..' */
		if (dp->d_name[0] == '.' &&
			(dp->d_name[1] == '\0' ||
			(dp->d_name[1] == '.' && dp->d_name[2] == '\0'))) {
			continue;
		}

		rc = fstatat(path_fd, dp->d_name,
			     &sb, AT_SYMLINK_NOFOLLOW);
		if (rc != 0) {
			continue;
		}

		if (S_ISDIR(sb.st_mode)) {
			rc = p_rmdirs_at(dp->d_name, path_fd);
		} else {
			rc = unlinkat(path_fd, dp->d_name, 0);
		}
		if (rc != 0) {
			continue;
		}
	}
	closedir(d);

	rc = unlinkat(parent_fd, path, AT_REMOVEDIR);
	if (rc != 0) {
		rc = errno;
		PWRAP_LOG(PWRAP_LOG_TRACE,
			  "cannot unlink %s error %d\n", path, rc);
		return -1;
	}

	return 0;
}

static int p_rmdirs(const char *path)
{
	/*
	 * If path is absolute, p_rmdirs_at ignores parent_fd.
	 * If it's relative, start from cwd.
	 */
	return p_rmdirs_at(path, AT_FDCWD);
}

/*
 * This function is called when the library is unloaded and makes sure that
 * resources are freed.
 */
void pwrap_destructor(void)
{
	const char *env;

	PWRAP_LOG(PWRAP_LOG_TRACE, "entering pwrap_destructor");

	if (pwrap.libpam.handle != NULL) {
		dlclose(pwrap.libpam.handle);
	}

	if (pwrap.libpam_so != NULL) {
		free(pwrap.libpam_so);
		pwrap.libpam_so = NULL;
	}

	if (!pwrap.initialised) {
		return;
	}
	pwrap.initialised = false;

	PWRAP_LOG(PWRAP_LOG_TRACE,
		  "destructor called for pam_wrapper dir %s",
		  pwrap.config_dir);
	env = getenv("PAM_WRAPPER_KEEP_DIR");
	if (env == NULL || env[0] != '1') {
		p_rmdirs(pwrap.config_dir);
	}

	if (pwrap.config_dir != NULL) {
		free(pwrap.config_dir);
		pwrap.config_dir = NULL;
	}
}
