/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Elrond               2002
   Copyright (C) Simo Sorce           2002

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include <talloc.h>
#include "system/filesys.h"
#include "system/syslog.h"
#include "system/locale.h"
#include "time_basic.h"
#include "close_low_fd.h"
#include "memory.h"
#include "util_strlist.h" /* LIST_SEP */
#include "blocking.h"
#include "debug.h"
#include <assert.h>

/* define what facility to use for syslog */
#ifndef SYSLOG_FACILITY
#define SYSLOG_FACILITY LOG_DAEMON
#endif

/* -------------------------------------------------------------------------- **
 * Defines...
 */

/*
 * format_bufr[FORMAT_BUFR_SIZE - 1] should always be reserved
 * for a terminating null byte.
 */
#define FORMAT_BUFR_SIZE 4096

/* -------------------------------------------------------------------------- **
 * This module implements Samba's debugging utility.
 *
 * The syntax of a debugging log file is represented as:
 *
 *  <debugfile> :== { <debugmsg> }
 *
 *  <debugmsg>  :== <debughdr> '\n' <debugtext>
 *
 *  <debughdr>  :== '[' TIME ',' LEVEL ']' [ [FILENAME ':'] [FUNCTION '()'] ]
 *
 *  <debugtext> :== { <debugline> }
 *
 *  <debugline> :== TEXT '\n'
 *
 * TEXT     is a string of characters excluding the newline character.
 * LEVEL    is the DEBUG level of the message (an integer in the range 0..10).
 * TIME     is a timestamp.
 * FILENAME is the name of the file from which the debug message was generated.
 * FUNCTION is the function from which the debug message was generated.
 *
 * Basically, what that all means is:
 *
 * - A debugging log file is made up of debug messages.
 *
 * - Each debug message is made up of a header and text.  The header is
 *   separated from the text by a newline.
 *
 * - The header begins with the timestamp and debug level of the message
 *   enclosed in brackets.  The filename and function from which the
 *   message was generated may follow.  The filename is terminated by a
 *   colon, and the function name is terminated by parenthesis.
 *
 * - The message text is made up of zero or more lines, each terminated by
 *   a newline.
 */

/* state variables for the debug system */
static struct {
	bool initialized;
	enum debug_logtype logtype; /* The type of logging we are doing: eg stdout, file, stderr */
	char prog_name[255];
	bool reopening_logs;
	bool schedule_reopen_logs;

	struct debug_settings settings;
	debug_callback_fn callback;
	void *callback_private;
} state = {
	.settings = {
		.timestamp_logs = true
	},
};

struct debug_class {
	/*
	 * The debug loglevel of the class.
	 */
	int loglevel;

	/*
	 * An optional class specific logfile, may be NULL in which case the
	 * "global" logfile is used and fd is -1.
	 */
	char *logfile;
	int fd;
	/* inode number of the logfile to detect logfile rotation */
	ino_t ino;
};

static const char *default_classname_table[] = {
	[DBGC_ALL] =			"all",
	[DBGC_TDB] =			"tdb",
	[DBGC_PRINTDRIVERS] =		"printdrivers",
	[DBGC_LANMAN] =			"lanman",
	[DBGC_SMB] =			"smb",
	[DBGC_RPC_PARSE] =		"rpc_parse",
	[DBGC_RPC_SRV] =		"rpc_srv",
	[DBGC_RPC_CLI] =		"rpc_cli",
	[DBGC_PASSDB] =			"passdb",
	[DBGC_SAM] =			"sam",
	[DBGC_AUTH] =			"auth",
	[DBGC_WINBIND] =		"winbind",
	[DBGC_VFS] =			"vfs",
	[DBGC_IDMAP] =			"idmap",
	[DBGC_QUOTA] =			"quota",
	[DBGC_ACLS] =			"acls",
	[DBGC_LOCKING] =		"locking",
	[DBGC_MSDFS] =			"msdfs",
	[DBGC_DMAPI] =			"dmapi",
	[DBGC_REGISTRY] =		"registry",
	[DBGC_SCAVENGER] =		"scavenger",
	[DBGC_DNS] =			"dns",
	[DBGC_LDB] =			"ldb",
	[DBGC_TEVENT] =			"tevent",
	[DBGC_AUTH_AUDIT] =		"auth_audit",
	[DBGC_AUTH_AUDIT_JSON] =	"auth_json_audit",
	[DBGC_KERBEROS] =       	"kerberos",
	[DBGC_DRS_REPL] =       	"drs_repl",
	[DBGC_SMB2] =           	"smb2",
	[DBGC_SMB2_CREDITS] =   	"smb2_credits",
	[DBGC_DSDB_AUDIT] =		"dsdb_audit",
	[DBGC_DSDB_AUDIT_JSON] =	"dsdb_json_audit",
	[DBGC_DSDB_PWD_AUDIT]  =	"dsdb_password_audit",
	[DBGC_DSDB_PWD_AUDIT_JSON] =	"dsdb_password_json_audit",
	[DBGC_DSDB_TXN_AUDIT]  =	"dsdb_transaction_audit",
	[DBGC_DSDB_TXN_AUDIT_JSON] =	"dsdb_transaction_json_audit",
	[DBGC_DSDB_GROUP_AUDIT] =	"dsdb_group_audit",
	[DBGC_DSDB_GROUP_AUDIT_JSON] =	"dsdb_group_json_audit",
};

/*
 * This is to allow reading of dbgc_config before the debug
 * system has been initialized.
 */
static struct debug_class debug_class_list_initial[ARRAY_SIZE(default_classname_table)] = {
	[DBGC_ALL] = (struct debug_class) { .fd = 2 },
};

static size_t debug_num_classes = 0;
static struct debug_class *dbgc_config = debug_class_list_initial;

static int current_msg_level = 0;
static int current_msg_class = 0;

#if defined(WITH_SYSLOG) || defined(HAVE_LIBSYSTEMD_JOURNAL) || defined(HAVE_LIBSYSTEMD)
static int debug_level_to_priority(int level)
{
	/*
	 * map debug levels to syslog() priorities
	 */
	static const int priority_map[] = {
		LOG_ERR,     /* 0 */
		LOG_WARNING, /* 1 */
		LOG_NOTICE,  /* 2 */
		LOG_NOTICE,  /* 3 */
		LOG_NOTICE,  /* 4 */
		LOG_NOTICE,  /* 5 */
		LOG_INFO,    /* 6 */
		LOG_INFO,    /* 7 */
		LOG_INFO,    /* 8 */
		LOG_INFO,    /* 9 */
	};
	int priority;

	if (level < 0 || (size_t)level >= ARRAY_SIZE(priority_map))
		priority = LOG_DEBUG;
	else
		priority = priority_map[level];

	return priority;
}
#endif

/* -------------------------------------------------------------------------- **
 * Debug backends. When logging to DEBUG_FILE, send the log entries to
 * all active backends.
 */

static void debug_file_log(int msg_level,
			   const char *msg, const char *msg_no_nl)
{
	ssize_t ret;
	int fd;

	check_log_size();

	if (dbgc_config[current_msg_class].fd != -1) {
		fd = dbgc_config[current_msg_class].fd;
	} else {
		fd = dbgc_config[DBGC_ALL].fd;
	}

	do {
		ret = write(fd, msg, strlen(msg));
	} while (ret == -1 && errno == EINTR);
}

#ifdef WITH_SYSLOG
static void debug_syslog_reload(bool enabled, bool previously_enabled,
				const char *prog_name, char *option)
{
	if (enabled && !previously_enabled) {
		const char *ident = NULL;
		if ((prog_name != NULL) && (prog_name[0] != '\0')) {
			ident = prog_name;
		}
#ifdef LOG_DAEMON
		openlog(ident, LOG_PID, SYSLOG_FACILITY);
#else
		/* for old systems that have no facility codes. */
		openlog(ident, LOG_PID);
#endif
		return;
	}

	if (!enabled && previously_enabled) {
		closelog();
	}
}

static void debug_syslog_log(int msg_level,
			     const char *msg, const char *msg_no_nl)
{
	int priority;

	priority = debug_level_to_priority(msg_level);

	/*
	 * Specify the facility to interoperate with other syslog
	 * callers (vfs_full_audit for example).
	 */
	priority |= SYSLOG_FACILITY;

	syslog(priority, "%s", msg);
}
#endif /* WITH_SYSLOG */

#if defined(HAVE_LIBSYSTEMD_JOURNAL) || defined(HAVE_LIBSYSTEMD)
#include <systemd/sd-journal.h>
static void debug_systemd_log(int msg_level,
			      const char *msg, const char *msg_no_nl)
{
	sd_journal_send("MESSAGE=%s", msg_no_nl,
			"PRIORITY=%d", debug_level_to_priority(msg_level),
			"LEVEL=%d", msg_level,
			NULL);
}
#endif

#ifdef HAVE_LTTNG_TRACEF
#include <lttng/tracef.h>
static void debug_lttng_log(int msg_level,
			    const char *msg, const char *msg_no_nl)
{
	tracef(msg_no_nl);
}
#endif /* WITH_LTTNG_TRACEF */

#ifdef HAVE_GPFS
#include "gpfswrap.h"
static void debug_gpfs_reload(bool enabled, bool previously_enabled,
			      const char *prog_name, char *option)
{
	gpfswrap_init();

	if (enabled && !previously_enabled) {
		gpfswrap_init_trace();
		return;
	}

	if (!enabled && previously_enabled) {
		gpfswrap_fini_trace();
		return;
	}

	if (enabled) {
		/*
		 * Trigger GPFS library to adjust state if necessary.
		 */
		gpfswrap_query_trace();
	}
}

static void debug_gpfs_log(int msg_level,
			   const char *msg, const char *msg_no_nl)
{
	gpfswrap_add_trace(msg_level, msg_no_nl);
}
#endif /* HAVE_GPFS */

#define DEBUG_RINGBUF_SIZE (1024 * 1024)
#define DEBUG_RINGBUF_SIZE_OPT "size="

static char *debug_ringbuf;
static size_t debug_ringbuf_size;
static size_t debug_ringbuf_ofs;

/* We ensure in debug_ringbuf_log() that this is always \0 terminated */
char *debug_get_ringbuf(void)
{
	return debug_ringbuf;
}

/* Return the size of the ringbuf (including a \0 terminator) */
size_t debug_get_ringbuf_size(void)
{
	return debug_ringbuf_size;
}

static void debug_ringbuf_reload(bool enabled, bool previously_enabled,
				 const char *prog_name, char *option)
{
	bool cmp;
	size_t optlen = strlen(DEBUG_RINGBUF_SIZE_OPT);

	debug_ringbuf_size = DEBUG_RINGBUF_SIZE;
	debug_ringbuf_ofs = 0;

	SAFE_FREE(debug_ringbuf);

	if (!enabled) {
		return;
	}

	if (option != NULL) {
		cmp = strncmp(option, DEBUG_RINGBUF_SIZE_OPT, optlen);
		if (cmp == 0) {
			debug_ringbuf_size = (size_t)strtoull(
				option + optlen, NULL, 10);
		}
	}

	debug_ringbuf = calloc(debug_ringbuf_size, sizeof(char));
	if (debug_ringbuf == NULL) {
		return;
	}
}

static void debug_ringbuf_log(int msg_level,
			      const char *msg,
			      const char *msg_no_nl)
{
	size_t msglen = strlen(msg);
	size_t allowed_size;

	if (debug_ringbuf == NULL) {
		return;
	}

	/* Ensure the buffer is always \0 terminated */
	allowed_size = debug_ringbuf_size - 1;

	if (msglen > allowed_size) {
		return;
	}

	if ((debug_ringbuf_ofs + msglen) < debug_ringbuf_ofs) {
		return;
	}

	if ((debug_ringbuf_ofs + msglen) > allowed_size) {
		debug_ringbuf_ofs = 0;
	}

	memcpy(debug_ringbuf + debug_ringbuf_ofs, msg, msglen);
	debug_ringbuf_ofs += msglen;
}

static struct debug_backend {
	const char *name;
	int log_level;
	int new_log_level;
	void (*reload)(bool enabled, bool prev_enabled,
		       const char *prog_name, char *option);
	void (*log)(int msg_level, const char *msg, const char *msg_no_nl);
	char *option;
} debug_backends[] = {
	{
		.name = "file",
		.log = debug_file_log,
	},
#ifdef WITH_SYSLOG
	{
		.name = "syslog",
		.reload = debug_syslog_reload,
		.log = debug_syslog_log,
	},
#endif

#if defined(HAVE_LIBSYSTEMD_JOURNAL) || defined(HAVE_LIBSYSTEMD)
	{
		.name = "systemd",
		.log = debug_systemd_log,
	},
#endif

#ifdef HAVE_LTTNG_TRACEF
	{
		.name = "lttng",
		.log = debug_lttng_log,
	},
#endif

#ifdef HAVE_GPFS
	{
		.name = "gpfs",
		.reload = debug_gpfs_reload,
		.log = debug_gpfs_log,
	},
#endif
	{
		.name = "ringbuf",
		.log = debug_ringbuf_log,
		.reload = debug_ringbuf_reload,
	},
};

static struct debug_backend *debug_find_backend(const char *name)
{
	unsigned i;

	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		if (strcmp(name, debug_backends[i].name) == 0) {
			return &debug_backends[i];
		}
	}

	return NULL;
}

/*
 * parse "backend[:option][@loglevel]
 */
static void debug_backend_parse_token(char *tok)
{
	char *backend_name_option, *backend_name,*backend_level, *saveptr;
	char *backend_option;
	struct debug_backend *b;

	/*
	 * First parse into backend[:option] and loglevel
	 */
	backend_name_option = strtok_r(tok, "@\0", &saveptr);
	if (backend_name_option == NULL) {
		return;
	}

	backend_level = strtok_r(NULL, "\0", &saveptr);

	/*
	 * Now parse backend[:option]
	 */
	backend_name = strtok_r(backend_name_option, ":\0", &saveptr);
	if (backend_name == NULL) {
		return;
	}

	backend_option = strtok_r(NULL, "\0", &saveptr);

	/*
	 * Find and update backend
	 */
	b = debug_find_backend(backend_name);
	if (b == NULL) {
		return;
	}

	if (backend_level == NULL) {
		b->new_log_level = MAX_DEBUG_LEVEL;
	} else {
		b->new_log_level = atoi(backend_level);
	}

	if (backend_option != NULL) {
		b->option = strdup(backend_option);
		if (b->option == NULL) {
			return;
		}
	}
}

/*
 * parse "backend1[:option1][@loglevel1] backend2[option2][@loglevel2] ... "
 * and enable/disable backends accordingly
 */
static void debug_set_backends(const char *param)
{
	size_t str_len = strlen(param);
	char str[str_len+1];
	char *tok, *saveptr;
	unsigned i;

	/*
	 * initialize new_log_level to detect backends that have been
	 * disabled
	 */
	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		SAFE_FREE(debug_backends[i].option);
		debug_backends[i].new_log_level = -1;
	}

	memcpy(str, param, str_len + 1);

	tok = strtok_r(str, LIST_SEP, &saveptr);
	if (tok == NULL) {
		return;
	}

	while (tok != NULL) {
		debug_backend_parse_token(tok);
		tok = strtok_r(NULL, LIST_SEP, &saveptr);
	}

	/*
	 * Let backends react to config changes
	 */
	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		struct debug_backend *b = &debug_backends[i];

		if (b->reload) {
			bool enabled = b->new_log_level > -1;
			bool previously_enabled = b->log_level > -1;

			b->reload(enabled, previously_enabled, state.prog_name,
				  b->option);
		}
		b->log_level = b->new_log_level;
	}
}

static void debug_backends_log(const char *msg, int msg_level)
{
	char msg_no_nl[FORMAT_BUFR_SIZE];
	size_t i;
	size_t len;

	/*
	 * Some backends already add an extra newline, so also provide
	 * a buffer without the newline character.
	 */
	len = MIN(strlen(msg), FORMAT_BUFR_SIZE - 1);
	if ((len > 0) && (msg[len - 1] == '\n')) {
		len--;
	}

	memcpy(msg_no_nl, msg, len);
	msg_no_nl[len] = '\0';

	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		if (msg_level <= debug_backends[i].log_level) {
			debug_backends[i].log(msg_level, msg, msg_no_nl);
		}
	}
}

/* -------------------------------------------------------------------------- **
 * External variables.
 */

/*
   used to check if the user specified a
   logfile on the command line
*/
bool    override_logfile;

int debuglevel_get_class(size_t idx)
{
	return dbgc_config[idx].loglevel;
}

void debuglevel_set_class(size_t idx, int level)
{
	dbgc_config[idx].loglevel = level;
}


/* -------------------------------------------------------------------------- **
 * Internal variables.
 *
 *  debug_count     - Number of debug messages that have been output.
 *                    Used to check log size.
 *
 *  current_msg_level    - Internal copy of the message debug level.  Written by
 *                    dbghdr() and read by Debug1().
 *
 *  format_bufr     - Used to format debug messages.  The dbgtext() function
 *                    prints debug messages to a string, and then passes the
 *                    string to format_debug_text(), which uses format_bufr
 *                    to build the formatted output.
 *
 *  format_pos      - Marks the first free byte of the format_bufr.
 *
 *
 *  log_overflow    - When this variable is true, never attempt to check the
 *                    size of the log. This is a hack, so that we can write
 *                    a message using DEBUG, from open_logs() when we
 *                    are unable to open a new log file for some reason.
 */

static int     debug_count    = 0;
static char format_bufr[FORMAT_BUFR_SIZE];
static size_t     format_pos     = 0;
static bool    log_overflow   = false;

/*
 * Define all the debug class selection names here. Names *MUST NOT* contain
 * white space. There must be one name for each DBGC_<class name>, and they
 * must be in the table in the order of DBGC_<class name>..
 */

static char **classname_table = NULL;


/* -------------------------------------------------------------------------- **
 * Functions...
 */

static void debug_init(void);

/***************************************************************************
 Free memory pointed to by global pointers.
****************************************************************************/

void gfree_debugsyms(void)
{
	unsigned i;

	TALLOC_FREE(classname_table);

	if ( dbgc_config != debug_class_list_initial ) {
		TALLOC_FREE( dbgc_config );
		dbgc_config = discard_const_p(struct debug_class,
						   debug_class_list_initial);
	}

	debug_num_classes = 0;

	state.initialized = false;

	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		SAFE_FREE(debug_backends[i].option);
	}
}

/****************************************************************************
utility lists registered debug class names's
****************************************************************************/

char *debug_list_class_names_and_levels(void)
{
	char *buf = NULL;
	size_t i;
	/* prepare strings */
	for (i = 0; i < debug_num_classes; i++) {
		buf = talloc_asprintf_append(buf,
					     "%s:%d%s",
					     classname_table[i],
					     dbgc_config[i].loglevel,
					     i == (debug_num_classes - 1) ? "\n" : " ");
		if (buf == NULL) {
			return NULL;
		}
	}
	return buf;
}

/****************************************************************************
 Utility to translate names to debug class index's (internal version).
****************************************************************************/

static int debug_lookup_classname_int(const char* classname)
{
	size_t i;

	if (classname == NULL) {
		return -1;
	}

	for (i=0; i < debug_num_classes; i++) {
		char *entry = classname_table[i];
		if (entry != NULL && strcmp(classname, entry)==0) {
			return i;
		}
	}
	return -1;
}

/****************************************************************************
 Add a new debug class to the system.
****************************************************************************/

int debug_add_class(const char *classname)
{
	int ndx;
	struct debug_class *new_class_list = NULL;
	char **new_name_list;
	int default_level;

	if (classname == NULL) {
		return -1;
	}

	/* check the init has yet been called */
	debug_init();

	ndx = debug_lookup_classname_int(classname);
	if (ndx >= 0) {
		return ndx;
	}
	ndx = debug_num_classes;

	if (dbgc_config == debug_class_list_initial) {
		/* Initial loading... */
		new_class_list = NULL;
	} else {
		new_class_list = dbgc_config;
	}

	default_level = dbgc_config[DBGC_ALL].loglevel;

	new_class_list = talloc_realloc(NULL,
					new_class_list,
					struct debug_class,
					ndx + 1);
	if (new_class_list == NULL) {
		return -1;
	}

	dbgc_config = new_class_list;

	dbgc_config[ndx] = (struct debug_class) {
		.loglevel = default_level,
		.fd = -1,
	};

	new_name_list = talloc_realloc(NULL, classname_table, char *, ndx + 1);
	if (new_name_list == NULL) {
		return -1;
	}
	classname_table = new_name_list;

	classname_table[ndx] = talloc_strdup(classname_table, classname);
	if (classname_table[ndx] == NULL) {
		return -1;
	}

	debug_num_classes = ndx + 1;

	return ndx;
}

/****************************************************************************
 Utility to translate names to debug class index's (public version).
****************************************************************************/

static int debug_lookup_classname(const char *classname)
{
	int ndx;

	if (classname == NULL || !*classname)
		return -1;

	ndx = debug_lookup_classname_int(classname);

	if (ndx != -1)
		return ndx;

	DEBUG(0, ("debug_lookup_classname(%s): Unknown class\n",
		  classname));
	return debug_add_class(classname);
}

/****************************************************************************
 Dump the current registered debug levels.
****************************************************************************/

static void debug_dump_status(int level)
{
	size_t q;

	DEBUG(level, ("INFO: Current debug levels:\n"));
	for (q = 0; q < debug_num_classes; q++) {
		const char *classname = classname_table[q];
		DEBUGADD(level, ("  %s: %d\n",
				 classname,
				 dbgc_config[q].loglevel));
	}
}

static bool debug_parse_param(char *param)
{
	char *class_name;
	char *class_file = NULL;
	char *class_level;
	char *saveptr = NULL;
	int ndx;

	class_name = strtok_r(param, ":", &saveptr);
	if (class_name == NULL) {
		return false;
	}

	class_level = strtok_r(NULL, "@\0", &saveptr);
	if (class_level == NULL) {
		return false;
	}

	class_file = strtok_r(NULL, "\0", &saveptr);

	ndx = debug_lookup_classname(class_name);
	if (ndx == -1) {
		return false;
	}

	dbgc_config[ndx].loglevel = atoi(class_level);

	if (class_file == NULL) {
		return true;
	}

	TALLOC_FREE(dbgc_config[ndx].logfile);

	dbgc_config[ndx].logfile = talloc_strdup(NULL, class_file);
	if (dbgc_config[ndx].logfile == NULL) {
		return false;
	}
	return true;
}

/****************************************************************************
 Parse the debug levels from smb.conf. Example debug level string:
  3 tdb:5 printdrivers:7
 Note: the 1st param has no "name:" preceding it.
****************************************************************************/

bool debug_parse_levels(const char *params_str)
{
	size_t str_len = strlen(params_str);
	char str[str_len+1];
	char *tok, *saveptr;
	size_t i;

	/* Just in case */
	debug_init();

	memcpy(str, params_str, str_len+1);

	tok = strtok_r(str, LIST_SEP, &saveptr);
	if (tok == NULL) {
		return true;
	}

	/* Allow DBGC_ALL to be specified w/o requiring its class name e.g."10"
	 * v.s. "all:10", this is the traditional way to set DEBUGLEVEL
	 */
	if (isdigit(tok[0])) {
		dbgc_config[DBGC_ALL].loglevel = atoi(tok);
		tok = strtok_r(NULL, LIST_SEP, &saveptr);
	} else {
		dbgc_config[DBGC_ALL].loglevel = 0;
	}

	/* Array is debug_num_classes long */
	for (i = DBGC_ALL+1; i < debug_num_classes; i++) {
		dbgc_config[i].loglevel = dbgc_config[DBGC_ALL].loglevel;
		TALLOC_FREE(dbgc_config[i].logfile);
	}

	while (tok != NULL) {
		bool ok;

		ok = debug_parse_param(tok);
		if (!ok) {
			DEBUG(0,("debug_parse_params: unrecognized debug "
				 "class name or format [%s]\n", tok));
			return false;
		}

		tok = strtok_r(NULL, LIST_SEP, &saveptr);
	}

	debug_dump_status(5);

	return true;
}

/* setup for logging of talloc warnings */
static void talloc_log_fn(const char *msg)
{
	DEBUG(0,("%s", msg));
}

void debug_setup_talloc_log(void)
{
	talloc_set_log_fn(talloc_log_fn);
}


/****************************************************************************
Init debugging (one time stuff)
****************************************************************************/

static void debug_init(void)
{
	size_t i;

	if (state.initialized)
		return;

	state.initialized = true;

	debug_setup_talloc_log();

	for (i = 0; i < ARRAY_SIZE(default_classname_table); i++) {
		debug_add_class(default_classname_table[i]);
	}
	dbgc_config[DBGC_ALL].fd = 2;

	for (i = 0; i < ARRAY_SIZE(debug_backends); i++) {
		debug_backends[i].log_level = -1;
		debug_backends[i].new_log_level = -1;
	}
}

void debug_set_settings(struct debug_settings *settings,
			const char *logging_param,
			int syslog_level, bool syslog_only)
{
	char fake_param[256];
	size_t len = 0;

	/*
	 * This forces in some smb.conf derived values into the debug
	 * system. There are no pointers in this structure, so we can
	 * just structure-assign it in
	 */
	state.settings = *settings;

	/*
	 * If 'logging' is not set, create backend settings from
	 * deprecated 'syslog' and 'syslog only' parameters
	 */
	if (logging_param != NULL) {
		len = strlen(logging_param);
	}
	if (len == 0) {
		if (syslog_only) {
			snprintf(fake_param, sizeof(fake_param),
				 "syslog@%d", syslog_level - 1);
		} else {
			snprintf(fake_param, sizeof(fake_param),
				 "syslog@%d file@%d", syslog_level -1,
				 MAX_DEBUG_LEVEL);
		}

		logging_param = fake_param;
	}

	debug_set_backends(logging_param);
}

/**
  control the name of the logfile and whether logging will be to stdout, stderr
  or a file, and set up syslog

  new_log indicates the destination for the debug log (an enum in
  order of precedence - once set to DEBUG_FILE, it is not possible to
  reset to DEBUG_STDOUT for example.  This makes it easy to override
  for debug to stderr on the command line, as the smb.conf cannot
  reset it back to file-based logging
*/
void setup_logging(const char *prog_name, enum debug_logtype new_logtype)
{
	debug_init();
	if (state.logtype < new_logtype) {
		state.logtype = new_logtype;
	}
	if (prog_name) {
		const char *p = strrchr(prog_name, '/');

		if (p) {
			prog_name = p + 1;
		}

		strlcpy(state.prog_name, prog_name, sizeof(state.prog_name));
	}
	reopen_logs_internal();
}

/***************************************************************************
 Set the logfile name.
**************************************************************************/

void debug_set_logfile(const char *name)
{
	if (name == NULL || *name == 0) {
		/* this copes with calls when smb.conf is not loaded yet */
		return;
	}
	TALLOC_FREE(dbgc_config[DBGC_ALL].logfile);
	dbgc_config[DBGC_ALL].logfile = talloc_strdup(NULL, name);
}

static void debug_close_fd(int fd)
{
	if (fd > 2) {
		close(fd);
	}
}

bool debug_get_output_is_stderr(void)
{
	return (state.logtype == DEBUG_DEFAULT_STDERR) || (state.logtype == DEBUG_STDERR);
}

bool debug_get_output_is_stdout(void)
{
	return (state.logtype == DEBUG_DEFAULT_STDOUT) || (state.logtype == DEBUG_STDOUT);
}

void debug_set_callback(void *private_ptr, debug_callback_fn fn)
{
	debug_init();
	if (fn) {
		state.logtype = DEBUG_CALLBACK;
		state.callback_private = private_ptr;
		state.callback = fn;
	} else {
		state.logtype = DEBUG_DEFAULT_STDERR;
		state.callback_private = NULL;
		state.callback = NULL;
	}
}

static void debug_callback_log(const char *msg, int msg_level)
{
	size_t msg_len = strlen(msg);
	char msg_copy[msg_len];

	if ((msg_len > 0) && (msg[msg_len-1] == '\n')) {
		memcpy(msg_copy, msg, msg_len-1);
		msg_copy[msg_len-1] = '\0';
		msg = msg_copy;
	}

	state.callback(state.callback_private, msg_level, msg);
}

/**************************************************************************
 reopen the log files
 note that we now do this unconditionally
 We attempt to open the new debug fp before closing the old. This means
 if we run out of fd's we just keep using the old fd rather than aborting.
 Fix from dgibson@linuxcare.com.
**************************************************************************/

static bool reopen_one_log(struct debug_class *config)
{
	int old_fd = config->fd;
	const char *logfile = config->logfile;
	struct stat st;
	int new_fd;
	int ret;

	if (logfile == NULL) {
		debug_close_fd(old_fd);
		config->fd = -1;
		return true;
	}

	new_fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT, 0644);
	if (new_fd == -1) {
		log_overflow = true;
		DBG_ERR("Unable to open new log file '%s': %s\n",
			logfile, strerror(errno));
		log_overflow = false;
		return false;
	}

	debug_close_fd(old_fd);
	smb_set_close_on_exec(new_fd);
	config->fd = new_fd;

	ret = fstat(new_fd, &st);
	if (ret != 0) {
		log_overflow = true;
		DBG_ERR("Unable to fstat() new log file '%s': %s\n",
			logfile, strerror(errno));
		log_overflow = false;
		return false;
	}

	config->ino = st.st_ino;
	return true;
}

/**
  reopen the log file (usually called because the log file name might have changed)
*/
bool reopen_logs_internal(void)
{
	struct debug_backend *b = NULL;
	mode_t oldumask;
	int new_fd = 0;
	size_t i;
	bool ok;

	if (state.reopening_logs) {
		return true;
	}

	/* Now clear the SIGHUP induced flag */
	state.schedule_reopen_logs = false;

	switch (state.logtype) {
	case DEBUG_CALLBACK:
		return true;
	case DEBUG_STDOUT:
	case DEBUG_DEFAULT_STDOUT:
		debug_close_fd(dbgc_config[DBGC_ALL].fd);
		dbgc_config[DBGC_ALL].fd = 1;
		return true;

	case DEBUG_DEFAULT_STDERR:
	case DEBUG_STDERR:
		debug_close_fd(dbgc_config[DBGC_ALL].fd);
		dbgc_config[DBGC_ALL].fd = 2;
		return true;

	case DEBUG_FILE:
		b = debug_find_backend("file");
		assert(b != NULL);

		b->log_level = MAX_DEBUG_LEVEL;
		break;
	}

	oldumask = umask( 022 );

	for (i = DBGC_ALL; i < debug_num_classes; i++) {
		if (dbgc_config[i].logfile != NULL) {
			break;
		}
	}
	if (i == debug_num_classes) {
		return false;
	}

	state.reopening_logs = true;

	for (i = DBGC_ALL; i < debug_num_classes; i++) {
		ok = reopen_one_log(&dbgc_config[i]);
		if (!ok) {
			break;
		}
	}

	/* Fix from klausr@ITAP.Physik.Uni-Stuttgart.De
	 * to fix problem where smbd's that generate less
	 * than 100 messages keep growing the log.
	 */
	force_check_log_size();
	(void)umask(oldumask);

	/*
	 * If log file was opened or created successfully, take over stderr to
	 * catch output into logs.
	 */
	if (new_fd != -1) {
		if (dup2(dbgc_config[DBGC_ALL].fd, 2) == -1) {
			/* Close stderr too, if dup2 can't point it -
			   at the logfile.  There really isn't much
			   that can be done on such a fundamental
			   failure... */
			close_low_fd(2);
		}
	}

	state.reopening_logs = false;

	return ok;
}

/**************************************************************************
 Force a check of the log size.
 ***************************************************************************/

void force_check_log_size( void )
{
	debug_count = 100;
}

_PUBLIC_ void debug_schedule_reopen_logs(void)
{
	state.schedule_reopen_logs = true;
}


/***************************************************************************
 Check to see if there is any need to check if the logfile has grown too big.
**************************************************************************/

bool need_to_check_log_size(void)
{
	int maxlog;
	size_t i;

	if (debug_count < 100) {
		return false;
	}

	maxlog = state.settings.max_log_size * 1024;
	if (maxlog <= 0) {
		debug_count = 0;
		return false;
	}

	if (dbgc_config[DBGC_ALL].fd > 2) {
		return true;
	}

	for (i = DBGC_ALL + 1; i < debug_num_classes; i++) {
		if (dbgc_config[i].fd != -1) {
			return true;
		}
	}

	debug_count = 0;
	return false;
}

/**************************************************************************
 Check to see if the log has grown to be too big.
 **************************************************************************/

static void do_one_check_log_size(off_t maxlog, struct debug_class *config)
{
	char name[strlen(config->logfile) + 5];
	struct stat st;
	int ret;
	bool reopen = false;
	bool ok;

	if (maxlog == 0) {
		return;
	}

	ret = stat(config->logfile, &st);
	if (ret != 0) {
		return;
	}
	if (st.st_size >= maxlog ) {
		reopen = true;
	}

	if (st.st_ino != config->ino) {
		reopen = true;
	}

	if (!reopen) {
		return;
	}

	/* reopen_logs_internal() modifies *_fd */
	(void)reopen_logs_internal();

	if (config->fd <= 2) {
		return;
	}
	ret = fstat(config->fd, &st);
	if (ret != 0) {
		config->ino = (ino_t)0;
		return;
	}

	config->ino = st.st_ino;

	if (st.st_size < maxlog) {
		return;
	}

	snprintf(name, sizeof(name), "%s.old", config->logfile);

	(void)rename(config->logfile, name);

	ok = reopen_logs_internal();
	if (ok) {
		return;
	}
	/* We failed to reopen a log - continue using the old name. */
	(void)rename(name, config->logfile);
}

static void do_check_log_size(off_t maxlog)
{
	size_t i;

	for (i = DBGC_ALL; i < debug_num_classes; i++) {
		if (dbgc_config[i].fd == -1) {
			continue;
		}
		if (dbgc_config[i].logfile == NULL) {
			continue;
		}
		do_one_check_log_size(maxlog, &dbgc_config[i]);
	}
}

void check_log_size( void )
{
	off_t maxlog;

	/*
	 *  We need to be root to check/change log-file, skip this and let the main
	 *  loop check do a new check as root.
	 */

#if _SAMBA_BUILD_ == 3
	if (geteuid() != sec_initial_uid())
#else
	if( geteuid() != 0)
#endif
	{
		/* We don't check sec_initial_uid() here as it isn't
		 * available in common code and we don't generally
		 * want to rotate and the possibly lose logs in
		 * make test or the build farm */
		return;
	}

	if(log_overflow || (!state.schedule_reopen_logs && !need_to_check_log_size())) {
		return;
	}

	maxlog = state.settings.max_log_size * 1024;

	if (state.schedule_reopen_logs) {
		(void)reopen_logs_internal();
	}

	do_check_log_size(maxlog);

	/*
	 * Here's where we need to panic if dbgc_config[DBGC_ALL].fd == 0 or -1
	 * (invalid values)
	 */

	if (dbgc_config[DBGC_ALL].fd <= 0) {
		/* This code should only be reached in very strange
		 * circumstances. If we merely fail to open the new log we
		 * should stick with the old one. ergo this should only be
		 * reached when opening the logs for the first time: at
		 * startup or when the log level is increased from zero.
		 * -dwg 6 June 2000
		 */
		int fd = open( "/dev/console", O_WRONLY, 0);
		if (fd != -1) {
			smb_set_close_on_exec(fd);
			dbgc_config[DBGC_ALL].fd = fd;
			DBG_ERR("check_log_size: open of debug file %s failed "
				"- using console.\n",
				dbgc_config[DBGC_ALL].logfile);
		} else {
			/*
			 * We cannot continue without a debug file handle.
			 */
			abort();
		}
	}
	debug_count = 0;
}

/*************************************************************************
 Write an debug message on the debugfile.
 This is called by dbghdr() and format_debug_text().
************************************************************************/

static void Debug1(const char *msg)
{
	int old_errno = errno;

	debug_count++;

	switch(state.logtype) {
	case DEBUG_CALLBACK:
		debug_callback_log(msg, current_msg_level);
		break;
	case DEBUG_STDOUT:
	case DEBUG_STDERR:
	case DEBUG_DEFAULT_STDOUT:
	case DEBUG_DEFAULT_STDERR:
		if (dbgc_config[DBGC_ALL].fd > 0) {
			ssize_t ret;
			do {
				ret = write(dbgc_config[DBGC_ALL].fd,
					    msg,
					    strlen(msg));
			} while (ret == -1 && errno == EINTR);
		}
		break;
	case DEBUG_FILE:
		debug_backends_log(msg, current_msg_level);
		break;
	};

	errno = old_errno;
}

/**************************************************************************
 Print the buffer content via Debug1(), then reset the buffer.
 Input:  none
 Output: none
****************************************************************************/

static void bufr_print( void )
{
	format_bufr[format_pos] = '\0';
	(void)Debug1(format_bufr);
	format_pos = 0;
}

/***************************************************************************
 Format the debug message text.

 Input:  msg - Text to be added to the "current" debug message text.

 Output: none.

 Notes:  The purpose of this is two-fold.  First, each call to syslog()
         (used by Debug1(), see above) generates a new line of syslog
         output.  This is fixed by storing the partial lines until the
         newline character is encountered.  Second, printing the debug
         message lines when a newline is encountered allows us to add
         spaces, thus indenting the body of the message and making it
         more readable.
**************************************************************************/

static void format_debug_text( const char *msg )
{
	size_t i;
	bool timestamp = (state.logtype == DEBUG_FILE && (state.settings.timestamp_logs));

	debug_init();

	for( i = 0; msg[i]; i++ ) {
		/* Indent two spaces at each new line. */
		if(timestamp && 0 == format_pos) {
			format_bufr[0] = format_bufr[1] = ' ';
			format_pos = 2;
		}

		/* If there's room, copy the character to the format buffer. */
		if (format_pos < FORMAT_BUFR_SIZE - 1)
			format_bufr[format_pos++] = msg[i];

		/* If a newline is encountered, print & restart. */
		if( '\n' == msg[i] )
			bufr_print();

		/* If the buffer is full dump it out, reset it, and put out a line
		 * continuation indicator.
		 */
		if (format_pos >= FORMAT_BUFR_SIZE - 1) {
			bufr_print();
			(void)Debug1( " +>\n" );
		}
	}

	/* Just to be safe... */
	format_bufr[format_pos] = '\0';
}

/***************************************************************************
 Flush debug output, including the format buffer content.

 Input:  none
 Output: none
***************************************************************************/

void dbgflush( void )
{
	bufr_print();
}

bool dbgsetclass(int level, int cls)
{
	/* Set current_msg_level. */
	current_msg_level = level;

	/* Set current message class */
	current_msg_class = cls;

	return true;
}

/***************************************************************************
 Print a Debug Header.

 Input:  level    - Debug level of the message (not the system-wide debug
                    level. )
         cls      - Debuglevel class of the calling module.
         location - Pointer to a string containing the name of the file
                    from which this function was called, or an empty string
                    if the __FILE__ macro is not implemented.
         func     - Pointer to a string containing the name of the function
                    from which this function was called, or an empty string
                    if the __FUNCTION__ macro is not implemented.

 Output: Always true.  This makes it easy to fudge a call to dbghdr()
         in a macro, since the function can be called as part of a test.
         Eg: ( (level <= DEBUGLEVEL) && (dbghdr(level,"",line)) )

 Notes:  This function takes care of setting current_msg_level.

****************************************************************************/

bool dbghdrclass(int level, int cls, const char *location, const char *func)
{
	/* Ensure we don't lose any real errno value. */
	int old_errno = errno;
	bool verbose = false;
	char header_str[300];
	size_t hs_len;
	struct timeval tv;
	struct timeval_buf tvbuf;

	if( format_pos ) {
		/* This is a fudge.  If there is stuff sitting in the format_bufr, then
		 * the *right* thing to do is to call
		 *   format_debug_text( "\n" );
		 * to write the remainder, and then proceed with the new header.
		 * Unfortunately, there are several places in the code at which
		 * the DEBUG() macro is used to build partial lines.  That in mind,
		 * we'll work under the assumption that an incomplete line indicates
		 * that a new header is *not* desired.
		 */
		return( true );
	}

	dbgsetclass(level, cls);

	/* Don't print a header if we're logging to stdout. */
	if ( state.logtype != DEBUG_FILE ) {
		return( true );
	}

	/* Print the header if timestamps are turned on.  If parameters are
	 * not yet loaded, then default to timestamps on.
	 */
	if (!(state.settings.timestamp_logs ||
	      state.settings.debug_prefix_timestamp)) {
		return true;
	}

	GetTimeOfDay(&tv);
	timeval_str_buf(&tv, false, state.settings.debug_hires_timestamp,
			&tvbuf);

	hs_len = snprintf(header_str, sizeof(header_str), "[%s, %2d",
			  tvbuf.buf, level);
	if (hs_len >= sizeof(header_str)) {
		goto full;
	}

	if (unlikely(dbgc_config[cls].loglevel >= 10)) {
		verbose = true;
	}

	if (verbose || state.settings.debug_pid) {
		hs_len += snprintf(
			header_str + hs_len, sizeof(header_str) - hs_len,
			", pid=%u", (unsigned int)getpid());
		if (hs_len >= sizeof(header_str)) {
			goto full;
		}
	}

	if (verbose || state.settings.debug_uid) {
		hs_len += snprintf(
			header_str + hs_len, sizeof(header_str) - hs_len,
			", effective(%u, %u), real(%u, %u)",
			(unsigned int)geteuid(), (unsigned int)getegid(),
			(unsigned int)getuid(), (unsigned int)getgid());
		if (hs_len >= sizeof(header_str)) {
			goto full;
		}
	}

	if ((verbose || state.settings.debug_class)
	    && (cls != DBGC_ALL)) {
		hs_len += snprintf(
			header_str + hs_len, sizeof(header_str) - hs_len,
			", class=%s", classname_table[cls]);
		if (hs_len >= sizeof(header_str)) {
			goto full;
		}
	}

	/*
	 * No +=, see man man strlcat
	 */
	hs_len = strlcat(header_str, "] ", sizeof(header_str));
	if (hs_len >= sizeof(header_str)) {
		goto full;
	}

	if (!state.settings.debug_prefix_timestamp) {
		hs_len += snprintf(
			header_str + hs_len, sizeof(header_str) - hs_len,
			"%s(%s)\n", location, func);
		if (hs_len >= sizeof(header_str)) {
			goto full;
		}
	}

full:
	(void)Debug1(header_str);

	errno = old_errno;
	return( true );
}

/***************************************************************************
 Add text to the body of the "current" debug message via the format buffer.

  Input:  format_str  - Format string, as used in printf(), et. al.
          ...         - Variable argument list.

  ..or..  va_alist    - Old style variable parameter list starting point.

  Output: Always true.  See dbghdr() for more info, though this is not
          likely to be used in the same way.

***************************************************************************/

static inline bool __dbgtext_va(const char *format_str, va_list ap) PRINTF_ATTRIBUTE(1,0);
static inline bool __dbgtext_va(const char *format_str, va_list ap)
{
	char *msgbuf = NULL;
	bool ret = true;
	int res;

	res = vasprintf(&msgbuf, format_str, ap);
	if (res != -1) {
		format_debug_text(msgbuf);
	} else {
		ret = false;
	}
	SAFE_FREE(msgbuf);
	return ret;
}

bool dbgtext_va(const char *format_str, va_list ap)
{
	return __dbgtext_va(format_str, ap);
}

bool dbgtext(const char *format_str, ... )
{
	va_list ap;
	bool ret;

	va_start(ap, format_str);
	ret = __dbgtext_va(format_str, ap);
	va_end(ap);

	return ret;
}
