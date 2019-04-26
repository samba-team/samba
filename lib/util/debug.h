/* 
   Unix SMB/CIFS implementation.
   SMB debug stuff
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) John H Terpstra 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton 1998

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

#ifndef _SAMBA_DEBUG_H
#define _SAMBA_DEBUG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include "attr.h"


/* -------------------------------------------------------------------------- **
 * Debugging code.  See also debug.c
 */

/* the maximum debug level to compile into the code. This assumes a good
   optimising compiler that can remove unused code
   for embedded or low-memory systems set this to a value like 2 to get
   only important messages. This gives *much* smaller binaries
*/
#ifndef MAX_DEBUG_LEVEL
#define MAX_DEBUG_LEVEL 1000
#endif

bool dbgtext_va(const char *, va_list ap) PRINTF_ATTRIBUTE(1,0);
bool dbgtext( const char *, ... ) PRINTF_ATTRIBUTE(1,2);
bool dbghdrclass( int level, int cls, const char *location, const char *func);
bool dbgsetclass(int level, int cls);

/*
 * Define all new debug classes here. A class is represented by an entry in
 * the DEBUGLEVEL_CLASS array. Index zero of this arrray is equivalent to the
 * old DEBUGLEVEL. Any source file that does NOT add the following lines:
 *
 *   #undef  DBGC_CLASS
 *   #define DBGC_CLASS DBGC_<your class name here>
 *
 * at the start of the file (after #include "includes.h") will default to
 * using index zero, so it will behaive just like it always has.
 */
#define DBGC_ALL		0 /* index equivalent to DEBUGLEVEL */

#define DBGC_TDB		1
#define DBGC_PRINTDRIVERS	2
#define DBGC_LANMAN		3
#define DBGC_SMB		4
#define DBGC_RPC_PARSE		5
#define DBGC_RPC_SRV		6
#define DBGC_RPC_CLI		7
#define DBGC_PASSDB		8
#define DBGC_SAM		9
#define DBGC_AUTH		10
#define DBGC_WINBIND		11
#define DBGC_VFS		12
#define DBGC_IDMAP		13
#define DBGC_QUOTA		14
#define DBGC_ACLS		15
#define DBGC_LOCKING		16
#define DBGC_MSDFS		17
#define DBGC_DMAPI		18
#define DBGC_REGISTRY		19
#define DBGC_SCAVENGER		20
#define DBGC_DNS		21
#define DBGC_LDB		22
#define DBGC_TEVENT		23
#define DBGC_AUTH_AUDIT		24
#define DBGC_AUTH_AUDIT_JSON	25
#define DBGC_KERBEROS           26
#define DBGC_DRS_REPL           27
#define DBGC_SMB2               28
#define DBGC_SMB2_CREDITS       29
#define DBGC_DSDB_AUDIT	30
#define DBGC_DSDB_AUDIT_JSON	31
#define DBGC_DSDB_PWD_AUDIT		32
#define DBGC_DSDB_PWD_AUDIT_JSON	33
#define DBGC_DSDB_TXN_AUDIT		34
#define DBGC_DSDB_TXN_AUDIT_JSON	35
#define DBGC_DSDB_GROUP_AUDIT	36
#define DBGC_DSDB_GROUP_AUDIT_JSON	37

/* So you can define DBGC_CLASS before including debug.h */
#ifndef DBGC_CLASS
#define DBGC_CLASS            0     /* override as shown above */
#endif

#define DEBUGLEVEL debuglevel_get()

#define debuglevel_get() debuglevel_get_class(DBGC_ALL)
#define debuglevel_set(lvl) debuglevel_set_class(DBGC_ALL, (lvl))

/* Debugging macros
 *
 * DEBUGLVL()
 *   If the 'file specific' debug class level >= level OR the system-wide
 *   DEBUGLEVEL (synomym for DEBUGLEVEL_CLASS[ DBGC_ALL ]) >= level then
 *   generate a header using the default macros for file, line, and
 *   function name. Returns True if the debug level was <= DEBUGLEVEL.
 *
 *   Example: if( DEBUGLVL( 2 ) ) dbgtext( "Some text.\n" );
 *
 * DEBUG()
 *   If the 'file specific' debug class level >= level OR the system-wide
 *   DEBUGLEVEL (synomym for DEBUGLEVEL_CLASS[ DBGC_ALL ]) >= level then
 *   generate a header using the default macros for file, line, and
 *   function name. Each call to DEBUG() generates a new header *unless* the
 *   previous debug output was unterminated (i.e. no '\n').
 *   See debug.c:dbghdr() for more info.
 *
 *   Example: DEBUG( 2, ("Some text and a value %d.\n", value) );
 *
 * DEBUGC()
 *   If the 'macro specified' debug class level >= level OR the system-wide
 *   DEBUGLEVEL (synomym for DEBUGLEVEL_CLASS[ DBGC_ALL ]) >= level then
 *   generate a header using the default macros for file, line, and
 *   function name. Each call to DEBUG() generates a new header *unless* the
 *   previous debug output was unterminated (i.e. no '\n').
 *   See debug.c:dbghdr() for more info.
 *
 *   Example: DEBUGC( DBGC_TDB, 2, ("Some text and a value %d.\n", value) );
 *
 *  DEBUGADD(), DEBUGADDC()
 *    Same as DEBUG() and DEBUGC() except the text is appended to the previous
 *    DEBUG(), DEBUGC(), DEBUGADD(), DEBUGADDC() with out another interviening
 *    header.
 *
 *    Example: DEBUGADD( 2, ("Some text and a value %d.\n", value) );
 *             DEBUGADDC( DBGC_TDB, 2, ("Some text and a value %d.\n", value) );
 *
 * Note: If the debug class has not be redeined (see above) then the optimizer
 * will remove the extra conditional test.
 */

/*
 * From talloc.c:
 */

/* these macros gain us a few percent of speed on gcc */
#if (__GNUC__ >= 3)
/* the strange !! is to ensure that __builtin_expect() takes either 0 or 1
   as its first argument */
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#else
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif
#endif

int debuglevel_get_class(size_t idx);
void debuglevel_set_class(size_t idx, int level);

#define CHECK_DEBUGLVL( level ) \
  ( ((level) <= MAX_DEBUG_LEVEL) && \
    unlikely(debuglevel_get_class(DBGC_CLASS) >= (level)))

#define CHECK_DEBUGLVLC( dbgc_class, level ) \
  ( ((level) <= MAX_DEBUG_LEVEL) && \
    unlikely(debuglevel_get_class(dbgc_class) >= (level)))

#define DEBUGLVL( level ) \
  ( CHECK_DEBUGLVL(level) \
   && dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ ) )

#define DEBUGLVLC( dbgc_class, level ) \
  ( CHECK_DEBUGLVLC( dbgc_class, level ) \
   && dbghdrclass( level, dbgc_class, __location__, __FUNCTION__ ) )

#define DEBUG( level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
       unlikely(debuglevel_get_class(DBGC_CLASS) >= (level))             \
       && (dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ )) \
       && (dbgtext body) )

#define DEBUGC( dbgc_class, level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
       unlikely(debuglevel_get_class(dbgc_class) >= (level))             \
       && (dbghdrclass( level, dbgc_class, __location__, __FUNCTION__ )) \
       && (dbgtext body) )

#define DEBUGADD( level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
       unlikely(debuglevel_get_class(DBGC_CLASS) >= (level)) \
       && (dbgsetclass(level, DBGC_CLASS))                   \
       && (dbgtext body) )

#define DEBUGADDC( dbgc_class, level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
       unlikely((debuglevel_get_class(dbgc_class) >= (level))) \
       && (dbgsetclass(level, dbgc_class))                     \
       && (dbgtext body) )

/* Print a separator to the debug log. */
#define DEBUGSEP(level)\
	DEBUG((level),("===============================================================\n"))

/* Prefix messages with the function name */
#define DBG_PREFIX(level, body ) \
	(void)( ((level) <= MAX_DEBUG_LEVEL) &&			\
		unlikely(debuglevel_get_class(DBGC_CLASS) >= (level))	\
		&& (dbghdrclass(level, DBGC_CLASS, __location__, __func__ )) \
		&& (dbgtext("%s: ", __func__))				\
		&& (dbgtext body) )

/* Prefix messages with the function name - class specific */
#define DBGC_PREFIX(dbgc_class, level, body ) \
	(void)( ((level) <= MAX_DEBUG_LEVEL) &&			\
		unlikely(debuglevel_get_class(dbgc_class) >= (level))	\
		&& (dbghdrclass(level, dbgc_class, __location__, __func__ )) \
		&& (dbgtext("%s: ", __func__))				\
		&& (dbgtext body) )

/*
 * Debug levels matching RFC 3164
 */
#define DBGLVL_ERR	 0	/* error conditions */
#define DBGLVL_WARNING	 1	/* warning conditions */
#define DBGLVL_NOTICE	 3	/* normal, but significant, condition */
#define DBGLVL_INFO	 5	/* informational message */
#define DBGLVL_DEBUG	10	/* debug-level message */

#define DBG_ERR(...)		DBG_PREFIX(DBGLVL_ERR,		(__VA_ARGS__))
#define DBG_WARNING(...)	DBG_PREFIX(DBGLVL_WARNING,	(__VA_ARGS__))
#define DBG_NOTICE(...)		DBG_PREFIX(DBGLVL_NOTICE,	(__VA_ARGS__))
#define DBG_INFO(...)		DBG_PREFIX(DBGLVL_INFO,		(__VA_ARGS__))
#define DBG_DEBUG(...)		DBG_PREFIX(DBGLVL_DEBUG,	(__VA_ARGS__))

#define DBGC_ERR(dbgc_class, ...)	DBGC_PREFIX(dbgc_class, \
						DBGLVL_ERR, (__VA_ARGS__))
#define DBGC_WARNING(dbgc_class, ...)	DBGC_PREFIX(dbgc_class, \
						DBGLVL_WARNING,	(__VA_ARGS__))
#define DBGC_NOTICE(dbgc_class, ...)	DBGC_PREFIX(dbgc_class, \
						DBGLVL_NOTICE,	(__VA_ARGS__))
#define DBGC_INFO(dbgc_class, ...)	DBGC_PREFIX(dbgc_class, \
						DBGLVL_INFO,	(__VA_ARGS__))
#define DBGC_DEBUG(dbgc_class, ...)	DBGC_PREFIX(dbgc_class, \
						DBGLVL_DEBUG,	(__VA_ARGS__))

#define D_ERR(...)		DEBUG(DBGLVL_ERR,	(__VA_ARGS__))
#define D_WARNING(...)		DEBUG(DBGLVL_WARNING,	(__VA_ARGS__))
#define D_NOTICE(...)		DEBUG(DBGLVL_NOTICE,	(__VA_ARGS__))
#define D_INFO(...)		DEBUG(DBGLVL_INFO,	(__VA_ARGS__))
#define D_DEBUG(...)		DEBUG(DBGLVL_DEBUG,	(__VA_ARGS__))

#define DC_ERR(...)		DEBUGC(dbgc_class, \
					DBGLVL_ERR,	(__VA_ARGS__))
#define DC_WARNING(...)		DEBUGC(dbgc_class, \
					DBGLVL_WARNING,	(__VA_ARGS__))
#define DC_NOTICE(...)		DEBUGC(dbgc_class, \
					DBGLVL_NOTICE,	(__VA_ARGS__))
#define DC_INFO(...)		DEBUGC(dbgc_class, \
					DBGLVL_INFO,	(__VA_ARGS__))
#define DC_DEBUG(...)		DEBUGC(dbgc_class, \
					DBGLVL_DEBUG,	(__VA_ARGS__))

/* The following definitions come from lib/debug.c  */

/** Possible destinations for the debug log (in order of precedence -
 * once set to DEBUG_FILE, it is not possible to reset to DEBUG_STDOUT
 * for example.  This makes it easy to override for debug to stderr on
 * the command line, as the smb.conf cannot reset it back to
 * file-based logging */
enum debug_logtype {
	DEBUG_DEFAULT_STDERR = 0,
	DEBUG_DEFAULT_STDOUT = 1,
	DEBUG_FILE = 2,
	DEBUG_STDOUT = 3,
	DEBUG_STDERR = 4,
	DEBUG_CALLBACK = 5
};

struct debug_settings {
	size_t max_log_size;
	bool timestamp_logs;
	bool debug_prefix_timestamp;
	bool debug_hires_timestamp;
	bool debug_pid;
	bool debug_uid;
	bool debug_class;
};

void setup_logging(const char *prog_name, enum debug_logtype new_logtype);

void gfree_debugsyms(void);
int debug_add_class(const char *classname);
bool debug_parse_levels(const char *params_str);
void debug_setup_talloc_log(void);
void debug_set_logfile(const char *name);
void debug_set_settings(struct debug_settings *settings,
			const char *logging_param,
			int syslog_level, bool syslog_only);
bool reopen_logs_internal( void );
void force_check_log_size( void );
bool need_to_check_log_size( void );
void check_log_size( void );
void dbgflush( void );
bool debug_get_output_is_stderr(void);
bool debug_get_output_is_stdout(void);
void debug_schedule_reopen_logs(void);
char *debug_list_class_names_and_levels(void);

typedef void (*debug_callback_fn)(void *private_ptr, int level, const char *msg);

/**
   Set a callback for all debug messages.  Use in dlz_bind9 to push output to the bind logs
 */
void debug_set_callback(void *private_ptr, debug_callback_fn fn);

char *debug_get_ringbuf(void);
size_t debug_get_ringbuf_size(void);

#endif /* _SAMBA_DEBUG_H */
