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

bool dbgtext( const char *, ... ) PRINTF_ATTRIBUTE(1,2);
bool dbghdrclass( int level, int cls, const char *location, const char *func);
bool dbghdr( int level, const char *location, const char *func);

/*
 * Redefine DEBUGLEVEL because so we don't have to change every source file
 * that *unnecessarily* references it.
 */
#define DEBUGLEVEL DEBUGLEVEL_CLASS[DBGC_ALL]

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

/* Always ensure this is updated when new fixed classes area added, to ensure the array in debug.c is the right size */
#define DBGC_MAX_FIXED		22

/* So you can define DBGC_CLASS before including debug.h */
#ifndef DBGC_CLASS
#define DBGC_CLASS            0     /* override as shown above */
#endif

extern int  *DEBUGLEVEL_CLASS;

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

#define CHECK_DEBUGLVL( level ) \
  ( ((level) <= MAX_DEBUG_LEVEL) && \
    unlikely(DEBUGLEVEL_CLASS[ DBGC_CLASS ] >= (level)))

#define CHECK_DEBUGLVLC( dbgc_class, level ) \
  ( ((level) <= MAX_DEBUG_LEVEL) && \
    unlikely(DEBUGLEVEL_CLASS[ dbgc_class ] >= (level)))

#define DEBUGLVL( level ) \
  ( CHECK_DEBUGLVL(level) \
   && dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ ) )

#define DEBUGLVLC( dbgc_class, level ) \
  ( CHECK_DEBUGLVLC( dbgc_class, level ) \
   && dbghdrclass( level, dbgc_class, __location__, __FUNCTION__ ) )

#define DEBUG( level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
	  unlikely(DEBUGLEVEL_CLASS[ DBGC_CLASS ] >= (level))		\
       && (dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ )) \
       && (dbgtext body) )

#define DEBUGC( dbgc_class, level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
	  unlikely(DEBUGLEVEL_CLASS[ dbgc_class ] >= (level))		\
       && (dbghdrclass( level, DBGC_CLASS, __location__, __FUNCTION__ )) \
       && (dbgtext body) )

#define DEBUGADD( level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
	  unlikely(DEBUGLEVEL_CLASS[ DBGC_CLASS ] >= (level))	\
       && (dbgtext body) )

#define DEBUGADDC( dbgc_class, level, body ) \
  (void)( ((level) <= MAX_DEBUG_LEVEL) && \
          unlikely((DEBUGLEVEL_CLASS[ dbgc_class ] >= (level))) \
       && (dbgtext body) )

/* Print a separator to the debug log. */
#define DEBUGSEP(level)\
	DEBUG((level),("===============================================================\n"))

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
	int syslog;
	bool syslog_only;
	bool timestamp_logs;
	bool debug_prefix_timestamp;
	bool debug_hires_timestamp;
	bool debug_pid;
	bool debug_uid;
	bool debug_class;
};

void setup_logging(const char *prog_name, enum debug_logtype new_logtype);

void debug_close_dbf(void);
void gfree_debugsyms(void);
int debug_add_class(const char *classname);
int debug_lookup_classname(const char *classname);
bool debug_parse_levels(const char *params_str);
void debug_setup_talloc_log(void);
void debug_set_logfile(const char *name);
void debug_set_settings(struct debug_settings *settings);
bool reopen_logs_internal( void );
void force_check_log_size( void );
bool need_to_check_log_size( void );
void check_log_size( void );
void dbgflush( void );
bool dbghdrclass(int level, int cls, const char *location, const char *func);
bool dbghdr(int level, const char *location, const char *func);
bool debug_get_output_is_stderr(void);
bool debug_get_output_is_stdout(void);
void debug_schedule_reopen_logs(void);
char *debug_list_class_names_and_levels(void);

typedef void (*debug_callback_fn)(void *private_ptr, int level, const char *msg);

/**
   Set a callback for all debug messages.  Use in dlz_bind9 to push output to the bind logs
 */
void debug_set_callback(void *private_ptr, debug_callback_fn fn);

#endif /* _SAMBA_DEBUG_H */
