/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* -------------------------------------------------------------------------- **
 * Defines...
 *
 *  FORMAT_BUFR_MAX - Index of the last byte of the format buffer;
 *                    format_bufr[FORMAT_BUFR_MAX] should always be reserved
 *                    for a terminating nul byte.
 */

#define FORMAT_BUFR_MAX ( sizeof( format_bufr ) - 1 )

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

/* -------------------------------------------------------------------------- **
 * External variables.
 *
 *  dbf           - Global debug file handle.
 *  debugf        - Debug file name.
 *  append_log    - If True, then the output file will be opened in append
 *                  mode.
 *  DEBUGLEVEL    - System-wide debug message limit.  Messages with message-
 *                  levels higher than DEBUGLEVEL will not be processed.
 */

FILE   *dbf        = NULL;
pstring debugf     = "";
BOOL    append_log = False;

int     DEBUGLEVEL_CLASS[DBGC_LAST];
int     DEBUGLEVEL = DEBUGLEVEL_CLASS;
BOOL	AllowDebugChange = True;
int	parsed_debuglevel_class[DBGC_LAST];

/* -------------------------------------------------------------------------- **
 * Internal variables.
 *
 *  stdout_logging  - Default False, if set to True then dbf will be set to
 *                    stdout and debug output will go to dbf only, and not
 *                    to syslog.  Set in setup_logging() and read in Debug1().
 *
 *  debug_count     - Number of debug messages that have been output.
 *                    Used to check log size.
 *
 *  syslog_level    - Internal copy of the message debug level.  Written by
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
 *  log_overflow    - When this variable is True, never attempt to check the
 *                    size of the log. This is a hack, so that we can write
 *                    a message using DEBUG, from open_logs() when we
 *                    are unable to open a new log file for some reason.
 */

static BOOL    stdout_logging = False;
static int     debug_count    = 0;
#ifdef WITH_SYSLOG
static int     syslog_level   = 0;
#endif
static pstring format_bufr    = { '\0' };
static size_t     format_pos     = 0;
static BOOL    log_overflow   = False;

/*
* Define all the debug class selection names here. Names *MUST NOT* contain 
* white space. There must be one name for each DBGC_<class name>, and they 
* must be in the table in the order of DBGC_<class name>.. 
*/
const char *classname_table[] = {
	"all",               /* DBGC_ALL; index references traditional DEBUGLEVEL */
	"tdb",               /* DBGC_TDB	*/
	"printdrivers",      /* DBGC_PRINTDRIVERS */
	"lanman",            /* DBGC_LANMAN */
};


/* -------------------------------------------------------------------------- **
 * Functions...
 */

/****************************************************************************
utility access to debug class names's
****************************************************************************/
const char* debug_classname_from_index(int ndx)
{
	return classname_table[ndx];
}

/****************************************************************************
utility to translate names to debug class index's
****************************************************************************/
int debug_lookup_classname(char* classname)
{
	int i;

	if (!classname) return -1;

	for (i=0; i<DBGC_LAST; i++) {
		if (strcmp(classname, classname_table[i])==0)
			return i;
	}
	return -1;
}

/****************************************************************************
parse the debug levels from smbcontrol. Example debug level parameter:
  printdrivers:7
****************************************************************************/
BOOL debug_parse_params(char **params, int *debuglevel_class)
{
	int   i, ndx;
	char *class_name;
	char *class_level;
	
	/* Set the new debug level array to the current DEBUGLEVEL array */
	memcpy(debuglevel_class, DEBUGLEVEL_CLASS, sizeof(DEBUGLEVEL_CLASS));

	/* Allow DBGC_ALL to be specifies w/o requiring its class name e.g."10"  
	 * v.s. "all:10", this is the traditional way to set DEBUGLEVEL 
	 */
	if (isdigit((int)params[0][0])) {
		debuglevel_class[DBGC_ALL] = atoi(params[0]);
		i = 1; /* start processing at the next params */
	}
	else
		i = 0; /* DBGC_ALL not specified  OR calss name was included */

	/* Fill in new debug class levels */
	for (; i < DBGC_LAST && params[i]; i++) {
		if ((class_name=strtok(params[i],":")) &&
			(class_level=strtok(NULL, "\0")) &&
            ((ndx = debug_lookup_classname(class_name)) != -1)) {
				debuglevel_class[ndx] = atoi(class_level);
		} else {
			DEBUG(0,("debug_parse_params: unrecognized debug class name or format [%s]\n", params[i]));
			return False;
		}
	}

	return True;
}

/****************************************************************************
parse the debug levels from smb.conf. Example debug level string:
  3 tdb:5 printdrivers:7
Note: the 1st param has no "name:" preceeding it.
****************************************************************************/
BOOL debug_parse_levels(char *params_str)
{
	int  i;
	char *params[DBGC_LAST];
	int  debuglevel_class[DBGC_LAST];	

	ZERO_ARRAY(params);
	ZERO_ARRAY(debuglevel_class);

	if ((params[0]=strtok(params_str," ,"))) {
		for (i=1; i<DBGC_LAST;i++) {
			if ((params[i]=strtok(NULL," ,"))==NULL)
				break;
		}
	}
	else
		return False;

	if (AllowDebugChange == False) {
		int old_debuglevel_class[DBGC_LAST];

		/* save current debug level */
		memcpy(old_debuglevel_class, DEBUGLEVEL_CLASS, sizeof(DEBUGLEVEL_CLASS));
		if (debug_parse_params(params, debuglevel_class))
			memcpy(parsed_debuglevel_class, debuglevel_class, sizeof(DEBUGLEVEL_CLASS));
		memcpy(DEBUGLEVEL_CLASS, old_debuglevel_class, sizeof(old_debuglevel_class));
		return True;
	}
	if (debug_parse_params(params, debuglevel_class)) {
		debug_message(MSG_DEBUG, getpid(), (void*)debuglevel_class, sizeof(debuglevel_class));
		return True;
	} else
		return False;
}

/****************************************************************************
receive a "set debug level" message
****************************************************************************/
void debug_message(int msg_type, pid_t src, void *buf, size_t len)
{
	int i;

	/* Set the new DEBUGLEVEL_CLASS array from the pased array */
	memcpy(DEBUGLEVEL_CLASS, buf, sizeof(DEBUGLEVEL_CLASS));
	
	DEBUG(1,("INFO: Debug class %s level = %d   (pid %u from pid %u)\n",
			classname_table[DBGC_ALL],
			DEBUGLEVEL_CLASS[DBGC_ALL], (unsigned int)getpid(), (unsigned int)src));

	for (i=1; i<DBGC_LAST; i++) {
		if (DEBUGLEVEL_CLASS[i])
			 DEBUGADD(1,("INFO: Debug class %s level = %d\n", 
						classname_table[i], DEBUGLEVEL_CLASS[i]));
	}
}


/****************************************************************************
send a "set debug level" message
****************************************************************************/
void debug_message_send(pid_t pid, int level)
{
	message_send_pid(pid, MSG_DEBUG, &level, sizeof(int), False);
}


/* ************************************************************************** **
 * get ready for syslog stuff
 * ************************************************************************** **
 */
void setup_logging(const char *pname, BOOL interactive)
{
	message_register(MSG_DEBUG, debug_message);

	/* reset to allow multiple setup calls, going from interactive to
	   non-interactive */
	stdout_logging = False;
	dbf = NULL;

	if (interactive) {
		stdout_logging = True;
		dbf = stdout;
	}
#ifdef WITH_SYSLOG
	else {
		char *p = strrchr( pname,'/' );
		if (p)
			pname = p + 1;
#ifdef LOG_DAEMON
		openlog( pname, LOG_PID, SYSLOG_FACILITY );
#else /* for old systems that have no facility codes. */
		openlog( pname, LOG_PID );
#endif
	}
#endif
} /* setup_logging */

/* ************************************************************************** **
 * reopen the log files
 * note that we now do this unconditionally
 * We attempt to open the new debug fp before closing the old. This means
 * if we run out of fd's we just keep using the old fd rather than aborting.
 * Fix from dgibson@linuxcare.com.
 * ************************************************************************** **
 */

BOOL reopen_logs( void )
{
	pstring fname;
	mode_t oldumask;
	FILE *new_dbf = NULL;
	BOOL ret = True;

	if (stdout_logging)
		return True;

	oldumask = umask( 022 );
  
	pstrcpy(fname, debugf );

	if (lp_loaded()) {
		char *logfname;

		logfname = lp_logfile();
		if (*logfname)
			pstrcpy(fname, logfname);
	}

	pstrcpy(debugf, fname);

	if (append_log)
		new_dbf = sys_fopen( debugf, "a" );
	else
		new_dbf = sys_fopen( debugf, "w" );

	if (!new_dbf) {
		log_overflow = True;
		DEBUG(0, ("Unable to open new log file %s: %s\n", debugf, strerror(errno)));
		log_overflow = False;
		if (dbf)
			fflush(dbf);
		ret = False;
	} else {
		setbuf(new_dbf, NULL);
		if (dbf)
			(void) fclose(dbf);
		dbf = new_dbf;
	}

	/* Fix from klausr@ITAP.Physik.Uni-Stuttgart.De
	 * to fix problem where smbd's that generate less
	 * than 100 messages keep growing the log.
	 */
	force_check_log_size();
	(void)umask(oldumask);

	return ret;
}

/* ************************************************************************** **
 * Force a check of the log size.
 * ************************************************************************** **
 */
void force_check_log_size( void )
{
  debug_count = 100;
}

/***************************************************************************
 Check to see if there is any need to check if the logfile has grown too big.
**************************************************************************/

BOOL need_to_check_log_size( void )
{
	int maxlog;

	if( debug_count++ < 100 )
		return( False );

	maxlog = lp_max_log_size() * 1024;
	if( !dbf || maxlog <= 0 ) {
		debug_count = 0;
		return(False);
	}
	return( True );
}

/* ************************************************************************** **
 * Check to see if the log has grown to be too big.
 * ************************************************************************** **
 */

void check_log_size( void )
{
	int         maxlog;
	SMB_STRUCT_STAT st;

	/*
	 *  We need to be root to check/change log-file, skip this and let the main
	 *  loop check do a new check as root.
	 */

	if( geteuid() != 0 )
		return;

	if(log_overflow || !need_to_check_log_size() )
		return;

	maxlog = lp_max_log_size() * 1024;

	if( sys_fstat( fileno( dbf ), &st ) == 0 && st.st_size > maxlog ) {
		(void)reopen_logs();
		if( dbf && get_file_size( debugf ) > maxlog ) {
			pstring name;

			slprintf( name, sizeof(name)-1, "%s.old", debugf );
			(void)rename( debugf, name );
      
			if (!reopen_logs()) {
				/* We failed to reopen a log - continue using the old name. */
				(void)rename(name, debugf);
			}
		}
	}

	/*
	 * Here's where we need to panic if dbf == NULL..
	 */

	if(dbf == NULL) {
		/* This code should only be reached in very strange
			circumstances. If we merely fail to open the new log we
			should stick with the old one. ergo this should only be
			reached when opening the logs for the first time: at
			startup or when the log level is increased from zero.
			-dwg 6 June 2000
		*/
		dbf = sys_fopen( "/dev/console", "w" );
		if(dbf) {
			DEBUG(0,("check_log_size: open of debug file %s failed - using console.\n",
					debugf ));
		} else {
			/*
			 * We cannot continue without a debug file handle.
			 */
			abort();
		}
	}
	debug_count = 0;
} /* check_log_size */

/* ************************************************************************** **
 * Write an debug message on the debugfile.
 * This is called by dbghdr() and format_debug_text().
 * ************************************************************************** **
 */
 int Debug1( const char *format_str, ... )
{
  va_list ap;  
  int old_errno = errno;

  if( stdout_logging )
    {
    va_start( ap, format_str );
    if(dbf)
      (void)vfprintf( dbf, format_str, ap );
    va_end( ap );
    errno = old_errno;
    return( 0 );
    }
  
#ifdef WITH_SYSLOG
  if( !lp_syslog_only() )
#endif
    {
    if( !dbf )
      {
      mode_t oldumask = umask( 022 );

      if( append_log )
        dbf = sys_fopen( debugf, "a" );
      else
        dbf = sys_fopen( debugf, "w" );
      (void)umask( oldumask );
      if( dbf )
        {
        setbuf( dbf, NULL );
        }
      else
        {
        errno = old_errno;
        return(0);
        }
      }
    }

#ifdef WITH_SYSLOG
  if( syslog_level < lp_syslog() )
    {
    /* map debug levels to syslog() priorities
     * note that not all DEBUG(0, ...) calls are
     * necessarily errors
     */
    static int priority_map[] = { 
      LOG_ERR,     /* 0 */
      LOG_WARNING, /* 1 */
      LOG_NOTICE,  /* 2 */
      LOG_INFO,    /* 3 */
      };
    int     priority;
    pstring msgbuf;

    if( syslog_level >= ( sizeof(priority_map) / sizeof(priority_map[0]) )
     || syslog_level < 0)
      priority = LOG_DEBUG;
    else
      priority = priority_map[syslog_level];
      
    va_start( ap, format_str );
    vslprintf( msgbuf, sizeof(msgbuf)-1, format_str, ap );
    va_end( ap );
      
    msgbuf[255] = '\0';
    syslog( priority, "%s", msgbuf );
    }
#endif
  
  check_log_size();

#ifdef WITH_SYSLOG
  if( !lp_syslog_only() )
#endif
    {
    va_start( ap, format_str );
    if(dbf)
      (void)vfprintf( dbf, format_str, ap );
    va_end( ap );
    if(dbf)
      (void)fflush( dbf );
    }

  errno = old_errno;

  return( 0 );
  } /* Debug1 */


/* ************************************************************************** **
 * Print the buffer content via Debug1(), then reset the buffer.
 *
 *  Input:  none
 *  Output: none
 *
 * ************************************************************************** **
 */
static void bufr_print( void )
  {
  format_bufr[format_pos] = '\0';
  (void)Debug1( "%s", format_bufr );
  format_pos = 0;
  } /* bufr_print */

/* ************************************************************************** **
 * Format the debug message text.
 *
 *  Input:  msg - Text to be added to the "current" debug message text.
 *
 *  Output: none.
 *
 *  Notes:  The purpose of this is two-fold.  First, each call to syslog()
 *          (used by Debug1(), see above) generates a new line of syslog
 *          output.  This is fixed by storing the partial lines until the
 *          newline character is encountered.  Second, printing the debug
 *          message lines when a newline is encountered allows us to add
 *          spaces, thus indenting the body of the message and making it
 *          more readable.
 *
 * ************************************************************************** **
 */
static void format_debug_text( char *msg )
  {
  size_t i;
  BOOL timestamp = (!stdout_logging && (lp_timestamp_logs() || 
					!(lp_loaded())));

  for( i = 0; msg[i]; i++ )
    {
    /* Indent two spaces at each new line. */
    if(timestamp && 0 == format_pos)
      {
      format_bufr[0] = format_bufr[1] = ' ';
      format_pos = 2;
      }

    /* If there's room, copy the character to the format buffer. */
    if( format_pos < FORMAT_BUFR_MAX )
      format_bufr[format_pos++] = msg[i];

    /* If a newline is encountered, print & restart. */
    if( '\n' == msg[i] )
      bufr_print();

    /* If the buffer is full dump it out, reset it, and put out a line
     * continuation indicator.
     */
    if( format_pos >= FORMAT_BUFR_MAX )
      {
      bufr_print();
      (void)Debug1( " +>\n" );
      }
    }

  /* Just to be safe... */
  format_bufr[format_pos] = '\0';
  } /* format_debug_text */

/* ************************************************************************** **
 * Flush debug output, including the format buffer content.
 *
 *  Input:  none
 *  Output: none
 *
 * ************************************************************************** **
 */
void dbgflush( void )
  {
  bufr_print();
  if(dbf)
    (void)fflush( dbf );
  } /* dbgflush */

/* ************************************************************************** **
 * Print a Debug Header.
 *
 *  Input:  level - Debug level of the message (not the system-wide debug
 *                  level.
 *          file  - Pointer to a string containing the name of the file
 *                  from which this function was called, or an empty string
 *                  if the __FILE__ macro is not implemented.
 *          func  - Pointer to a string containing the name of the function
 *                  from which this function was called, or an empty string
 *                  if the __FUNCTION__ macro is not implemented.
 *          line  - line number of the call to dbghdr, assuming __LINE__
 *                  works.
 *
 *  Output: Always True.  This makes it easy to fudge a call to dbghdr()
 *          in a macro, since the function can be called as part of a test.
 *          Eg: ( (level <= DEBUGLEVEL) && (dbghdr(level,"",line)) )
 *
 *  Notes:  This function takes care of setting syslog_level.
 *
 * ************************************************************************** **
 */

BOOL dbghdr( int level, const char *file, const char *func, int line )
{
  /* Ensure we don't lose any real errno value. */
  int old_errno = errno;

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
    return( True );
  }

#ifdef WITH_SYSLOG
  /* Set syslog_level. */
  syslog_level = level;
#endif

  /* Don't print a header if we're logging to stdout. */
  if( stdout_logging )
    return( True );

  /* Print the header if timestamps are turned on.  If parameters are
   * not yet loaded, then default to timestamps on.
   */
  if( lp_timestamp_logs() || !(lp_loaded()) ) {
    char header_str[200];

	header_str[0] = '\0';

	if( lp_debug_pid())
	  slprintf(header_str,sizeof(header_str)-1,", pid=%u",(unsigned int)sys_getpid());

	if( lp_debug_uid()) {
      size_t hs_len = strlen(header_str);
	  slprintf(header_str + hs_len,
               sizeof(header_str) - 1 - hs_len,
			   ", effective(%u, %u), real(%u, %u)",
               (unsigned int)geteuid(), (unsigned int)getegid(),
			   (unsigned int)getuid(), (unsigned int)getgid()); 
	}
  
    /* Print it all out at once to prevent split syslog output. */
    (void)Debug1( "[%s, %d%s] %s:%s(%d)\n",
                  timestring(lp_debug_hires_timestamp()), level,
				  header_str, file, func, line );
  }

  errno = old_errno;
  return( True );
}

/* ************************************************************************** **
 * Add text to the body of the "current" debug message via the format buffer.
 *
 *  Input:  format_str  - Format string, as used in printf(), et. al.
 *          ...         - Variable argument list.
 *
 *  ..or..  va_alist    - Old style variable parameter list starting point.
 *
 *  Output: Always True.  See dbghdr() for more info, though this is not
 *          likely to be used in the same way.
 *
 * ************************************************************************** **
 */
 BOOL dbgtext( const char *format_str, ... )
  {
  va_list ap;
  pstring msgbuf;

  va_start( ap, format_str ); 
  vslprintf( msgbuf, sizeof(msgbuf)-1, format_str, ap );
  va_end( ap );

  format_debug_text( msgbuf );

  return( True );
  } /* dbgtext */


/* ************************************************************************** */
