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
 *  timestamp_log - 
 *  DEBUGLEVEL    - System-wide debug message limit.  Messages with message-
 *                  levels higher than DEBUGLEVEL will not be processed.
 */

FILE   *dbf        = NULL;
pstring debugf     = "";
BOOL    append_log = False;
BOOL    timestamp_log = True;
int     DEBUGLEVEL = 1;


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
 */

static BOOL    stdout_logging = False;
static int     debug_count    = 0;
#ifdef WITH_SYSLOG
static int     syslog_level   = 0;
#endif
static pstring format_bufr    = { '\0' };
static size_t     format_pos     = 0;


/* -------------------------------------------------------------------------- **
 * Functions...
 */

/* ************************************************************************** **
 * tells us if interactive logging was requested
 * ************************************************************************** **
 */
BOOL dbg_interactive(void)
{
	return stdout_logging;
}

#if defined(SIGUSR2) && !defined(MEM_MAN)
/* ************************************************************************** **
 * catch a sigusr2 - decrease the debug log level.
 * ************************************************************************** **
 */
void sig_usr2( int sig )
  {
  BlockSignals( True, SIGUSR2 );

  DEBUGLEVEL--;
  if( DEBUGLEVEL < 0 )
    DEBUGLEVEL = 0;

  DEBUG( 0, ( "Got SIGUSR2; set debug level to %d.\n", DEBUGLEVEL ) );

  BlockSignals( False, SIGUSR2 );
  CatchSignal( SIGUSR2, SIGNAL_CAST sig_usr2 );

  } /* sig_usr2 */
#endif /* SIGUSR2 */

#if defined(SIGUSR1) && !defined(MEM_MAN)
/* ************************************************************************** **
 * catch a sigusr1 - increase the debug log level. 
 * ************************************************************************** **
 */
void sig_usr1( int sig )
  {
  BlockSignals( True, SIGUSR1 );

  DEBUGLEVEL++;

  if( DEBUGLEVEL > 10 )
    DEBUGLEVEL = 10;

  DEBUG( 0, ( "Got SIGUSR1; set debug level to %d.\n", DEBUGLEVEL ) );

  BlockSignals( False, SIGUSR1 );
  CatchSignal( SIGUSR1, SIGNAL_CAST sig_usr1 );

  } /* sig_usr1 */
#endif /* SIGUSR1 */


/* ************************************************************************** **
 * get ready for syslog stuff
 * ************************************************************************** **
 */
void setup_logging( char *pname, BOOL interactive )
  {
  if( interactive )
    {
    stdout_logging = True;
    dbf = stdout;
    }
#ifdef WITH_SYSLOG
  else
    {
    char *p = strrchr( pname,'/' );

    if( p )
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
 * ************************************************************************** **
 */
void reopen_logs( void )
  {
  pstring fname;
  
  if( DEBUGLEVEL > 0 )
    {
    pstrcpy( fname, debugf );
    if( lp_loaded() && (*lp_logfile()) )
      pstrcpy( fname, lp_logfile() );

    if( !strcsequal( fname, debugf ) || !dbf || !file_exist( debugf, NULL ) )
      {
      mode_t oldumask = umask( 022 );

      pstrcpy( debugf, fname );
      if( dbf )
        (void)fclose( dbf );
      if( append_log )
        dbf = sys_fopen( debugf, "a" );
      else
        dbf = sys_fopen( debugf, "w" );
      /* Fix from klausr@ITAP.Physik.Uni-Stuttgart.De
       * to fix problem where smbd's that generate less
       * than 100 messages keep growing the log.
       */
      force_check_log_size();
      if( dbf )
        setbuf( dbf, NULL );
      (void)umask( oldumask );
      }
    }
  else
    {
    if( dbf )
      {
      (void)fclose( dbf );
      dbf = NULL;
      }
    }
  } /* reopen_logs */

/* ************************************************************************** **
 * Force a check of the log size.
 * ************************************************************************** **
 */
void force_check_log_size( void )
  {
  debug_count = 100;
  } /* force_check_log_size */

/* ************************************************************************** **
 * Check to see if the log has grown to be too big.
 * ************************************************************************** **
 */
static void check_log_size( void )
{
  int         maxlog;
  SMB_STRUCT_STAT st;

  if( debug_count++ < 100 || geteuid() != 0 )
    return;

  maxlog = lp_max_log_size() * 1024;
  if( !dbf || maxlog <= 0 )
    return;

  if( sys_fstat( fileno( dbf ), &st ) == 0 && st.st_size > maxlog )
    {
    (void)fclose( dbf );
    dbf = NULL;
    reopen_logs();
    if( dbf && get_file_size( debugf ) > maxlog )
      {
      pstring name;

      (void)fclose( dbf );
      dbf = NULL;
      slprintf( name, sizeof(name)-1, "%s.old", debugf );
      (void)rename( debugf, name );
      reopen_logs();
      }
    }
  debug_count = 0;
} /* check_log_size */

/* ************************************************************************** **
 * Write an debug message on the debugfile.
 * This is called by dbghdr() and format_debug_text().
 * ************************************************************************** **
 */
#ifdef HAVE_STDARG_H
 int Debug1( char *format_str, ... )
{
#else
 int Debug1(va_alist)
va_dcl
{  
  char *format_str;
#endif
  va_list ap;  
  int old_errno = errno;

  if( stdout_logging )
    {
#ifdef HAVE_STDARG_H
    va_start( ap, format_str );
#else
    va_start( ap );
    format_str = va_arg( ap, char * );
#endif
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
      
#ifdef HAVE_STDARG_H
    va_start( ap, format_str );
#else
    va_start( ap );
    format_str = va_arg( ap, char * );
#endif
    vslprintf( msgbuf, sizeof(msgbuf)-1, format_str, ap );
    va_end( ap );
      
    msgbuf[255] = '\0';
    syslog( priority, "%s", msgbuf );
    }
#endif
  
#ifdef WITH_SYSLOG
  if( !lp_syslog_only() )
#endif
    {
#ifdef HAVE_STDARG_H
    va_start( ap, format_str );
#else
    va_start( ap );
    format_str = va_arg( ap, char * );
#endif
    if(dbf)
      (void)vfprintf( dbf, format_str, ap );
    va_end( ap );
    if(dbf)
      (void)fflush( dbf );
    }

  check_log_size();

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
  BOOL timestamp = (timestamp_log && !stdout_logging && (lp_timestamp_logs() || 
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

BOOL dbghdr( int level, char *file, char *func, int line )
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
  if( timestamp_log && (lp_timestamp_logs() || !(lp_loaded()) ))
    {
    char header_str[200];

	header_str[0] = '\0';

	if( lp_debug_pid())
	  slprintf(header_str,sizeof(header_str)-1,", pid=%u",(unsigned int)getpid());

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
#ifdef HAVE_STDARG_H
 BOOL dbgtext( char *format_str, ... )
  {
  va_list ap;
  pstring msgbuf;

  va_start( ap, format_str ); 
  vslprintf( msgbuf, sizeof(msgbuf)-1, format_str, ap );
  va_end( ap );

  format_debug_text( msgbuf );

  return( True );
  } /* dbgtext */

#else
 BOOL dbgtext( va_alist )
 va_dcl
  {
  char *format_str;
  va_list ap;
  pstring msgbuf;

  va_start( ap );
  format_str = va_arg( ap, char * );
  vslprintf( msgbuf, sizeof(msgbuf)-1, format_str, ap );
  va_end( ap );

  format_debug_text( msgbuf );

  return( True );
  } /* dbgtext */

#endif

dbg_Token dbg_char2token( dbg_Token *state, int c )
  /* ************************************************************************ **
   * Parse input one character at a time.
   *
   *  Input:  state - A pointer to a token variable.  This is used to
   *                  maintain the parser state between calls.  For
   *                  each input stream, you should set up a separate
   *                  state variable and initialize it to dbg_null.
   *                  Pass a pointer to it into this function with each
   *                  character in the input stream.  See dbg_test()
   *                  for an example.
   *          c     - The "current" character in the input stream.
   *
   *  Output: A token.
   *          The token value will change when delimiters are found,
   *          which indicate a transition between syntactical objects.
   *          Possible return values are:
   *
   *          dbg_null        - The input character was an end-of-line.
   *                            This resets the parser to its initial state
   *                            in preparation for parsing the next line.
   *          dbg_eof         - Same as dbg_null, except that the character
   *                            was an end-of-file.
   *          dbg_ignore      - Returned for whitespace and delimiters.
   *                            These lexical tokens are only of interest
   *                            to the parser.
   *          dbg_header      - Indicates the start of a header line.  The
   *                            input character was '[' and was the first on
   *                            the line.
   *          dbg_timestamp   - Indicates that the input character was part
   *                            of a header timestamp.
   *          dbg_level       - Indicates that the input character was part
   *                            of the debug-level value in the header.
   *          dbg_sourcefile  - Indicates that the input character was part
   *                            of the sourcefile name in the header.
   *          dbg_function    - Indicates that the input character was part
   *                            of the function name in the header.
   *          dbg_lineno      - Indicates that the input character was part
   *                            of the DEBUG call line number in the header.
   *          dbg_message     - Indicates that the input character was part
   *                            of the DEBUG message text.
   *
   * ************************************************************************ **
   */
  {
  /* The terminating characters that we see will greatly depend upon
   * how they are read.  For example, if gets() is used instead of
   * fgets(), then we will not see newline characters.  A lot also
   * depends on the calling function, which may handle terminators
   * itself.
   *
   * '\n', '\0', and EOF are all considered line terminators.  The
   * dbg_eof token is sent back if an EOF is encountered.
   *
   * Warning:  only allow the '\0' character to be sent if you are
   *           using gets() to read whole lines (thus replacing '\n'
   *           with '\0').  Sending '\0' at the wrong time will mess
   *           up the parsing.
   */
  switch( c )
    {
    case EOF:
      *state = dbg_null;   /* Set state to null (initial state) so */
      return( dbg_eof );   /* that we can restart with new input.  */
    case '\n':
    case '\0':
      *state = dbg_null;   /* A newline or eoln resets to the null state. */
      return( dbg_null );
    }

  /* When within the body of the message, only a line terminator
   * can cause a change of state.  We've already checked for line
   * terminators, so if the current state is dbg_msgtxt, simply
   * return that as our current token.
   */
  if( dbg_message == *state )
    return( dbg_message );

  /* If we are at the start of a new line, and the input character 
   * is an opening bracket, then the line is a header line, otherwise
   * it's a message body line.
   */
  if( dbg_null == *state )
    {
    if( '[' == c )
      {
      *state = dbg_timestamp;
      return( dbg_header );
      }
    *state = dbg_message;
    return( dbg_message );
    }

  /* We've taken care of terminators, text blocks and new lines.
   * The remaining possibilities are all within the header line
   * itself.
   */

  /* Within the header line, whitespace can be ignored *except*
   * within the timestamp.
   */
  if( isspace( c ) )
    {
    /* Fudge.  The timestamp may contain space characters. */
    if( (' ' == c) && (dbg_timestamp == *state) )
      return( dbg_timestamp );
    /* Otherwise, ignore whitespace. */
    return( dbg_ignore );
    }

  /* Okay, at this point we know we're somewhere in the header.
   * Valid header *states* are: dbg_timestamp, dbg_level,
   * dbg_sourcefile, dbg_function, and dbg_lineno.
   */
  switch( c )
    {
    case ',':
      if( dbg_timestamp == *state )
        {
        *state = dbg_level;
        return( dbg_ignore );
        }
      break;
    case ']':
      if( dbg_level == *state )
        {
        *state = dbg_sourcefile;
        return( dbg_ignore );
        }
      break;
    case ':':
      if( dbg_sourcefile == *state )
        {
        *state = dbg_function;
        return( dbg_ignore );
        }
      break;
    case '(':
      if( dbg_function == *state )
        {
        *state = dbg_lineno;
        return( dbg_ignore );
        }
      break;
    case ')':
      if( dbg_lineno == *state )
        {
        *state = dbg_null;
        return( dbg_ignore );
        }
      break;
    }

  /* If the previous block did not result in a state change, then
   * return the current state as the current token.
   */
  return( *state );
  } /* dbg_char2token */

/* ************************************************************************** */
