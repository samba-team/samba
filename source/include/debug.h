/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB debug stuff
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) John H Terpstra 1996-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Paul Ashton 1998
   
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

#ifndef _DEBUG_H_
#define _DEBUG_H_

/* -------------------------------------------------------------------------- **
 * Debugging code.  See also debug.c
 */

/* mkproto.awk has trouble with ifdef'd function definitions (it ignores
 * the #ifdef directive and will read both definitions, thus creating two
 * diffferent prototype declarations), so we must do these by hand.
 */
/* I know the __attribute__ stuff is ugly, but it does ensure we get the 
   arguemnts to DEBUG() right. We have got them wrong too often in the 
   past.
 */
#ifdef HAVE_STDARG_H
int  Debug1( char *, ... )
#ifdef __GNUC__
     __attribute__ ((format (printf, 1, 2)))
#endif
;
BOOL dbgtext( char *, ... )
#ifdef __GNUC__
     __attribute__ ((format (printf, 1, 2)))
#endif
;
#else
int  Debug1();
BOOL dbgtext();
#endif

/* If we have these macros, we can add additional info to the header. */
#ifdef HAVE_FILE_MACRO
#define FILE_MACRO (__FILE__)
#else
#define FILE_MACRO ("")
#endif

#ifdef HAVE_FUNCTION_MACRO
#define FUNCTION_MACRO  (__FUNCTION__)
#else
#define FUNCTION_MACRO  ("")
#endif

/* Debugging macros. 
 *  DEBUGLVL() - If level is <= the system-wide DEBUGLEVEL then generate a
 *               header using the default macros for file, line, and
 *               function name.
 *               Returns True if the debug level was <= DEBUGLEVEL.
 *               Example usage:
 *                 if( DEBUGLVL( 2 ) )
 *                   dbgtext( "Some text.\n" );
 *  DEGUG()    - Good old DEBUG().  Each call to DEBUG() will generate a new
 *               header *unless* the previous debug output was unterminated
 *               (i.e., no '\n').  See debug.c:dbghdr() for more info.
 *               Example usage:
 *                 DEBUG( 2, ("Some text.\n") );
 *  DEBUGADD() - If level <= DEBUGLEVEL, then the text is appended to the
 *               current message (i.e., no header).
 *               Usage:
 *                 DEBUGADD( 2, ("Some additional text.\n") );
 */
#define DEBUGLVL( level ) \
  ( (DEBUGLEVEL >= (level)) \
   && dbghdr( level, FILE_MACRO, FUNCTION_MACRO, (__LINE__) ) )

#define DEBUG( level, body ) \
  (void)( (DEBUGLEVEL >= (level)) \
       && (dbghdr( level, FILE_MACRO, FUNCTION_MACRO, (__LINE__) )) \
       && (dbgtext body) )

#define DEBUGADD( level, body ) \
  (void)( (DEBUGLEVEL >= (level)) && (dbgtext body) )

/* -------------------------------------------------------------------------- **
 * These are the tokens returned by dbg_char2token().
 */

typedef enum
  {
  dbg_null = 0,
  dbg_ignore,
  dbg_header,
  dbg_timestamp,
  dbg_level,
  dbg_sourcefile,
  dbg_function,
  dbg_lineno,
  dbg_message,
  dbg_eof
  } dbg_Token;

/* End Debugging code section.
 * -------------------------------------------------------------------------- **
 */

#endif
