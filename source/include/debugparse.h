#ifndef DEBUGPARSE_H
#define DEBUGPARSE_H
/* ========================================================================== **
 *                                debugparse.c
 *
 * Copyright (C) 1998 by Christopher R. Hertel
 *
 * Email: crh@ubiqx.mn.org
 *
 * -------------------------------------------------------------------------- **
 * This module is a very simple parser for Samba debug log files.
 * -------------------------------------------------------------------------- **
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * -------------------------------------------------------------------------- **
 * The important function in this module is dbg_char2token().  The rest is
 * basically fluff.  (Potentially useful fluff, but still fluff.)
 *
 * NOTE:  Use this header if you are compiling with Samba headers.  See
 *        debugparse-nonsamba.h for an alternate version.
 *
 * -------------------------------------------------------------------------- **
 *
 * $Log: debugparse.h,v $
 * Revision 1.2  1998/10/28 17:51:48  jra
 * Quick fixes to fix the broken tree. Needed for my morning compiles.
 * Chris - feel free to fix these things differently if these fixes don't
 * work for you.
 * Jeremy.
 *
 * Revision 1.1  1998/10/26 23:21:37  crh
 * Here is the simple debug parser and the debug2html converter.  Still to do:
 *
 *   * Debug message filtering.
 *   * I need to add all this to Makefile.in
 *     (If it looks at all strange I'll ask for help.)
 *
 * If you want to compile debug2html, you'll need to do it by hand until I
 * make the changes to Makefile.in.  Sorry.
 *
 * Chris -)-----
 *
 * ========================================================================== **
 */

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

/* -------------------------------------------------------------------------- */
#endif /* DEBUGPARSE_H */
