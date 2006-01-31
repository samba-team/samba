/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   
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

/**
 * @file dynconfig.c
 *
 * @brief Global configurations, initialized to configured defaults.
 *
 * This file should be the only file that depends on path
 * configuration (--prefix, etc), so that if ./configure is re-run,
 * all programs will be appropriately updated.  Everything else in
 * Samba should import extern variables from here, rather than relying
 * on preprocessor macros.
 *
 * Eventually some of these may become even more variable, so that
 * they can for example consistently be set across the whole of Samba
 * by command-line parameters, config file entries, or environment
 * variables.
 *
 * @todo Perhaps eventually these should be merged into the parameter
 * table?  There's kind of a chicken-and-egg situation there...
 **/

/** Directory with super-user binaries */
const char *dyn_SBINDIR = SBINDIR;

/** Directory with generic binaries */
const char *dyn_BINDIR = BINDIR;

/**< Location of smb.conf file. **/
const char *dyn_CONFIGFILE = CONFIGFILE; 

/** Log file directory. **/
const char *dyn_LOGFILEBASE = LOGFILEBASE; 

/** Directory for local RPC (ncalrpc: transport) */
const char *dyn_NCALRPCDIR = NCALRPCDIR;

/** Statically configured LanMan hosts. **/
const char *dyn_LMHOSTSFILE = LMHOSTSFILE; 

/** Samba library directory. */
const char *dyn_LIBDIR = LIBDIR;

const char *dyn_MODULESDIR = MODULESDIR;

/** Shared library extension */
const char *dyn_SHLIBEXT = SHLIBEXT;

/**
 * @brief Directory holding lock files.
 *
 * Not writable, but used to set a default in the parameter table.
 **/
const char *dyn_LOCKDIR = LOCKDIR;

/** pid file directory */
const char *dyn_PIDDIR  = PIDDIR;

/** Private data directory; holds ldb files and the like */
const char *dyn_PRIVATE_DIR = PRIVATE_DIR;

/** SWAT data file (images, etc) directory */
const char *dyn_SWATDIR = SWATDIR;

/** SETUP files (source files used by the provision) */
const char *dyn_SETUPDIR = SETUPDIR;

/** EJS Javascript library includes */
const char *dyn_JSDIR = JSDIR;

/** Where to find the winbindd socket */

const char *dyn_WINBINDD_SOCKET_DIR = WINBINDD_SOCKET_DIR;

