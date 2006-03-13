/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)  2003.
   Copyright (C) Stefan Metzmacher	2003
   
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
#include "version.h"

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
_PUBLIC_ const char *dyn_SBINDIR = SBINDIR;

/** Directory with generic binaries */
_PUBLIC_ const char *dyn_BINDIR = BINDIR;

/**< Location of smb.conf file. **/
_PUBLIC_ const char *dyn_CONFIGFILE = CONFIGFILE; 

/** Log file directory. **/
_PUBLIC_ const char *dyn_LOGFILEBASE = LOGFILEBASE; 

/** Directory for local RPC (ncalrpc: transport) */
_PUBLIC_ const char *dyn_NCALRPCDIR = NCALRPCDIR;

/** Statically configured LanMan hosts. **/
_PUBLIC_ const char *dyn_LMHOSTSFILE = LMHOSTSFILE; 

/** Samba data directory. */
_PUBLIC_ const char *dyn_DATADIR = DATADIR;

_PUBLIC_ const char *dyn_MODULESDIR = MODULESDIR;

/** Shared library extension */
_PUBLIC_ const char *dyn_SHLIBEXT = SHLIBEXT;

/**
 * @brief Directory holding lock files.
 *
 * Not writable, but used to set a default in the parameter table.
 **/
_PUBLIC_ const char *dyn_LOCKDIR = LOCKDIR;

/** pid file directory */
_PUBLIC_ const char *dyn_PIDDIR  = PIDDIR;

/** Private data directory; holds ldb files and the like */
_PUBLIC_ const char *dyn_PRIVATE_DIR = PRIVATE_DIR;

/** SWAT data file (images, etc) directory */
_PUBLIC_ const char *dyn_SWATDIR = SWATDIR;

/** SETUP files (source files used by the provision) */
_PUBLIC_ const char *dyn_SETUPDIR = SETUPDIR;

/** EJS Javascript library includes */
_PUBLIC_ const char *dyn_JSDIR = JSDIR;

/** Where to find the winbindd socket */

_PUBLIC_ const char *dyn_WINBINDD_SOCKET_DIR = WINBINDD_SOCKET_DIR;

_PUBLIC_ const char *samba_version_string(void)
{
	const char *official_string = SAMBA_VERSION_OFFICIAL_STRING;
#ifdef SAMBA_VERSION_RELEASE_NICKNAME
 	const char *release_nickname = SAMBA_VERSION_RELEASE_NICKNAME;
#else
 	const char *release_nickname = NULL;
#endif
#ifdef SAMBA_VERSION_VENDOR_SUFFIX
 	const char *vendor_suffix = SAMBA_VERSION_VENDOR_SUFFIX;
#else
 	const char *vendor_suffix = NULL;
#endif
#ifdef SAMBA_VERSION_VENDOR_PATCH
 	const char *vendor_patch = SAMBA_VERSION_VENDOR_PATCH;
#else
 	const char *vendor_patch = NULL;
#endif
	static char *samba_version;
	static BOOL init_samba_version;

	if (init_samba_version) {
		return samba_version;
	}

	samba_version = talloc_asprintf(talloc_autofree_context(),
					"%s%s%s%s%s%s%s%s",
					official_string,
					(vendor_suffix?"-":""),
					(vendor_suffix?vendor_suffix:""),
					(vendor_patch?"-":""),
					(vendor_patch?vendor_patch:""),
					(release_nickname?" (":""),
					(release_nickname?release_nickname:""),
					(release_nickname?")":""));

	init_samba_version = True;
	return samba_version;
}
