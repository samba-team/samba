/*
   Unix SMB/CIFS implementation.
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) 2003 by Jim McDonough <jmcd@us.ibm.com>
   Copyright (C) 2007 by Jeremy Allison <jra@samba.org>

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

#include "includes.h"

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

#if 0
static char const *dyn_SBINDIR = SBINDIR;
static char const *dyn_BINDIR = BINDIR;
static char const *dyn_SWATDIR = SWATDIR;
#endif

#define DEFINE_DYN_CONFIG_PARAM(name) \
static char *dyn_##name; \
\
 const char *get_dyn_##name(void) \
{\
	if (dyn_##name == NULL) {\
		return name;\
	}\
	return dyn_##name;\
}\
\
 const char *set_dyn_##name(const char *newpath) \
{\
	if (dyn_##name) {\
		SAFE_FREE(dyn_##name);\
	}\
	dyn_##name = SMB_STRDUP(newpath);\
	return dyn_##name;\
}\
\
 bool is_default_dyn_##name(void) \
{\
	return (dyn_##name == NULL);\
}

DEFINE_DYN_CONFIG_PARAM(SBINDIR)
DEFINE_DYN_CONFIG_PARAM(BINDIR)
DEFINE_DYN_CONFIG_PARAM(SWATDIR)
DEFINE_DYN_CONFIG_PARAM(CONFIGFILE) /**< Location of smb.conf file. **/
DEFINE_DYN_CONFIG_PARAM(LOGFILEBASE) /** Log file directory. **/
DEFINE_DYN_CONFIG_PARAM(LMHOSTSFILE) /** Statically configured LanMan hosts. **/
DEFINE_DYN_CONFIG_PARAM(CODEPAGEDIR)
DEFINE_DYN_CONFIG_PARAM(LIBDIR)
DEFINE_DYN_CONFIG_PARAM(SHLIBEXT)
DEFINE_DYN_CONFIG_PARAM(LOCKDIR)
DEFINE_DYN_CONFIG_PARAM(PIDDIR)
DEFINE_DYN_CONFIG_PARAM(SMB_PASSWD_FILE)
DEFINE_DYN_CONFIG_PARAM(PRIVATE_DIR)

#if 0
static char *dyn_CONFIGFILE; /**< Location of smb.conf file. **/

const char *get_dyn_CONFIGFILE(void)
{
	if (dyn_CONFIGFILE == NULL) {
		return CONFIGFILE;
	}
	return dyn_CONFIGFILE;
}

const char *set_dyn_CONFIGFILE(const char *newpath)
{
	if (dyn_CONFIGFILE) {
		SAFE_FREE(dyn_CONFIGFILE);
	}
	dyn_CONFIGFILE = SMB_STRDUP(newpath);
	return dyn_CONFIGFILE;
}

/** Log file directory. **/
static char *dyn_LOGFILEBASE;

const char *get_dyn_LOGFILEBASE(void)
{
	if (dyn_LOGFILEBASE == NULL) {
		return LOGFILEBASE;
	}
	return dyn_LOGFILEBASE;
}

const char *set_dyn_LOGFILEBASE(const char *newpath)
{
	if (dyn_LOGFILEBASE) {
		SAFE_FREE(dyn_LOGFILEBASE);
	}
	dyn_LOGFILEBASE = SMB_STRDUP(newpath);
	return dyn_LOGFILEBASE;
}

/** Statically configured LanMan hosts. **/
static char *dyn_LMHOSTSFILE;

const char *get_dyn_LMHOSTSFILE(void)
{
	if (dyn_LMHOSTSFILE == NULL) {
		return LMHOSTSFILE;
	}
	return dyn_LMHOSTSFILE;
}

const char *set_dyn_LMHOSTSFILE(const char *newpath)
{
	if (dyn_LMHOSTSFILE) {
		SAFE_FREE(dyn_LMHOSTSFILE);
	}
	dyn_LMHOSTSFILE = SMB_STRDUP(newpath);
	return dyn_LMHOSTSFILE;
}

/**
 * @brief Samba data directory.
 *
 * @sa data_path() to get the path to a file inside the CODEPAGEDIR.
 **/
static char *dyn_CODEPAGEDIR;

const char *get_dyn_CODEPAGEDIR(void)
{
	if (dyn_CODEPAGEDIR == NULL) {
		return CODEPAGEDIR;
	}
	return dyn_CODEPAGEDIR;
}

const char *set_dyn_CODEPAGEDIR(const char *newpath)
{
	if (dyn_CODEPAGEDIR) {
		SAFE_FREE(dyn_CODEPAGEDIR);
	}
	dyn_CODEPAGEDIR = SMB_STRDUP(newpath);
	return dyn_CODEPAGEDIR;
}

/**
 * @brief Samba library directory.
 *
 * @sa lib_path() to get the path to a file inside the LIBDIR.
 **/
static char *dyn_LIBDIR;

const char *get_dyn_LIBDIR(void)
{
	if (dyn_LIBDIR == NULL) {
		return LIBDIR;
	}
	return dyn_CODEPAGEDIR;
}

const char *set_dyn_LIBDIR(const char *newpath)
{
	if (dyn_LIBDIR) {
		SAFE_FREE(dyn_LIBDIR);
	}
	dyn_LIBDIR = SMB_STRDUP(newpath);
	return dyn_LIBDIR;
}

static char *dyn_SHLIBEXT;

const char *get_dyn_SHLIBEXT(void)
{
	if (dyn_SHLIBEXT == NULL) {
		return SHLIBEXT;
	}
	return dyn_SHLIBEXT;
}

const char *set_dyn_SHLIBEXT(const char *newpath)
{
	if (dyn_SHLIBEXT) {
		SAFE_FREE(dyn_SHLIBEXT);
	}
	dyn_SHLIBEXT = SMB_STRDUP(newpath);
	return dyn_SHLIBEXT;
}

/**
 * @brief Directory holding lock files.
 *
 * Not writable, but used to set a default in the parameter table.
 **/

static char *dyn_LOCKDIR;

const char *get_dyn_LOCKDIR(void)
{
	if (dyn_LOCKDIR == NULL) {
		return LOCKDIR;
	}
	return dyn_LOCKDIR;
}

const char *set_dyn_LOCKDIR(const char *newpath)
{
	if (dyn_LOCKDIR) {
		SAFE_FREE(dyn_LOCKDIR);
	}
	dyn_LOCKDIR = SMB_STRDUP(newpath);
	return dyn_LOCKDIR;
}

static char *dyn_PIDDIR;

const char *get_dyn_PIDDIR(void)
{
	if (dyn_PIDDIR == NULL) {
		return PIDDIR;
	}
	return dyn_PIDDIR;
}

const char *set_dyn_PIDDIR(const char *newpath)
{
	if (dyn_PIDDIR) {
		SAFE_FREE(dyn_PIDDIR);
	}
	dyn_PIDDIR = SMB_STRDUP(newpath);
	return dyn_PIDDIR;
}

static char *dyn_SMB_PASSWD_FILE;

const char *get_dyn_SMB_PASSWD_FILE(void)
{
	if (dyn_SMB_PASSWD_FILE == NULL) {
		return SMB_PASSWD_FILE;
	}
	return dyn_SMB_PASSWD_FILE;
}

const char *set_dyn_SMB_PASSWD_FILE(const char *newpath)
{
	if (dyn_SMB_PASSWD_FILE) {
		SAFE_FREE(dyn_SMB_PASSWD_FILE);
	}
	dyn_SMB_PASSWD_FILE = SMB_STRDUP(newpath);
	return dyn_SMB_PASSWD_FILE;
}

static char *dyn_PRIVATE_DIR;

const char *get_dyn_PRIVATE_DIR(void)
{
	if (dyn_PRIVATE_DIR == NULL) {
		return PRIVATE_DIR;
	}
	return dyn_PRIVATE_DIR;
}

const char *set_dyn_PRIVATE_DIR(const char *newpath)
{
	if (dyn_PRIVATE_DIR) {
		SAFE_FREE(dyn_PRIVATE_DIR);
	}
	dyn_PRIVATE_DIR = SMB_STRDUP(newpath);
	return dyn_PRIVATE_DIR;
}
#endif

/* In non-FHS mode, these should be configurable using 'lock dir =';
   but in FHS mode, they are their own directory.  Implement as wrapper
   functions so that everything can still be kept in dynconfig.c.
 */

const char *get_dyn_STATEDIR(void)
{
#ifdef FHS_COMPATIBLE
	return STATEDIR;
#else
	return lp_lockdir();
#endif
}

const char *get_dyn_CACHEDIR(void)
{
#ifdef FHS_COMPATIBLE
	return CACHEDIR;
#else
	return lp_lockdir();
#endif
}
