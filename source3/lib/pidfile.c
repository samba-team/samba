/* this code is broken - there is a race condition with the unlink (tridge) */

/*
   Unix SMB/CIFS implementation.
   pidfile handling
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Jeremy Allison 2012

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
#include "system/filesys.h"
#include "../lib/util/pidfile.h"

/* Malloc a pidfile name. */
static char *get_pidfile_name(const char *program_name)
{
	char *name = NULL;

	/* Add a suffix to the program name if this is a process with a
	 * none default configuration file name. */
	if (strcmp( CONFIGFILE, get_dyn_CONFIGFILE()) == 0) {
		name = SMB_STRDUP(program_name);
	} else {
		const char *short_configfile;
		short_configfile = strrchr( get_dyn_CONFIGFILE(), '/');
		if (short_configfile == NULL) {
			/* conf file in current directory */
			short_configfile = get_dyn_CONFIGFILE();
		} else {
			/* full/relative path provided */
			short_configfile++;
		}
		if (asprintf(&name, "%s-%s", program_name,
				short_configfile) == -1) {
			smb_panic("asprintf failed");
		}
	}
	return name;
}

/* return the pid in a pidfile. return 0 if the process (or pidfile)
   does not exist */
pid_t pidfile_pid_s3(const char *program_name)
{
	pid_t pid = 0;
	char *name = get_pidfile_name(program_name);

	pid = pidfile_pid(lp_piddir(), name);
	SAFE_FREE(name);
	return pid;
}

/* create a pid file in the pid directory. open it and leave it locked */
void pidfile_create_s3(const char *program_name)
{
	char *name = get_pidfile_name(program_name);

	pidfile_create(lp_piddir(), name);
	SAFE_FREE(name);
}

/* Remove a pidfile. */
void pidfile_unlink_s3(const char *program_name)
{
	char *name = get_pidfile_name(program_name);
	pidfile_unlink(lp_piddir(), name);
	SAFE_FREE(name);
}
