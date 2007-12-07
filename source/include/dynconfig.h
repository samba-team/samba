/* 
   Unix SMB/CIFS implementation.
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   Copyright (C) 2003 by Jim McDonough <jmcd@us.ibm.com>
   
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

/**
 * @file dynconfig.h
 *
 * @brief Exported global configurations.
 **/

extern char const *dyn_SBINDIR,
	*dyn_BINDIR,
	*dyn_SWATDIR;

extern char dyn_CONFIGFILE[1024];
extern char dyn_LOGFILEBASE[1024], dyn_LMHOSTSFILE[1024];
extern char dyn_LIBDIR[1024];
extern char dyn_CODEPAGEDIR[1024];
extern fstring dyn_SHLIBEXT;
extern char dyn_LOCKDIR[1024];
extern char dyn_PIDDIR[1024];
extern char dyn_SMB_PASSWD_FILE[1024];
extern char dyn_PRIVATE_DIR[1024];

char *dyn_STATEDIR(void);
char *dyn_CACHEDIR(void);
