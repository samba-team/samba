/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions - frontend
   Copyright (C) Andrew Tridgell 1998
   
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

int main(int argc, char *argv[])
{
	char *p, *u;
	char *libd = BINDIR;	
	pstring line;
	extern FILE *dbf;

	smbw_setup_shared();

	p = getenv("SMBW_DEBUG");
	if (p) smbw_setshared("DEBUG", p);

	p = getenv("SMBW_WORKGROUP");
	if (p) smbw_setshared("WORKGROUP", p);

	p = getenv("SMBW_USER");
	if (p) smbw_setshared("USER", p);

	p = getenv("SMBW_PASSWORD");
	if (p) smbw_setshared("PASSWORD", p);

	charset_initialise();

	if (!smbw_getshared("USER")) {
		printf("Username: ");
		u = fgets_slash(line, sizeof(line)-1, stdin);
		smbw_setshared("USER", u);
	}

	if (!smbw_getshared("PASSWORD")) {
		p = getpass("Password: ");
		smbw_setshared("PASSWORD", p);
	}

	setenv("PS1", "smbsh$ ", 1);

	sys_getwd(line);

	setenv("PWD", line, 1);

	slprintf(line,sizeof(line)-1,"%s/smbwrapper.so", libd);
	setenv("LD_PRELOAD", line, 1);

	slprintf(line,sizeof(line)-1,"%s/smbwrapper.32.so", libd);

	if (file_exist(line, NULL)) {
		slprintf(line,sizeof(line)-1,"%s/smbwrapper.32.so:DEFAULT", libd);
		setenv("_RLD_LIST", line, 1);
		slprintf(line,sizeof(line)-1,"%s/smbwrapper.so:DEFAULT", libd);
		setenv("_RLD32_LIST", line, 1);
	} else {
		slprintf(line,sizeof(line)-1,"%s/smbwrapper.so:DEFAULT", libd);
		setenv("_RLD_LIST", line, 1);
	}

	execl("/bin/sh","sh",NULL);
	printf("launch failed!\n");
	return 1;
}	
