/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   html status reporting
   Copyright (C) Andrew Tridgell 1997-1998
   
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

#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

static void print_header(void)
{
	printf("Content-type: text/html\n\n");
	printf("<HTML>\n<HEAD>\n<TITLE>smbstatus</TITLE>\n</HEAD>\n<BODY>\n\n");
}

static void print_footer(void)
{
	printf("\n</BODY>\n</HTML>\n");
}

static void show_connections(void)
{
	static pstring servicesf = CONFIGFILE;
	pstring fname;
	FILE *f;
	struct connect_record crec;

	if(!get_myname(myhostname,NULL))
	{
	    printf("Failed to get my hostname.\n");
	    return;
	}

	if (!lp_load(servicesf,False)) {
		printf("Can't load %s - run testparm to debug it\n", servicesf);
		return;
	}

	pstrcpy(fname,lp_lockdir());
	standard_sub_basic(fname);
	trim_string(fname,"","/");
	pstrcat(fname,"/STATUS..LCK");

	f = fopen(fname,"r");
	if (!f) {
		printf("Couldn't open status file %s\n",fname);
		if (!lp_status(-1))
			printf("You need to have status=yes in your smb config file\n");
		return;
	}


	printf("\nSamba version %s\n<p>",VERSION);

	while (!feof(f)) {
		if (fread(&crec,sizeof(crec),1,f) != 1)
			break;
		if (crec.magic == 0x280267 && process_exists(crec.pid)) {
			printf("%-10.10s   %-8s %-8s %5d   %-8s (%s) %s<br>",
			       crec.name,uidtoname(crec.uid),
			       gidtoname(crec.gid),crec.pid,
			       crec.machine,crec.addr,
			       asctime(LocalTime(&crec.start)));
		}
	}
	fclose(f);
}

int main(int argc, char *argv[])
{
	print_header();
	show_connections();
	print_footer();
	return 0;
}
