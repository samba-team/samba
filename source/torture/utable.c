/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   SMB torture tester - unicode table dumper
   Copyright (C) Andrew Tridgell 2001
   
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

#define NO_SYSLOG

#include "includes.h"

BOOL torture_utable(int dummy)
{
	static struct cli_state cli;
	fstring fname, alt_name;
	int fnum;
	smb_ucs2_t c2;
	int c, len;
	int chars_allowed=0, alt_allowed=0;

	printf("starting utable\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	cli_mkdir(&cli, "\\utable");

	for (c=1; c < 0x10000; c++) {
		char *p;

		SSVAL(&c2, 0, c);
		fstrcpy(fname, "\\utable\\x");
		p = fname+strlen(fname);
		len = convert_string(CH_UCS2, CH_UNIX, 
				     &c2, 2, 
				     p, sizeof(fname)-strlen(fname));
		p[len] = 0;
		fstrcat(fname,"_a_long_extension");

		fnum = cli_open(&cli, fname, O_RDWR | O_CREAT | O_TRUNC, 
				DENY_NONE);
		if (fnum == -1) continue;

		chars_allowed++;

		cli_qpathinfo_alt_name(&cli, fname, alt_name);

		if (strncmp(alt_name, "X_A_L", 5) != 0) {
			alt_allowed++;
			/* d_printf("fname=[%s] alt_name=[%s]\n", fname, alt_name); */
		}

		cli_close(&cli, fnum);
		cli_unlink(&cli, fname);

		if (c % 100 == 0) {
			printf("%d (%d/%d)\r", c, chars_allowed, alt_allowed);
		}
	}
	printf("%d (%d/%d)\n", c, chars_allowed, alt_allowed);

	cli_rmdir(&cli, "\\utable");

	d_printf("%d chars allowed   %d alt chars allowed\n", chars_allowed, alt_allowed);

	return True;
}
