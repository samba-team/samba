/* 
   Unix SMB/CIFS implementation.
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

#include "includes.h"
#include "system/iconv.h"
#include "librpc/gen_ndr/ndr_security.h"

BOOL torture_utable(void)
{
	struct smbcli_state *cli;
	fstring fname;
	const char *alt_name;
	int fnum;
	char c2[4];
	int c, len, fd;
	int chars_allowed=0, alt_allowed=0;
	uint8_t valid[0x10000];

	printf("starting utable\n");

	printf("Generating valid character table\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	memset(valid, 0, sizeof(valid));

	if (!torture_setup_dir(cli, "\\utable")) {
		return False;
	}

	for (c=1; c < 0x10000; c++) {
		char *p;

		SSVAL(c2, 0, c);
		fstrcpy(fname, "\\utable\\x");
		p = fname+strlen(fname);
		len = convert_string(CH_UTF16, CH_UNIX, 
				     c2, 2, 
				     p, sizeof(fname)-strlen(fname));
		p[len] = 0;
		fstrcat(fname,"_a_long_extension");

		fnum = smbcli_open(cli->tree, fname, O_RDWR | O_CREAT | O_TRUNC, 
				DENY_NONE);
		if (fnum == -1) continue;

		chars_allowed++;

		smbcli_qpathinfo_alt_name(cli->tree, fname, &alt_name);

		if (strncmp(alt_name, "X_A_L", 5) != 0) {
			alt_allowed++;
			valid[c] = 1;
			d_printf("fname=[%s] alt_name=[%s]\n", fname, alt_name);
		}

		smbcli_close(cli->tree, fnum);
		smbcli_unlink(cli->tree, fname);

		if (c % 100 == 0) {
			printf("%d (%d/%d)\r", c, chars_allowed, alt_allowed);
		}
	}
	printf("%d (%d/%d)\n", c, chars_allowed, alt_allowed);

	smbcli_rmdir(cli->tree, "\\utable");

	d_printf("%d chars allowed   %d alt chars allowed\n", chars_allowed, alt_allowed);

	fd = open("valid.dat", O_WRONLY|O_CREAT|O_TRUNC, 0644);
	if (fd == -1) {
		d_printf("Failed to create valid.dat - %s", strerror(errno));
		return False;
	}
	write(fd, valid, 0x10000);
	close(fd);
	d_printf("wrote valid.dat\n");

	return True;
}


static char *form_name(int c)
{
	static fstring fname;
	char c2[4];
	char *p;
	int len;

	fstrcpy(fname, "\\utable\\");
	p = fname+strlen(fname);
	SSVAL(c2, 0, c);

	len = convert_string(CH_UTF16, CH_UNIX, 
			     c2, 2, 
			     p, sizeof(fname)-strlen(fname));
	p[len] = 0;
	return fname;
}

BOOL torture_casetable(void)
{
	static struct smbcli_state *cli;
	char *fname;
	int fnum;
	int c, i;
#define MAX_EQUIVALENCE 8
	codepoint_t equiv[0x10000][MAX_EQUIVALENCE];
	printf("starting casetable\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	printf("Determining upper/lower case table\n");

	memset(equiv, 0, sizeof(equiv));

	if (!torture_setup_dir(cli, "\\utable")) {
		return False;
	}

	for (c=1; c < 0x10000; c++) {
		size_t size;

		if (c == '.' || c == '\\') continue;

		d_printf("%04x (%c)\n", c, isprint(c)?c:'.');

		fname = form_name(c);
		fnum = smbcli_nt_create_full(cli->tree, fname, 0,
#if 0
					     SEC_RIGHT_MAXIMUM_ALLOWED, 
#else
					     SEC_RIGHTS_FULL_CONTROL,
#endif
					     FILE_ATTRIBUTE_NORMAL,
					     NTCREATEX_SHARE_ACCESS_NONE,
					     NTCREATEX_DISP_OPEN_IF, 0, 0);

		if (fnum == -1) {
			printf("Failed to create file with char %04x\n", c);
			continue;
		}

		size = 0;

		if (NT_STATUS_IS_ERR(smbcli_qfileinfo(cli->tree, fnum, NULL, &size, 
						   NULL, NULL, NULL, NULL, NULL))) continue;

		if (size > 0) {
			/* found a character equivalence! */
			int c2[MAX_EQUIVALENCE];

			if (size/sizeof(int) >= MAX_EQUIVALENCE) {
				printf("too many chars match?? size=%d c=0x%04x\n",
				       size, c);
				smbcli_close(cli->tree, fnum);
				return False;
			}

			smbcli_read(cli->tree, fnum, (char *)c2, 0, size);
			printf("%04x: ", c);
			equiv[c][0] = c;
			for (i=0; i<size/sizeof(int); i++) {
				printf("%04x ", c2[i]);
				equiv[c][i+1] = c2[i];
			}
			printf("\n");
			fflush(stdout);
		}

		smbcli_write(cli->tree, fnum, 0, (char *)&c, size, sizeof(c));
		smbcli_close(cli->tree, fnum);
	}

	smbcli_unlink(cli->tree, "\\utable\\*");
	smbcli_rmdir(cli->tree, "\\utable");

	return True;
}
