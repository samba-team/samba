/* 
   Unix SMB/CIFS implementation.
   SMB torture tester - mangling test
   Copyright (C) Andrew Tridgell 2002
   
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

static TDB_CONTEXT *tdb;

#define NAME_LENGTH 30

static unsigned total, collisions;

static BOOL test_one(struct cli_state *cli, const char *name)
{
	int fnum;
	fstring shortname;
	fstring name2;
	NTSTATUS status;
	TDB_DATA data;

	total++;

	fnum = cli_open(cli, name, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", name, cli_errstr(cli));
		return False;
	}

	if (!cli_close(cli, fnum)) {
		printf("close of %s failed (%s)\n", name, cli_errstr(cli));
		return False;
	}

	/* get the short name */
	status = cli_qpathinfo_alt_name(cli, name, shortname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("query altname of %s failed (%s)\n", name, cli_errstr(cli));
		return False;
	}

	snprintf(name2, sizeof(name2), "\\mangle_test\\%s", shortname);
	if (!cli_unlink(cli, name2)) {
		printf("unlink of %s  (%s) failed (%s)\n", 
		       name2, name, cli_errstr(cli));
		return False;
	}

	/* see if the short name is already in the tdb */
	data = tdb_fetch_by_string(tdb, shortname);
	if (data.dptr) {
		/* maybe its a duplicate long name? */
		if (strcasecmp(name, data.dptr) != 0) {
			/* we have a collision */
			collisions++;
			printf("Collision between %s and %s   ->  %s\n", 
			       name, data.dptr, shortname);
		}
		free(data.dptr);
	} else {
		/* store it for later */
		tdb_store_by_string(tdb, shortname, name, strlen(name)+1);
	}

	return True;
}


static void gen_name(char *name)
{
	const char *chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-$~";
	unsigned max_idx = strlen(chars);
	unsigned len;
	int i;
	char *p;

	fstrcpy(name, "\\mangle_test\\");
	p = name + strlen(name);

	len = 1 + random() % NAME_LENGTH;
	
	for (i=0;i<len;i++) {
		p[i] = chars[random() % max_idx];
	}

	p[i] = 0;

	if (strcmp(p, ".") == 0 || strcmp(p, "..") == 0) {
		p[0] = '_';
	}
}


BOOL torture_mangle(int dummy)
{
	extern int torture_numops;
	static struct cli_state cli;
	int i;

	printf("starting mangle test\n");

	if (!torture_open_connection(&cli)) {
		return False;
	}

	/* we will use an internal tdb to store the names we have used */
	tdb = tdb_open(NULL, 100000, TDB_INTERNAL, 0, 0);
	if (!tdb) {
		printf("ERROR: Failed to open tdb\n");
		return False;
	}

	cli_unlink(&cli, "\\mangle_test\\*");
	cli_rmdir(&cli, "\\mangle_test");

	if (!cli_mkdir(&cli, "\\mangle_test")) {
		printf("ERROR: Failed to make directory\n");
		return False;
	}

	for (i=0;i<torture_numops;i++) {
		fstring name;

		gen_name(name);

		if (!test_one(&cli, name)) {
			break;
		}
		if (total && total % 100 == 0) {
			printf("collisions %u/%u  - %.2f%%\r",
			       collisions, total, (100.0*collisions) / total);
		}
	}

	if (!cli_rmdir(&cli, "\\mangle_test")) {
		printf("ERROR: Failed to remove directory\n");
		return False;
	}

	printf("\nTotal collisions %u/%u  - %.2f%%\n",
	       collisions, total, (100.0*collisions) / total);

	torture_close_connection(&cli);

	printf("mangle test finished\n");
	return True;
}
