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
#include "torture/torture.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/util_tdb.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "pstring.h"

static TDB_CONTEXT *tdb;

#define NAME_LENGTH 20

static uint_t total, collisions, failures;

static BOOL test_one(struct smbcli_state *cli, const char *name)
{
	int fnum;
	const char *shortname;
	fstring name2;
	NTSTATUS status;
	TDB_DATA data;

	total++;

	fnum = smbcli_open(cli->tree, name, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open of %s failed (%s)\n", name, smbcli_errstr(cli->tree));
		return False;
	}

	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum))) {
		printf("close of %s failed (%s)\n", name, smbcli_errstr(cli->tree));
		return False;
	}

	/* get the short name */
	status = smbcli_qpathinfo_alt_name(cli->tree, name, &shortname);
	if (!NT_STATUS_IS_OK(status)) {
		printf("query altname of %s failed (%s)\n", name, smbcli_errstr(cli->tree));
		return False;
	}

	snprintf(name2, sizeof(name2), "\\mangle_test\\%s", shortname);
	if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, name2))) {
		printf("unlink of %s  (%s) failed (%s)\n", 
		       name2, name, smbcli_errstr(cli->tree));
		return False;
	}

	/* recreate by short name */
	fnum = smbcli_open(cli->tree, name2, O_RDWR|O_CREAT|O_EXCL, DENY_NONE);
	if (fnum == -1) {
		printf("open2 of %s failed (%s)\n", name2, smbcli_errstr(cli->tree));
		return False;
	}
	if (NT_STATUS_IS_ERR(smbcli_close(cli->tree, fnum))) {
		printf("close of %s failed (%s)\n", name, smbcli_errstr(cli->tree));
		return False;
	}

	/* and unlink by long name */
	if (NT_STATUS_IS_ERR(smbcli_unlink(cli->tree, name))) {
		printf("unlink2 of %s  (%s) failed (%s)\n", 
		       name, name2, smbcli_errstr(cli->tree));
		failures++;
		smbcli_unlink(cli->tree, name2);
		return True;
	}

	/* see if the short name is already in the tdb */
	data = tdb_fetch_bystring(tdb, shortname);
	if (data.dptr) {
		/* maybe its a duplicate long name? */
		if (strcasecmp(name, (const char *)data.dptr) != 0) {
			/* we have a collision */
			collisions++;
			printf("Collision between %s and %s   ->  %s "
				" (coll/tot: %u/%u)\n", 
				name, data.dptr, shortname, collisions, total);
		}
		free(data.dptr);
	} else {
		TDB_DATA namedata;
		/* store it for later */
		namedata.dptr = discard_const_p(uint8_t, name);
		namedata.dsize = strlen(name)+1;
		tdb_store_bystring(tdb, shortname, namedata, TDB_REPLACE);
	}

	return True;
}


static void gen_name(char *name)
{
	const char *chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-$~...";
	uint_t max_idx = strlen(chars);
	uint_t len;
	int i;
	char *p;

	fstrcpy(name, "\\mangle_test\\");
	p = name + strlen(name);

	len = 1 + random() % NAME_LENGTH;
	
	for (i=0;i<len;i++) {
		p[i] = chars[random() % max_idx];
	}

	p[i] = 0;

	if (ISDOT(p) || ISDOTDOT(p)) {
		p[0] = '_';
	}

	/* have a high probability of a common lead char */
	if (random() % 2 == 0) {
		p[0] = 'A';
	}

	/* and a medium probability of a common lead string */
	if (random() % 10 == 0) {
		strncpy(p, "ABCDE", 5);
	}

	/* and a high probability of a good extension length */
	if (random() % 2 == 0) {
		char *s = strrchr(p, '.');
		if (s) {
			s[4] = 0;
		}
	}
}


BOOL torture_mangle(struct torture_context *torture, 
					struct smbcli_state *cli)
{
	extern int torture_numops;
	int i;

	/* we will use an internal tdb to store the names we have used */
	tdb = tdb_open(NULL, 100000, TDB_INTERNAL, 0, 0);
	if (!tdb) {
		printf("ERROR: Failed to open tdb\n");
		return False;
	}

	if (!torture_setup_dir(cli, "\\mangle_test")) {
		return False;
	}

	for (i=0;i<torture_numops;i++) {
		fstring name;

		ZERO_STRUCT(name);

		gen_name(name);

		if (!test_one(cli, name)) {
			break;
		}
		if (total && total % 100 == 0) {
			if (torture_setting_bool(torture, "progress", true)) {
				printf("collisions %u/%u  - %.2f%%   (%u failures)\r",
				       collisions, total, (100.0*collisions) / total, failures);
			}
		}
	}

	smbcli_unlink(cli->tree, "\\mangle_test\\*");
	if (NT_STATUS_IS_ERR(smbcli_rmdir(cli->tree, "\\mangle_test"))) {
		printf("ERROR: Failed to remove directory\n");
		return False;
	}

	printf("\nTotal collisions %u/%u  - %.2f%%   (%u failures)\n",
	       collisions, total, (100.0*collisions) / total, failures);

	return (failures == 0);
}
