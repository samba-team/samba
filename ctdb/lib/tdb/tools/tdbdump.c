/* 
   Unix SMB/CIFS implementation.
   simple tdb dump util
   Copyright (C) Andrew Tridgell              2001

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

#include "replace.h"
#include "tdb.h"
#include "system/locale.h"
#include "system/filesys.h"

static void print_data(TDB_DATA d)
{
	unsigned char *p = (unsigned char *)d.dptr;
	int len = d.dsize;
	while (len--) {
		if (isprint(*p) && !strchr("\"\\", *p)) {
			fputc(*p, stdout);
		} else {
			printf("\\%02X", *p);
		}
		p++;
	}
}

static int traverse_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA dbuf, void *state)
{
	printf("{\n");
	printf("key = \"");
	print_data(key);
	printf("\"\n");
	printf("data = \"");
	print_data(dbuf);
	printf("\"\n");
	printf("}\n");
	return 0;
}

static int dump_tdb(const char *fname)
{
	struct tdb_context *tdb;
	
	tdb = tdb_open(fname, 0, 0, O_RDONLY, 0);
	if (!tdb) {
		printf("Failed to open %s\n", fname);
		return 1;
	}

	tdb_traverse(tdb, traverse_fn, NULL);
	return 0;
}

 int main(int argc, char *argv[])
{
	char *fname;

	if (argc < 2) {
		printf("Usage: tdbdump <fname>\n");
		exit(1);
	}

	fname = argv[1];

	return dump_tdb(fname);
}
