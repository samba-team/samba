 /* 
   Unix SMB/CIFS implementation.

   a utility to delete elements in a ldb

   Copyright (C) Andrew Tridgell 2004
   
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

 int main(int argc, const char *argv[])
{
	static struct ldb_context *ldb;
	int ret, i;

	if (argc < 2) {
		printf("Usage: ldbdel <dn...>\n");
		exit(1);
	}

	ldb = ltdb_connect("tdb://test.ldb", 0, NULL);
	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	for (i=1;i<argc;i++) {
		ret = ldb->ops->delete(ldb, argv[i]);
		if (ret != 0) {
			printf("delete of '%s' failed\n", argv[i]);
		}
	}

	ldb->ops->close(ldb);
	return 0;
}
