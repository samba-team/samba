 /* 
   Unix SMB/CIFS implementation.

   simple ldb search tool

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
	struct ldb_message **msgs;
	int ret, i;
	const char *expression;
	const char **attrs = NULL;

	if (argc < 2) {
		printf("Usage: ldbsearch <expression> [attrs...]\n");
		exit(1);
	}

	if (argc > 2) {
		attrs = argv+2;
	}

	expression = argv[1];

	ldb = ltdb_connect("tdb://test.ldb", 0, NULL);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ret = ldb->ops->search(ldb, expression, attrs, &msgs);

	if (ret == -1) {
		printf("search failed\n");
		exit(1);
	}

	printf("# returned %d records\n", ret);

	for (i=0;i<ret;i++) {
		printf("# record %d\n", i+1);
		ldif_write(stdout, msgs[i]);
	}

	ret = ldb->ops->search_free(ldb, msgs);
	if (ret == -1) {
		fprintf(stderr, "search_free failed\n");
		exit(1);
	}

	ldb->ops->close(ldb);
	return 0;
}
