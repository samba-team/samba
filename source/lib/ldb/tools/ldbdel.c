/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldbdel
 *
 *  Description: utility to delete records - modelled on ldapdelete
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

static int ldb_delete_recursive(struct ldb_context *ldb, const char *dn)
{
	int ret, i, total=0;
	const char *attrs[] = { "dn", NULL };
	struct ldb_message **res;
	
	ret = ldb_search(ldb, dn, LDB_SCOPE_SUBTREE, "dn=*", attrs, &res);
	if (ret <= 0) return -1;

	for (i=0;i<ret;i++) {
		if (ldb_delete(ldb, res[i]->dn) == 0) {
			total++;
		}
	}

	ldb_search_free(ldb, res);

	if (total == 0) {
		return -1;
	}
	printf("Deleted %d records\n", total);
	return 0;
}

static void usage(void)
{
	printf("Usage: ldbdel <options> <DN...>\n");
	printf("Options:\n");
	printf("  -r               recursively delete the given subtree\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("\n");
	printf("Deletes records from a ldb\n\n");
	exit(1);
}

 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	int ret, i;
	const char *ldb_url;
	int opt, recursive=0;

	ldb_url = getenv("LDB_URL");

	while ((opt = getopt(argc, argv, "hH:r")) != EOF) {
		switch (opt) {
		case 'H':
			ldb_url = optarg;
			break;

		case 'r':
			recursive=1;
			break;

		case 'h':
		default:
			usage();
			break;
		}
	}

	if (!ldb_url) {
		fprintf(stderr, "You must specify a ldb URL\n\n");
		usage();
	}

	argc -= optind;
	argv += optind;

	if (argc < 1) {
		usage();
		exit(1);
	}

	ldb = ldb_connect(ldb_url, 0, NULL);
	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ldb_set_debug_stderr(ldb);

	for (i=0;i<argc;i++) {
		if (recursive) {
			ret = ldb_delete_recursive(ldb, argv[i]);
		} else {
			ret = ldb_delete(ldb, argv[i]);
			if (ret == 0) {
				printf("Deleted 1 record\n");
			}
		}
		if (ret != 0) {
			printf("delete of '%s' failed - %s\n", 
			       argv[i], ldb_errstring(ldb));
		}
	}

	ldb_close(ldb);

	return 0;
}
