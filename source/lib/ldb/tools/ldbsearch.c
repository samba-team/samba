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
 *  Component: ldbsearch
 *
 *  Description: utility for ldb search - modelled on ldapsearch
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

static void usage(void)
{
	printf("Usage: ldbsearch <options> <expression> <attrs...>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("  -s base|sub|one  choose search scope\n");
	printf("  -b basedn        choose baseDN\n");
	printf("  -i               read search expressions from stdin\n");
	exit(1);
}

static void do_search(struct ldb_context *ldb,
		      const char *basedn,
		      int scope,
		      const char *expression,
		      char * const *attrs)
{
	int ret, i;
	struct ldb_message **msgs;

	ret = ldb_search(ldb, basedn, scope, expression, attrs, &msgs);
	if (ret == -1) {
		printf("search failed - %s\n", ldb_errstring(ldb));
		return;
	}

	printf("# returned %d records\n", ret);

	for (i=0;i<ret;i++) {
		struct ldb_ldif ldif;
		printf("# record %d\n", i+1);

		ldif.changetype = LDB_CHANGETYPE_NONE;
		ldif.msg = *msgs[i];

		ldif_write_file(stdout, &ldif);
	}

	if (ret > 0) {
		ret = ldb_search_free(ldb, msgs);
		if (ret == -1) {
			fprintf(stderr, "search_free failed\n");
			exit(1);
		}
	}
}

 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	char * const * attrs = NULL;
	const char *ldb_url;
	const char *basedn = NULL;
	int opt;
	enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	int interactive = 0;

	ldb_url = getenv("LDB_URL");

	while ((opt = getopt(argc, argv, "b:H:s:hi")) != EOF) {
		switch (opt) {
		case 'b':
			basedn = optarg;
			break;

		case 'H':
			ldb_url = optarg;
			break;

		case 's':
			if (strcmp(optarg, "base") == 0) {
				scope = LDB_SCOPE_BASE;
			} else if (strcmp(optarg, "sub") == 0) {
				scope = LDB_SCOPE_SUBTREE;
			} else if (strcmp(optarg, "one") == 0) {
				scope = LDB_SCOPE_ONELEVEL;
			}
			break;

		case 'i':
			interactive = 1;
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

	if (argc < 1 && !interactive) {
		usage();
		exit(1);
	}

	if (argc > 1) {
		attrs = argv+1;
	}

	ldb = ldb_connect(ldb_url, 0, NULL);
	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	if (interactive) {
		char line[1024];
		while (fgets(line, sizeof(line), stdin)) {
			do_search(ldb, basedn, scope, line, attrs);
		}
	} else {
		do_search(ldb, basedn, scope, argv[0], attrs);
	}

	ldb_close(ldb);
	return 0;
}
