/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Stefan Metzmacher  2004

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
 *  Component: ldbrename
 *
 *  Description: utility to rename records - modelled on ldapmodrdn
 *
 *  Author: Andrew Tridgell
 *  Author: Stefan Metzmacher
 */

#include "includes.h"

static void usage(void)
{
	printf("Usage: ldbrename [<options>] <olddn> <newdn>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("\n");
	printf("Renames records in a ldb\n\n");
	exit(1);
}


 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	const char *ldb_url;
	const char **options = NULL;
	int ldbopts;
	int opt, ret;

	ldb_url = getenv("LDB_URL");

	ldbopts = 0;
	while ((opt = getopt(argc, argv, "hH:o:")) != EOF) {
		switch (opt) {
		case 'H':
			ldb_url = optarg;
			break;

		case 'o':
			ldbopts++;
			if (options == NULL) {
				options = (const char **)malloc(sizeof(char *) * (ldbopts + 1));
			} else {
				options = (const char **)realloc(options, sizeof(char *) * (ldbopts + 1));
				if (options == NULL) {
					fprintf(stderr, "Out of memory!\n");
					exit(-1);
				}
			}
			options[ldbopts - 1] = optarg;
			options[ldbopts] = NULL;
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

	ldb = ldb_connect(ldb_url, 0, options);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ldb_set_debug_stderr(ldb);

	if (argc < 2) {
		usage();
	}

	ret = ldb_rename(ldb, argv[0], argv[1]);
	if (ret == 0) {
		printf("Renamed 1 record\n");
	} else  {
		printf("rename of '%s' to '%s' failed - %s\n", 
			argv[0], argv[1], ldb_errstring(ldb));
	}

	ldb_close(ldb);
	
	return ret;
}
