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
 *  Component: ldbmodify
 *
 *  Description: utility to modify records - modelled on ldapmodify
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

static int failures;

static void usage(void)
{
	printf("Usage: ldbmodify <options> <ldif...>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("  -o options       pass options like modules to activate\n");
	printf("              e.g: -o modules:timestamps\n");
	printf("\n");
	printf("Modifies a ldb based upon ldif change records\n\n");
	exit(1);
}

/*
  process modifies for one file
*/
static int process_file(struct ldb_context *ldb, FILE *f)
{
	struct ldb_ldif *ldif;
	int ret = -1, count = 0;
	
	while ((ldif = ldb_ldif_read_file(ldb, f))) {
		switch (ldif->changetype) {
		case LDB_CHANGETYPE_NONE:
		case LDB_CHANGETYPE_ADD:
			ret = ldb_add(ldb, &ldif->msg);
			break;
		case LDB_CHANGETYPE_DELETE:
			ret = ldb_delete(ldb, ldif->msg.dn);
			break;
		case LDB_CHANGETYPE_MODIFY:
			ret = ldb_modify(ldb, &ldif->msg);
			break;
		}
		if (ret != 0) {
			fprintf(stderr, "ERR: \"%s\" on DN %s\n", 
				ldb_errstring(ldb), ldif->msg.dn);
			failures++;
		} else {
			count++;
		}
		ldb_ldif_read_free(ldb, ldif);
	}

	return count;
}

 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	int count=0;
	const char *ldb_url;
	const char **options = NULL;
	int ldbopts;
	int opt, i;

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

	if (argc == 0) {
		usage();
		exit(1);
	}

	for (i=0;i<argc;i++) {
		FILE *f;
		if (strcmp(argv[i],"-") == 0) {
			f = stdin;
		} else {
			f = fopen(argv[i], "r");
		}
		if (!f) {
			perror(argv[i]);
			exit(1);
		}
		count += process_file(ldb, f);
		if (f != stdin) {
			fclose(f);
		}
	}

	ldb_close(ldb);

	printf("Modified %d records with %d failures\n", count, failures);

	if (failures != 0) {
		return -1;
	}
	
	return 0;
}
