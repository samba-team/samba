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
 *  Component: ldbtest
 *
 *  Description: utility to test ldb
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"

static const char *ldb_url;

static struct timeval tp1,tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return((tp2.tv_sec - tp1.tv_sec) + 
	       (tp2.tv_usec - tp1.tv_usec)*1.0e-6);
}

static void add_records(struct ldb_context *ldb,
			const char *basedn,
			int count)
{
	struct ldb_message msg;
	int i;

	for (i=0;i<count;i++) {
		struct ldb_message_element el[6];
		struct ldb_val vals[6][1];
		char *name;
		int j;

		asprintf(&name, "Test%d", i);

		asprintf(&msg.dn, "cn=%s,%s", name, basedn);
		msg.num_elements = 6;
		msg.elements = el;

		el[0].flags = 0;
		el[0].name = strdup("cn");
		el[0].num_values = 1;
		el[0].values = vals[0];
		vals[0][0].data = name;
		vals[0][0].length = strlen(name);

		el[1].flags = 0;
		el[1].name = strdup("title");
		el[1].num_values = 1;
		el[1].values = vals[1];
		asprintf((char **)&vals[1][0].data, "The title of %s", name);
		vals[1][0].length = strlen(vals[1][0].data);

		el[2].flags = 0;
		el[2].name = strdup("uid");
		el[2].num_values = 1;
		el[2].values = vals[2];
		vals[2][0].data = ldb_casefold(ldb, name);
		vals[2][0].length = strlen(vals[2][0].data);

		el[3].flags = 0;
		el[3].name = strdup("mail");
		el[3].num_values = 1;
		el[3].values = vals[3];
		asprintf((char **)&vals[3][0].data, "%s@example.com", name);
		vals[3][0].length = strlen(vals[3][0].data);

		el[4].flags = 0;
		el[4].name = strdup("objectClass");
		el[4].num_values = 1;
		el[4].values = vals[4];
		vals[4][0].data = strdup("OpenLDAPperson");
		vals[4][0].length = strlen(vals[4][0].data);

		el[5].flags = 0;
		el[5].name = strdup("sn");
		el[5].num_values = 1;
		el[5].values = vals[5];
		vals[5][0].data = name;
		vals[5][0].length = strlen(vals[5][0].data);

		ldb_delete(ldb, msg.dn);

		if (ldb_add(ldb, &msg) != 0) {
			printf("Add of %s failed - %s\n", name, ldb_errstring(ldb));
			exit(1);
		}

		printf("adding uid %s\r", name);
		fflush(stdout);

		for (j=0;j<msg.num_elements;j++) {
			free(el[j].name);
		}
		free(name);
		free(msg.dn);
		free(vals[1][0].data);
		ldb_free(ldb, vals[2][0].data);
		free(vals[3][0].data);
		free(vals[4][0].data);
	}

	printf("\n");
}

static void modify_records(struct ldb_context *ldb,
			   const char *basedn,
			   int count)
{
	struct ldb_message msg;
	int i;

	for (i=0;i<count;i++) {
		struct ldb_message_element el[3];
		struct ldb_val vals[3];
		char *name;
		int j;
		
		asprintf(&name, "Test%d", i);
		asprintf(&msg.dn, "cn=%s,%s", name, basedn);

		msg.num_elements = 3;
		msg.elements = el;

		el[0].flags = LDB_FLAG_MOD_DELETE;
		el[0].name = strdup("mail");
		el[0].num_values = 0;

		el[1].flags = LDB_FLAG_MOD_ADD;
		el[1].name = strdup("mail");
		el[1].num_values = 1;
		el[1].values = &vals[1];
		asprintf((char **)&vals[1].data, "%s@other.example.com", name);
		vals[1].length = strlen(vals[1].data);

		el[2].flags = LDB_FLAG_MOD_REPLACE;
		el[2].name = strdup("mail");
		el[2].num_values = 1;
		el[2].values = &vals[2];
		asprintf((char **)&vals[2].data, "%s@other2.example.com", name);
		vals[2].length = strlen(vals[2].data);

		if (ldb_modify(ldb, &msg) != 0) {
			printf("Modify of %s failed - %s\n", name, ldb_errstring(ldb));
			exit(1);
		}

		printf("Modifying uid %s\r", name);
		fflush(stdout);

		for (j=0;j<msg.num_elements;j++) {
			free(el[j].name);
		}
		free(name);
		free(msg.dn);
		free(vals[1].data);
		free(vals[2].data);
	}

	printf("\n");
}


static void delete_records(struct ldb_context *ldb,
			   const char *basedn,
			   int count)
{
	int i;

	for (i=0;i<count;i++) {
		char *dn;
		asprintf(&dn, "cn=Test%d,%s", i, basedn);

		printf("Deleting uid Test%d\r", i);
		fflush(stdout);

		if (ldb_delete(ldb, dn) != 0) {
			printf("Delete of %s failed - %s\n", dn, ldb_errstring(ldb));
			exit(1);
		}
		free(dn);
	}

	printf("\n");
}

static void search_uid(struct ldb_context *ldb, int nrecords, int nsearches)
{
	int i;

	for (i=0;i<nsearches;i++) {
		int uid = (i * 700 + 17) % (nrecords * 2);
		char *expr;
		struct ldb_message **res;
		int ret;

		asprintf(&expr, "(uid=TEST%d)", uid);
		ret = ldb_search(ldb, NULL, LDB_SCOPE_SUBTREE, expr, NULL, &res);

		if (uid < nrecords && ret != 1) {
			printf("Failed to find %s - %s\n", expr, ldb_errstring(ldb));
			exit(1);
		}

		if (uid >= nrecords && ret > 0) {
			printf("Found %s !? - %d\n", expr, ret);
			exit(1);
		}

		if (ret > 0) {
			ldb_search_free(ldb, res);
		}

		printf("testing uid %d/%d - %d  \r", i, uid, ret);
		fflush(stdout);

		free(expr);
	}

	printf("\n");
}

static void start_test(struct ldb_context *ldb, int nrecords, int nsearches)
{
	const char *base = "ou=Ldb Test,ou=People,o=University of Michigan,c=US";

	printf("Adding %d records\n", nrecords);
	add_records(ldb, base, nrecords);

	printf("Starting search on uid\n");
	start_timer();
	search_uid(ldb, nrecords, nsearches);
	printf("uid search took %.2f seconds\n", end_timer());

	printf("Modifying records\n");
	modify_records(ldb, base, nrecords);

	printf("Deleting records\n");
	delete_records(ldb, base, nrecords);
}


/*
      2) Store an @indexlist record

      3) Store a record that contains fields that should be index according
to @index

      4) disconnection from database

      5) connect to same database

      6) search for record added in step 3 using a search key that should
be indexed
*/
static void start_test_index(struct ldb_context **ldb)
{
	struct ldb_message msg;
	struct ldb_message_element el[1];
	struct ldb_val val[1];
	struct ldb_message **res;
	int ret;

	printf("Starting index test\n");

	msg.dn = strdup("@INDEXLIST");
	msg.num_elements = 1;
	msg.elements = el;

	el[0].flags = 0;
	el[0].name = strdup("@IDXATTR");
	el[0].num_values = 1;
	el[0].values = val;
	
	val[0].data = strdup("test");
	val[0].length = strlen(val[0].data);

	if (ldb_add(*ldb, &msg) != 0) {
		printf("Add of %s failed - %s\n", msg.dn, ldb_errstring(*ldb));
		exit(1);
	}

	msg.dn = strdup("test1");
	el[0].name = strdup("test");
	val[0].data = strdup("foo");
	val[0].length = strlen(val[0].data);

	if (ldb_add(*ldb, &msg) != 0) {
		printf("Add of %s failed - %s\n", msg.dn, ldb_errstring(*ldb));
		exit(1);
	}

	if (ldb_close(*ldb) != 0) {
		printf("ldb_close failed - %s\n", ldb_errstring(*ldb));
		exit(1);
	}

	*ldb = ldb_connect(ldb_url, 0, NULL);

	if (!*ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ret = ldb_search(*ldb, NULL, LDB_SCOPE_SUBTREE, "test=foo", NULL, &res);
	if (ret != 1) {
		printf("Should have found 1 record - found %d\n", ret);
		exit(1);
	}

	if (ldb_delete(*ldb, "test1") != 0 ||
	    ldb_delete(*ldb, "@INDEXLIST") != 0) {
		printf("cleanup failed - %s\n", ldb_errstring(*ldb));
		exit(1);
	}

	printf("Finished index test\n");
}


static void usage(void)
{
	printf("Usage: ldbtest <options>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("  -r nrecords      database size to use\n");
	printf("  -s nsearches     number of searches to do\n");
	printf("\n");
	printf("tests ldb API\n\n");
	exit(1);
}

 int main(int argc, char * const argv[])
{
	struct ldb_context *ldb;
	int opt;
	int nrecords = 5000;
	int nsearches = 2000;

	ldb_url = getenv("LDB_URL");

	while ((opt = getopt(argc, argv, "hH:r:s:")) != EOF) {
		switch (opt) {
		case 'H':
			ldb_url = optarg;
			break;

		case 'r':
			nrecords = atoi(optarg);
			break;

		case 's':
			nsearches = atoi(optarg);
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

	ldb = ldb_connect(ldb_url, 0, NULL);

	if (!ldb) {
		perror("ldb_connect");
		exit(1);
	}

	ldb_set_debug_stderr(ldb);

	srandom(1);

	start_test_index(&ldb);

	start_test(ldb, nrecords, nsearches);

	ldb_close(ldb);

	return 0;
}
