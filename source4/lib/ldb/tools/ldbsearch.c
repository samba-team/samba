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
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_errors.h"
#include "ldb/include/ldb_private.h"
#include "ldb/tools/cmdline.h"

#ifdef _SAMBA_BUILD_
#include "system/filesys.h"
#endif

static void usage(void)
{
	printf("Usage: ldbsearch <options> <expression> <attrs...>\n");
	printf("Options:\n");
	printf("  -H ldb_url       choose the database (or $LDB_URL)\n");
	printf("  -s base|sub|one  choose search scope\n");
	printf("  -b basedn        choose baseDN\n");
	printf("  -i               read search expressions from stdin\n");
        printf("  -S               sort returned attributes\n");
	printf("  -o options       pass options like modules to activate\n");
	printf("              e.g: -o modules:timestamps\n");
	exit(1);
}

static int do_compare_msg(struct ldb_message **el1,
			  struct ldb_message **el2,
			  void *opaque)
{
	struct ldb_context *ldb = talloc_get_type(opaque, struct ldb_context);
	return ldb_dn_compare(ldb, (*el1)->dn, (*el2)->dn);
}

static int do_search(struct ldb_context *ldb,
		     const struct ldb_dn *basedn,
		     int scope,
                     int sort_attribs,
		     const char *expression,
		     const char * const *attrs)
{
	int ret, i;
	struct ldb_result *result = NULL;

	ret = ldb_search(ldb, basedn, scope, expression, attrs, &result);
	if (ret != LDB_SUCCESS) {
		printf("search failed - %s\n", ldb_errstring(ldb));
		return -1;
	}

	printf("# returned %d records\n", ret);

	if (sort_attribs) {
		ldb_qsort(result->msgs, ret, sizeof(struct ldb_message *),
			  ldb, (ldb_qsort_cmp_fn_t)do_compare_msg);
	}

	for (i = 0; i < result->count; i++) {
		struct ldb_ldif ldif;
		printf("# record %d\n", i+1);

		ldif.changetype = LDB_CHANGETYPE_NONE;
		ldif.msg = result->msgs[i];

                if (sort_attribs) {
                        /*
                         * Ensure attributes are always returned in the same
                         * order.  For testing, this makes comparison of old
                         * vs. new much easier.
                         */
                        ldb_msg_sort_elements(ldif.msg);
                }
                
		ldb_ldif_write_file(ldb, stdout, &ldif);
	}

	if (result) {
		ret = talloc_free(result);
		if (ret == -1) {
			fprintf(stderr, "talloc_free failed\n");
			exit(1);
		}
	}

	return 0;
}

 int main(int argc, const char **argv)
{
	struct ldb_context *ldb;
	struct ldb_dn *basedn = NULL;
	const char * const * attrs = NULL;
	struct ldb_cmdline *options;
	int ret = -1;
	const char *expression = "(objectclass=*)";

	ldb = ldb_init(NULL);

	options = ldb_cmdline_process(ldb, argc, argv, usage);

	/* the check for '=' is for compatibility with ldapsearch */
	if (!options->interactive &&
	    options->argc > 0 && 
	    strchr(options->argv[0], '=')) {
		expression = options->argv[0];
		options->argv++;
		options->argc--;
	}

	if (options->argc > 0) {
		attrs = (const char * const *)(options->argv);
	}

	if (options->basedn != NULL) {
		basedn = ldb_dn_explode(ldb, options->basedn);
		if (basedn == NULL) {
			fprintf(stderr, "Invalid Base DN format\n");
			exit(1);
		}
	}

	if (options->interactive) {
		char line[1024];
		while (fgets(line, sizeof(line), stdin)) {
			if (do_search(ldb, basedn, 
				      options->scope, options->sorted, line, attrs) == -1) {
				ret = -1;
			}
		}
	} else {
		ret = do_search(ldb, basedn, options->scope, options->sorted, 
				expression, attrs);
	}

	talloc_free(ldb);
	return ret;
}
