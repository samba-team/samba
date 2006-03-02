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
#include "ldb/include/includes.h"
#include "ldb/tools/cmdline.h"

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
		     struct ldb_cmdline *options,
		     const char *expression,
		     const char * const *attrs)
{
	int ret, i, n;
	int loop = 0;
	int total = 0;
	int refs = 0;
	struct ldb_request req;
	struct ldb_result *result = NULL;

	req.operation = LDB_REQ_SEARCH;
	req.op.search.base = basedn;
	req.op.search.scope = options->scope;
	req.op.search.tree = ldb_parse_tree(ldb, expression);
	if (req.op.search.tree == NULL) return -1;
	req.op.search.attrs = attrs;
	req.op.search.res = NULL;
	req.controls = parse_controls(ldb, options->controls);
	if (options->controls != NULL && req.controls == NULL) return -1;
	req.creds = NULL;

	do {
		loop = 0;

		ret = ldb_request(ldb, &req);
		if (ret != LDB_SUCCESS) {
			printf("search failed - %s\n", ldb_errstring(ldb));
			if (req.op.search.res && req.op.search.res->controls) {
				handle_controls_reply(req.op.search.res->controls, req.controls);
			}
			return -1;
		}

		result = req.op.search.res;

		if (options->sorted) {
			ldb_qsort(result->msgs, result->count, sizeof(struct ldb_message *),
				  ldb, (ldb_qsort_cmp_fn_t)do_compare_msg);
		}

		for (i = 0; i < result->count; i++, total++) {
			struct ldb_ldif ldif;
			printf("# record %d\n", total + 1);

			ldif.changetype = LDB_CHANGETYPE_NONE;
			ldif.msg = result->msgs[i];

	                if (options->sorted) {
        	                /*
                	         * Ensure attributes are always returned in the same
                        	 * order.  For testing, this makes comparison of old
	                         * vs. new much easier.
        	                 */
                	        ldb_msg_sort_elements(ldif.msg);
	                }
	
			ldb_ldif_write_file(ldb, stdout, &ldif);
		}

		if (result->refs) {
			for(n = 0;result->refs[n]; n++, refs++) {
				printf("# referral %d\nref: %s\n\n", refs + 1, result->refs[n]);
			}
		}
		
		if (result->controls) {
			if (handle_controls_reply(result->controls, req.controls) == 1)
				loop = 1;
		}

		if (result) {
			ret = talloc_free(result);
			if (ret == -1) {
				fprintf(stderr, "talloc_free failed\n");
				exit(1);
			}
		}

		req.op.search.res = NULL;
		
	} while(loop);

	printf("# returned %d records\n# %d entries\n# %d referrals\n", total + refs, total, refs);

	return 0;
}

int main(int argc, const char **argv)
{
	struct ldb_context *ldb;
	struct ldb_dn *basedn = NULL;
	const char * const * attrs = NULL;
	struct ldb_cmdline *options;
	int ret = -1;
	const char *expression = "(|(objectClass=*)(distinguishedName=*))";

	ldb_global_init();

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
			if (do_search(ldb, basedn, options, line, attrs) == -1) {
				ret = -1;
			}
		}
	} else {
		ret = do_search(ldb, basedn, options, expression, attrs);
	}

	talloc_free(ldb);
	return ret;
}
