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

static struct ldb_control **parse_controls(void *mem_ctx, char **control_strings)
{
	int i;
	struct ldb_control **ctrl;

	if (control_strings == NULL || control_strings[0] == NULL)
		return NULL;

	for (i = 0; control_strings[i]; i++);

	ctrl = talloc_array(mem_ctx, struct ldb_control *, i + 1);

	for (i = 0; control_strings[i]; i++) {
		if (strncmp(control_strings[i], "asq:", 4) == 0) {
			struct ldb_asq_control *control;
			const char *p;
			char attr[256];
			int crit, ret;

			attr[0] = '\0';
			p = &(control_strings[i][4]);
			ret = sscanf(p, "%d:%255[^$]", &crit, attr);
			if ((ret != 2) || (crit < 0) || (crit > 1) || (attr[0] == '\0')) {
				fprintf(stderr, "invalid asq control syntax\n");
				return NULL;
			}

			ctrl[i] = talloc(ctrl, struct ldb_control);
			ctrl[i]->oid = LDB_CONTROL_ASQ_OID;
			ctrl[i]->critical = crit;
			control = talloc(ctrl[i], struct ldb_asq_control);
			control->request = 1;
			control->source_attribute = talloc_strdup(control, attr);
			control->src_attr_len = strlen(attr);
			ctrl[i]->data = control;

			continue;
		}

		if (strncmp(control_strings[i], "extended_dn:", 12) == 0) {
			struct ldb_extended_dn_control *control;
			const char *p;
			int crit, type, ret;

			p = &(control_strings[i][12]);
			ret = sscanf(p, "%d:%d", &crit, &type);
			if ((ret != 2) || (crit < 0) || (crit > 1) || (type < 0) || (type > 1)) {
				fprintf(stderr, "invalid extended_dn control syntax\n");
				return NULL;
			}

			ctrl[i] = talloc(ctrl, struct ldb_control);
			ctrl[i]->oid = LDB_CONTROL_EXTENDED_DN_OID;
			ctrl[i]->critical = crit;
			control = talloc(ctrl[i], struct ldb_extended_dn_control);
			control->type = type;
			ctrl[i]->data = control;

			continue;
		}

		if (strncmp(control_strings[i], "paged_results:", 14) == 0) {
			struct ldb_paged_control *control;
			const char *p;
			int crit, size, ret;
		       
			p = &(control_strings[i][14]);
			ret = sscanf(p, "%d:%d", &crit, &size);

			if ((ret != 2) || (crit < 0) || (crit > 1) || (size < 0)) {
				fprintf(stderr, "invalid paged_results control syntax\n");
				return NULL;
			}

			ctrl[i] = talloc(ctrl, struct ldb_control);
			ctrl[i]->oid = LDB_CONTROL_PAGED_RESULTS_OID;
			ctrl[i]->critical = crit;
			control = talloc(ctrl[i], struct ldb_paged_control);
			control->size = size;
			control->cookie = NULL;
			control->cookie_len = 0;
			ctrl[i]->data = control;

			continue;
		}

		if (strncmp(control_strings[i], "server_sort:", 12) == 0) {
			struct ldb_server_sort_control **control;
			const char *p;
			char attr[256];
			char rule[128];
			int crit, rev, ret;

			attr[0] = '\0';
			rule[0] = '\0';
			p = &(control_strings[i][12]);
			ret = sscanf(p, "%d:%d:%255[^:]:%127[^:]", &crit, &rev, attr, rule);
			if ((ret < 3) || (crit < 0) || (crit > 1) || (rev < 0 ) || (rev > 1) ||attr[0] == '\0') {
				fprintf(stderr, "invalid server_sort control syntax\n");
				return NULL;
			}
			ctrl[i] = talloc(ctrl, struct ldb_control);
			ctrl[i]->oid = LDB_CONTROL_SERVER_SORT_OID;
			ctrl[i]->critical = crit;
			control = talloc_array(ctrl[i], struct ldb_server_sort_control *, 2);
			control[0] = talloc(control, struct ldb_server_sort_control);
			control[0]->attributeName = talloc_strdup(control, attr);
			if (rule[0])
				control[0]->orderingRule = talloc_strdup(control, rule);
			else
				control[0]->orderingRule = NULL;
			control[0]->reverse = rev;
			control[1] = NULL;
			ctrl[i]->data = control;

			continue;
		}

		/* no controls matched, throw an error */
		fprintf(stderr, "Invalid control name\n");
		return NULL;
	}

	ctrl[i] = NULL;

	return ctrl;
}

/* this function check controls reply and determines if more
 * processing is needed setting up the request controls correctly
 *
 * returns:
 * 	-1 error
 * 	0 all ok
 * 	1 all ok, more processing required
 */
static int handle_controls_reply(struct ldb_control **reply, struct ldb_control **request)
{
	int i, j;
       	int ret = 0;

	if (reply == NULL || request == NULL) return -1;
	
	for (i = 0; reply[i]; i++) {
		if (strcmp(LDB_CONTROL_ASQ_OID, reply[i]->oid) == 0) {
			struct ldb_asq_control *rep_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_asq_control);

			/* check the result */
			if (rep_control->result != 0) {
				fprintf(stderr, "Warning: ASQ not performed with error: %d\n", rep_control->result);
			}

			continue;
		}
		if (strcmp(LDB_CONTROL_PAGED_RESULTS_OID, reply[i]->oid) == 0) {
			struct ldb_paged_control *rep_control, *req_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_paged_control);
			if (rep_control->cookie_len == 0) /* we are done */
				break;

			/* more processing required */
			/* let's fill in the request control with the new cookie */

			for (j = 0; request[j]; j++) {
				if (strcmp(LDB_CONTROL_PAGED_RESULTS_OID, request[j]->oid) == 0)
					break;
			}
			/* if there's a reply control we must find a request
			 * control matching it */
			if (! request[j]) return -1;

			req_control = talloc_get_type(request[j]->data, struct ldb_paged_control);

			if (req_control->cookie)
				talloc_free(req_control->cookie);
			req_control->cookie = talloc_memdup(req_control,
							    rep_control->cookie,
							    rep_control->cookie_len);
			req_control->cookie_len = rep_control->cookie_len;

			ret = 1;

			continue;
		}

		if (strcmp(LDB_CONTROL_SORT_RESP_OID, reply[i]->oid) == 0) {
			struct ldb_sort_resp_control *rep_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_sort_resp_control);

			/* check we have a matching control in the request */
			for (j = 0; request[j]; j++) {
				if (strcmp(LDB_CONTROL_SERVER_SORT_OID, request[j]->oid) == 0)
					break;
			}
			if (! request[j]) {
				fprintf(stderr, "Warning Server Sort reply received but no request found\n");
				continue;
			}

			/* check the result */
			if (rep_control->result != 0) {
				fprintf(stderr, "Warning: Sorting not performed with error: %d\n", rep_control->result);
			}

			continue;
		}

		/* no controls matched, throw a warning */
		fprintf(stderr, "Unknown reply control oid: %s\n", reply[i]->oid);
	}

	return ret;
}


static int do_search(struct ldb_context *ldb,
		     const struct ldb_dn *basedn,
		     struct ldb_cmdline *options,
		     const char *expression,
		     const char * const *attrs)
{
	int ret, i;
	int loop = 0;
	int total = 0;
	struct ldb_request req;
	struct ldb_result *result = NULL;

	req.operation = LDB_REQ_SEARCH;
	req.op.search.base = basedn;
	req.op.search.scope = options->scope;
	req.op.search.tree = ldb_parse_tree(ldb, expression);
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
			return -1;
		}

		result = req.op.search.res;
		printf("# returned %d records\n", result->count);

		if (options->sorted) {
			ldb_qsort(result->msgs, ret, sizeof(struct ldb_message *),
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
