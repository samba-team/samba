/* 
   ldb database library - command line handling for ldb tools

   Copyright (C) Andrew Tridgell  2005

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

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "ldb/tools/cmdline.h"

/*
  process command line options
*/
struct ldb_cmdline *ldb_cmdline_process(struct ldb_context *ldb, int argc, const char **argv,
					void (*usage)(void))
{
	struct ldb_cmdline options, *ret;
	poptContext pc;
	int num_options = 0;
	char opt;
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "url",       'H', POPT_ARG_STRING, &options.url, 0, "database URL", "URL" },
		{ "basedn",    'b', POPT_ARG_STRING, &options.basedn, 0, "base DN", "DN" },
		{ "editor",    'e', POPT_ARG_STRING, &options.editor, 0, "external editor", "PROGRAM" },
		{ "scope",     's', POPT_ARG_STRING, NULL, 's', "search scope", "SCOPE" },
		{ "verbose",   'v', POPT_ARG_NONE, NULL, 'v', "increase verbosity", NULL },
		{ "interactive", 'i', POPT_ARG_NONE, &options.interactive, 0, "input from stdin", NULL },
		{ "recursive", 'r', POPT_ARG_NONE, &options.recursive, 0, "recursive delete", NULL },
		{ "num-searches", 0, POPT_ARG_INT, &options.num_searches, 0, "number of test searches", NULL },
		{ "num-records", 0, POPT_ARG_INT, &options.num_records, 0, "number of test records", NULL },
		{ "all", 'a',    POPT_ARG_NONE, &options.all_records, 0, "dn=*", NULL },
		{ "sorted", 'S', POPT_ARG_NONE, &options.sorted, 0, "sort attributes", NULL },
		{ NULL,    'o', POPT_ARG_STRING, NULL, 'o', "ldb_connect option", "OPTION" },
		POPT_TABLEEND
	};

	ret = talloc_zero(ldb, struct ldb_cmdline);
	if (ret == NULL) {
		ldb_oom(ldb);
		goto failed;
	}

	options = *ret;
	
	/* pull in URL */
	options.url = getenv("LDB_URL");

	/* and editor (used by ldbedit) */
	options.editor = getenv("VISUAL");
	if (!options.editor) {
		options.editor = getenv("EDITOR");
	}
	if (!options.editor) {
		options.editor = "vi";
	}

	pc = poptGetContext(argv[0], argc, argv, popt_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 's': {
			const char *arg = poptGetOptArg(pc);
			if (strcmp(arg, "base") == 0) {
				options.scope = LDB_SCOPE_BASE;
			} else if (strcmp(arg, "sub") == 0) {
				options.scope = LDB_SCOPE_SUBTREE;
			} else if (strcmp(arg, "one") == 0) {
				options.scope = LDB_SCOPE_ONELEVEL;
			} else {
				fprintf(stderr, "Invalid scope '%s'\n", arg);
				goto failed;
			}
			break;
		}

		case 'v':
			options.verbose++;
			break;

		case 'o':
			options.options = talloc_realloc(ret, options.options, 
							 const char *, num_options+2);
			if (options.options == NULL) {
				ldb_oom(ldb);
				goto failed;
			}
			options.options[num_options++] = poptGetOptArg(pc);
			options.options[num_options+1] = NULL;
			break;
			
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			if (usage) usage();
			goto failed;
		}
	}

	/* setup the remaining options for the main program to use */
	options.argv = poptGetArgs(pc);
	if (options.argv) {
		options.argv++;
		while (options.argv[options.argc]) options.argc++;
	}

	*ret = options;

	/* all utils need some option */
	if (ret->url == NULL) {
		fprintf(stderr, "You must supply a url with -H or with $LDB_URL\n");
		if (usage) usage();
		goto failed;
	}

	return ret;

failed:
	talloc_free(ret);
	exit(1);
	return NULL;
}
