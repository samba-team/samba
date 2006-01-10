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
#include "ldb/include/includes.h"
#include "ldb/tools/cmdline.h"

#ifdef _SAMBA_BUILD_
#include "lib/cmdline/popt_common.h"
#include "auth/auth.h"
#endif

/*
  process command line options
*/
struct ldb_cmdline *ldb_cmdline_process(struct ldb_context *ldb, int argc, const char **argv,
					void (*usage)(void))
{
	struct ldb_cmdline options, *ret=NULL;
	poptContext pc;
#ifdef _SAMBA_BUILD_
	int r;
#endif
        int num_options = 0;
	int opt;
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
		{ "all", 'a',    POPT_ARG_NONE, &options.all_records, 0, "objectClass=*", NULL },
		{ "nosync", 0,   POPT_ARG_NONE, &options.nosync, 0, "non-synchronous transactions", NULL },
		{ "sorted", 'S', POPT_ARG_NONE, &options.sorted, 0, "sort attributes", NULL },
		{ "sasl-mechanism", 0, POPT_ARG_STRING, &options.sasl_mechanism, 0, "choose SASL mechanism", "MECHANISM" },
		{ "input", 'I', POPT_ARG_STRING, &options.input, 0, "Input File", "Input" },
		{ "output", 'O', POPT_ARG_STRING, &options.output, 0, "Output File", "Output" },
		{ NULL,    'o', POPT_ARG_STRING, NULL, 'o', "ldb_connect option", "OPTION" },
		{ "controls", 0, POPT_ARG_STRING, NULL, 'c', "controls", NULL },
#ifdef _SAMBA_BUILD_
		POPT_COMMON_SAMBA
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
#endif
		POPT_TABLEEND
	};

#ifdef _SAMBA_BUILD_
	gensec_init(); 

	r = ldb_register_samba_handlers(ldb);
	if (r != 0) {
		goto failed;
	}

#endif

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

	options.scope = LDB_SCOPE_DEFAULT;

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
							 const char *, num_options+3);
			if (options.options == NULL) {
				ldb_oom(ldb);
				goto failed;
			}
			options.options[num_options] = poptGetOptArg(pc);
			options.options[num_options+1] = NULL;
			num_options++;
			break;

		case 'c': {
			const char *cs = poptGetOptArg(pc);
			const char *p, *q;
			int cc;

			for (p = cs, cc = 1; (q = strchr(p, ',')); cc++, p = q + 1) ;

			options.controls = talloc_array(ret, char *, cc + 1);
			if (options.controls == NULL) {
				ldb_oom(ldb);
				goto failed;
			}
			for (p = cs, cc = 0; p != NULL; cc++) {
				const char *t;

				t = strchr(p, ',');
				if (t == NULL) {
					options.controls[cc] = talloc_strdup(options.controls, p);
					p = NULL;
				} else {
					options.controls[cc] = talloc_strndup(options.controls, p, t-p);
			        	p = t + 1;
				}
			}
			options.controls[cc] = NULL;

			break;	  
		}
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

	if (strcmp(ret->url, "NONE") != 0) {
		int flags = 0;
		if (options.nosync) {
			flags |= LDB_FLG_NOSYNC;
		}

#ifdef _SAMBA_BUILD_
		if (ldb_set_opaque(ldb, "sessionInfo", system_session(ldb))) {
			goto failed;
		}
		if (ldb_set_opaque(ldb, "credentials", cmdline_credentials)) {
			goto failed;
		}
#endif
		if (ldb_connect(ldb, ret->url, flags, ret->options) != 0) {
			fprintf(stderr, "Failed to connect to %s - %s\n", 
				ret->url, ldb_errstring(ldb));
			goto failed;
		}
	}

	return ret;

failed:
	talloc_free(ret);
	exit(1);
	return NULL;
}
