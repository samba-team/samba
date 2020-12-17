/* 
   ldb database library - command line handling for ldb tools

   Copyright (C) Andrew Tridgell  2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/time.h"
#include "ldb.h"
#include "ldb_module.h"
#include "tools/cmdline.h"

static struct ldb_cmdline options; /* needs to be static for older compilers */

enum ldb_cmdline_options { CMDLINE_RELAX=1 };

static struct poptOption builtin_popt_options[] = {
	POPT_AUTOHELP
	{
		.longName   = "url",
		.shortName  = 'H',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.url,
		.val        = 0,
		.descrip    = "database URL",
		.argDescrip = "URL"
	},
	{
		.longName   = "basedn",
		.shortName  = 'b',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.basedn,
		.val        = 0,
		.descrip    = "base DN",
		.argDescrip = "DN"
	},
	{
		.longName   = "editor",
		.shortName  = 'e',
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.editor,
		.val        = 0,
		.descrip    = "external editor",
		.argDescrip = "PROGRAM"
	},
	{
		.longName   = "scope",
		.shortName  = 's',
		.argInfo    = POPT_ARG_STRING,
		.arg        = NULL,
		.val        = 's',
		.descrip    = "search scope",
		.argDescrip = "SCOPE"
	},
	{
		.longName   = "verbose",
		.shortName  = 'v',
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'v',
		.descrip    = "increase verbosity",
		.argDescrip = NULL
	},
	{
		.longName   = "trace",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.tracing,
		.val        = 0,
		.descrip    = "enable tracing",
		.argDescrip = NULL
	},
	{
		.longName   = "interactive",
		.shortName  = 'i',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.interactive,
		.val        = 0,
		.descrip    = "input from stdin",
		.argDescrip = NULL
	},
	{
		.longName   = "recursive",
		.shortName  = 'r',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.recursive,
		.val        = 0,
		.descrip    = "recursive delete",
		.argDescrip = NULL
	},
	{
		.longName   = "modules-path",
		.shortName  = 0,
		.argInfo    = POPT_ARG_STRING,
		.arg        = &options.modules_path,
		.val        = 0,
		.descrip    = "modules path",
		.argDescrip = "PATH"
	},
	{
		.longName   = "num-searches",
		.shortName  = 0,
		.argInfo    = POPT_ARG_INT,
		.arg        = &options.num_searches,
		.val        = 0,
		.descrip    = "number of test searches",
		.argDescrip = NULL
	},
	{
		.longName   = "num-records",
		.shortName  = 0,
		.argInfo    = POPT_ARG_INT,
		.arg        = &options.num_records,
		.val        = 0,
		.descrip    = "number of test records",
		.argDescrip = NULL
	},
	{
		.longName   = "all",
		.shortName  = 'a',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.all_records,
		.val        = 0,
		.descrip    = "(|(objectClass=*)(distinguishedName=*))",
		.argDescrip = NULL
	},
	{
		.longName   = "nosync",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.nosync,
		.val        = 0,
		.descrip    = "non-synchronous transactions",
		.argDescrip = NULL
	},
	{
		.longName   = "sorted",
		.shortName  = 'S',
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.sorted,
		.val        = 0,
		.descrip    = "sort attributes",
		.argDescrip = NULL
	},
	{
		.longName   = NULL,
		.shortName  = 'o',
		.argInfo    = POPT_ARG_STRING,
		.arg        = NULL,
		.val        = 'o',
		.descrip    = "ldb_connect option",
		.argDescrip = "OPTION"
	},
	{
		.longName   = "controls",
		.shortName  = 0,
		.argInfo    = POPT_ARG_STRING,
		.arg        = NULL,
		.val        = 'c',
		.descrip    = "controls",
		.argDescrip = NULL
	},
	{
		.longName   = "show-binary",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = &options.show_binary,
		.val        = 0,
		.descrip    = "display binary LDIF",
		.argDescrip = NULL
	},
	{
		.longName   = "paged",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'P',
		.descrip    = "use a paged search",
		.argDescrip = NULL
	},
	{
		.longName   = "show-deleted",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'D',
		.descrip    = "show deleted objects",
		.argDescrip = NULL
	},
	{
		.longName   = "show-recycled",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'R',
		.descrip    = "show recycled objects",
		.argDescrip = NULL
	},
	{
		.longName   = "show-deactivated-link",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'd',
		.descrip    = "show deactivated links",
		.argDescrip = NULL
	},
	{
		.longName   = "reveal",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'r',
		.descrip    = "reveal ldb internals",
		.argDescrip = NULL
	},
	{
		.longName   = "relax",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = CMDLINE_RELAX,
		.descrip    = "pass relax control",
		.argDescrip = NULL
	},
	{
		.longName   = "cross-ncs",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'N',
		.descrip    = "search across NC boundaries",
		.argDescrip = NULL
	},
	{
		.longName   = "extended-dn",
		.shortName  = 0,
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = 'E',
		.descrip    = "show extended DNs",
		.argDescrip = NULL
	},
	{0}
};

void ldb_cmdline_help(struct ldb_context *ldb, const char *cmdname, FILE *f)
{
	poptContext pc;
	struct poptOption **popt_options = ldb_module_popt_options(ldb);
	pc = poptGetContext(cmdname, 0, NULL, *popt_options,
			    POPT_CONTEXT_KEEP_FIRST);
	poptPrintHelp(pc, f, 0);
}

/*
  add a control to the options structure
 */
static bool add_control(TALLOC_CTX *mem_ctx, const char *control)
{
	unsigned int i;

	/* count how many controls we already have */
	for (i=0; options.controls && options.controls[i]; i++) ;

	options.controls = talloc_realloc(mem_ctx, options.controls, const char *, i + 2);
	if (options.controls == NULL) {
		return false;
	}
	options.controls[i] = control;
	options.controls[i+1] = NULL;
	return true;
}

/**
  process command line options
*/
static struct ldb_cmdline *ldb_cmdline_process_internal(struct ldb_context *ldb,
					int argc, const char **argv,
					void (*usage)(struct ldb_context *),
					bool dont_create,
					bool search)
{
	struct ldb_cmdline *ret=NULL;
	poptContext pc;
	int num_options = 0;
	int opt;
	unsigned int flags = 0;
	int rc;
	struct poptOption **popt_options;

	/* make the ldb utilities line buffered */
	setlinebuf(stdout);

	ret = talloc_zero(ldb, struct ldb_cmdline);
	if (ret == NULL) {
		fprintf(stderr, "Out of memory!\n");
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

	popt_options = ldb_module_popt_options(ldb);
	(*popt_options) = builtin_popt_options;

	rc = ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_OPTIONS);
	if (rc != LDB_SUCCESS) {
		fprintf(stderr, "ldb: failed to run command line hooks : %s\n", ldb_strerror(rc));
		goto failed;
	}

	pc = poptGetContext(argv[0], argc, argv, *popt_options,
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
				fprintf(stderr, "Out of memory!\n");
				goto failed;
			}
			options.options[num_options] = poptGetOptArg(pc);
			options.options[num_options+1] = NULL;
			num_options++;
			break;

		case 'c': {
			const char *cs = poptGetOptArg(pc);
			const char *p;

			for (p = cs; p != NULL; ) {
				const char *t, *c;

				t = strchr(p, ',');
				if (t == NULL) {
					c = talloc_strdup(options.controls, p);
					p = NULL;
				} else {
					c = talloc_strndup(options.controls, p, t-p);
			        	p = t + 1;
				}
				if (c == NULL || !add_control(ret, c)) {
					fprintf(stderr, __location__ ": out of memory\n");
					goto failed;
				}
			}

			break;	  
		}
		case 'P':
			if (!add_control(ret, "paged_results:1:1024")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'D':
			if (!add_control(ret, "show_deleted:1")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'R':
			if (!add_control(ret, "show_recycled:0")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'd':
			if (!add_control(ret, "show_deactivated_link:0")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'r':
			if (!add_control(ret, "reveal_internals:0")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case CMDLINE_RELAX:
			if (!add_control(ret, "relax:0")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'N':
			if (!add_control(ret, "search_options:1:2")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		case 'E':
			if (!add_control(ret, "extended_dn:1:1")) {
				fprintf(stderr, __location__ ": out of memory\n");
				goto failed;
			}
			break;
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			if (usage) usage(ldb);
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
		if (usage) usage(ldb);
		goto failed;
	}

	if (strcmp(ret->url, "NONE") == 0) {
		return ret;
	}

	if (options.nosync) {
		flags |= LDB_FLG_NOSYNC;
	}

	if (search) {
		flags |= LDB_FLG_DONT_CREATE_DB;

		if (options.show_binary) {
			flags |= LDB_FLG_SHOW_BINARY;
		}
	}

	if (options.tracing) {
		flags |= LDB_FLG_ENABLE_TRACING;
	}

	if (options.modules_path != NULL) {
		ldb_set_modules_dir(ldb, options.modules_path);
	}

	rc = ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_PRECONNECT);
	if (rc != LDB_SUCCESS) {
		fprintf(stderr, "ldb: failed to run preconnect hooks : %s\n", ldb_strerror(rc));
		goto failed;
	}

	/* now connect to the ldb */
	if (ldb_connect(ldb, ret->url, flags, ret->options) != LDB_SUCCESS) {
		fprintf(stderr, "Failed to connect to %s - %s\n", 
			ret->url, ldb_errstring(ldb));
		goto failed;
	}

	rc = ldb_modules_hook(ldb, LDB_MODULE_HOOK_CMDLINE_POSTCONNECT);
	if (rc != LDB_SUCCESS) {
		fprintf(stderr, "ldb: failed to run post connect hooks : %s\n", ldb_strerror(rc));
		goto failed;
	}

	return ret;

failed:
	talloc_free(ret);
	exit(LDB_ERR_OPERATIONS_ERROR);
	return NULL;
}

struct ldb_cmdline *ldb_cmdline_process_search(struct ldb_context *ldb,
					       int argc, const char **argv,
					       void (*usage)(struct ldb_context *))
{
	return ldb_cmdline_process_internal(ldb, argc, argv, usage, true, true);
}

struct ldb_cmdline *ldb_cmdline_process_edit(struct ldb_context *ldb,
					     int argc, const char **argv,
					     void (*usage)(struct ldb_context *))
{
	return ldb_cmdline_process_internal(ldb, argc, argv, usage, false, true);
}

struct ldb_cmdline *ldb_cmdline_process(struct ldb_context *ldb,
					int argc, const char **argv,
					void (*usage)(struct ldb_context *))
{
	return ldb_cmdline_process_internal(ldb, argc, argv, usage, false, false);
}

/* this function check controls reply and determines if more
 * processing is needed setting up the request controls correctly
 *
 * returns:
 * 	-1 error
 * 	0 all ok
 * 	1 all ok, more processing required
 */
int handle_controls_reply(struct ldb_control **reply, struct ldb_control **request)
{
	unsigned int i, j;
	int ret = 0;

	if (reply == NULL || request == NULL) return -1;

	for (i = 0; reply[i]; i++) {
		if (strcmp(LDB_CONTROL_VLV_RESP_OID, reply[i]->oid) == 0) {
			struct ldb_vlv_resp_control *rep_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_vlv_resp_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning VLV reply OID received "
					"with no VLV data\n");
				continue;
			}

			/* check we have a matching control in the request */
			for (j = 0; request[j]; j++) {
				if (strcmp(LDB_CONTROL_VLV_REQ_OID, request[j]->oid) == 0)
					break;
			}
			if (! request[j]) {
				fprintf(stderr, "Warning VLV reply received but no request have been made\n");
				continue;
			}

			/* check the result */
			if (rep_control->vlv_result != 0) {
				fprintf(stderr, "Warning: VLV not performed with error: %d\n", rep_control->vlv_result);
			} else {
				fprintf(stderr, "VLV Info: target position = %d, content count = %d\n", rep_control->targetPosition, rep_control->contentCount);
			}

			continue;
		}

		if (strcmp(LDB_CONTROL_ASQ_OID, reply[i]->oid) == 0) {
			struct ldb_asq_control *rep_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_asq_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning ASQ reply OID received "
					"with no ASQ data\n");
				continue;
			}

			/* check the result */
			if (rep_control->result != 0) {
				fprintf(stderr, "Warning: ASQ not performed with error: %d\n", rep_control->result);
			}

			continue;
		}

		if (strcmp(LDB_CONTROL_PAGED_RESULTS_OID, reply[i]->oid) == 0) {
			struct ldb_paged_control *rep_control, *req_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_paged_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning PAGED_RESULTS reply OID "
					"received with no data\n");
				continue;
			}

			if (rep_control->cookie_len == 0) { /* we are done */
				break;
			}

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
			req_control->cookie = (char *)talloc_memdup(
				req_control, rep_control->cookie,
				rep_control->cookie_len);
			req_control->cookie_len = rep_control->cookie_len;

			ret = 1;

			continue;
		}

		if (strcmp(LDB_CONTROL_SORT_RESP_OID, reply[i]->oid) == 0) {
			struct ldb_sort_resp_control *rep_control;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_sort_resp_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning SORT reply OID "
					"received with no data\n");
				continue;
			}

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

		if (strcmp(LDB_CONTROL_DIRSYNC_OID, reply[i]->oid) == 0) {
			struct ldb_dirsync_control *rep_control, *req_control;
			char *cookie;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_dirsync_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning DIRSYNC reply OID "
					"received with no data\n");
				continue;
			}
			if (rep_control->cookie_len == 0) /* we are done */
				break;

			/* more processing required */
			/* let's fill in the request control with the new cookie */

			for (j = 0; request[j]; j++) {
				if (strcmp(LDB_CONTROL_DIRSYNC_OID, request[j]->oid) == 0)
					break;
			}
			/* if there's a reply control we must find a request
			 * control matching it */
			if (! request[j]) return -1;

			req_control = talloc_get_type(request[j]->data, struct ldb_dirsync_control);

			if (req_control->cookie)
				talloc_free(req_control->cookie);
			req_control->cookie = (char *)talloc_memdup(
				req_control, rep_control->cookie,
				rep_control->cookie_len);
			req_control->cookie_len = rep_control->cookie_len;

			cookie = ldb_base64_encode(req_control, rep_control->cookie, rep_control->cookie_len);
			printf("# DIRSYNC cookie returned was:\n# %s\n", cookie);

			continue;
		}
		if (strcmp(LDB_CONTROL_DIRSYNC_EX_OID, reply[i]->oid) == 0) {
			struct ldb_dirsync_control *rep_control, *req_control;
			char *cookie;

			rep_control = talloc_get_type(reply[i]->data, struct ldb_dirsync_control);
			if (rep_control == NULL) {
				fprintf(stderr,
					"Warning DIRSYNC_EX reply OID "
					"received with no data\n");
				continue;
			}
			if (rep_control->cookie_len == 0) /* we are done */
				break;

			/* more processing required */
			/* let's fill in the request control with the new cookie */

			for (j = 0; request[j]; j++) {
				if (strcmp(LDB_CONTROL_DIRSYNC_EX_OID, request[j]->oid) == 0)
					break;
			}
			/* if there's a reply control we must find a request
			 * control matching it */
			if (! request[j]) return -1;

			req_control = talloc_get_type(request[j]->data, struct ldb_dirsync_control);

			if (req_control->cookie)
				talloc_free(req_control->cookie);
			req_control->cookie = (char *)talloc_memdup(
				req_control, rep_control->cookie,
				rep_control->cookie_len);
			req_control->cookie_len = rep_control->cookie_len;

			cookie = ldb_base64_encode(req_control, rep_control->cookie, rep_control->cookie_len);
			printf("# DIRSYNC_EX cookie returned was:\n# %s\n", cookie);

			continue;
		}

		/* no controls matched, throw a warning */
		fprintf(stderr, "Unknown reply control oid: %s\n", reply[i]->oid);
	}

	return ret;
}
