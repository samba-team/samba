/* 
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/filesys.h"
#include "system/readline.h"
#include "lib/smbreadline/smbreadline.h"
#include "libcli/libcli.h"
#include "lib/ldb/include/ldb.h"
#include "lib/events/events.h"
#include "dynconfig.h"

#include "torture/torture.h"
#include "build.h"
#include "lib/util/dlinklist.h"
#include "librpc/rpc/dcerpc.h"

static bool run_matching(struct torture_context *torture,
						 const char *prefix, 
						 const char *expr,
						 struct torture_suite *suite,
						 bool *matched)
{
	bool ret = true;

	if (suite == NULL) {
		struct torture_suite *o;

		for (o = torture_root->children; o; o = o->next) {
			if (gen_fnmatch(expr, o->name) == 0) {
				*matched = true;
				init_iconv();
				ret &= torture_run_suite(torture, o);
				continue;
			}

			ret &= run_matching(torture, o->name, expr, o, matched);
		}
	} else {
		char *name;
		struct torture_suite *c;
		struct torture_tcase *t;

		for (c = suite->children; c; c = c->next) {
			asprintf(&name, "%s-%s", prefix, c->name);

			if (gen_fnmatch(expr, name) == 0) {
				*matched = true;
				init_iconv();
				torture->active_testname = talloc_strdup(torture, prefix);
				ret &= torture_run_suite(torture, c);
				free(name);
				continue;
			}
			
			ret &= run_matching(torture, name, expr, c, matched);

			free(name);
		}

		for (t = suite->testcases; t; t = t->next) {
			asprintf(&name, "%s-%s", prefix, t->name);
			if (gen_fnmatch(expr, name) == 0) {
				*matched = true;
				init_iconv();
				torture->active_testname = talloc_strdup(torture, prefix);
				ret &= torture_run_tcase(torture, t);
				talloc_free(torture->active_testname);
			}
			free(name);
		}
	}

	return ret;
}

#define MAX_COLS 80 /* FIXME: Determine this at run-time */

/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
static bool run_test(struct torture_context *torture, const char *name)
{
	bool ret = true;
	bool matched = false;
	struct torture_suite *o;

	if (strequal(name, "ALL")) {
		for (o = torture_root->children; o; o = o->next) {
			ret &= torture_run_suite(torture, o);
		}
		return ret;
	}

	ret = run_matching(torture, NULL, name, NULL, &matched);

	if (!matched) {
		printf("Unknown torture operation '%s'\n", name);
		return false;
	}

	return ret;
}

static void parse_dns(const char *dns)
{
	char *userdn, *basedn, *secret;
	char *p, *d;

	/* retrievieng the userdn */
	p = strchr_m(dns, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_userdn", "");
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	userdn = strndup(dns, p - dns);
	lp_set_cmdline("torture:ldap_userdn", userdn);

	/* retrieve the basedn */
	d = p + 1;
	p = strchr_m(d, '#');
	if (!p) {
		lp_set_cmdline("torture:ldap_basedn", "");
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	basedn = strndup(d, p - d);
	lp_set_cmdline("torture:ldap_basedn", basedn);

	/* retrieve the secret */
	p = p + 1;
	if (!p) {
		lp_set_cmdline("torture:ldap_secret", "");
		return;
	}
	secret = strdup(p);
	lp_set_cmdline("torture:ldap_secret", secret);

	printf ("%s - %s - %s\n", userdn, basedn, secret);

}

static void print_test_list(void)
{
	struct torture_suite *o;
	struct torture_suite *s;
	struct torture_tcase *t;

	for (o = torture_root->children; o; o = o->next) {
		for (s = o->children; s; s = s->next) {
			printf("%s-%s\n", o->name, s->name);
		}

		for (t = o->testcases; t; t = t->next) {
			printf("%s-%s\n", o->name, t->name);
		}
	}
}

static void usage(poptContext pc)
{
	struct torture_suite *o;
	struct torture_suite *s;
	struct torture_tcase *t;
	int i;

	poptPrintUsage(pc, stdout, 0);
	printf("\n");

	printf("The binding format is:\n\n");

	printf("  TRANSPORT:host[flags]\n\n");

	printf("  where TRANSPORT is either ncacn_np for SMB, ncacn_ip_tcp for RPC/TCP\n");
	printf("  or ncalrpc for local connections.\n\n");

	printf("  'host' is an IP or hostname or netbios name. If the binding string\n");
	printf("  identifies the server side of an endpoint, 'host' may be an empty\n");
	printf("  string.\n\n");

	printf("  'flags' can include a SMB pipe name if using the ncacn_np transport or\n");
	printf("  a TCP port number if using the ncacn_ip_tcp transport, otherwise they\n");
	printf("  will be auto-determined.\n\n");

	printf("  other recognised flags are:\n\n");

	printf("    sign : enable ntlmssp signing\n");
	printf("    seal : enable ntlmssp sealing\n");
	printf("    connect : enable rpc connect level auth (auth, but no sign or seal)\n");
	printf("    validate: enable the NDR validator\n");
	printf("    print: enable debugging of the packets\n");
	printf("    bigendian: use bigendian RPC\n");
	printf("    padcheck: check reply data for non-zero pad bytes\n\n");

	printf("  For example, these all connect to the samr pipe:\n\n");

	printf("    ncacn_np:myserver\n");
	printf("    ncacn_np:myserver[samr]\n");
	printf("    ncacn_np:myserver[\\pipe\\samr]\n");
	printf("    ncacn_np:myserver[/pipe/samr]\n");
	printf("    ncacn_np:myserver[samr,sign,print]\n");
	printf("    ncacn_np:myserver[\\pipe\\samr,sign,seal,bigendian]\n");
	printf("    ncacn_np:myserver[/pipe/samr,seal,validate]\n");
	printf("    ncacn_np:\n");
	printf("    ncacn_np:[/pipe/samr]\n\n");

	printf("    ncacn_ip_tcp:myserver\n");
	printf("    ncacn_ip_tcp:myserver[1024]\n");
	printf("    ncacn_ip_tcp:myserver[1024,sign,seal]\n\n");

	printf("    ncalrpc:\n\n");

	printf("The UNC format is:\n\n");

	printf("  //server/share\n\n");

	printf("Tests are:");

	for (o = torture_root->children; o; o = o->next) {
		printf("\n%s (%s):\n  ", o->description, o->name);

		i = 0;
		for (s = o->children; s; s = s->next) {
			if (i + strlen(o->name) + strlen(s->name) >= (MAX_COLS - 3)) {
				printf("\n  ");
				i = 0;
			}
			i+=printf("%s-%s ", o->name, s->name);
		}

		for (t = o->testcases; t; t = t->next) {
			if (i + strlen(o->name) + strlen(t->name) >= (MAX_COLS - 3)) {
				printf("\n  ");
				i = 0;
			}
			i+=printf("%s-%s ", o->name, t->name);
		}

		if (i) printf("\n");
	}

	printf("\nThe default test is ALL.\n");

	exit(1);
}

static void max_runtime_handler(int sig)
{
	DEBUG(0,("maximum runtime exceeded for smbtorture - terminating\n"));
	exit(1);
}

struct timeval last_suite_started;

static void simple_suite_start(struct torture_context *ctx,
							   struct torture_suite *suite)
{
	last_suite_started = timeval_current();
	printf("Running %s\n", suite->name);
}

static void simple_suite_finish(struct torture_context *ctx,
							   struct torture_suite *suite)
{

	printf("%s took %g secs\n\n", suite->name, 
		   timeval_elapsed(&last_suite_started));
}

static void simple_test_result (struct torture_context *context, 
								enum torture_result res, const char *reason)
{
	switch (res) {
	case TORTURE_OK:
		if (reason)
			printf("OK: %s\n", reason);
		break;
	case TORTURE_FAIL:
		printf("TEST %s FAILED! - %s\n", context->active_test->name, reason);
		break;
	case TORTURE_ERROR:
		printf("ERROR IN TEST %s! - %s\n", context->active_test->name, reason); 
		break;
	case TORTURE_SKIP:
		printf("SKIP: %s - %s\n", context->active_test->name, reason);
		break;
	}
}

static void simple_comment (struct torture_context *test, 
							const char *comment)
{
	printf("%s", comment);
}

static void simple_warning(struct torture_context *test, 
						   const char *comment)
{
	fprintf(stderr, "WARNING: %s\n", comment);
}

const static struct torture_ui_ops std_ui_ops = {
	.comment = simple_comment,
	.warning = simple_warning,
	.suite_start = simple_suite_start,
	.suite_finish = simple_suite_finish,
	.test_result = simple_test_result
};

static void subunit_init(struct torture_context *ctx) 
{
	/* FIXME: register segv and bus handler */
}

static void subunit_suite_start(struct torture_context *ctx,
							   struct torture_suite *suite)
{
	printf("testsuite: %s\n", suite->name);
}

static void subunit_test_start (struct torture_context *ctx, 
							    struct torture_tcase *tcase,
								struct torture_test *test)
{
	printf("test: %s\n", test->name);
}

static void subunit_test_result (struct torture_context *context, 
								 enum torture_result res, const char *reason)
{
	switch (res) {
	case TORTURE_OK:
		printf("success: %s", context->active_test->name);
		break;
	case TORTURE_FAIL:
		printf("failure: %s", context->active_test->name);
		break;
	case TORTURE_ERROR:
		printf("error: %s", context->active_test->name);
		break;
	case TORTURE_SKIP:
		printf("skip: %s", context->active_test->name);
		break;
	}
	if (reason)
		printf(" [\n%s\n]", reason);
	printf("\n");
}

static void subunit_comment (struct torture_context *test, 
							 const char *comment)
{
	fprintf(stderr, "%s", comment);
}

const static struct torture_ui_ops subunit_ui_ops = {
	.init = subunit_init,
	.comment = subunit_comment,
	.test_start = subunit_test_start,
	.test_result = subunit_test_result,
	.suite_start = subunit_suite_start
};

static void harness_test_start (struct torture_context *ctx, 
							    struct torture_tcase *tcase,
								struct torture_test *test)
{
}

static void harness_test_result (struct torture_context *context, 
								 enum torture_result res, const char *reason)
{
	switch (res) {
	case TORTURE_OK:
		printf("ok %s - %s\n", context->active_test->name, reason);
		break;
	case TORTURE_FAIL:
	case TORTURE_ERROR:
		printf("not ok %s - %s\n", context->active_test->name, reason);
		break;
	case TORTURE_SKIP:
		printf("skip %s - %s\n", context->active_test->name, reason);
		break;
	}
}

static void harness_comment (struct torture_context *test, 
							 const char *comment)
{
	printf("# %s\n", comment);
}

const static struct torture_ui_ops harness_ui_ops = {
	.comment = harness_comment,
	.test_start = harness_test_start,
	.test_result = harness_test_result
};

static void quiet_suite_start(struct torture_context *ctx,
				       		  struct torture_suite *suite)
{
	int i;
	ctx->quiet = true;
	for (i = 1; i < ctx->level; i++) putchar('\t');
	printf("%s: ", suite->name);
	fflush(stdout);
}

static void quiet_suite_finish(struct torture_context *ctx,
				       		  struct torture_suite *suite)
{
	putchar('\n');
}

static void quiet_test_result (struct torture_context *context, 
							   enum torture_result res, const char *reason)
{
	fflush(stdout);
	switch (res) {
	case TORTURE_OK: putchar('.'); break;
	case TORTURE_FAIL: putchar('F'); break;
	case TORTURE_ERROR: putchar('E'); break;
	case TORTURE_SKIP: putchar('I'); break;
	}
}

const static struct torture_ui_ops quiet_ui_ops = {
	.suite_start = quiet_suite_start,
	.suite_finish = quiet_suite_finish,
	.test_result = quiet_test_result
};

void run_shell(struct torture_context *tctx)
{
	char *cline;
	int argc;
	const char **argv;
	int ret;

	while (1) {
		cline = smb_readline("torture> ", NULL, NULL);

		if (cline == NULL)
			return;
	
		ret = poptParseArgvString(cline, &argc, &argv);
		if (ret != 0) {
			fprintf(stderr, "Error parsing line\n");
			continue;
		}

		if (!strcmp(argv[0], "quit")) {
			return;
		} else if (!strcmp(argv[0], "set")) {
			if (argc < 3) {
				fprintf(stderr, "Usage: set <variable> <value>\n");
			} else {
				char *name = talloc_asprintf(NULL, "torture:%s", argv[1]);
				lp_set_cmdline(name, argv[2]);
				talloc_free(name);
			}
		} else if (!strcmp(argv[0], "help")) {
			fprintf(stderr, "Available commands:\n"
							" help - This help command\n"
							" run - Run test\n"
							" set - Change variables\n"
							"\n");
		} else if (!strcmp(argv[0], "run")) {
			if (argc < 2) {
				fprintf(stderr, "Usage: run TEST-NAME [OPTIONS...]\n");
			} else {
				run_test(tctx, argv[1]);
			}
		}
	}
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc,char *argv[])
{
	int opt, i;
	bool correct = true;
	int max_runtime=0;
	int argc_new;
	struct torture_context *torture;
	const struct torture_ui_ops *ui_ops;
	char **argv_new;
	poptContext pc;
	static const char *target = "other";
	struct dcerpc_binding *binding_struct;
	NTSTATUS status;
	int shell = False;
	static const char *ui_ops_name = "simple";
	static int list_tests = 0;
	enum {OPT_LOADFILE=1000,OPT_UNCLIST,OPT_TIMELIMIT,OPT_DNS, OPT_LIST,
	      OPT_DANGEROUS,OPT_SMB_PORTS,OPT_ASYNC,OPT_NUMPROGS, OPT_BASEDIR};
	
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"format", 0, POPT_ARG_STRING, &ui_ops_name, 0, "Output format (one of: simple, subunit, harness)", NULL },
		{"smb-ports",	'p', POPT_ARG_STRING, NULL,     OPT_SMB_PORTS,	"SMB ports", 	NULL},
		{"basedir",	  0, POPT_ARG_STRING, NULL, OPT_BASEDIR, "base directory", "BSAEDIR" },
		{"seed",	  0, POPT_ARG_INT,  &torture_seed, 	0,	"seed", 	NULL},
		{"num-progs",	  0, POPT_ARG_INT,  NULL, 	OPT_NUMPROGS,	"num progs",	NULL},
		{"num-ops",	  0, POPT_ARG_INT,  &torture_numops, 	0, 	"num ops",	NULL},
		{"entries",	  0, POPT_ARG_INT,  &torture_entries, 	0,	"entries",	NULL},
		{"loadfile",	  0, POPT_ARG_STRING,	NULL, 	OPT_LOADFILE,	"loadfile", 	NULL},
		{"list", 	  0, POPT_ARG_NONE, &list_tests, 0, NULL, NULL },
		{"unclist",	  0, POPT_ARG_STRING,	NULL, 	OPT_UNCLIST,	"unclist", 	NULL},
		{"timelimit",	't', POPT_ARG_INT,	NULL, 	OPT_TIMELIMIT,	"timelimit", 	NULL},
		{"failures",	'f', POPT_ARG_INT,  &torture_failures, 	0,	"failures", 	NULL},
		{"parse-dns",	'D', POPT_ARG_STRING,	NULL, 	OPT_DNS,	"parse-dns", 	NULL},
		{"dangerous",	'X', POPT_ARG_NONE,	NULL,   OPT_DANGEROUS,
		 "run dangerous tests (eg. wiping out password database)", NULL},
		{"shell", 		0, POPT_ARG_NONE, &shell, True, "Run shell", NULL},
		{"target", 		'T', POPT_ARG_STRING, &target, 0, "samba3|samba4|other", NULL},
		{"async",       'a', POPT_ARG_NONE,     NULL,   OPT_ASYNC,
		 "run async tests", NULL},
		{"num-async",    0, POPT_ARG_INT,  &torture_numasync,  0,
		 "number of simultaneous async requests", NULL},
		{"maximum-runtime", 0, POPT_ARG_INT, &max_runtime, 0, 
		 "set maximum time for smbtorture to live", "seconds"},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		{ NULL }
	};

	setlinebuf(stdout);

	/* we are never interested in SIGPIPE */
	BlockSignals(true, SIGPIPE);

	pc = poptGetContext("smbtorture", argc, (const char **) argv, long_options, 
			    POPT_CONTEXT_KEEP_FIRST);

	poptSetOtherOptionHelp(pc, "<binding>|<unc> TEST1 TEST2 ...");

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_LOADFILE:
			lp_set_cmdline("torture:loadfile", poptGetOptArg(pc));
			break;
		case OPT_UNCLIST:
			lp_set_cmdline("torture:unclist", poptGetOptArg(pc));
			break;
		case OPT_TIMELIMIT:
			lp_set_cmdline("torture:timelimit", poptGetOptArg(pc));
			break;
		case OPT_NUMPROGS:
			lp_set_cmdline("torture:nprocs", poptGetOptArg(pc));
			break;
		case OPT_BASEDIR:
			lp_set_cmdline("torture:basedir", poptGetOptArg(pc));
			break;
		case OPT_DNS:
			parse_dns(poptGetOptArg(pc));
			break;
		case OPT_DANGEROUS:
			lp_set_cmdline("torture:dangerous", "Yes");
			break;
		case OPT_ASYNC:
			lp_set_cmdline("torture:async", "Yes");
			break;
		case OPT_SMB_PORTS:
			lp_set_cmdline("smb ports", poptGetOptArg(pc));
			break;
		}
	}

	if (strcmp(target, "samba3") == 0) {
		lp_set_cmdline("torture:samba3", "true");
	} else if (strcmp(target, "samba4") == 0) {
		lp_set_cmdline("torture:samba4", "true");
	}

	if (max_runtime) {
		/* this will only work if nobody else uses alarm(),
		   which means it won't work for some tests, but we
		   can't use the event context method we use for smbd
		   as so many tests create their own event
		   context. This will at least catch most cases. */
		signal(SIGALRM, max_runtime_handler);
		alarm(max_runtime);
	}

	torture_init();
	ldb_global_init();

	if (list_tests) {
		print_test_list();
		return 0;
	}

	if (torture_seed == 0) {
		torture_seed = time(NULL);
	} 
	printf("Using seed %d\n", torture_seed);
	srandom(torture_seed);

	argv_new = discard_const_p(char *, poptGetArgs(pc));

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (!(argc_new >= 3 || (shell && argc_new >= 2))) {
		usage(pc);
		exit(1);
	}

	/* see if its a RPC transport specifier */
	status = dcerpc_parse_binding(talloc_autofree_context(), argv_new[1], &binding_struct);
	if (NT_STATUS_IS_OK(status)) {
		lp_set_cmdline("torture:host", binding_struct->host);
		lp_set_cmdline("torture:share", "IPC$");
		lp_set_cmdline("torture:binding", argv_new[1]);
	} else {
		char *binding = NULL;
		char *host = NULL, *share = NULL;

		if (!smbcli_parse_unc(argv_new[1], NULL, &host, &share)) {
			d_printf("Invalid option: %s is not a valid torture target (share or binding string)\n\n", argv_new[1]);
			usage(pc);
		}

		lp_set_cmdline("torture:host", host);
		lp_set_cmdline("torture:share", share);
		asprintf(&binding, "ncacn_np:%s", host);
		lp_set_cmdline("torture:binding", binding);
	}

	if (!strcmp(ui_ops_name, "simple")) {
		ui_ops = &std_ui_ops;
	} else if (!strcmp(ui_ops_name, "subunit")) {
		ui_ops = &subunit_ui_ops;
	} else if (!strcmp(ui_ops_name, "harness")) {
		ui_ops = &harness_ui_ops;
	} else if (!strcmp(ui_ops_name, "quiet")) {
		ui_ops = &quiet_ui_ops;
	} else {
		printf("Unknown output format '%s'\n", ui_ops_name);
		exit(1);
	}

	torture = torture_context_init(talloc_autofree_context(), ui_ops);

	if (argc_new == 0) {
		printf("You must specify a test to run, or 'ALL'\n");
	} else if (shell) {
		run_shell(torture);
	} else {
		for (i=2;i<argc_new;i++) {
			if (!run_test(torture, argv_new[i])) {
				correct = false;
			}
		}
	}

	if (torture->returncode) {
		return(0);
	} else {
		return(1);
	}
}
