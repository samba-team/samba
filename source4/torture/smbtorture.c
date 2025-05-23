/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006-2008

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
#include "lib/util/util_file.h"
#include "lib/cmdline/cmdline.h"
#include "system/time.h"
#include "system/wait.h"
#include "system/filesys.h"
#include "system/readline.h"
#include "../libcli/smbreadline/smbreadline.h"
#include "libcli/libcli.h"
#include "lib/events/events.h"

#include "torture/smbtorture.h"
#include "librpc/rpc/dcerpc.h"
#include "auth/gensec/gensec.h"
#include "param/param.h"
#include "lib/util/samba_modules.h"

#ifdef HAVE_READLINE_HISTORY_H
#include <readline/history.h>
#endif

static int use_fullname;

static char *prefix_name(TALLOC_CTX *mem_ctx, const char *prefix, const char *name)
{
	if (prefix == NULL)
		return talloc_strdup(mem_ctx, name);
	else
		return talloc_asprintf(mem_ctx, "%s.%s", prefix, name);
}

static void print_test_list(const struct torture_suite *suite, const char *prefix, const char *expr)
{
	struct torture_suite *o;
	struct torture_tcase *t;
	struct torture_test *p;

	for (o = suite->children; o; o = o->next) {
		char *name = prefix_name(NULL, prefix, o->name);
		print_test_list(o, name, expr);
		talloc_free(name);
	}

	for (t = suite->testcases; t; t = t->next) {
		for (p = t->tests; p; p = p->next) {
			char *name = talloc_asprintf(NULL, "%s.%s.%s", prefix, t->name, p->name);
			if (strncmp(name, expr, strlen(expr)) == 0) {
				printf("%s\n", name);
			}
			talloc_free(name);
		}
	}
}

static bool run_matching(struct torture_context *torture,
						 const char *prefix,
						 const char *expr,
						 const char **restricted,
						 struct torture_suite *suite,
						 bool *matched)
{
	bool ret = true;
	struct torture_suite *o;
	struct torture_tcase *t;
	struct torture_test *p;

	for (o = suite->children; o; o = o->next) {
		char *name = NULL;
		name = prefix_name(torture, prefix, o->name);
		if (gen_fnmatch(expr, name) == 0) {
			*matched = true;
			reload_charcnv(torture->lp_ctx);
			if (use_fullname == 1) {
				torture_subunit_prefix_reset(torture, prefix);
			}
			ret &= torture_run_suite_restricted(torture, o, restricted);
			if (use_fullname == 1) {
				torture_subunit_prefix_reset(torture, NULL);
			}
			/*
			 * torture_run_suite_restricted() already implements
			 * recursion, so we're done with this child suite.
			 */
			continue;
		}
		ret &= run_matching(torture, name, expr, restricted, o, matched);
	}

	for (t = suite->testcases; t; t = t->next) {
		char *tname = prefix_name(torture, prefix, t->name);
		if (gen_fnmatch(expr, tname) == 0) {
			*matched = true;
			reload_charcnv(torture->lp_ctx);
			if (use_fullname == 1) {
				torture_subunit_prefix_reset(torture, prefix);
			}
			ret &= torture_run_tcase_restricted(torture, t, restricted);
			if (use_fullname == 1) {
				torture_subunit_prefix_reset(torture, NULL);
			}
			/*
			 * torture_run_tcase_restricted() already implements
			 * recursion, so we're done for this tcase.
			 */
			continue;
		}
		for (p = t->tests; p; p = p->next) {
			char *pname = prefix_name(torture, tname, p->name);
			if (gen_fnmatch(expr, pname) == 0) {
				*matched = true;
				reload_charcnv(torture->lp_ctx);
				if (use_fullname == 1) {
					torture_subunit_prefix_reset(torture,
								     tname);
				}
				ret &= torture_run_test_restricted(torture, t, p, restricted);
				if (use_fullname == 1) {
					torture_subunit_prefix_reset(torture,
								     NULL);
				}
			}
		}
	}

	return ret;
}

#define MAX_COLS 80 /* FIXME: Determine this at run-time */

/****************************************************************************
run a specified test or "ALL"
****************************************************************************/
bool torture_run_named_tests(struct torture_context *torture, const char *name,
			    const char **restricted)
{
	bool ret = true;
	bool matched = false;
	struct torture_suite *o;

	torture_ui_report_time(torture);

	if (strequal(name, "ALL")) {
		if (restricted != NULL) {
			printf("--load-list and ALL are incompatible\n");
			return false;
		}
		for (o = torture_root->children; o; o = o->next) {
			ret &= torture_run_suite(torture, o);
		}
		return ret;
	}

	ret = run_matching(torture, NULL, name, restricted, torture_root, &matched);

	if (!matched) {
		printf("Unknown torture operation '%s'\n", name);
		return false;
	}

	return ret;
}

bool torture_parse_target(TALLOC_CTX *ctx,
				struct loadparm_context *lp_ctx,
				const char *target)
{
	char *host = NULL, *share = NULL;
	struct dcerpc_binding *binding_struct;
	NTSTATUS status;

	/* see if its a RPC transport specifier */
	if (!smbcli_parse_unc(target, ctx, &host, &share)) {
		const char *h;

		status = dcerpc_parse_binding(ctx, target, &binding_struct);
		if (NT_STATUS_IS_ERR(status)) {
			d_printf("Invalid option: %s is not a valid torture target (share or binding string)\n\n", target);
			return false;
		}

		h = dcerpc_binding_get_string_option(binding_struct, "host");
		host = discard_const_p(char, h);
		if (host != NULL) {
			lpcfg_set_cmdline(lp_ctx, "torture:host", host);
		}

		if (lpcfg_parm_string(lp_ctx, NULL, "torture", "share") == NULL)
			lpcfg_set_cmdline(lp_ctx, "torture:share", "IPC$");
		lpcfg_set_cmdline(lp_ctx, "torture:binding", target);
	} else {
		lpcfg_set_cmdline(lp_ctx, "torture:host", host);
		lpcfg_set_cmdline(lp_ctx, "torture:share", share);
		lpcfg_set_cmdline(lp_ctx, "torture:binding", host);

		TALLOC_FREE(host);
		TALLOC_FREE(share);
	}

	return true;
}

static void parse_dns(struct loadparm_context *lp_ctx, const char *dns)
{
	char *userdn, *basedn, *secret;
	char *p, *d;

	/* retrieve the userdn */
	p = strchr_m(dns, '#');
	if (!p) {
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_userdn", "");
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_basedn", "");
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_secret", "");
		return;
	}
	userdn = strndup(dns, p - dns);
	lpcfg_set_cmdline(lp_ctx, "torture:ldap_userdn", userdn);

	/* retrieve the basedn */
	d = p + 1;
	p = strchr_m(d, '#');
	if (!p) {
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_basedn", "");
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_secret", "");
		return;
	}
	basedn = strndup(d, p - d);
	lpcfg_set_cmdline(lp_ctx, "torture:ldap_basedn", basedn);

	/* retrieve the secret */
	p = p + 1;
	if (!p) {
		lpcfg_set_cmdline(lp_ctx, "torture:ldap_secret", "");
		return;
	}
	secret = strdup(p);
	lpcfg_set_cmdline(lp_ctx, "torture:ldap_secret", secret);

	printf ("%s - %s - %s\n", userdn, basedn, secret);

}

/* Print the full test list, formatted into separate labelled test
 * groups.
 */
static void print_structured_testsuite_list(void)
{
	struct torture_suite *o;
	struct torture_suite *s;
	struct torture_tcase *t;
	int i;

	if (torture_root == NULL) {
	    printf("NO TESTS LOADED\n");
	    return;
	}

	for (o = torture_root->children; o; o = o->next) {
		printf("\n%s (%s):\n  ", o->description, o->name);

		i = 0;
		for (s = o->children; s; s = s->next) {
			if (i + strlen(o->name) + strlen(s->name) >= (MAX_COLS - 3)) {
				printf("\n  ");
				i = 0;
			}
			i+=printf("%s.%s ", o->name, s->name);
		}

		for (t = o->testcases; t; t = t->next) {
			if (i + strlen(o->name) + strlen(t->name) >= (MAX_COLS - 3)) {
				printf("\n  ");
				i = 0;
			}
			i+=printf("%s.%s ", o->name, t->name);
		}

		if (i) printf("\n");
	}

	printf("\nThe default test is ALL.\n");
}

static void print_testsuite_list(void)
{
	struct torture_suite *o;
	struct torture_suite *s;
	struct torture_tcase *t;

	if (torture_root == NULL)
		return;

	for (o = torture_root->children; o; o = o->next) {
		for (s = o->children; s; s = s->next) {
			printf("%s.%s\n", o->name, s->name);
		}

		for (t = o->testcases; t; t = t->next) {
			printf("%s.%s\n", o->name, t->name);
		}
	}
}

void torture_print_testsuites(bool structured)
{
	if (structured) {
		print_structured_testsuite_list();
	} else {
		print_testsuite_list();
	}
}

static void usage(poptContext pc)
{
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

	print_structured_testsuite_list();

}

_NORETURN_ static void max_runtime_handler(int sig)
{
	DEBUG(0,("maximum runtime exceeded for smbtorture - terminating\n"));
	exit(1);
}

/****************************************************************************
  main program
****************************************************************************/
int main(int argc, const char *argv[])
{
	int opt, i;
	bool correct = true;
	int max_runtime=0;
	int argc_new;
	struct torture_context *torture;
	struct torture_results *results;
	const struct torture_ui_ops *ui_ops;
	char **argv_new;
	poptContext pc;
	static const char *target = "other";
	NTSTATUS status;
	int shell = false;
	static const char *ui_ops_name = "subunit";
	const char *basedir = NULL;
	char *outputdir;
	const char *extra_module = NULL;
	static int list_tests = 0, list_testsuites = 0;
	int num_extra_users = 0;
	const char **restricted = NULL;
	int num_restricted = -1;
	const char *load_list = NULL;
	enum {OPT_LOADFILE=1000,OPT_UNCLIST,OPT_TIMELIMIT,OPT_DNS, OPT_LIST,
	      OPT_DANGEROUS,OPT_SMB_PORTS,OPT_ASYNC,OPT_NUMPROGS,
	      OPT_EXTRA_USER,};
	TALLOC_CTX *mem_ctx = NULL;
	struct tevent_context *ev = NULL;
	struct loadparm_context *lp_ctx = NULL;
	bool ok;

	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"fullname",	0, POPT_ARG_NONE, &use_fullname, 0,
		 "use full name for the test", NULL },
		{"format", 0, POPT_ARG_STRING, &ui_ops_name, 0, "Output format (one of: simple, subunit)", NULL },
		{"smb-ports",	'p', POPT_ARG_STRING, NULL,     OPT_SMB_PORTS,	"SMB ports", 	NULL},
		{"basedir",	  0, POPT_ARG_STRING, &basedir, 0, "base directory", "BASEDIR" },
		{"seed",	  0, POPT_ARG_INT,  &torture_seed, 	0,	"Seed to use for randomizer", 	NULL},
		{"num-progs",	  0, POPT_ARG_INT,  NULL, 	OPT_NUMPROGS,	"num progs",	NULL},
		{"num-ops",	  0, POPT_ARG_INT,  &torture_numops, 	0, 	"num ops",	NULL},
		{"entries",	  0, POPT_ARG_INT,  &torture_entries, 	0,	"entries",	NULL},
		{"loadfile",	  0, POPT_ARG_STRING,	NULL, 	OPT_LOADFILE,	"NBench load file to use", 	NULL},
		{"list-suites", 	  0, POPT_ARG_NONE, &list_testsuites, 0, "List available testsuites and exit", NULL },
		{"list", 	  0, POPT_ARG_NONE, &list_tests, 0, "List available tests in specified suites and exit", NULL },
		{"unclist",	  0, POPT_ARG_STRING,	NULL, 	OPT_UNCLIST,	"unclist", 	NULL},
		{"timelimit",	't', POPT_ARG_INT,	NULL, 	OPT_TIMELIMIT,	"Set time limit (in seconds)", 	NULL},
		{"failures",	'f', POPT_ARG_INT,  &torture_failures, 	0,	"failures", 	NULL},
		{"parse-dns",	'D', POPT_ARG_STRING,	NULL, 	OPT_DNS,	"parse-dns", 	NULL},
		{"dangerous",	'X', POPT_ARG_NONE,	NULL,   OPT_DANGEROUS,
		 "run dangerous tests (eg. wiping out password database)", NULL},
		{"load-module",  0,  POPT_ARG_STRING, &extra_module,     0, "load tests from DSO file",    "SOFILE"},
                {"shell",               0, POPT_ARG_NONE, &shell, true, "Run shell", NULL},
		{"target", 		'T', POPT_ARG_STRING, &target, 0, "samba3|samba4|other", NULL},
		{"async",       'a', POPT_ARG_NONE,     NULL,   OPT_ASYNC,
		 "run async tests", NULL},
		{"num-async",    0, POPT_ARG_INT,  &torture_numasync,  0,
		 "number of simultaneous async requests", NULL},
		{"maximum-runtime", 0, POPT_ARG_INT, &max_runtime, 0,
		 "set maximum time for smbtorture to live", "seconds"},
		{"extra-user",   0, POPT_ARG_STRING, NULL, OPT_EXTRA_USER,
		 "extra user credentials", NULL},
		{"load-list", 0, POPT_ARG_STRING, &load_list, 0,
	     "load a test id list from a text file", NULL},
		POPT_COMMON_SAMBA
		POPT_COMMON_CONNECTION
		POPT_COMMON_CREDENTIALS
		POPT_COMMON_VERSION
		POPT_LEGACY_S4
		POPT_TABLEEND
	};

	setlinebuf(stdout);

	mem_ctx = talloc_named_const(NULL, 0, "torture_ctx");
	if (mem_ctx == NULL) {
		printf("Unable to allocate torture_ctx\n");
		exit(1);
	}

	printf("smbtorture %s\n", samba_version_string());

	/* we are never interested in SIGPIPE */
	BlockSignals(true, SIGPIPE);

	ok = samba_cmdline_init(mem_ctx,
				SAMBA_CMDLINE_CONFIG_CLIENT,
				false /* require_smbconf */);
	if (!ok) {
		DBG_ERR("Unable to init cmdline parser\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	pc = samba_popt_get_context(getprogname(),
				    argc,
				    argv,
				    long_options,
				    POPT_CONTEXT_KEEP_FIRST);
	if (pc == NULL) {
		DBG_ERR("Failed cmdline parser\n");
		TALLOC_FREE(mem_ctx);
		exit(1);
	}

	poptSetOtherOptionHelp(pc, "<binding>|<unc> TEST1 TEST2 ...");

	lp_ctx = samba_cmdline_get_lp_ctx();

	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_LOADFILE:
			lpcfg_set_cmdline(lp_ctx, "torture:loadfile", poptGetOptArg(pc));
			break;
		case OPT_UNCLIST:
			lpcfg_set_cmdline(lp_ctx, "torture:unclist", poptGetOptArg(pc));
			break;
		case OPT_TIMELIMIT:
			lpcfg_set_cmdline(lp_ctx, "torture:timelimit", poptGetOptArg(pc));
			break;
		case OPT_NUMPROGS:
			lpcfg_set_cmdline(lp_ctx, "torture:nprocs", poptGetOptArg(pc));
			break;
		case OPT_DNS:
			parse_dns(lp_ctx, poptGetOptArg(pc));
			break;
		case OPT_DANGEROUS:
			lpcfg_set_cmdline(lp_ctx, "torture:dangerous", "Yes");
			break;
		case OPT_ASYNC:
			lpcfg_set_cmdline(lp_ctx, "torture:async", "Yes");
			break;
		case OPT_SMB_PORTS:
			lpcfg_set_cmdline(lp_ctx, "client smb transports", poptGetOptArg(pc));
			break;
		case OPT_EXTRA_USER:
			{
				char *option = talloc_asprintf(mem_ctx,
						"torture:extra_user%u",
						++num_extra_users);
				const char *value = poptGetOptArg(pc);
				if (option == NULL) {
					printf("talloc fail\n");
					talloc_free(mem_ctx);
					exit(1);
				}
				lpcfg_set_cmdline(lp_ctx, option, value);
				talloc_free(option);
			}
			break;
		default:
			if (opt < 0) {
				printf("Invalid command line option %s (%d)\n",
				       poptBadOption(pc, 0),
				       opt);
				talloc_free(mem_ctx);
				exit(1);
			}
		}
	}

	if (load_list != NULL) {
		char **r;
		r = file_lines_load(load_list, &num_restricted, 0, mem_ctx);
		restricted = discard_const_p(const char *, r);
		if (restricted == NULL) {
			printf("Unable to read load list file '%s'\n", load_list);
			talloc_free(mem_ctx);
			exit(1);
		}
	}

	if (strcmp(target, "samba3") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:samba3", "true");
		lpcfg_set_cmdline(lp_ctx, "torture:resume_key_support", "false");
	} else if (strcmp(target, "samba4") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:samba4", "true");
	} else if (strcmp(target, "samba4-ntvfs") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:samba4", "true");
		lpcfg_set_cmdline(lp_ctx, "torture:samba4-ntvfs", "true");
	} else if (strcmp(target, "winxp") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:winxp", "true");
	} else if (strcmp(target, "w2k3") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:w2k3", "true");
	} else if (strcmp(target, "w2k8") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:w2k8", "true");
		lpcfg_set_cmdline(lp_ctx,
		    "torture:invalid_lock_range_support", "false");
	} else if (strcmp(target, "w2k12") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:w2k12", "true");
	} else if (strcmp(target, "win7") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:win7", "true");
		lpcfg_set_cmdline(lp_ctx, "torture:resume_key_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:rewind_support", "false");

		/* RAW-SEARCH for fails for inexplicable reasons against win7 */
		lpcfg_set_cmdline(lp_ctx, "torture:search_ea_support", "false");

		lpcfg_set_cmdline(lp_ctx, "torture:hide_on_access_denied",
		    "true");
	} else if (strcmp(target, "onefs") == 0) {
		lpcfg_set_cmdline(lp_ctx, "torture:onefs", "true");
		lpcfg_set_cmdline(lp_ctx, "torture:openx_deny_dos_support",
		    "false");
		lpcfg_set_cmdline(lp_ctx, "torture:range_not_locked_on_file_close", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:sacl_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:ea_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:smbexit_pdu_support",
		    "false");
		lpcfg_set_cmdline(lp_ctx, "torture:smblock_pdu_support",
		    "false");
		lpcfg_set_cmdline(lp_ctx, "torture:2_step_break_to_none",
		    "true");
		lpcfg_set_cmdline(lp_ctx, "torture:deny_dos_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:deny_fcb_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:read_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:writeclose_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:resume_key_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:rewind_support", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:raw_search_search", "false");
		lpcfg_set_cmdline(lp_ctx, "torture:search_ea_size", "false");
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

	if (extra_module != NULL) {
		init_module_fn fn = load_module(poptGetOptArg(pc), false, NULL);

		if (fn == NULL)
			d_printf("Unable to load module from %s\n", poptGetOptArg(pc));
		else {
			status = fn(mem_ctx);
			if (NT_STATUS_IS_ERR(status)) {
				d_printf("Error initializing module %s: %s\n",
					poptGetOptArg(pc), nt_errstr(status));
			}
		}
	} else {
		torture_init(mem_ctx);
	}

	if (list_testsuites) {
		print_testsuite_list();
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 0;
	}

	argv_new = discard_const_p(char *, poptGetArgs(pc));

	argc_new = argc;
	for (i=0; i<argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
	}

	if (list_tests) {
		if (argc_new == 1) {
			print_test_list(torture_root, NULL, "");
		} else {
			for (i=1;i<argc_new;i++) {
				print_test_list(torture_root, NULL, argv_new[i]);
			}
		}
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 0;
	}

	if (torture_seed == 0) {
		torture_seed = time(NULL);
	}
	printf("Using seed %d\n", torture_seed);
	srandom(torture_seed);

	if (!strcmp(ui_ops_name, "simple")) {
		ui_ops = &torture_simple_ui_ops;
	} else if (!strcmp(ui_ops_name, "subunit")) {
		ui_ops = &torture_subunit_ui_ops;
	} else {
		printf("Unknown output format '%s'\n", ui_ops_name);
		talloc_free(mem_ctx);
		exit(1);
	}

	results = torture_results_init(mem_ctx, ui_ops);
	if (results == NULL) {
		perror("torture_results_init() failed");
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 1;
	}

	ev = s4_event_context_init(mem_ctx);
	if (ev == NULL) {
		perror("s4_event_context_init() failed");
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 1;
	}

	if (basedir != NULL) {
		if (basedir[0] != '/') {
			fprintf(stderr, "Please specify an absolute path to --basedir\n");
			poptFreeContext(pc);
			talloc_free(mem_ctx);
			return 1;
		}
		outputdir = talloc_asprintf(mem_ctx, "%s/smbtortureXXXXXX", basedir);
	} else {
		char *pwd = talloc_size(mem_ctx, PATH_MAX);
		if (!getcwd(pwd, PATH_MAX)) {
			fprintf(stderr, "Unable to determine current working directory\n");
			poptFreeContext(pc);
			talloc_free(mem_ctx);
			return 1;
		}
		outputdir = talloc_asprintf(mem_ctx, "%s/smbtortureXXXXXX", pwd);
	}
	if (!outputdir) {
		fprintf(stderr, "Could not allocate per-run output dir\n");
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 1;
	}

	torture = torture_context_init(mem_ctx, ev, lp_ctx, results, outputdir);
	if (torture == NULL) {
		perror("torture_context_init() failed");
		poptFreeContext(pc);
		talloc_free(mem_ctx);
		return 1;
	}

	gensec_init();

	if (shell) {
		/* In shell mode, just ignore any remaining test names. */
		torture_shell(torture);
	} else {

		/* At this point, we should just have a target string,
		 * followed by a series of test names. Unless we are in
		 * shell mode, in which case we don't need anything more.
		 */

		if (argc_new < 3) {
			printf("You must specify a test to run, or 'ALL'\n");
			usage(pc);
			torture->results->returncode = 1;
		} else if (!torture_parse_target(torture,
					lp_ctx, argv_new[1])) {
			/* Take the target name or binding. */
			usage(pc);
			torture->results->returncode = 1;
		} else {
			for (i=2;i<argc_new;i++) {
				if (!torture_run_named_tests(torture, argv_new[i],
					    (const char **)restricted)) {
					correct = false;
				}
			}
		}
	}

	/* Now delete the temp dir we created */
	torture_deltree_outputdir(torture);

	if (torture->results->returncode && correct) {
		poptFreeContext(pc);
		talloc_free(torture);
		talloc_free(mem_ctx);
		return(0);
	} else {
		poptFreeContext(pc);
		talloc_free(torture);
		talloc_free(mem_ctx);
		return(1);
	}
}
