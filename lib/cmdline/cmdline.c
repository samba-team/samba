/*
 * Copyright (c) 2020      Andreas Schneider <asn@samba.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "auth/credentials/credentials.h"
#include "lib/param/param.h"
#include "dynconfig/dynconfig.h"
#include "auth/gensec/gensec.h"
#include "libcli/smb/smb_util.h"
#include "cmdline_private.h"
#include "lib/util/util_process.h"

#include <samba/version.h>

static TALLOC_CTX *cmdline_mem_ctx;
static struct loadparm_context *cmdline_lp_ctx;
static struct cli_credentials *cmdline_creds;
static samba_cmdline_load_config cmdline_load_config_fn;
static struct samba_cmdline_daemon_cfg cmdline_daemon_cfg;

static NTSTATUS (*cli_credentials_set_machine_account_fn)(
	struct cli_credentials *cred,
	struct loadparm_context *lp_ctx) =
	cli_credentials_set_machine_account;

/* PRIVATE */
bool samba_cmdline_set_talloc_ctx(TALLOC_CTX *mem_ctx)
{
	if (cmdline_mem_ctx != NULL) {
		return false;
	}

	cmdline_mem_ctx = mem_ctx;
	return true;
}

TALLOC_CTX *samba_cmdline_get_talloc_ctx(void)
{
	return cmdline_mem_ctx;
}

static void _samba_cmdline_talloc_log(const char *message)
{
	D_ERR("%s", message);
}

bool samba_cmdline_init_common(TALLOC_CTX *mem_ctx)
{
	bool ok;

	ok = samba_cmdline_set_talloc_ctx(mem_ctx);
	if (!ok) {
		return false;
	}

	cmdline_daemon_cfg = (struct samba_cmdline_daemon_cfg) {
		.fork = true,
	};

	fault_setup();

	/*
	 * Log to stderr by default.
	 * This can be changed to stdout using the option: --debug-stdout
	 */
	setup_logging(getprogname(), DEBUG_DEFAULT_STDERR);

	talloc_set_log_fn(_samba_cmdline_talloc_log);
	talloc_set_abort_fn(smb_panic);

	return true;
}

bool samba_cmdline_set_load_config_fn(samba_cmdline_load_config fn)
{
	cmdline_load_config_fn = fn;
	return true;
}

/* PUBLIC */
bool samba_cmdline_set_lp_ctx(struct loadparm_context *lp_ctx)
{
	if (lp_ctx == NULL) {
		return false;
	}
	cmdline_lp_ctx = lp_ctx;

	return true;
}

struct loadparm_context *samba_cmdline_get_lp_ctx(void)
{
	return cmdline_lp_ctx;
}

bool samba_cmdline_set_creds(struct cli_credentials *creds)
{
	if (creds == NULL) {
		return false;
	}

	TALLOC_FREE(cmdline_creds);
	cmdline_creds = creds;

	return true;
}

struct cli_credentials *samba_cmdline_get_creds(void)
{
	return cmdline_creds;
}

struct samba_cmdline_daemon_cfg *samba_cmdline_get_daemon_cfg(void)
{
	return &cmdline_daemon_cfg;
}

void samba_cmdline_set_machine_account_fn(
	NTSTATUS (*fn) (struct cli_credentials *cred,
			struct loadparm_context *lp_ctx))
{
	cli_credentials_set_machine_account_fn = fn;
}

/*
 * Are the strings p and option equal from the point of view of option
 * parsing, meaning is the next character '\0' or '='.
 */
static bool strneq_cmdline_exact(const char *p, const char *option, size_t len)
{
	if (strncmp(p, option, len) == 0) {
		if (p[len] == 0 || p[len] == '=') {
			return true;
		}
	}
	return false;
}

/*
 * Return true if the argument to the option should be redacted.
 *
 * The option name is presumed to contain the substring "pass". It is checked
 * against a list of options that specify secrets. If it is there, the value
 * should be redacted and we return early.
 *
 * Otherwise, it is checked against a list of known safe options. If it is
 * there, we return false.
 *
 * If the option is not in either list, we assume it might be secret and
 * redact the argument, but warn loudly about it. The hope is that developers
 * will see what they're doing and add the option to the appropriate list.
 *
 * If true is returned, *ulen will be set to the apparent length of the
 * option. It is set to zero if false is returned (we don't need it in that
 * case).
 */
static bool is_password_option(const char *p, size_t *ulen)
{
	size_t i, len;
	static const char *must_burn[] = {
		"--password",
		"--newpassword",
		"--password2",
		"--adminpass",
		"--dnspass",
		"--machinepass",
		"--krbtgtpass",
		"--fixed-password",
	};
	static const char *allowed[] = {
		"--bad-password-count-reset",
		"--badpassword-frequency",
		"--change-user-password",
		"--force-initialized-passwords",
		"--machine-pass",  /* distinct from --machinepass */
		"--managed-password-interval",
		"--no-pass",
		"--no-pass2",
		"--no-passthrough",
		"--no-password",
		"--passcmd",
		"--passwd",
		"--passwd_path",
		"--password-file",
		"--password-from-stdin",
		"--random-password",
		"--smbpasswd-style",
		"--strip-passed-output",
		"--with-smbpasswd-file",
	};

	char *equals = NULL;
	*ulen = 0;

	for (i = 0; i < ARRAY_SIZE(must_burn); i++) {
		bool secret;
		len = strlen(must_burn[i]);
		secret = strneq_cmdline_exact(p, must_burn[i], len);
		if (secret) {
			*ulen = len;
			return true;
		}
	}

	for (i = 0; i < ARRAY_SIZE(allowed); i++) {
		bool safe;
		len = strlen(allowed[i]);
		safe = strneq_cmdline_exact(p, allowed[i], len);
		if (safe) {
			return false;
		}
	}
	/*
	 * We have found a suspicious option, and we need to work out where to
	 * burn it from. It could be
	 *
	 * --secret-password=cow    -> password after '='
	 * --secret-password        -> password is in next argument.
	 *
	 * but we also have the possibility of
	 *
	 * --cow=secret-password
	 *
	 * that is, the 'pass' in this option string is not in the option but
	 * the argument to it, which should not be burnt.
	 */
	equals = strchr(p, '=');
	if (equals == NULL) {
		*ulen = strlen(p);
	} else {
		char *pass = (strstr(p, "pass"));
		if (pass > equals) {
			/* this is --foo=pass, not --pass=foo */
			return false;
		}
		*ulen = equals - p;
	}
	/*
	 * This message will be seen with Python tools when an option
	 * is misspelt, but not with C tools, because in C burning
	 * happens after the command line is parsed, while in Python
	 * it happens before (on a copy of argv).
	 *
	 * In either case it will appear for a newly added option, and
	 * we hope developers will notice it before pushing.
	 */
	DBG_ERR("\nNote for developers: if '%*s' is not misspelt, it should be "
		"added to the appropriate list in is_password_option().\n\n",
		(int)(*ulen), p);
	return true;
}

bool samba_cmdline_burn(int argc, char *argv[])
{
	bool burnt = false;
	int i;

	for (i = 0; i < argc; i++) {
		bool found = false;
		bool is_user = false;
		size_t ulen = 0;
		char *p = NULL;

		p = argv[i];
		if (p == NULL) {
			return burnt;
		}

		if (strncmp(p, "-U", 2) == 0) {
			/*
			 * Note: this won't catch combinations of
			 * short options like
			 * `samba-tool -NUAdministrator%...`, which is
			 * not possible in general outside of the
			 * actual parser (consider for example
			 * `-NHUroot%password`, which parses as
			 * `-N -H 'Uroot%password'`). We don't know
			 * here which short options might take
			 * arguments.
			 *
			 * This is an argument for embedding redaction
			 * inside the parser (e.g. by adding a flag to
			 * the option definitions), but we decided not
			 * to do that in order to share cmdline_burn().
			 */
			ulen = 2;
			found = true;
			is_user = true;
		} else if (strneq_cmdline_exact(p, "--user", 6)) {
			ulen = 6;
			found = true;
			is_user = true;
		} else if (strneq_cmdline_exact(p, "--username", 10)) {
			ulen = 10;
			found = true;
			is_user = true;
		} else if (strncmp(p, "--", 2) == 0 && strstr(p, "pass")) {
			/*
			 * We have many secret options like --password,
			 * --adminpass, --newpassword, and we could easily
			 * add more, so we will use an allowlist to let the
			 * safe ones through (of which there are also many).
			 */
			found = is_password_option(p, &ulen);
		}

		if (found) {
			if (strlen(p) == ulen) {
				/*
				 * The option string has no '=', so
				 * its argument will come in the NEXT
				 * argv member. If there is one, we
				 * can just step forward and take it,
				 * setting ulen to 0.
				 *
				 * {"--password=secret"}    --> {"--password"}
				 * {"--password", "secret"} --> {"--password", ""}
				 * {"-Uadmin%secret"}       --> {"-Uadmin"}
				 * {"-U", "admin%secret"}   --> {"-U", "admin"}
				 */
				i++;
				if (i == argc) {
					/*
					 * this looks like an invalid
					 * command line, but that's
					 * for the caller to decide.
					 */
					return burnt;
				}
				p = argv[i];
				if (p == NULL) {
					return burnt;
				}
				ulen = 0;
			}

			if (is_user) {
				char *q = strchr_m(p, '%');
				if (q == NULL) {
					/* -U without '%' has no secret */
					continue;
				}
				p = q;
			} else {
				p += ulen;
			}

			BURN_PTR_SIZE(p, strlen(p));
			burnt = true;
		}
	}
	return burnt;
}

static bool is_popt_table_end(const struct poptOption *o)
{
	if (o->longName == NULL &&
	    o->shortName == 0 &&
	    o->argInfo == 0 &&
	    o->arg == NULL &&
	    o->val == 0 &&
	    o->descrip == NULL &&
	    o->argDescrip == NULL) {
		return true;
	}

	return false;
}

static void find_duplicates(const struct poptOption *needle,
			    const struct poptOption *haystack,
			    size_t *count)
{
	for(;
	    !is_popt_table_end(haystack);
	    haystack++) {
		switch (haystack->argInfo) {
		case POPT_ARG_INCLUDE_TABLE:
			if (haystack->arg != NULL) {
				find_duplicates(needle, haystack->arg, count);
			}

			break;
		default:
			if (needle->shortName != 0 &&
			    needle->shortName == haystack->shortName) {
				(*count)++;
				break;
			}

			if (needle->longName != NULL &&
			    haystack->longName != NULL &&
			    strequal(needle->longName, haystack->longName)) {
				(*count)++;
				break;
			}
			break;
		}

		if (*count > 1) {
			return;
		}
	}
}

static bool cmdline_sanity_checker(const struct poptOption *current_opts,
			     const struct poptOption *full_opts)
{
	const struct poptOption *o = current_opts;

	for(;
	    !is_popt_table_end(o);
	    o++) {
		bool ok;

		switch (o->argInfo) {
		case POPT_ARG_INCLUDE_TABLE:
			if (o->arg != NULL) {
				ok = cmdline_sanity_checker(o->arg, full_opts);
				if (!ok) {
					return false;
				}
			}

			break;
		default:
			if (o->longName != NULL || o->shortName != 0) {
				size_t count = 0;

				find_duplicates(o, full_opts, &count);
				if (count > 1) {
					DBG_ERR("Duplicate option '--%s|-%c' "
						"detected!\n",
						o->longName,
						o->shortName != 0 ?
							o->shortName :
							'-');
					return false;
				}
			}

			break;
		}
	}

	return true;
}

bool samba_cmdline_sanity_check(const struct poptOption *opts)
{
	return cmdline_sanity_checker(opts, opts);
}

poptContext samba_popt_get_context(const char * name,
				   int argc, const char ** argv,
				   const struct poptOption * options,
				   unsigned int flags)
{
#ifdef DEVELOPER
	bool ok;

	ok = samba_cmdline_sanity_check(options);
	if (!ok) {
		return NULL;
	}
#endif
	process_save_binary_name(name);
	return poptGetContext(name, argc, argv, options, flags);
}

/**********************************************************
 * COMMON SAMBA POPT
 **********************************************************/

static bool log_to_file;

static bool set_logfile(TALLOC_CTX *mem_ctx,
			struct loadparm_context *lp_ctx,
			const char *log_basename,
			const char *process_name,
			bool from_cmdline)
{
	bool ok = false;
	char *new_logfile = talloc_asprintf(mem_ctx,
					    "%s/log.%s",
					    log_basename,
					    process_name);
	if (new_logfile == NULL) {
		return false;
	}

	if (from_cmdline) {
		ok = lpcfg_set_cmdline(lp_ctx,
				       "log file",
				       new_logfile);
	} else {
		ok = lpcfg_do_global_parameter(lp_ctx,
					       "log file",
					       new_logfile);
	}
	if (!ok) {
		fprintf(stderr,
			"Failed to set log to %s\n",
			new_logfile);
		TALLOC_FREE(new_logfile);
		return false;
	}
	debug_set_logfile(new_logfile);
	TALLOC_FREE(new_logfile);

	return true;
}

static void popt_samba_callback(poptContext popt_ctx,
				enum poptCallbackReason reason,
				const struct poptOption *opt,
				const char *arg, const void *data)
{
	TALLOC_CTX *mem_ctx = samba_cmdline_get_talloc_ctx();
	struct loadparm_context *lp_ctx = samba_cmdline_get_lp_ctx();
	const char *pname = NULL;
	bool ok;

	/* Find out basename of current program */
	pname = getprogname();

	if (reason == POPT_CALLBACK_REASON_PRE) {
		if (lp_ctx == NULL) {
			fprintf(stderr,
				"Command line parsing not initialized!\n");
			exit(1);
		}
		ok = set_logfile(mem_ctx,
				 lp_ctx,
				 get_dyn_LOGFILEBASE(),
				 pname,
				 false);
		if (!ok) {
			fprintf(stderr,
				"Failed to set log file for %s\n",
				pname);
			exit(1);
		}
		return;
	}

	if (reason == POPT_CALLBACK_REASON_POST) {
		ok = cmdline_load_config_fn();
		if (!ok) {
			fprintf(stderr,
				"%s - Failed to load config file!\n",
				getprogname());
			exit(1);
		}

		if (log_to_file) {
			const struct loadparm_substitution *lp_sub =
				lpcfg_noop_substitution();
			char *logfile = NULL;

			logfile = lpcfg_logfile(lp_ctx, lp_sub, mem_ctx);
			if (logfile == NULL) {
				fprintf(stderr,
					"Failed to setup logging to file!");
					exit(1);
			}
			debug_set_logfile(logfile);
			setup_logging(logfile, DEBUG_FILE);
			TALLOC_FREE(logfile);
		}

		return;
	}

	switch(opt->val) {
	case OPT_LEAK_REPORT:
		talloc_enable_leak_report();
		break;
	case OPT_LEAK_REPORT_FULL:
		talloc_enable_leak_report_full();
		break;
	case OPT_OPTION:
		if (arg != NULL) {
			ok = lpcfg_set_option(lp_ctx, arg);
			if (!ok) {
				fprintf(stderr, "Error setting option '%s'\n", arg);
				exit(1);
			}
		}
		break;
	case 'd':
		if (arg != NULL) {
			ok = lpcfg_set_cmdline(lp_ctx, "log level", arg);
			if (!ok) {
				fprintf(stderr,
					"Failed to set debug level to: %s\n",
					arg);
				exit(1);
			}
		}
		break;
	case OPT_DEBUG_STDOUT:
		setup_logging(pname, DEBUG_STDOUT);
		break;
	case OPT_CONFIGFILE:
		if (arg != NULL) {
			set_dyn_CONFIGFILE(arg);
		}
		break;
	case 'l':
		if (arg != NULL) {
			ok = set_logfile(mem_ctx, lp_ctx, arg, pname, true);
			if (!ok) {
				fprintf(stderr,
					"Failed to set log file for %s\n",
					arg);
				exit(1);
			}
			log_to_file = true;

			set_dyn_LOGFILEBASE(arg);
		}
		break;
	}
}

static struct poptOption popt_common_debug[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
	},
	{
		.longName   = "debuglevel",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'd',
		.descrip    = "Set debug level",
		.argDescrip = "DEBUGLEVEL",
	},
	{
		.longName   = "debug-stdout",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_DEBUG_STDOUT,
		.descrip    = "Send debug output to standard output",
	},
	POPT_TABLEEND
};

static struct poptOption popt_common_option[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	POPT_TABLEEND
};

static struct poptOption popt_common_config[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
	},
	{
		.longName   = "configfile",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_CONFIGFILE,
		.descrip    = "Use alternative configuration file",
		.argDescrip = "CONFIGFILE",
	},
	POPT_TABLEEND
};

static struct poptOption popt_common_samba[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
	},
	{
		.longName   = "debuglevel",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'd',
		.descrip    = "Set debug level",
		.argDescrip = "DEBUGLEVEL",
	},
	{
		.longName   = "debug-stdout",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_DEBUG_STDOUT,
		.descrip    = "Send debug output to standard output",
	},
	{
		.longName   = "configfile",
		.shortName  = 's',
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_CONFIGFILE,
		.descrip    = "Use alternative configuration file",
		.argDescrip = "CONFIGFILE",
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	{
		.longName   = "log-basename",
		.shortName  = 'l',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'l',
		.descrip    = "Basename for log/debug files",
		.argDescrip = "LOGFILEBASE",
	},
	{
		.longName   = "leak-report",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT,
		.descrip    = "enable talloc leak reporting on exit",
	},
	{
		.longName   = "leak-report-full",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT_FULL,
		.descrip    = "enable full talloc leak reporting on exit",
	},
	POPT_TABLEEND
};

static struct poptOption popt_common_samba_ldb[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_samba_callback,
	},
	{
		.longName   = "debuglevel",
		.shortName  = 'd',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'd',
		.descrip    = "Set debug level",
		.argDescrip = "DEBUGLEVEL",
	},
	{
		.longName   = "debug-stdout",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_DEBUG_STDOUT,
		.descrip    = "Send debug output to standard output",
	},
	{
		.longName   = "configfile",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_CONFIGFILE,
		.descrip    = "Use alternative configuration file",
		.argDescrip = "CONFIGFILE",
	},
	{
		.longName   = "option",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_OPTION,
		.descrip    = "Set smb.conf option from command line",
		.argDescrip = "name=value",
	},
	{
		.longName   = "log-basename",
		.shortName  = 'l',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'l',
		.descrip    = "Basename for log/debug files",
		.argDescrip = "LOGFILEBASE",
	},
	{
		.longName   = "leak-report",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT,
		.descrip    = "enable talloc leak reporting on exit",
	},
	{
		.longName   = "leak-report-full",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_LEAK_REPORT_FULL,
		.descrip    = "enable full talloc leak reporting on exit",
	},
	POPT_TABLEEND
};

/**********************************************************
 * CONNECTION POPT
 **********************************************************/

static void popt_connection_callback(poptContext popt_ctx,
				     enum poptCallbackReason reason,
				     const struct poptOption *opt,
				     const char *arg,
				     const void *data)
{
	struct loadparm_context *lp_ctx = cmdline_lp_ctx;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		if (lp_ctx == NULL) {
			fprintf(stderr,
				"Command line parsing not initialized!\n");
			exit(1);
		}
		return;
	}

	switch(opt->val) {
	case 'O':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "socket options", arg);
		}
		break;
	case 'R':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "name resolve order", arg);
		}
		break;
	case 'm':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "client max protocol", arg);
		}
		break;
	case OPT_NETBIOS_SCOPE:
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "netbios scope", arg);
		}
		break;
	case 'n':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "netbios name", arg);
		}
		break;
	case 'W':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "workgroup", arg);
		}
		break;
	case 'r':
		if (arg != NULL) {
			lpcfg_set_cmdline(lp_ctx, "realm", arg);
		}
		break;
	}
}

static struct poptOption popt_common_connection[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE,
		.arg        = (void *)popt_connection_callback,
	},
	{
		.longName   = "name-resolve",
		.shortName  = 'R',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'R',
		.descrip    = "Use these name resolution services only",
		.argDescrip = "NAME-RESOLVE-ORDER",
	},
	{
		.longName   = "socket-options",
		.shortName  = 'O',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'O',
		.descrip    = "socket options to use",
		.argDescrip = "SOCKETOPTIONS",
	},
	{
		.longName   = "max-protocol",
		.shortName  = 'm',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'm',
		.descrip    = "Set max protocol level",
		.argDescrip = "MAXPROTOCOL",
	},
	{
		.longName   = "netbiosname",
		.shortName  = 'n',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'n',
		.descrip    = "Primary netbios name",
		.argDescrip = "NETBIOSNAME",
	},
	{
		.longName   = "netbios-scope",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_NETBIOS_SCOPE,
		.descrip    = "Use this Netbios scope",
		.argDescrip = "SCOPE",
	},
	{
		.longName   = "workgroup",
		.shortName  = 'W',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'W',
		.descrip    = "Set the workgroup name",
		.argDescrip = "WORKGROUP",
	},
	{
		.longName   = "realm",
		.argInfo    = POPT_ARG_STRING,
		.val        = 'r',
		.descrip    = "Set the realm name",
		.argDescrip = "REALM",
	},
	POPT_TABLEEND
};

/**********************************************************
 * CREDENTIALS POPT
 **********************************************************/

static bool skip_password_callback;
static bool machine_account_pending;
static char *krb5_ccache = NULL;

static void popt_common_credentials_callback(poptContext popt_ctx,
					     enum poptCallbackReason reason,
					     const struct poptOption *opt,
					     const char *arg,
					     const void *data)
{
	struct loadparm_context *lp_ctx = samba_cmdline_get_lp_ctx();
	struct cli_credentials *creds = samba_cmdline_get_creds();
	bool ok;

	if (reason == POPT_CALLBACK_REASON_PRE) {
		if (creds == NULL) {
			fprintf(stderr,
				"Command line parsing not initialized!\n");
			exit(1);
		}
		return;
	}

	if (reason == POPT_CALLBACK_REASON_POST) {
		const char *username = NULL;
		enum credentials_obtained username_obtained =
			CRED_UNINITIALISED;
		enum credentials_obtained password_obtained =
			CRED_UNINITIALISED;

		/*
		 * This calls cli_credentials_set_conf() to get the defaults
		 * form smb.conf and set the winbind separator.
		 *
		 * Just warn that we can't read the smb.conf. There might not be
		 * one available or we want to ignore it.
		 */
		ok = cli_credentials_guess(creds, lp_ctx);
		if (!ok) {
			fprintf(stderr,
				"Unable to read defaults from smb.conf\n");
		}

		if (machine_account_pending) {
			NTSTATUS status;

			status = cli_credentials_set_machine_account_fn(
				creds, lp_ctx);
			if (!NT_STATUS_IS_OK(status)) {
				fprintf(stderr,
					"Failed to set machine account: %s\n",
					nt_errstr(status));
				exit(1);
			}
		}

		/*
		 * When we set the username during the handling of the options
		 * passed to the binary we haven't loaded the config yet. This
		 * means that we didn't take the 'winbind separator' into
		 * account.
		 *
		 * The username might contain the domain name and thus it
		 * hasn't been correctly parsed yet. If we have a username we
		 * need to set it again to run the string parser for the
		 * username correctly.
		 */
		username =
			cli_credentials_get_username_and_obtained(
					creds, &username_obtained);
		if (username_obtained == CRED_SPECIFIED &&
		    username != NULL && username[0] != '\0') {
			cli_credentials_parse_string(creds,
						     username,
						     CRED_SPECIFIED);
		}

		/*
		 * If --use-krb5-ccache was passed on the command line we need
		 * to overwrite the values set by cli_credentials_guess().
		 */
		if (krb5_ccache != NULL) {
			const char *error_string = NULL;
			int rc;

			rc = cli_credentials_set_ccache(creds,
							lp_ctx,
							krb5_ccache,
							CRED_SPECIFIED,
							&error_string);
			SAFE_FREE(krb5_ccache);
			if (rc != 0) {
				fprintf(stderr,
					"Error setting krb5 credentials cache: "
					"'%s'"
					" - %s\n",
					krb5_ccache,
					error_string);
				exit(1);
			}
		}

		if (cli_credentials_get_kerberos_state(creds) ==
		    CRED_USE_KERBEROS_REQUIRED)
		{
			enum credentials_obtained ccache_obtained =
				CRED_UNINITIALISED;
			enum credentials_obtained principal_obtained =
				CRED_UNINITIALISED;
			bool ccache_valid;

			principal_obtained =
				cli_credentials_get_principal_obtained(creds);
			ccache_valid = cli_credentials_get_ccache_name_obtained(
				creds, NULL, NULL, &ccache_obtained);
			if (ccache_valid &&
			    ccache_obtained == principal_obtained)
			{
				skip_password_callback = true;
			}
		}

		(void)cli_credentials_get_password_and_obtained(
			creds, &password_obtained);

		if (!skip_password_callback &&
		    password_obtained < CRED_CALLBACK) {
			ok = cli_credentials_set_cmdline_callbacks(creds);
			if (!ok) {
				fprintf(stderr,
					"Failed to set cmdline password "
					"callback\n");
				exit(1);
			}
		}

		/*
		 * If the user specified a password on the command line always
		 * do a kinit!
		 */
		if (password_obtained == CRED_SPECIFIED) {
			cli_credentials_invalidate_ccache(creds,
							  CRED_SPECIFIED);
		}

		return;
	}

	switch(opt->val) {
	case 'U':
		if (arg != NULL) {
			cli_credentials_parse_string(creds,
						     arg,
						     CRED_SPECIFIED);
		}
		break;
	case OPT_PASSWORD:
		if (arg != NULL) {
			ok = cli_credentials_set_password(creds,
							  arg,
							  CRED_SPECIFIED);
			if (!ok) {
				fprintf(stderr,
					"Failed to set password!\n");
				exit(1);
			}

			skip_password_callback = true;
		}
		break;
	case OPT_NT_HASH:
		cli_credentials_set_password_will_be_nt_hash(creds, true);
		break;
	case 'A':
		if (arg != NULL) {
			ok = cli_credentials_parse_file(creds,
							arg,
							CRED_SPECIFIED);
			if (!ok) {
				fprintf(stderr,
					"Failed to set parse authentication file!\n");
				exit(1);
			}
			skip_password_callback = true;
		}
		break;
	case 'N':
		ok = cli_credentials_set_password(creds,
						  NULL,
						  CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
			        "Failed to set password!\n");
			exit(1);
		}
		skip_password_callback = true;
		break;
	case 'P':
		/*
		 * Later, after this is all over, get the machine account
		 * details from the secrets.(l|t)db.
		 */
		machine_account_pending = true;
		break;
	case OPT_SIMPLE_BIND_DN:
		if (arg != NULL) {
			ok = cli_credentials_set_bind_dn(creds, arg);
			if (!ok) {
				fprintf(stderr,
					"Failed to set bind DN!\n");
				exit(1);
			}
		}
		break;
	case OPT_USE_KERBEROS: {
		int32_t use_kerberos = INT_MIN;
		if (arg == NULL) {
			fprintf(stderr,
				"Failed to parse "
				"--use-kerberos=desired|required|off: "
				"Missing argument\n");
			exit(1);
		}

		use_kerberos = lpcfg_parse_enum_vals("client use kerberos",
						     arg);
		if (use_kerberos == INT_MIN) {
			fprintf(stderr,
				"Failed to parse "
				"--use-kerberos=desired|required|off: "
				"Invalid argument\n");
			exit(1);
		}

		ok = cli_credentials_set_kerberos_state(creds,
							use_kerberos,
							CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set Kerberos state to %s!\n", arg);
			exit(1);
		}
		break;
	}
	case OPT_USE_KERBEROS_CCACHE: {
		if (arg == NULL) {
			fprintf(stderr,
				"Failed to parse --use-krb5-ccache=CCACHE: "
				"Missing argument\n");
			exit(1);
		}

		/*
		 * Remember the value and handle it in
		 * POPT_CALLBACK_REASON_POST.
		 */
		if (arg[0] != '\0') {
			krb5_ccache = strdup(arg);
			if (krb5_ccache == NULL) {
				fprintf(stderr, "Failed allocate memory\n");
				exit(1);
			}
		}

		ok = cli_credentials_set_kerberos_state(
			creds, CRED_USE_KERBEROS_REQUIRED, CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set Kerberos state to %s!\n",
				arg);
			exit(1);
		}

		/*
		 * The password callback will be skipped, if we have a valid
		 * ccache. This is handled in POPT_CALLBACK_REASON_POST.
		 */
		break;
	}
	case OPT_USE_WINBIND_CCACHE:
	{
		ok = cli_credentials_add_gensec_features(
			creds, GENSEC_FEATURE_NTLM_CCACHE, CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set gensec feature!\n");
			exit(1);
		}

		skip_password_callback = true;
		break;
	}
	case OPT_CLIENT_PROTECTION: {
		uint32_t gensec_features;
		enum smb_signing_setting signing_state =
			SMB_SIGNING_OFF;
		enum smb_encryption_setting encryption_state =
			SMB_ENCRYPTION_OFF;

		if (arg == NULL) {
			fprintf(stderr,
				"Failed to parse "
				"--client-protection=sign|encrypt|off: "
				"Missing argument\n");
			exit(1);
		}

		gensec_features =
			cli_credentials_get_gensec_features(
					creds);

		if (strequal(arg, "off")) {
			gensec_features &=
				~(GENSEC_FEATURE_SIGN|GENSEC_FEATURE_SEAL);

			signing_state = SMB_SIGNING_OFF;
			encryption_state = SMB_ENCRYPTION_OFF;
		} else if (strequal(arg, "sign")) {
			gensec_features |= GENSEC_FEATURE_SIGN;

			signing_state = SMB_SIGNING_REQUIRED;
			encryption_state = SMB_ENCRYPTION_OFF;
		} else if (strequal(arg, "encrypt")) {
			gensec_features |= GENSEC_FEATURE_SEAL;

			signing_state = SMB_SIGNING_REQUIRED;
			encryption_state = SMB_ENCRYPTION_REQUIRED;
		} else {
			fprintf(stderr,
				"Failed to parse --client-protection\n");
			exit(1);
		}

		ok = cli_credentials_set_gensec_features(creds,
								gensec_features,
								CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set gensec feature!\n");
			exit(1);
		}

		ok = cli_credentials_set_smb_signing(creds,
							signing_state,
							CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set smb signing!\n");
			exit(1);
		}

		ok = cli_credentials_set_smb_encryption(creds,
							encryption_state,
							CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set smb encryption!\n");
			exit(1);
		}
		break;
	}
	} /* switch */
}

static struct poptOption popt_common_credentials[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK|POPT_CBFLAG_PRE|POPT_CBFLAG_POST,
		.arg        = (void *)popt_common_credentials_callback,
	},
	{
		.longName   = "user",
		.shortName  = 'U',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'U',
		.descrip    = "Set the network username",
		.argDescrip = "[DOMAIN/]USERNAME[%PASSWORD]",
	},
	{
		.longName   = "no-pass",
		.shortName  = 'N',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'N',
		.descrip    = "Don't ask for a password",
	},
	{
		.longName   = "password",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_PASSWORD,
		.descrip    = "Password",
	},
	{
		.longName   = "pw-nt-hash",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_NT_HASH,
		.descrip    = "The supplied password is the NT hash",
	},
	{
		.longName   = "authentication-file",
		.shortName  = 'A',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'A',
		.descrip    = "Get the credentials from a file",
		.argDescrip = "FILE",
	},
	{
		.longName   = "machine-pass",
		.shortName  = 'P',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'P',
		.descrip    = "Use stored machine account password",
	},
	{
		.longName   = "simple-bind-dn",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_SIMPLE_BIND_DN,
		.descrip    = "DN to use for a simple bind",
		.argDescrip = "DN",
	},
	{
		.longName   = "use-kerberos",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_USE_KERBEROS,
		.descrip    = "Use Kerberos authentication",
		.argDescrip = "desired|required|off",
	},
	{
		.longName   = "use-krb5-ccache",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_USE_KERBEROS_CCACHE,
		.descrip    = "Credentials cache location for Kerberos",
		.argDescrip = "CCACHE",
	},
	{
		.longName   = "use-winbind-ccache",
		.argInfo    = POPT_ARG_NONE,
		.val        = OPT_USE_WINBIND_CCACHE,
		.descrip    = "Use the winbind ccache for authentication",
	},
	{
		.longName   = "client-protection",
		.argInfo    = POPT_ARG_STRING,
		.val        = OPT_CLIENT_PROTECTION,
		.descrip    = "Configure used protection for client connections",
		.argDescrip = "sign|encrypt|off",
	},
	POPT_TABLEEND
};

/**********************************************************
 * VERSION POPT
 **********************************************************/

static void popt_version_callback(poptContext ctx,
				  enum poptCallbackReason reason,
				  const struct poptOption *opt,
				  const char *arg,
				  const void *data)
{
	switch(opt->val) {
	case 'V':
		printf("Version %s\n", SAMBA_VERSION_STRING);
		exit(0);
	}
}

static struct poptOption popt_common_version[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_version_callback,
	},
	{
		.longName   = "version",
		.shortName  = 'V',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'V',
		.descrip    = "Print version",
	},
	POPT_TABLEEND
};

/**********************************************************
 * DAEMON POPT
 **********************************************************/

static void popt_daemon_callback(poptContext ctx,
				 enum poptCallbackReason reason,
				 const struct poptOption *opt,
				 const char *arg,
				 const void *data)
{
	switch(opt->val) {
	case OPT_DAEMON:
		cmdline_daemon_cfg.daemon = true;
		break;
	case OPT_INTERACTIVE:
		cmdline_daemon_cfg.interactive = true;
		cmdline_daemon_cfg.fork = false;
		break;
	case OPT_FORK:
		cmdline_daemon_cfg.fork = false;
		break;
	case OPT_NO_PROCESS_GROUP:
		cmdline_daemon_cfg.no_process_group = true;
		break;
	}
}

static struct poptOption popt_common_daemon[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_daemon_callback
	},
	{
		.longName   = "daemon",
		.shortName  = 'D',
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = OPT_DAEMON,
		.descrip    = "Become a daemon (default)" ,
	},
	{
		.longName   = "interactive",
		.shortName  = 'i',
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = OPT_INTERACTIVE,
		.descrip    = "Run interactive (not a daemon) and log to stdout",
	},
	{
		.longName   = "foreground",
		.shortName  = 'F',
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = OPT_FORK,
		.descrip    = "Run daemon in foreground (for daemontools, etc.)",
	},
	{
		.longName   = "no-process-group",
		.shortName  = '\0',
		.argInfo    = POPT_ARG_NONE,
		.arg        = NULL,
		.val        = OPT_NO_PROCESS_GROUP,
		.descrip    = "Don't create a new process group" ,
	},
	POPT_TABLEEND
};

/**********************************************************
 * LEGACY S3 POPT
 **********************************************************/

static void popt_legacy_s3_callback(poptContext ctx,
				    enum poptCallbackReason reason,
				    const struct poptOption *opt,
				    const char *arg,
				    const void *data)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();
	bool ok;

	switch(opt->val) {
	case 'k':
		fprintf(stderr,
			"WARNING: The option -k|--kerberos is deprecated!\n");

		ok = cli_credentials_set_kerberos_state(creds,
							CRED_USE_KERBEROS_REQUIRED,
							CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set Kerberos state to %s!\n", arg);
			exit(1);
		}

		skip_password_callback = true;
		break;
	}
}

/* We allow '-k yes' too. */
static struct poptOption popt_legacy_s3[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_legacy_s3_callback,
	},
	{
		.longName   = "kerberos",
		.shortName  = 'k',
		.argInfo    = POPT_ARG_NONE,
		.val        = 'k',
		.descrip    = "DEPRECATED: Migrate to --use-kerberos",
	},
	POPT_TABLEEND
};

/**********************************************************
 * LEGACY S4 POPT
 **********************************************************/

static void popt_legacy_s4_callback(poptContext ctx,
				    enum poptCallbackReason reason,
				    const struct poptOption *opt,
				    const char *arg,
				    const void *data)
{
	struct cli_credentials *creds = samba_cmdline_get_creds();
	bool ok;

	switch(opt->val) {
	case 'k': {
		enum credentials_use_kerberos use_kerberos =
			CRED_USE_KERBEROS_REQUIRED;

		fprintf(stderr,
			"WARNING: The option -k|--kerberos is deprecated!\n");

		if (arg != NULL) {
			if (strcasecmp_m(arg, "yes") == 0) {
				use_kerberos = CRED_USE_KERBEROS_REQUIRED;
			} else if (strcasecmp_m(arg, "no") == 0) {
				use_kerberos = CRED_USE_KERBEROS_DISABLED;
			} else {
				fprintf(stderr,
					"Error parsing -k %s. Should be "
					"-k [yes|no]\n",
					arg);
				exit(1);
			}
		}

		ok = cli_credentials_set_kerberos_state(creds,
							use_kerberos,
							CRED_SPECIFIED);
		if (!ok) {
			fprintf(stderr,
				"Failed to set Kerberos state to %s!\n", arg);
			exit(1);
		}

		break;
	}
	}
}

static struct poptOption popt_legacy_s4[] = {
	{
		.argInfo    = POPT_ARG_CALLBACK,
		.arg        = (void *)popt_legacy_s4_callback,
	},
	{
		.longName   = "kerberos",
		.shortName  = 'k',
		.argInfo    = POPT_ARG_STRING,
		.val        = 'k',
		.descrip    = "DEPRECATED: Migrate to --use-kerberos",
	},
	POPT_TABLEEND
};

struct poptOption *samba_cmdline_get_popt(enum smb_cmdline_popt_options opt)
{
	switch (opt) {
	case SAMBA_CMDLINE_POPT_OPT_DEBUG_ONLY:
		return popt_common_debug;
		break;
	case SAMBA_CMDLINE_POPT_OPT_OPTION_ONLY:
		return popt_common_option;
		break;
	case SAMBA_CMDLINE_POPT_OPT_CONFIG_ONLY:
		return popt_common_config;
		break;
	case SAMBA_CMDLINE_POPT_OPT_SAMBA:
		return popt_common_samba;
		break;
	case SAMBA_CMDLINE_POPT_OPT_CONNECTION:
		return popt_common_connection;
		break;
	case SAMBA_CMDLINE_POPT_OPT_CREDENTIALS:
		return popt_common_credentials;
		break;
	case SAMBA_CMDLINE_POPT_OPT_VERSION:
		return popt_common_version;
		break;
	case SAMBA_CMDLINE_POPT_OPT_DAEMON:
		return popt_common_daemon;
		break;
	case SAMBA_CMDLINE_POPT_OPT_SAMBA_LDB:
		return popt_common_samba_ldb;
		break;
	case SAMBA_CMDLINE_POPT_OPT_LEGACY_S3:
		return popt_legacy_s3;
		break;
	case SAMBA_CMDLINE_POPT_OPT_LEGACY_S4:
		return popt_legacy_s4;
		break;
	}

	/* Never reached */
	return NULL;
}
