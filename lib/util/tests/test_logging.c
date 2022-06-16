/*
   Unix SMB/CIFS implementation.

   A test server that only does logging.

   Copyright (C) Andrew Tridgell		1992-2005
   Copyright (C) Martin Pool			2002
   Copyright (C) Jelmer Vernooij		2002
   Copyright (C) James J Myers 			2003 <myersjj@samba.org>
   Copyright (C) Douglas Bagnall		2022

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
#include "lib/cmdline/cmdline.h"

#ifdef USING_CMDLINE_S3
#include "lib/util/debug_s3.h"
#endif

#define BINARY_NAME "test_s4_logging"

static int log_level = 1;


#include "lib/util/debug-classes/debug-classname-table.c"

static int log_all_classes(int level)
{
	size_t i;
	const char *name = NULL;
	for (i = 0; i < ARRAY_SIZE(default_classname_table); i++) {
		name = default_classname_table[i];
		DEBUGC(i, level,
		       ("logging for '%s' [%zu], at level %d\n",
			name, i, level));

		/*
		 * That's it for the tests *here*. The invoker of this
		 * process will have set up an smb.conf that directs the
		 * output in particular ways, and will be looking to see that
		 * happens correctly.
		 */
	}
	return 0;
}


static int init_daemon(TALLOC_CTX *mem_ctx,
		       int argc,
		       const char *argv[],
		       const char **error)
{
	poptContext pc;
	int opt;
	bool ok;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{
			.longName   = "level",
			.shortName  = 'L',
			.argInfo    = POPT_ARG_INT,
			.arg        = &log_level,
			.descrip    = "log at this level",
			.argDescrip = "LEVEL",
		},
		POPT_COMMON_SAMBA
		POPT_COMMON_DAEMON
		POPT_COMMON_VERSION
		POPT_TABLEEND
	};

	setproctitle(BINARY_NAME);

	ok = samba_cmdline_init(mem_ctx,
				SAMBA_CMDLINE_CONFIG_SERVER,
				true /* require_smbconf */);
	if (!ok) {
		*error = "Failed to init cmdline parser!\n";
		return EINVAL;
	}

	pc = samba_popt_get_context(BINARY_NAME,
				    argc,
				    argv,
				    long_options,
				    0);
	if (pc == NULL) {
		*error = "Failed to setup popt context!\n";
		return ENOTRECOVERABLE;
	}

	while((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "\nInvalid option %s: %s\n\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		poptPrintUsage(pc, stderr, 0);
		return 1;
	}

	poptFreeContext(pc);

#ifdef USING_CMDLINE_S3
	reopen_logs();
#endif
	return 0;
}


int main(int argc, const char *argv[])
{
	int rc;
	const char *error = NULL;
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	if (mem_ctx == NULL) {
		exit(ENOMEM);
	}

	setproctitle_init(argc, discard_const(argv), environ);

	rc = init_daemon(mem_ctx, argc, argv, &error);
	if (rc != 0) {
		fprintf(stderr, "error [%d]: %s\n", rc, error);
		exit_daemon(error, rc);
	}

	rc = log_all_classes(log_level);
	if (rc != 0) {
		fprintf(stderr, "error in log_all_classes [%d]\n", rc);
		exit_daemon("logging error", rc);
	}

	TALLOC_FREE(mem_ctx);
	return rc;
}
