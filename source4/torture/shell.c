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
#include "system/readline.h"
#include "lib/smbreadline/smbreadline.h"
#include "torture/smbtorture.h"

void torture_shell(struct torture_context *tctx)
{
	char *cline;
	int argc;
	const char **argv;
	int ret;

	while (1) {
		cline = smb_readline("torture> ", NULL, NULL);

		if (cline == NULL)
			return;

#if HAVE_ADD_HISTORY
		add_history(cline);
#endif

		ret = poptParseArgvString(cline, &argc, &argv);
		if (ret != 0) {
			fprintf(stderr, "Error parsing line\n");
			continue;
		}

		if (!strcmp(argv[0], "quit")) {
			return;
		} else if (!strcmp(argv[0], "list")) {
			torture_print_tests(true);
		} else if (!strcmp(argv[0], "set")) {
			if (argc < 3) {
				lp_dump(tctx->lp_ctx, stdout,
					false /* show_defaults */,
					0 /* skip services */);
			} else {
				char *name = talloc_asprintf(NULL, "torture:%s", argv[1]);
				lp_set_cmdline(tctx->lp_ctx, name, argv[2]);
				talloc_free(name);
			}
		} else if (!strcmp(argv[0], "help")) {
			fprintf(stderr, "Available commands:\n"
							" help - This help command\n"
							" list - List the available\n"
							" run - Run test\n"
							" set - Change variables\n"
							"\n");
		} else if (!strcmp(argv[0], "run")) {
			if (argc < 2) {
				fprintf(stderr, "Usage: run TEST-NAME [OPTIONS...]\n");
			} else {
				torture_run_named_tests(tctx, argv[1]);
			}
		}
		free(cline);
	}
}
