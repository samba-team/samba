/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Tridgell 1997-2003
   Copyright (C) Jelmer Vernooij 2006-2008
   Copyright (C) James Peach 2010

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

struct shell_command;

typedef void (*shell_function)(const struct shell_command *,
	struct torture_context *, int, const char **);

static void shell_quit(const struct shell_command *,
	struct torture_context *, int, const char **);
static void shell_help(const struct shell_command *,
	struct torture_context *, int, const char **);
static void shell_set(const struct shell_command *,
	struct torture_context *, int, const char **);
static void shell_run(const struct shell_command *,
	struct torture_context *, int, const char **);
static void shell_list(const struct shell_command *,
	struct torture_context *, int, const char **);

static void shell_usage(const struct shell_command *);
static bool match_command(const char *, const struct shell_command *);

struct shell_command
{
    shell_function  handler;
    const char *    name;
    const char *    usage;
    const char *    help;
} shell_command;

static const struct shell_command commands[] =
{
    {
	shell_help, "help", NULL,
	"print this help message"
    },

    {
	shell_quit, "quit", NULL,
	"exit smbtorture"
    },

    {
	shell_list, "list", NULL,
	"list the available tests"
    },

    {
	shell_set, "set", "[NAME VALUE]",
	"print or set test configuration parameters"
    },

    {
	shell_run, "run", "[TESTNAME]",
	"run the specified test"
    }
};

void torture_shell(struct torture_context *tctx)
{
	char *cline;
	int argc;
	const char **argv;
	int ret;
	int i;

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

		for (i = 0; i < ARRAY_SIZE(commands); i++) {
			if (match_command(argv[0], &commands[i])) {
				argc--;
				argv++;
				commands[i].handler(&commands[i],
					tctx, argc, argv);
				break;
			}
		}

		free(cline);
	}
}

static void shell_quit(const struct shell_command * command,
	struct torture_context *tctx, int argc, const char **argv)
{
    exit(0);
}

static void shell_help(const struct shell_command * command,
	struct torture_context *tctx, int argc, const char **argv)
{
    int i;

    fprintf(stdout, "Available commands:\n");
    for (i = 0; i < ARRAY_SIZE(commands); i++) {
	    fprintf(stdout, "\t%s - %s\n",
		    commands[i].name, commands[i].help);
    }
}

static void shell_set(const struct shell_command *command,
	struct torture_context *tctx, int argc, const char **argv)
{
	char * name;

	switch (argc) {
	case 0:
	    lp_dump(tctx->lp_ctx, stdout,
		    false /* show_defaults */,
		    0 /* skip services */);
	    break;

	case 2:
	    name = talloc_asprintf(NULL, "torture:%s", argv[0]);
	    lp_set_cmdline(tctx->lp_ctx, name, argv[1]);
	    talloc_free(name);
	    break;

	default:
	    shell_usage(command);
	}
}

static void shell_run(const struct shell_command * command,
	struct torture_context *tctx, int argc, const char **argv)
{
    if (argc != 1) {
	shell_usage(command);
	return;
    }

    torture_run_named_tests(tctx, argv[0], NULL /* restricted */);
}

static void shell_list(const struct shell_command * command,
	struct torture_context *tctx, int argc, const char **argv)
{
    if (argc != 0) {
	shell_usage(command);
	return;
    }

    torture_print_tests(true);
}

static void shell_usage(const struct shell_command * command)
{
    if (command->usage) {
	    fprintf(stderr, "Usage: %s %s\n",
		    command->name, command->usage);
    } else {
	    fprintf(stderr, "Usage: %s\n",
		    command->name);
    }
}

static bool match_command(const char * name,
	const struct shell_command * command)
{
	if (!strcmp(name, command->name)) {
		return true;
	}

	if (name[0] == command->name[0] && name[1] == '\0') {
	    return true;
	}

	return false;
}

