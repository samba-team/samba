/*

This file is taken from nfsim (http://ozlabs.org/~jk/projects/nfsim/)

Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

This file is part of nfsim.

nfsim is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

nfsim is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with nfsim; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "tui.h"
#include "log.h"
#include "expect.h"
#include <fnmatch.h>
#include <talloc.h>
#include "utils.h"

/* Expect is used to set up expectations on logging, for automated
 * testing. */
struct expect {
	struct expect *next;
	int invert;
	int matched;
	char *command;
	char *pattern;
};

static struct expect *expect;
struct cmdstack
{
	struct cmdstack *prev;
	char *command;
};
static struct cmdstack *current_command;

/* We don't need to try to match every pattern length: we only need
 * lengths where the next char matches. */
static unsigned int maybe_skip(char next_char, const char *line)
{
	char str[2];

	/* If next one is *, we can't skip any. */
	if (next_char == '*')
		return 1;

	/* No more string? */
	if (*line == '\0')
		return 1;

	/* Next one is space, skip up to next space. */
	if (next_char == '\t' || next_char == ' ')
		return strcspn(line+1, "\t ") + 1;

	str[0] = next_char;
	str[1] = '\0';
	return strcspn(line+1, str) + 1;
}

/* Loose match for strings: whitespace can be any number of
 * whitespace, and * matches anything.  Approximately. */
static bool loose_match(const char *pattern, const char *line)
{
	/* Any whitespace in pattern matches any whitespace in line. */
	if (*pattern == '\t' || *pattern == ' ') {
		int i, j, pat_space, line_space;

		pat_space = strspn(pattern, "\t ");
		line_space = strspn(line, "\t ");

		for (i = 1; i <= pat_space; i++)
			for (j = 1; j <= line_space; j++)
				if (loose_match(pattern+i, line+j))
					return true;
		return false;
	}

	if (*pattern == '*') {
		int i, len = strlen(line);
		for (i = 0; i <= len; i += maybe_skip(pattern[1],line+i))
			if (loose_match(pattern+1, line+i))
				return true;

		return false;
	}

	if (*pattern == *line) {
		if (*pattern == '\0')
			return true;
		return loose_match(pattern+1, line+1);
	}

	return false;
}

/* Pattern can't have whitespace at start and end, due to our parser.
 * Strip ot here. */
static bool matches(const char *pattern, const char *line)
{
	unsigned int len;

	line += strspn(line, "\t ");
	len = strlen(line);
	if (len > 0 && (line[len-1] == '\t' || line[len-1] == ' ')) {
		char trimmed[len];
		memcpy(trimmed, line, len);
		while (trimmed[len-1] == '\t' || trimmed[len-1] == ' ') {
			if (len == 1)
				break;
			len--;
		}
		trimmed[len] = '\0';
		return loose_match(pattern, trimmed);
	}
	return loose_match(pattern, line);
}

bool expect_log_hook(const char *line)
{
	struct expect *e;
	bool ret = false;

	if (current_command == NULL)
		return false;

	/* Only allow each pattern to match once, so we can easily
	 * expect something to happen twice. */
	for (e = expect; e; e = e->next) {
		if (!e->matched
		    && streq(current_command->command, e->command)
		    && matches(e->pattern, line)) {
			e->matched = 1;
			ret = true;
		}
	}
	return ret;
}

bool expects_remaining(void)
{
	return expect != NULL;
}

static void expect_pre_command(const char *command)
{
	struct cmdstack *new = talloc(NULL, struct cmdstack);
	new->prev = current_command;
	new->command = talloc_strdup(new, command);
	current_command = new;
}

static bool expect_post_command(const char *command)
{
	struct expect **e, **next, *old;
	bool ret = true;
	struct cmdstack *oldcmd;

	for (e = &expect; *e; e = next) {
		next = &(*e)->next;

		if (!streq(current_command->command, (*e)->command))
			continue;

		if (!(*e)->invert && !(*e)->matched) {
			if (tui_abort_on_fail)
				script_fail("Pattern '%s' did not match",
					    (*e)->pattern);
			log_line(LOG_VERBOSE, "Pattern '%s' did not match",
				 (*e)->pattern);
			ret = false;
		} else if ((*e)->invert && (*e)->matched) {
			if (tui_abort_on_fail)
				script_fail("Pattern '%s' matched",
					    (*e)->pattern);
			log_line(LOG_VERBOSE, "Pattern '%s' matched",
				 (*e)->pattern);
			ret = false;
		}

		/* Unlink from list and free. */
		old = *e;
		*e = (*e)->next;
		next = e;

		talloc_free(old);
	}

	oldcmd = current_command;
	current_command = current_command->prev;
	talloc_free(oldcmd);
	return ret;
}

static bool expect_cmd(int argc, char **argv)
{
	struct expect *e;
	unsigned int i, len;
	bool invert = false;

	if (argc == 1) {
		for (e = expect; e; e = e->next)
			log_line(LOG_UI, "%s: %s\"%s\"",
				 e->command,
				 e->invert ? "! " : "",
				 e->pattern);
		return true;
	}

	if (argv[1] && streq(argv[1], "!")) {
		invert = true;
		argv++;
		argc--;
	}

	if (argc < 3)
		return false;

	if (!tui_is_command(argv[1])) {
		log_line(LOG_ALWAYS, "expect: %s is not a command\n",
			 argv[1]);
		return false;
	}

	e = talloc(NULL, struct expect);
	e->matched = 0;
	e->invert = invert;
	e->next = expect;

	e->command = talloc_strdup(e, argv[1]);

	for (len = 0, i = 2; i < argc; i++)
		len += strlen(argv[i])+1;
	e->pattern = talloc_array(e, char, len + 1);

	e->pattern[0] = '\0';
	for (i = 2; i < argc; i++) {
		if (i == 2)
			sprintf(e->pattern+strlen(e->pattern), "%s", argv[i]);
		else
			sprintf(e->pattern+strlen(e->pattern), " %s", argv[i]);
	}
	expect = e;
	return true;
}

static void expect_help(int argc, char **argv)
{
#include "generated-expect-help:expect"
/*** XML Help:
    <section id="c:expect">
     <title><command>expect</command></title>
     <para>Catch logging information for automated testing</para>
     <cmdsynopsis>
      <command>expect</command>
     </cmdsynopsis>
     <cmdsynopsis>
      <command>expect</command>
      <arg choice="opt">!</arg>
      <arg choice="req"><replaceable>command</replaceable></arg>
      <arg choice="req"><replaceable>pattern</replaceable></arg>
     </cmdsynopsis>
     <para><command>expect</command> will set up a set of patterns to expect in
      logging messages for a particular command. If that command finishes
      without matching the specified pattern, the simulator will exit with a
      non-zero return value.  After the command is run, all expectations on that
      command are deleted.</para>
     <para><command>expect</command> with no arguments will print out the
      current list of expectations, as a command and a pattern.</para>
     <para><command>expect <replaceable>command pattern</replaceable></command>
      will expect the specified pattern to occur the next time
      <replaceable>command</replaceable> is invoked. If an '!' appears before
      the command, then the expectation is negated - if the pattern appears in
      the output, then the simulator will exit with an error
     </para>
     <para>The pattern itself is similar to a simple shell wildcard,
      except whitespace is loosely matched.  The * character will
      match any a string of any length.</para>
     </section>
*/
}

static void init(void)
{
	tui_register_command("expect", expect_cmd, expect_help);
	tui_register_pre_post_hook(expect_pre_command, expect_post_command);
}

init_call(init);
