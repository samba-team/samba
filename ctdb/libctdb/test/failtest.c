/*

This file is taken from nfsim (http://ozlabs.org/~jk/projects/nfsim/)

Copyright (c) 2004 Jeremy Kerr & Rusty Russell

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
#include "utils.h"
#include "tui.h"
#include "log.h"
#include "failtest.h"
#include "ctdb-test.h"
#include "talloc.h"
#include "dlinklist.h"
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

static unsigned int fails = 0, excessive_fails = 2;
unsigned int failpoints = 0;
static const char *failtest_no_report = NULL;
bool failtest = true;

struct fail_decision {
	struct fail_decision *next, *prev;
	char *location;
	unsigned int tui_line;
	bool failed;
};

static struct fail_decision *decisions;

/* Failure path to follow (initialized by --failpath). */
static const char *failpath = NULL, *orig_failpath;

/*** XML Argument:
    <section id="a:failpath">
     <title><option>--failpath
      <replaceable>path</replaceable></option></title>
     <subtitle>Replay a failure path</subtitle>
     <para>Given a failure path, (from <option>--failtest</option>), this will
      replay the sequence of sucesses/failures, allowing debugging.  The input
      should be the same as the original which caused the failure.
      </para>

     <para>This testing can be slow, but allows for testing of failure
      paths which would otherwise be very difficult to test
     automatically.</para>
    </section>
*/
static void cmdline_failpath(struct option *opt)
{
	extern char *optarg;
	if (!optarg)
		errx(1, "failtest option requires an argument");
	orig_failpath = failpath = optarg;
}
cmdline_opt("failpath", 1, 0, cmdline_failpath);

/*** XML Argument:
    <section id="a:failtest-no-report">
     <title><option>--failtest-no-report
      <replaceable>function</replaceable></option></title>
     <subtitle>Exclude a function from excessive failure reports</subtitle>

     <para>Sometimes code deliberately ignores the failures of a
     certain function.  This suppresses complaints about that for any
     functions containing this name.</para> </section>
*/
static void cmdline_failtest_no_report(struct option *opt)
{
	extern char *optarg;
	if (!optarg)
		errx(1, "failtest-no-report option requires an argument");
	failtest_no_report = optarg;
}
cmdline_opt("failtest-no-report", 1, 0, cmdline_failtest_no_report);

/*** XML Argument:
    <section id="a:no-failtest">
     <title><option>--no-failtest</option></title>
     <subtitle>Don't test failure cases</subtitle>

     <para>This is the default in interactive mode.</para>
    </section>
*/
static void cmdline_no_failtest(struct option *opt)
{
	failtest = false;
}
cmdline_opt("no-failtest", 0, 0, cmdline_no_failtest);

/* Separate function to make .gdbinit easier */
static bool failpath_fail(void)
{
	return true;
}

static bool do_failpath(const char *func)
{
	if (*failpath == '[') {
		failpath++;
		if (strncmp(failpath, func, strlen(func)) != 0
		    || failpath[strlen(func)] != ']')
			errx(1, "Failpath expected %.*s not %s\n",
			     strcspn(failpath, "]"), failpath, func);
		failpath += strlen(func) + 1;
	}

	if (*failpath == ':') {
		unsigned long line;
		char *after;
		failpath++;
		line = strtoul(failpath, &after, 10);
		if (*after != ':')
			errx(1, "Bad failure path line number %s\n",
			     failpath);
		if (line != tui_linenum)
			errx(1, "Unexpected line number %lu vs %u\n",
			     line, tui_linenum);
		failpath = after+1;
	}

	switch ((failpath++)[0]) {
	case 'F':
	case 'f':
		return failpath_fail();
	case 'S':
	case 's':
		return false;
	case 0:
		failpath = NULL;
		return false;
	default:
		errx(1, "Failpath '%c' failed to path",
		     failpath[-1]);
	}
}

static char *failpath_string_for_line(struct fail_decision *dec)
{
	char *ret = NULL;
	struct fail_decision *i;

	for (i = decisions; i; i = i->next) {
		if (i->tui_line != dec->tui_line)
			continue;
		ret = talloc_asprintf_append(ret, "[%s]%c",
					     i->location,
					     i->failed ? 'F' : 'S');
	}
	return ret;
}

static char *failpath_string(void)
{
	char *ret = NULL;
	struct fail_decision *i;

	for (i = decisions; i; i = i->next)
		ret = talloc_asprintf_append(ret, "[%s]:%i:%c",
					     i->location, i->tui_line,
					     i->failed ? 'F' : 'S');
	return ret;
}

static void warn_failure(void)
{
	char *warning;
	struct fail_decision *i;
	int last_warning = 0;

	log_line(LOG_ALWAYS, "WARNING: test ignores failures at %s",
		 failpath_string());

	for (i = decisions; i; i = i->next) {
		if (i->failed && i->tui_line > last_warning) {
			warning = failpath_string_for_line(i);
			log_line(LOG_ALWAYS, " Line %i: %s",
				 i->tui_line, warning);
			talloc_free(warning);
			last_warning = i->tui_line;
		}
	}
}

bool am_parent(void)
{
	struct fail_decision *i;

	for (i = decisions; i; i = i->next) {
		if (i->failed)
			return false;
	}
	return true;
}

static char *make_location(const char *func, const char *caller)
{
	const char *afterslash;

	afterslash = strrchr(caller, '/');
	if (afterslash)
		afterslash++;
	else
		afterslash = caller;
	return talloc_asprintf(working, "%s(%s)", func, afterslash);
}

/* Should I fail at this point?  Once only: it would be too expensive
 * to fail at every possible call. */
bool should_i_fail_once(const char *func, const char *caller)
{
	char *p, *location = make_location(func, caller);
	struct fail_decision *i;

	if (failpath) {
		p = strstr(orig_failpath ?: "", location);
		if (p && p <= failpath
		    && p[-1] == '[' && p[strlen(location)] == ']')
			return false;

		return do_failpath(location);
	}

	for (i = decisions; i; i = i->next)
		if (streq(location, i->location))
			return false;

	if (should_i_fail(func, caller)) {
		excessive_fails++;
		return true;
	}
	return false;
}

/* Should I fail at this point? */
bool should_i_fail(const char *func, const char *caller)
{
	pid_t child;
	int status, pfd[2];
	struct fail_decision *dec;
	size_t log_size;
	char *log;
	char *location = make_location(func, caller);
	void *databases;

	if (failpath)
		return do_failpath(location);

	failpoints++;
	if (!failtest)
		return false;

	/* If a testcase ignores a spuriously-inserted failure, it's
	 * not specific enough, and we risk doing 2^n tests! */
	if (fails > excessive_fails) {
		static bool warned = false;
		if (!warned++)
			warn_failure();
	}

	dec = talloc(NULL, struct fail_decision);
	dec->location = talloc_steal(dec, location);
	dec->tui_line = tui_linenum;

	DLIST_ADD_END(decisions, dec, struct fail_decision);

	if (pipe(pfd) != 0)
		err(1, "pipe failed for failtest!");

	databases = save_databases();

	fflush(stdout);
	child = fork();
	if (child == -1)
		err(1, "fork failed for failtest!");

	/* The child actually fails.  The script will screw up at this
	 * point, but should not crash. */
	if (child == 0) {
		/* Log to parent (including stderr if things go really bad). */
		close(pfd[0]);
		dup2(pfd[1], STDOUT_FILENO);
		dup2(pfd[1], STDERR_FILENO);
		dec->failed = true;
		if (!failtest_no_report || !strstr(func, failtest_no_report))
			fails++;
		return true;
	}

	dec->failed = false;

	close(pfd[1]);
	log = grab_fd(pfd[0], &log_size);

	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			err(1, "failtest waitpid failed for child %i",
			    (int)child);
	}

	/* If child succeeded, or mere script failure, continue. */
	if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_SUCCESS
				  || WEXITSTATUS(status) == EXIT_SCRIPTFAIL)) {
		talloc_free(log);
		restore_databases(databases);
		return false;
	}

	/* Reproduce child's path: leave databases for post-mortem. */
	dec->failed = true;

	log_line(LOG_ALWAYS, "Child %s %i on failure path: %s",
		 WIFEXITED(status) ? "exited" : "signalled",
		 WIFEXITED(status) ? WEXITSTATUS(status)
		 : WTERMSIG(status), failpath_string());
	log_line(LOG_ALWAYS, "Child output:\n%s", log);
	exit(EXIT_FAILURE);
}

void dump_failinfo(void)
{
	log_line(LOG_VERBOSE, "Hit %u failpoints: %s",
		 failpoints, failpath_string());
}
