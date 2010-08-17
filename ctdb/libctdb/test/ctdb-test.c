/*
   test driver for libctdb

   Copyright (C) Rusty Russell 2010

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <talloc.h>
#include <tdb.h>

/* We replace the following functions, for finer control. */
#define poll(fds, nfds, timeout) ctdb_test_poll((fds), (nfds), (timeout), __location__)
#define malloc(size) ctdb_test_malloc((size), __location__)
#define free(ptr) ctdb_test_free((ptr), __location__)
#define realloc(ptr, size) ctdb_test_realloc((ptr), (size), __location__)
#define read(fd, buf, count) ctdb_test_read((fd), (buf), (count), __location__)
#define write(fd, buf, count) ctdb_test_write((fd), (buf), (count), __location__)
#define socket(domain, type, protocol) ctdb_test_socket((domain), (type), (protocol), __location__)
#define connect(sockfd, addr, addrlen) ctdb_test_connect((sockfd), (addr), (addrlen), __location__)

#define tdb_open_ex(name, hash_size, tdb_flags, open_flags, mode, log_ctx, hash_fn) ctdb_test_tdb_open_ex((name), (hash_size), (tdb_flags), (open_flags), (mode), (log_ctx), (hash_fn), __location__)
#define tdb_fetch(tdb, key) ctdb_test_tdb_fetch((tdb), (key))

/* Implement these if they're ever used. */
#define calloc ctdb_test_calloc
#define select ctdb_test_select
#define epoll_wait ctdb_test_epoll_wait
#define epoll_ctl ctdb_test_epoll_ctl
#define tdb_open ctdb_test_tdb_open

static int ctdb_test_poll(struct pollfd *fds, nfds_t nfds, int timeout, const char *location);
static void *ctdb_test_malloc(size_t size, const char *location);
static void ctdb_test_free(void *ptr, const char *location);
static void *ctdb_test_realloc(void *ptr, size_t size, const char *location);
static ssize_t ctdb_test_read(int fd, void *buf, size_t count, const char *location);
static ssize_t ctdb_test_write(int fd, const void *buf, size_t count, const char *location);
static int ctdb_test_socket(int domain, int type, int protocol, const char *location);
static int ctdb_test_connect(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen, const char *location);
static struct tdb_context *ctdb_test_tdb_open_ex(const char *name,
						 int hash_size, int tdb_flags,
						 int open_flags, mode_t mode,
						 const struct tdb_logging_context *log_ctx,
						 tdb_hash_func hash_fn, const char *location);
static TDB_DATA ctdb_test_tdb_fetch(struct tdb_context *tdb, TDB_DATA key);

#include "../sync.c"
#include "../control.c"
#include "../ctdb.c"
#include "../io_elem.c"
#include "../local_tdb.c"
#include "../logging.c"
#include "../messages.c"

#undef poll
#undef malloc
#undef realloc
#undef read
#undef write
#undef socket
#undef connect
#undef tdb_open_ex
#undef calloc
#undef select
#undef epoll_wait
#undef epoll_ctl
#undef tdb_open
#undef tdb_fetch

#include "ctdb-test.h"
#include "utils.h"
#include "tui.h"
#include "log.h"
#include "failtest.h"
#include "expect.h"
#include <err.h>

/* Talloc contexts */
void *allocations;
void *working;

static void run_inits(void)
{
	/* Linker magic creates these to delineate section. */
	extern initcall_t __start_init_call[], __stop_init_call[];
	initcall_t *p;

	for (p = __start_init_call; p < __stop_init_call; p++)
		(*p)();
}

static void print_license(void)
{
	printf("ctdb-test, Copyright (C) 2010 Jeremy Kerr, Rusty Russell\n"
	       "ctdb-test comes with ABSOLUTELY NO WARRANTY; see COPYING.\n"
	       "This is free software, and you are welcome to redistribute\n"
	       "it under certain conditions; see COPYING for details.\n");
}

/*** XML Argument:
    <section id="a:echo">
     <title><option>--echo</option>, <option>-x</option></title>
     <subtitle>Echo commands as they are executed</subtitle>
     <para>ctdb-test will echo each command before it is executed. Useful when
      commands are read from a file</para>
    </section>
*/
static void cmdline_echo(struct option *opt)
{
	tui_echo_commands = 1;
}
cmdline_opt("echo", 0, 'x', cmdline_echo);

/*** XML Argument:
    <section id="a:quiet">
     <title><option>--quiet</option>, <option>-q</option></title>
     <subtitle>Run quietly</subtitle>
     <para>Causes ctdb-test to reduce its output to the minimum possible - no prompt
      is displayed, and most warning messages are suppressed
     </para>
    </section>
*/
static void cmdline_quiet(struct option *opt)
{
	tui_quiet = 1;
}
cmdline_opt("quiet", 0, 'q', cmdline_quiet);

/*** XML Argument:
    <section id="a:exit">
     <title><option>--exit</option>, <option>-e</option></title>
     <subtitle>Exit on error</subtitle>
     <para>If <option>--exit</option> is specified, ctdb-test will exit (with a
     non-zero error code) on the first script error it encounters (eg an
     expect command does not match). This is the default when invoked as a
     non-interactive script.</para>
    </section>
*/
static void cmdline_abort_on_fail(struct option *opt)
{
	tui_abort_on_fail = 1;
}
cmdline_opt("exit", 0, 'e', cmdline_abort_on_fail);

/*** XML Argument:
    <section id="a:help">
     <title><option>--help</option></title>
     <subtitle>Print usage information</subtitle>
     <para>Causes ctdb-test to print its command line arguments and then exit</para>
    </section>
*/
static void cmdline_help(struct option *opt)
{
	print_license();
	print_usage();
	exit(EXIT_SUCCESS);
}
cmdline_opt("help", 0, 'h', cmdline_help);

extern struct cmdline_option __start_cmdline[], __stop_cmdline[];

static struct cmdline_option *get_cmdline_option(int opt)
{
	struct cmdline_option *copt;

	/* if opt is < '0', we have been passed a long option, which is
	 * indexed directly */
	if (opt < '0')
		return __start_cmdline + opt;

	/* otherwise search for the short option in the .val member */
	for (copt = __start_cmdline; copt < __stop_cmdline; copt++)
		if (copt->opt.val == opt)
			return copt;

	return NULL;
}

static struct option *get_cmdline_options(void)
{
	struct cmdline_option *copts;
	struct option *opts;
	unsigned int x, n_opts;

	n_opts = ((void *)__stop_cmdline - (void *)__start_cmdline) /
		sizeof(struct cmdline_option);

	opts = talloc_zero_array(NULL, struct option, n_opts + 1);
	copts = __start_cmdline;

	for (x = 0; x < n_opts; x++) {
		unsigned int y;

		if (copts[x].opt.has_arg > 2)
			errx(1, "Bad argument `%s'", copts[x].opt.name);

		for (y = 0; y < x; y++)
			if ((copts[x].opt.val && copts[x].opt.val
						== opts[y].val)
					|| streq(copts[x].opt.name,
						opts[y].name))
				errx(1, "Conflicting arguments %s = %s\n",
				     copts[x].opt.name, opts[y].name);

		opts[x] = copts[x].opt;
		opts[x].val = x;
	}

	return opts;
}

static char *get_cmdline_optstr(void)
{
	struct cmdline_option *copts;
	unsigned int x, n_opts;
	char *optstr, tmpstr[3], *colonstr = "::";

	n_opts = ((void *)__stop_cmdline - (void *)__start_cmdline) /
		sizeof(struct cmdline_option);

	optstr = talloc_size(NULL, 3 * n_opts * sizeof(*optstr) + 1);
	*optstr = '\0';

	copts = __start_cmdline;

	for (x = 0; x < n_opts; x++) {
		if (!copts[x].opt.val)
			continue;
		snprintf(tmpstr, 4, "%c%s", copts[x].opt.val,
			colonstr + 2 - copts[x].opt.has_arg);
		strcat(optstr, tmpstr);
	}
	return optstr;
}

static int ctdb_test_poll(struct pollfd *fds, nfds_t nfds, int timeout,
			  const char *location)
{
	if (should_i_fail("poll", location)) {
		errno = EINVAL;
		return -1;
	}
	return poll(fds, nfds, timeout);
}

static void *ctdb_test_malloc(size_t size, const char *location)
{
	if (should_i_fail("malloc", location)) {
		errno = ENOMEM;
		return NULL;
	}
	return talloc_named_const(allocations, size, location);
}

static void ctdb_test_free(void *ptr, const char *location)
{
	talloc_free(ptr);
}

static void *ctdb_test_realloc(void *ptr, size_t size, const char *location)
{
	if (should_i_fail("realloc", location)) {
		errno = ENOMEM;
		return NULL;
	}
	ptr = _talloc_realloc(allocations, ptr, size, location);
	if (ptr)
		talloc_set_name(ptr, "%s (reallocated to %u at %s)",
				talloc_get_name(ptr), size, location);
	return ptr;
}

static ssize_t ctdb_test_read(int fd, void *buf, size_t count,
			      const char *location)
{
	if (should_i_fail("read", location)) {
		errno = EBADF;
		return -1;
	}
	/* FIXME: We only let parent read and write.
	 * We should have child do short read, at least until whole packet is
	 * read.  Then we terminate child. */
	if (!am_parent()) {
		log_line(LOG_DEBUG, "Child reading fd");
		return 0;
	}
	return read(fd, buf, count);
}

static ssize_t ctdb_test_write(int fd, const void *buf, size_t count,
			       const char *location)
{
	if (should_i_fail("write", location)) {
		errno = EBADF;
		return -1;
	}
	/* FIXME: We only let parent read and write.
	 * We should have child do short write, at least until whole packet is
	 * written, then terminate child.  Check that all children and parent
	 * write the same data. */
	if (!am_parent()) {
		log_line(LOG_DEBUG, "Child writing fd");
		return 0;
	}
	return write(fd, buf, count);
}

static int ctdb_test_socket(int domain, int type, int protocol,
			    const char *location)
{
	if (should_i_fail("socket", location)) {
		errno = EINVAL;
		return -1;
	}
	return socket(domain, type, protocol);
}

static int ctdb_test_connect(int sockfd, const struct sockaddr *addr,
			     socklen_t addrlen, const char *location)
{
	if (should_i_fail("connect", location)) {
		errno = EINVAL;
		return -1;
	}
	return connect(sockfd, addr, addrlen);
}

static struct tdb_context *ctdb_test_tdb_open_ex(const char *name,
						 int hash_size, int tdb_flags,
						 int open_flags, mode_t mode,
						 const struct tdb_logging_context *log_ctx,
						 tdb_hash_func hash_fn,
						 const char *location)
{
	if (should_i_fail("tdb_open_ex", location)) {
		errno = ENOENT;
		return NULL;
	}
	return tdb_open_ex(name, hash_size, tdb_flags, open_flags, mode,
			   log_ctx, hash_fn);
}

/* We don't need to fail this, but as library expects to be able to free()
   dptr, we need to make sure it's talloced (see ctdb_test_free) */
static TDB_DATA ctdb_test_tdb_fetch(struct tdb_context *tdb, TDB_DATA key)
{
	TDB_DATA ret = tdb_fetch(tdb, key);
	if (ret.dptr) {
		ret.dptr = talloc_memdup(allocations, ret.dptr, ret.dsize);
		if (!ret.dptr) {
			err(1, "Could not memdup %zu bytes", ret.dsize);
		}
	}
	return ret;
}

void check_allocations(void)
{
	talloc_free(working);

	if (talloc_total_blocks(allocations) != 1) {
		log_line(LOG_ALWAYS, "Resource leak:");
		talloc_report_full(allocations, stdout);
		exit(1);
	}
}

/* This version adds one byte (for nul term) */
void *grab_fd(int fd, size_t *size)
{
	size_t max = 16384;
	int ret;
	void *buffer = talloc_array(NULL, char, max+1);

	*size = 0;
	while ((ret = read(fd, buffer + *size, max - *size)) > 0) {
		*size += ret;
		if (*size == max)
			buffer = talloc_realloc(NULL, buffer, char, max *= 2 + 1);
	}
	if (ret < 0) {
		talloc_free(buffer);
		buffer = NULL;
	}
	return buffer;
}

int main(int argc, char *argv[])
{
	int input_fd, c;
	const char *optstr;
	struct option *options;

	allocations = talloc_named_const(NULL, 1, "ctdb-test");
	working = talloc_named_const(NULL, 1, "ctdb-test-working");

	options = get_cmdline_options();
	optstr = get_cmdline_optstr();

	while ((c = getopt_long(argc, argv, optstr, options, NULL)) != EOF) {
		struct cmdline_option *copt = get_cmdline_option(c);
		if (!copt)
			errx(1, "Unknown argument");

		copt->parse(&copt->opt);
	}

	if (optind == argc) {
		log_line(LOG_DEBUG, "Disabling failtest due to stdin.");
		failtest = false;
		input_fd = STDIN_FILENO;
	} else if (optind + 1 != argc)
		errx(1, "Need a single argument: input filename");
	else {
		input_fd = open(argv[optind], O_RDONLY);
		if (input_fd < 0)
			err(1, "Opening %s", argv[optind]);
		tui_abort_on_fail = true;
	}

	run_inits();
	if (!tui_quiet)
		print_license();

	log_line(LOG_VERBOSE, "initialisation done");

	tui_run(input_fd);

	/* Everyone loves a good error haiku! */
	if (expects_remaining())
		errx(1, "Expectations still / "
		     "unfulfilled remaining. / "
		     "Testing blossoms fail.");
	check_allocations();
	check_databases();
	dump_failinfo();

	return EXIT_SUCCESS;
}
