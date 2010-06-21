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
#include "ctdb-test.h"
#include "utils.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <assert.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <talloc.h>
#include <dlinklist.h>

int tui_echo_commands;
int tui_abort_on_fail;
int tui_quiet;
int tui_linenum = 1;
char *extension_path;
static bool stop;

struct command {
	struct command *next, *prev;
	char	name[TUI_MAX_CMD_LEN+1];
	bool	(*handler)(int, char **);
	void	(*helpfn) (int, char **);
};

struct pre_post_hook {
	struct pre_post_hook *next, *prev;
	void	(*pre)(const char *);
	bool	(*post)(const char *);
};

static struct command *commands;
static struct pre_post_hook *pre_post_hooks;

static bool tui_exit(int argc, char **argv)
{
	stop = true;
	return true;
}

static bool tui_argtest(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++)
		log_line(LOG_UI, "argv[%d]: \"%s\"", i, argv[i]);

	return true;
}

static inline struct command *find_command(const char *name)
{
	struct command *cmd;
	for (cmd = commands; cmd; cmd = cmd->next)
		if (!strcmp(name, cmd->name))
			return cmd;

	return NULL;
}

bool tui_is_command(const char *name)
{
	return find_command(name) != NULL;
}

static void do_pre_commands(const char *cmd)
{
	struct pre_post_hook *i;
	for (i = pre_post_hooks; i; i = i->next)
		if (i->pre)
			i->pre(cmd);
}

static bool do_post_commands(const char *cmd)
{
	struct pre_post_hook *i;
	bool ret = true;

	for (i = pre_post_hooks; i; i = i->next)
		if (i->post && !i->post(cmd))
			ret = false;
	return ret;
}

static bool tui_help(int argc, char **argv)
{
	struct command *cmd;

	if (argc == 1) {
		log_line(LOG_UI, "CTDB tester\n"
		"help is available on the folowing commands:");
		for (cmd = commands; cmd; cmd = cmd->next) {
			if (cmd->helpfn)
				log_line(LOG_UI, "\t%s", cmd->name);
		}
	} else {
		if (!(cmd = find_command(argv[1]))) {
			log_line(LOG_ALWAYS, "No such command '%s'", argv[1]);
			return false;
		}
		if (!cmd->helpfn) {
			log_line(LOG_UI, "No help for the '%s' function",
				argv[1]);
			return false;
		}
		cmd->helpfn(argc-1, argv+1);
	}
	return true;


}

static void tui_help_help(int argc, char **argv)
{
#include "generated-tui-help:help"
/*** XML Help:
    <section id="c:help">
     <title><command>help</command></title>
     <para>Displays general help, or help for a specified command</para>
     <cmdsynopsis>
      <command>help</command>
      <arg choice="opt">command</arg>
     </cmdsynopsis>
     <para>With no arguments, <command>help</command> will show general system
      help, and list the available commands. If an argument is specified, then
      <command>help</command> will show help for that command, if
      available.</para>
    </section>
*/
}

static void tui_exit_help(int argc, char **argv)
{
#include "generated-tui-help:exit"
/*** XML Help:
    <section id="c:exit">
     <title><command>exit</command>,
     <command>quit</command></title>
     <para>Exit the simulator</para>
     <cmdsynopsis>
      <command>exit</command>
     </cmdsynopsis>
     <cmdsynopsis>
      <command>quit</command>
     </cmdsynopsis>

     <para>The <command>exit</command> and <command>quit</command>
      commands are synonomous.  They both exit the simulator.
     </para>
    </section>
 */
}

void script_fail(const char *fmt, ...)
{
	char *str;
	va_list arglist;

	log_line(LOG_ALWAYS, "Script failed at line %i: ", tui_linenum);

	va_start(arglist, fmt);
	str = talloc_vasprintf(NULL, fmt, arglist);
	va_end(arglist);

	log_line(LOG_ALWAYS, "%s", str);
	talloc_free(str);

	check_allocations();
	check_databases();
	exit(EXIT_SCRIPTFAIL);
}

bool tui_do_command(int argc, char *argv[], bool abort)
{
	struct command *cmd;
	bool ret = true;

	if ((cmd = find_command(argv[0]))) {
		do_pre_commands(cmd->name);
		if (!cmd->handler(argc, argv)) {
			/* Abort on UNEXPECTED failure. */
			if (!log_line(LOG_UI, "%s: command failed", argv[0])
			    && abort)
				script_fail("%s failed", argv[0]);
			ret = false;
		}
		if (!do_post_commands(cmd->name))
			ret = false;
		return ret;
	}

	if (abort)
		script_fail("%s not found", argv[0]);

	log_line(LOG_ALWAYS, "%s: command not found", argv[0]);
	return false;
}

/**
 * backslash-escape a binary data block into a newly allocated
 * string
 *
 * @param src a pointer to the data block
 * @param src_len the length of the data block
 * @return NULL if out of memory, or a pointer to the allocated escaped
 *    string, which is terminated with a '\0' character
 */
static char *escape(const char *src, size_t src_len)
{
	static const char hexbuf[]= "0123456789abcdef";
	char *dest, *p;
	size_t i;

	/* src_len * 4 is always safe, it's the longest escape
	   sequence for all characters */
	dest = talloc_array(src, char, src_len * 4 + 1);
	p = dest;

	for (i = 0; i < src_len; i++) {
		if (src[i] == '\n') {
			*p++ = '\\';
			*p++ = 'n';
		} else if (src[i] == '\r') {
			*p++ = '\\';
			*p++ = 'r';
		} else if (src[i] == '\0') {
			*p++ = '\\';
			*p++ = '0';
		} else if (src[i] == '\t') {
			*p++ = '\\';
			*p++ = 't';
		} else if (src[i] == '\\') {
			*p++ = '\\';
			*p++ = '\\';
		} else if (src[i] & 0x80 || (src[i] & 0xe0) == 0) {
			*p++ = '\\';
			*p++ = 'x';
			*p++ = hexbuf[(src[i] >> 4) & 0xf];
			*p++ = hexbuf[src[i] & 0xf];
		} else
			*p++ = src[i];
	}

	*p++ = 0;
	return dest;
}

/* Process `command`: update off to point to tail backquote */
static char *backquote(char *line, unsigned int *off)
{
	char *end, *cmdstr, *str;
	FILE *cmdfile;
	size_t used, len, i;
	int status;

	/* Skip first backquote, look for next one. */
	(*off)++;
	end = strchr(line + *off, '`');
	if (!end)
		script_fail("no matching \"`\" found");

	len = end - (line + *off);
	cmdstr = talloc_asprintf(line, "PATH=%s; %.*s",
				 extension_path, (int)len, line + *off);
	cmdfile = popen(cmdstr, "r");
	if (!cmdfile)
		script_fail("failed to popen '%s': %s\n",
			    cmdstr, strerror(errno));

       /* Jump to backquote. */
       *off += len;

	/* Read command output. */
	used = 0;
	len = 1024;
	str = talloc_array(line, char, len);

	while ((i = fread(str + used, 1, len - used, cmdfile)) != 0) {
		used += i;
		if (used == len) {
			if (len > 1024*1024)
				script_fail("command '%s' output too long\n",
					    cmdstr);
			len *= 2;
			str = talloc_realloc(line, str, char, len);
		}
	}
	status = pclose(cmdfile);
	if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		script_fail("command '%s' failed\n", cmdstr);

	return escape(str, used);
}

static char *append_char(char **argv, unsigned int argc, char c)
{
	if (!argv[argc])
		return talloc_asprintf(argv, "%c", c);
	return talloc_asprintf_append(argv[argc], "%c", c);
}

static char *append_string(char **argv, unsigned int argc, const char *str)
{
	if (!argv[argc])
		return talloc_asprintf(argv, "%s", str);
	return talloc_asprintf_append(argv[argc], "%s", str);
}

static void process_line(char *line, unsigned int off)
{
	unsigned int argc, i;
	char **argv;

	if (tui_echo_commands)
		printf("%u:%s\n", tui_linenum, line + off);

	/* Talloc argv off line so commands can use it for auto-cleanup. */
	argv = talloc_zero_array(line, char *, TUI_MAX_ARGS+1);
	argc = 0;
	for (i = off; line[i]; i++) {
		if (isspace(line[i])) {
			/* If anything in this arg, move to next. */
			if (argv[argc])
				argc++;
		} else if (line[i] == '`') {
			char *inside = backquote(line, &i);
			argv[argc] = append_string(argv, argc, inside);
		} else {
			/* If it is a comment, stop before we process `` */
			if (!argv[0] && line[i] == '#')
				goto out;

			argv[argc] = append_char(argv, argc, line[i]);
		}
	}

	if (argv[0]) {
		if (argv[argc])
			argv[++argc] = NULL;
		tui_do_command(argc, argv, tui_abort_on_fail);
	}

out:
	tui_linenum++;
	return;
}

static void readline_process_line(char *line)
{
	char *talloc_line;
	if (!line) {
		stop = true;
		return;
	}

	add_history(line);

	/* Readline isn't talloc-aware, so copy string: functions can
	 * hang temporary variables off this. */
	talloc_line = talloc_strdup(NULL, line);
	process_line(talloc_line, 0);
	talloc_free(talloc_line);
}

static void run_whole_file(int fd)
{
	char *file, *p;
	size_t size, len;

	file = grab_fd(fd, &size);
	if (!file)
		err(1, "Grabbing file");

	for (p = file; p < file + size; p += len+1) {
		len = strcspn(p, "\n");
		p[len] = '\0';
		process_line(file, p - file);
	}
}

void tui_run(int fd)
{
	tui_register_command("exit", tui_exit, tui_exit_help);
	tui_register_command("quit", tui_exit, tui_exit_help);
	tui_register_command("q", tui_exit, tui_exit_help);
	tui_register_command("test", tui_argtest, NULL);
	tui_register_command("help", tui_help, tui_help_help);

	if (fd == STDIN_FILENO) {
		stop = false;
		rl_callback_handler_install(tui_quiet ? "" : "> ",
					    readline_process_line);
		while (!stop)
			rl_callback_read_char();
		rl_callback_handler_remove();
		if (!tui_quiet)
			printf("\n");
	} else
		run_whole_file(fd);
}

int tui_register_pre_post_hook(void (*pre)(const char *),
			       bool (*post)(const char *))
{
	struct pre_post_hook *h;

	h = talloc(NULL, struct pre_post_hook);
	h->pre = pre;
	h->post = post;
	DLIST_ADD(pre_post_hooks, h);
	return 0;
}

int tui_register_command(const char *command,
			 bool (*handler)(int, char **),
			 void (*helpfn)(int, char **))
{
	struct command *cmd;

	assert(strlen(command) < TUI_MAX_CMD_LEN);

	cmd = talloc(NULL, struct command);
	strncpy(cmd->name, command, TUI_MAX_CMD_LEN);
	cmd->handler = handler;
	cmd->helpfn  = helpfn;

	DLIST_ADD(commands, cmd);

	return 0;
}
