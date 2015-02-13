/*
 * Copyright (c) 2008 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "replace.h"
#include "system/filesys.h"
#include "system/wait.h"

#ifdef HAVE_PTY_H
#include <pty.h>
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#ifdef HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#elif defined HAVE_LIBUTIL_H
#include <libutil.h>
#endif

#ifdef	STREAMSPTY
#include <stropts.h>
#endif /* STREAMPTY */

#include <popt.h>

#ifdef HAVE_ERR_H
#include <err.h>
#else
#include <ccan/err/err.h>
#endif

struct command {
	enum { CMD_EXPECT = 0, CMD_SEND, CMD_PASSWORD } type;
	unsigned int lineno;
	char *str;
	struct command *next;
};

/*
 *
 */

static struct command *commands, **next = &commands;

static sig_atomic_t alarmset = 0;

static int opt_timeout = 10;
static int opt_verbose;

static int master;
static int slave;
static char line[256] = { 0 };

static void caught_signal(int signo)
{
	alarmset = signo;
}


static void open_pty(void)
{
#ifdef _AIX
	printf("implement open_pty\n");
	exit(77);
#endif
#if defined(HAVE_OPENPTY) || defined(__linux) || defined(__osf__) /* XXX */
	if(openpty(&master, &slave, line, 0, 0) == 0)
		return;
#endif /* HAVE_OPENPTY .... */
#ifdef STREAMSPTY
	{
		char *clone[] = {
			"/dev/ptc",
			"/dev/ptmx",
			"/dev/ptm",
			"/dev/ptym/clone",
			NULL
		};
		char **q;

		for(q = clone; *q; q++){
			master = open(*q, O_RDWR);
			if(master >= 0){
#ifdef HAVE_GRANTPT
				grantpt(master);
#endif
#ifdef HAVE_UNLOCKPT
				unlockpt(master);
#endif
				strlcpy(line, ptsname(master), sizeof(line));
				slave = open(line, O_RDWR);
				if (slave < 0)
					errx(1, "failed to open slave when using %s", *q);
				ioctl(slave, I_PUSH, "ptem");
				ioctl(slave, I_PUSH, "ldterm");

				return;
			}
		}
	}
#endif /* STREAMSPTY */

	/* more cases, like open /dev/ptmx, etc */

	exit(77);
}

/*
 *
 */

static char *iscmd(const char *buf, const char *s)
{
	size_t len = strlen(s);

	if (strncmp(buf, s, len) != 0) {
		return NULL;
	}

	return strdup(buf + len);
}

/*******************************************************************
A write wrapper that will deal with EINTR.
********************************************************************/

static ssize_t sys_write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	do {
		ret = write(fd, buf, count);
#if defined(EWOULDBLOCK)
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK));
#else
	} while (ret == -1 && (errno == EINTR || errno == EAGAIN));
#endif
	return ret;
}

static void parse_configuration(const char *fn)
{
	struct command *c;
	char s[1024];
	char *str;
	unsigned int lineno = 0;
	FILE *cmd;

	cmd = fopen(fn, "r");
	if (cmd == NULL)
		err(1, "open: %s", fn);

	while (fgets(s, sizeof(s),  cmd) != NULL) {

		s[strcspn(s, "#\n")] = '\0';
		lineno++;

		c = calloc(1, sizeof(*c));
		if (c == NULL)
			errx(1, "malloc");

		c->lineno = lineno;
		(*next) = c;
		next = &(c->next);

		if ((str = iscmd(s, "expect ")) != NULL) {
			c->type = CMD_EXPECT;
			c->str = str;
		} else if ((str = iscmd(s, "send ")) != NULL) {
			c->type = CMD_SEND;
			c->str = str;
		} else if ((str = iscmd(s, "password ")) != NULL) {
			c->type = CMD_PASSWORD;
			c->str = str;
		} else
			errx(1, "Invalid command on line %d: %s", lineno, s);
	}

	fclose(cmd);
}

/* A wrapper to close als file descriptors above the given fd */
static int sys_closefrom(int fd)
{
	int num = getdtablesize();

	if (num < 0) {
		num = 1024;
	}

	for (; fd <= num; fd++) {
		close(fd);
	}

	return 0;
}


/*
 *
 */

static int eval_parent(pid_t pid)
{
	struct command *c;
	char in;
	size_t len = 0;
	ssize_t sret;

	for (c = commands; c != NULL; c = c->next) {
		switch(c->type) {
		case CMD_EXPECT:
			if (opt_verbose) {
				printf("[expecting %s]\n", c->str);
			}
			len = 0;
			alarm(opt_timeout);
			while((sret = read(master, &in, sizeof(in))) > 0) {
				alarm(opt_timeout);
				printf("%c", in);
				if (c->str[len] != in) {
					len = 0;
					continue;
				}
				len++;
				if (c->str[len] == '\0') {
					break;
				}
			}
			alarm(0);
			if (alarmset == SIGALRM) {
				errx(1, "timeout waiting for %s (line %u)",
						c->str, c->lineno);
			} else if (alarmset) {
				errx(1, "got a signal %d waiting for %s (line %u)",
						(int)alarmset, c->str, c->lineno);
			}

			if (sret <= 0) {
				errx(1, "end command while waiting for %s (line %u)",
						c->str, c->lineno);
			}
			break;
		case CMD_SEND:
		case CMD_PASSWORD: {
			size_t i = 0;
			const char *msg = (c->type == CMD_PASSWORD) ? "****" : c->str;

			if (opt_verbose) {
				printf("[send %s]\n", msg);
			}

			len = strlen(c->str);

			while (i < len) {
				if (c->str[i] == '\\' && i < len - 1) {
					char ctrl;
					i++;
					switch(c->str[i]) {
					case 'n':
						ctrl = '\n';
						break;
					case 'r':
						ctrl = '\r';
						break;
					case 't':
						ctrl = '\t';
						break;
					default:
						errx(1,
						     "unknown control char %c (line %u)",
						     c->str[i],
						     c->lineno);
					}
					if (sys_write(master, &ctrl, 1) != 1) {
						errx(1, "command refused input (line %u)", c->lineno);
					}
				} else {
					if (sys_write(master, &c->str[i], 1) != 1) {
						errx(1, "command refused input (line %u)", c->lineno);
					}
				}
				i++;
			}
			break;
		}
		default:
			abort();
		}
	}

	while(read(master, &in, sizeof(in)) > 0) {
		printf("%c", in);
	}

	if (opt_verbose) {
		printf("[end of program]\n");
	}

	/*
	 * Fetch status from child
	 */
	{
		int ret, status;

		ret = waitpid(pid, &status, 0);
		if (ret == -1) {
			err(1, "waitpid");
		}

		if (WIFEXITED(status) && WEXITSTATUS(status)) {
			return WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			printf("killed by signal: %d\n", WTERMSIG(status));
			return 1;
		}
	}

	return 0;
}

/*
 *
 */
struct poptOption long_options[] = {
	POPT_AUTOHELP
	{"timeout", 't', POPT_ARG_INT,	&opt_timeout, 't'},
	{"verbose", 'v', POPT_ARG_NONE,	&opt_verbose, 'v'},
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	int optidx = 0;
	pid_t pid;
	poptContext pc;
	const char *instruction_file;
	const char **args;
	const char *program;
	char * const *program_args;

	pc = poptGetContext("texpect",
			    argc,
			    argv,
			    long_options,
			    POPT_CONTEXT_POSIXMEHARDER);

	if (argc == 1) {
		poptPrintHelp(pc, stderr, 0);
		return 1;
	}

	while ((optidx = poptGetNextOpt(pc)) != -1) {
		;;
	}

	instruction_file = poptGetArg(pc);
	args = poptGetArgs(pc);
	program_args = (char * const *)discard_const_p(char *, args);
	program = program_args[0];

	if (opt_verbose) {
		int i;

		printf("Using instruction_file: %s\n", instruction_file);
		printf("Executing '%s' ", program);
		for (i = 0; program_args && program_args[i] != NULL; i++) {
			printf("'%s' ", program_args[i]);
		}
		printf("\n");
	}

	parse_configuration(instruction_file);

	open_pty();

	pid = fork();
	switch (pid) {
		case -1:
			err(1, "Failed to fork");
		case 0:

			if(setsid()<0)
				err(1, "setsid");

			dup2(slave, STDIN_FILENO);
			dup2(slave, STDOUT_FILENO);
			dup2(slave, STDERR_FILENO);

			sys_closefrom(STDERR_FILENO + 1);

			/* texpect <expect_instructions> <progname> [<args>] */
			execvp(program, program_args);
			err(1, "Failed to exec: %s", program);
		default:
			close(slave);
			{
				struct sigaction sa;

				sa.sa_handler = caught_signal;
				sa.sa_flags = 0;
				sigemptyset (&sa.sa_mask);

				sigaction(SIGALRM, &sa, NULL);
			}

			return eval_parent(pid);
	}
}
