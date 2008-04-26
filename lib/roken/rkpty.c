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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <util.h>

#include "roken.h"
#include <getarg.h>

struct command {
    enum { CMD_EXPECT = 0, CMD_SEND } type;
    char *str;
    struct command *next;
};

/*
 *
 */

static struct command *commands, **next = &commands;

static int verbose;
static int master;
static int slave;
static char line[256] = { 0 };

static void
open_pty(void)
{
#if defined(HAVE_OPENPTY) || defined(__linux) || defined(__osf__) /* XXX */
    if(openpty(&master, &slave, line, 0, 0) == 0)
	return;
#endif /* HAVE_OPENPTY .... */
    /* more cases, like open /dev/ptmx, etc */

    exit(77);
}

/*
 *
 */

static char *
iscmd(const char *buf, const char *s)
{
    size_t len = strlen(s);
    if (strncmp(buf, s, len) != 0)
	return NULL;
    return estrdup(buf + len);
}

static void
parse_configuration(const char *fn)
{
    struct command *c;
    char s[1024];
    char *str;
    int lineno = 0;
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

	(*next) = c;
	next = &(c->next);

	if ((str = iscmd(s, "expect ")) != NULL) {
	    c->type = CMD_EXPECT;
	    c->str = str;
	} else if ((str = iscmd(s, "send ")) != NULL) {
	    c->type = CMD_SEND;
	    c->str = str;
	} else
	    errx(1, "Invalid command on line %d: %s", lineno, s);
    }

    fclose(cmd);
}


/*
 *
 */

static int
eval_parent(pid_t pid)
{
    struct command *c;
    char in;
    size_t len = 0;
    ssize_t sret;

    for (c = commands; c != NULL; c = c->next) {
	switch(c->type) {
	case CMD_EXPECT:
	    len = 0;
	    while((sret = read(master, &in, sizeof(in))) > 0) {
		if (verbose)
		    printf("%c", in);
		if (c->str[len] != in) {
		    len = 0;
		    continue;
		}
		len++;
		if (c->str[len] == '\0')
		    break;
	    }
	    if (sret <= 0)
		errx(1, "end command while waiting for %s", c->str);
	    break;
	case CMD_SEND: {
	    size_t i = 0;

	    if (verbose)
		printf("[output]");

	    len = strlen(c->str);

	    while (i < len) {
		if (c->str[i] == '\\' && i < len - 1) {
		    char ctrl;
		    i++;
		    switch(c->str[i]) {
		    case 'n': ctrl = '\n'; break;
		    case 'r': ctrl = '\r'; break;
		    case 't': ctrl = '\t'; break;
		    default:
			errx(1, "unknown control char %c", c->str[i]);
		    }
		    if (net_write(master, &ctrl, 1) != 1)
			errx(1, "command refused input");
		} else {
		    if (net_write(master, &c->str[i], 1) != 1)
			errx(1, "command refused input");
		}
		i++;
	    }
	    break;
	}
	default:
	    abort();
	}
    }
    while(read(master, &in, sizeof(in)) > 0)
	if (verbose)
	    printf("%c", in);

    /*
     * Fetch status from child
     */
    {
	int ret, status;

	ret = waitpid(pid, &status, 0);
	if (ret == -1)
	    err(1, "waitpid");
	if (WIFEXITED(status) && WEXITSTATUS(status))
	    return WEXITSTATUS(status);
	else if (WIFSIGNALED(status)) {
	    printf("killed by signal: %d\n", WTERMSIG(status));
	    return 1;
	}
    }
    return 0;
}

/*
 *
 */

static struct getargs args[] = {
    { "verbose", 	'v', arg_flag, &verbose, "verbose debugging" }
};

static void
usage(int ret)
{
    arg_printusage (args, sizeof(args)/sizeof(*args), NULL, "infile command..");
    exit (ret);
}

int
main(int argc, char **argv)
{
    int optidx = 0;
    pid_t pid;

    setprogname(argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optidx))
	usage(1);

    argv += optidx;
    argc -= optidx;

    if (argc < 2)
	errx(1, "to few arguments");

    parse_configuration(argv[0]);

    argv += 1;
    argc -= 1;


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
	closefrom(STDERR_FILENO + 1);

	execvp(argv[0], argv); /* add NULL to end of array ? */
	err(1, "Failed to exec: %s", argv[0]);
    default:
	close(slave);

	return eval_parent(pid);
    }
}
