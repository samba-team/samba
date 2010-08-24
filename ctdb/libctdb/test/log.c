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
#include "log.h"
#include "tui.h"
#include "utils.h"
#include "expect.h"
#include <string.h>
#include <talloc.h>
#include <err.h>

static struct {
	enum log_type	type;
	char *		name;
} log_names[] = {
	{ LOG_WRITE,	"write" },
	{ LOG_READ,	"read" },
	{ LOG_LIB,	"lib" },
	{ LOG_VERBOSE,	"verbose" },
};

static int typemask = ~LOG_VERBOSE;

bool log_line(enum log_type type, const char *format, ...)
{
	va_list ap;
	char *line;
	bool ret;

	va_start(ap, format);
	line = talloc_vasprintf(NULL, format, ap);
	va_end(ap);

	if (!type || (type & typemask)) {
		printf("%s\n", line);
		fflush(stdout);
	}

	ret = expect_log_hook(line);
	talloc_free(line);
	return ret;
}

static void log_partial_v(enum log_type type,
			  char *buf,
			  unsigned bufsize,
			  const char *format,
			  va_list ap)
{
	char *ptr;
	int len = strlen(buf);

	/* write to the end of buffer */
	if (vsnprintf(buf + len, bufsize - len - 1, format, ap)
	    > bufsize - len - 1) {
		errx(1, "log_line_partial buffer is full!");
	}

	ptr = buf;

	/* print each bit that ends in a newline */
	for (len = strcspn(ptr, "\n"); *(ptr + len);
			ptr += len, len = strcspn(ptr, "\n")) {
		log_line(type, "%.*s", len++, ptr);
	}

	/* if we've printed, copy any remaining (non-newlined)
	   parts (including the \0) to the front of buf */
	memmove(buf, ptr, strlen(ptr) + 1);
}

void log_partial(enum log_type type, char *buf, unsigned bufsize,
		 const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_partial_v(type, buf, bufsize, format, ap);
	va_end(ap);
}

static inline int parsetype(const char *type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(log_names); i++)
		if (streq(log_names[i].name, type))
			return log_names[i].type;

	return 0;
}

static bool log_admin(int argc, char **argv)
{
	int i;
	int newtypemask = 0;

	if (argc == 1) {
		log_line(LOG_UI, "current log types:", typemask);

		for (i = 0; i < ARRAY_SIZE(log_names); i++) {
			if (typemask & log_names[i].type)
				log_line(LOG_UI, "\t%s", log_names[i].name);
		}
		return true;
	}

	if (argc == 2) {
		log_line(LOG_ALWAYS, "Expected =, + or - then args");
		return false;
	}

	for (i = 2; i < argc; i++) {
		int type;

		if (!(type = parsetype(argv[i]))) {
			log_line(LOG_ALWAYS, "no such type %s", argv[i]);
			return false;
		}
		newtypemask |= type;
	}

	switch (*argv[1]) {
	case '=':
		typemask = newtypemask;
		break;
	case '-':
		typemask &= ~newtypemask;
		break;
	case '+':
		typemask |= newtypemask;
		break;
	default:
		log_line(LOG_ALWAYS, "unknown modifer: %c", *argv[1]);
		return false;
	}

	return true;
}

static void log_admin_help(int agc, char **argv)
{
#include "generated-log-help:log"
/*** XML Help:
    <section id="c:log">
     <title><command>log</command></title>
     <para>Manage logging settings</para>
     <cmdsynopsis>
      <command>log</command>
      <group choice="opt">
       <arg choice="plain">=</arg>
       <arg choice="plain">+</arg>
       <arg choice="plain">-</arg>
      </group>
      <arg choice="req"><replaceable>type, ...</replaceable></arg>
     </cmdsynopsis>
     <para>Each log message is classified into one of the following
     types:</para>
      <varlistentry>
       <term>UI</term>
       <listitem>
        <para>Normal response from command lines.</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>LIB</term>
       <listitem>
        <para>Logging output from libctdb</para>
       </listitem>
      </varlistentry>
     <variablelist>
      <varlistentry>
       <term>READ</term>
       <listitem>
        <para>Messages from ctdbd</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>WRITE</term>
       <listitem>
        <para>Messages to ctdbd</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>VERBOSE</term>
       <listitem>
        <para>Verbose debug output</para>
       </listitem>
      </varlistentry>
     </variablelist>

     <para>The <command>log</command> command allows you to select
      which messages are displayed. By default, all messages except
      debug will be shown.</para>

     <para>Without any arguments, the current logged types are listed.</para>

     <para>With +, - or = character, those types will be added,
      removed or set as the current types of messages to be logged
      (repectively).</para>

      <para>Messages generated as a result of user input are always
      logged.  </para> </section>
*/
}

static void log_init(void)
{
	if (tui_quiet)
		typemask = 0;
	tui_register_command("log", log_admin, log_admin_help);
}

init_call(log_init);
