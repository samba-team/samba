/*
   Unix SMB/CIFS implementation.
   ctdb debug functions
   Copyright (C) Volker Lendecke 2007

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

#include "includes.h"
#include "system/time.h"
#include <unistd.h>
#include <ctype.h>

static void _do_debug_v(const char *format, va_list ap)
{
	struct timeval t;
	char *s = NULL;
	struct tm *tm;
	char tbuf[100];
	int ret;

	ret = vasprintf(&s, format, ap);
	if (ret == -1) {
		fprintf(stderr, "vasprintf failed in _do_debug_v, cannot print debug message.\n");
		fflush(stderr);
		return;
	}

	t = timeval_current();
	tm = localtime(&t.tv_sec);

	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

	fprintf(stderr, "%s.%06u [%s%5u]: %s", tbuf, (unsigned)t.tv_usec,
		debug_extra, (unsigned)getpid(), s);
	fflush(stderr);
	free(s);
}

/* default logging function */
void (*do_debug_v)(const char *, va_list ap) = _do_debug_v;
const char *debug_extra = "";

void do_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	do_debug_v(format, ap);
	va_end(ap);
}


static void _do_debug_add_v(const char *format, va_list ap)
{
	char *s = NULL;
	int ret;

	ret = vasprintf(&s, format, ap);
	if (ret == -1) {
		fprintf(stderr, "vasprintf failed in _do_debug_add_v, cannot print debug message.\n");
		fflush(stderr);
		return;
	}

	fprintf(stderr, "%s", s);
	fflush(stderr);
	free(s);
}

/* default logging function */
void (*do_debug_add_v)(const char *, va_list ap) = _do_debug_add_v;

void do_debug_add(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	do_debug_add_v(format, ap);
	va_end(ap);
}

static void print_asc(int level, const uint8_t *buf, size_t len)
{
	int i;
	for (i=0;i<len;i++) {
		DEBUGADD(level,("%c", isprint(buf[i])?buf[i]:'.'));
	}
}

void dump_data(int level, const uint8_t *buf, size_t len)
{
	int i=0;

	if (len<=0) return;

	if (!DEBUGLVL(level)) return;

	DEBUG(level, (__location__ " dump data of size %i:\n", (int)len));
	DEBUGADD(level,("[%03X] ",i));
	for (i=0;i<len;) {
		DEBUGADD(level,("%02X ",(int)buf[i]));
		i++;
		if (i%8 == 0) DEBUGADD(level,(" "));
		if (i%16 == 0) {
			print_asc(level,&buf[i-16],8); DEBUGADD(level,(" "));
			print_asc(level,&buf[i-8],8); DEBUGADD(level,("\n"));
			if (i<len) DEBUGADD(level,("[%03X] ",i));
		}
	}
	if (i%16) {
		int n;
		n = 16 - (i%16);
		DEBUGADD(level,(" "));
		if (n>8) DEBUGADD(level,(" "));
		while (n--) DEBUGADD(level,("   "));
		n = MIN(8,i%16);
		print_asc(level,&buf[i-(i%16)],n); DEBUGADD(level,( " " ));
		n = (i%16) - n;
		if (n>0) print_asc(level,&buf[i-n],n);
		DEBUGADD(level,("\n"));
	}
	DEBUG(level, (__location__ " dump data of size %i finished\n", (int)len));
}

