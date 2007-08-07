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


void do_debug(const char *format, ...)
{
	struct timeval t;
	va_list ap;
	char *s = NULL;
	struct tm *tm;
	char tbuf[100];

	va_start(ap, format);
	vasprintf(&s, format, ap);
	va_end(ap);

	t = timeval_current();
	tm = localtime(&t.tv_sec);

	strftime(tbuf,sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

	fprintf(stderr, "%s.%06u [%5u]: %s", tbuf, (unsigned)t.tv_usec, (unsigned)getpid(), s);
	fflush(stderr);
	free(s);
}
