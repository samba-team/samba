/*
   Unix SMB/CIFS implementation.
   ctdb debug functions
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "system/time.h"
#include <unistd.h>

static int vasprintf2(char **ptr, const char *format, va_list ap)
{
    int ret;
    va_list tmp_ap;

    va_copy(tmp_ap, ap);
    ret = vsnprintf(NULL, 0, format, tmp_ap);
    if (ret <= 0) return ret;

    (*ptr) = (char *)malloc(ret+1);
    if (!*ptr) return -1;
    ret = vsnprintf(*ptr, ret+1, format, ap);

    return ret;
}

void do_debug(const char *format, ...)
{
	struct timeval tm;
	va_list ap;
	char *s = NULL;

	va_start(ap, format);
	vasprintf2(&s, format, ap);
	va_end(ap);

	gettimeofday(&tm, NULL);
	printf("%-8.8d.%-6.6d [%d]: %s", (int)tm.tv_sec, (int)tm.tv_usec,
	       (int)getpid(), s);
	fflush(stdout);
	free(s);
}
