/*
 * Unix SMB/CIFS implementation.
 * time handling functions
 *
 * Copyright (C) Andrew Tridgell 		1992-2004
 * Copyright (C) Stefan (metze) Metzmacher	2002
 * Copyright (C) Jeremy Allison			2007
 * Copyright (C) Andrew Bartlett                2011
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "lib/util/time_basic.h"

/**
a gettimeofday wrapper
**/
_PUBLIC_ void GetTimeOfDay(struct timeval *tval)
{
#ifdef HAVE_GETTIMEOFDAY_TZ
	gettimeofday(tval,NULL);
#else
	gettimeofday(tval);
#endif
}

/****************************************************************************
 Return the date and time as a string
****************************************************************************/

char *timeval_str_buf(const struct timeval *tp, bool hires,
		      struct timeval_buf *dst)
{
	time_t t;
	struct tm *tm;
	size_t len;

	t = (time_t)tp->tv_sec;
	tm = localtime(&t);

	if (tm == NULL) {
		if (hires) {
			snprintf(dst->buf, sizeof(dst->buf),
				 "%ld.%06ld seconds since the Epoch",
				 (long)tp->tv_sec, (long)tp->tv_usec);
		} else {
			snprintf(dst->buf, sizeof(dst->buf),
				 "%ld seconds since the Epoch", (long)t);
		}
		return dst->buf;
	}

#ifdef HAVE_STRFTIME
	len = strftime(dst->buf, sizeof(dst->buf), "%Y/%m/%d %H:%M:%S", tm);
#else
	{
		const char *asct = asctime(tm);
		len = strlcpy(dst->buf, sizeof(dst->buf),
			      asct ? asct : "unknown");
	}
#endif
	if (hires && (len < sizeof(dst->buf))) {
		snprintf(dst->buf + len, sizeof(dst->buf) - len,
			 ".%06ld", (long)tp->tv_usec);
	}

	return dst->buf;
}
