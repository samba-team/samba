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
#include "system/time.h"
#include "lib/util/time_basic.h"

/**
a gettimeofday wrapper
**/
_PUBLIC_ void GetTimeOfDay(struct timeval *tval)
{
#if defined(HAVE_GETTIMEOFDAY_TZ) || defined(HAVE_GETTIMEOFDAY_TZ_VOID)
	gettimeofday(tval,NULL);
#else
	gettimeofday(tval);
#endif
}

/****************************************************************************
 Return the date and time as a string
****************************************************************************/

char *timeval_str_buf(const struct timeval *tp, bool rfc5424, bool hires,
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

	len = snprintf(dst->buf, sizeof(dst->buf),
		       (rfc5424 ?
			"%04d-%02d-%02dT%02d:%02d:%02d" :
			"%04d/%02d/%02d %02d:%02d:%02d"),
		       1900 + tm->tm_year, tm->tm_mon + 1, tm->tm_mday,
		       tm->tm_hour, tm->tm_min, tm->tm_sec);

	if ((rfc5424 || hires) && (len < sizeof(dst->buf))) {
		len += snprintf(dst->buf + len, sizeof(dst->buf) - len,
				".%06ld", (long)tp->tv_usec);
	}

	if (rfc5424 && (len < sizeof(dst->buf))) {
		struct tm tm_utc, tm_local;
		int offset;

		tm_local = *tm;
		/* It is reasonable to assume that if localtime()
		 * worked above, then gmtime() should also work
		 * without error. */
		tm_utc = *gmtime(&t);

		offset = (tm_local.tm_hour - tm_utc.tm_hour) * 60 +
			(tm_local.tm_min - tm_utc.tm_min);

		snprintf(dst->buf + len, sizeof(dst->buf) - len,
			 "%c%02d:%02d",
			 (offset >=0 ? '+' : '-'),
			 abs(offset) / 60,
			 abs(offset) % 60);
	}

	return dst->buf;
}
