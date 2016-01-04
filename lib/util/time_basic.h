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

#ifndef _SAMBA_TIME_BASIC_H_
#define _SAMBA_TIME_BASIC_H_

struct timeval;

/**
a gettimeofday wrapper
**/
_PUBLIC_ void GetTimeOfDay(struct timeval *tval);

struct timeval_buf { char buf[128]; };

/**
 Put a date and time into dst->buf, return it dst->buf
 (optionally with microseconds)

 If rfc5424 is true then produce the RFC5424 timestamp format (which
 is a stricter instance of RFC3339 and is used for syslog). For
 example: 2003-08-24T05:14:15.000003-07:00.  Otherwise,
 format is %Y/%m/%d %H:%M:%S
**/

char *timeval_str_buf(const struct timeval *tp, bool rfc5424, bool hires,
		      struct timeval_buf *dst);

#endif /* _SAMBA_TIME_BASIC_H_ */
