/* 
   Unix SMB/CIFS implementation.
   client string routines
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libsmb/proto.h"

bool clistr_is_previous_version_path(const char *path,
		const char **startp,
		const char **endp,
		time_t *ptime)
{
	char *q;
	time_t timestamp;
	struct tm tm;
	const char *p = strstr_m(path, "@GMT-");

	if (p == NULL) {
		return false;
	}
	if (p > path && (p[-1] != '\\')) {
		return false;
	}
	q = strptime(p, GMT_FORMAT, &tm);
	if (q == NULL) {
		return false;
	}
	tm.tm_isdst = -1;
	timestamp = timegm(&tm);
	if (timestamp == (time_t)-1) {
		return false;
	}
	if (q[0] != '\0' && q[0] != '\\') {
		return false;
	}
	if (startp) {
		*startp = p;
	}
	if (endp) {
		if (q[0] == '\\') {
			q++;
		}
		*endp = q;
	}
	if (ptime) {
		*ptime = timestamp;
	}
	return true;
}
