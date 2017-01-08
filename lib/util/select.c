/*
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba select/poll implementation
   Copyright (C) Andrew Tridgell 1992-1998

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

#include "replace.h"
#include "system/filesys.h"
#include "system/select.h"
#include "lib/util/select.h"
#include "lib/util/time.h"

int sys_poll_intr(struct pollfd *fds, int num_fds, int timeout)
{
	int orig_timeout = timeout;
	struct timespec start;
	int ret;

	clock_gettime_mono(&start);

	while (true) {
		struct timespec now;
		int64_t elapsed;

		ret = poll(fds, num_fds, timeout);
		if (ret != -1) {
			break;
		}
		if (errno != EINTR) {
			break;
		}
		/* Infinite timeout, no need to adjust. */
		if (timeout < 0) {
			continue;
		}
		clock_gettime_mono(&now);
		elapsed = nsec_time_diff(&now, &start) / 1000000;
		timeout = orig_timeout - elapsed;
		/* Unlikely, but might happen eg. when getting traced.
		 * Make sure we're not hanging in this case.
		 */
		if (timeout < 0) {
			timeout = 0;
		}
	};
	return ret;
}
