/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "closefrom_except.h"
#include <popt.h>

int closefrom_except(int lower, int *fds, size_t num_fds)
{
	size_t i;
	int max_keep = -1;
	int fd, ret;

	for (i=0; i<num_fds; i++) {
		max_keep = MAX(max_keep, fds[i]);
	}
	if (max_keep == -1) {
		return 0;
	}

	for (fd = lower; fd < max_keep; fd++) {
		bool keep = false;

		/*
		 * O(num_fds*max_keep), but we expect the number of
		 * fds to keep to be very small, typically 0,1,2 and
		 * very few more.
		 */
		for (i=0; i<num_fds; i++) {
			if (fd == fds[i]) {
				keep = true;
				break;
			}
		}
		if (keep) {
			continue;
		}
		ret = close(fd);
		if ((ret == -1) && (errno != EBADF)) {
			return errno;
		}
	}

	closefrom(MAX(lower, max_keep+1));
	return 0;
}

int closefrom_except_fd_params(
	int lower,
	size_t num_fd_params,
	const char *fd_params[],
	int argc,
	const char *argv[])
{
	int fds[num_fd_params];
	size_t i;
	struct poptOption long_options[num_fd_params + 1];
	poptContext pc;
	int ret;

	for (i=0; i<num_fd_params; i++) {
		fds[i] = -1;
		long_options[i] = (struct poptOption) {
			.longName = fd_params[i],
			.argInfo = POPT_ARG_INT,
			.arg = &fds[i],
		};
	}
	long_options[num_fd_params] = (struct poptOption) { .longName=NULL, };

	pc = poptGetContext(argv[0], argc, argv, long_options, 0);

	while ((ret = poptGetNextOpt(pc)) != -1) {
		/* do nothing */
	}

	poptFreeContext(pc);

	ret = closefrom_except(lower, fds, ARRAY_SIZE(fds));
	return ret;
}
