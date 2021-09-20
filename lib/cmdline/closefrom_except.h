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

#ifndef __LIB_CLOSEFROM_EXCEPT_H__
#define __LIB_CLOSEFROM_EXCEPT_H__

#include "replace.h"

int closefrom_except(int lower, int *fds, size_t num_fds);
int closefrom_except_fd_params(
	int lower,
	size_t num_fd_params,
	const char *fd_params[],
	int argc,
	const char *argv[]);

#endif
