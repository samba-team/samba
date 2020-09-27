/*
   Unix SMB/CIFS implementation.
   Files handle structure handling
   Copyright (C) Ralph Boehme 2020

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

#ifndef FD_HANDLE_PRIVATE_H
#define FD_HANDLE_PRIVATE_H

struct fd_handle {
	size_t ref_count;
	int fd;
	uint64_t position_information;
	off_t pos;
	/*
	 * NT Create options, but we only look at
	 * NTCREATEX_FLAG_DENY_DOS and
	 * NTCREATEX_FLAG_DENY_FCB and
	 * NTCREATEX_FLAG_DELETE_ON_CLOSE
	 * for print files *only*, where
	 * DELETE_ON_CLOSE is not stored in the share
	 * mode database.
	 */
	uint32_t private_options;
	uint64_t gen_id;
};

#endif
