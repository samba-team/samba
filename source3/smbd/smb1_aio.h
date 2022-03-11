/*
   Unix SMB/Netbios implementation.
   Version 3.0
   async_io read handling using POSIX async io.
   Copyright (C) Jeremy Allison 2005.

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

NTSTATUS schedule_aio_read_and_X(connection_struct *conn,
			     struct smb_request *req,
			     files_struct *fsp, off_t startpos,
			     size_t smb_maxcnt);
NTSTATUS schedule_aio_write_and_X(connection_struct *conn,
			      struct smb_request *req,
			      files_struct *fsp, const char *data,
			      off_t startpos,
			      size_t numtowrite);
