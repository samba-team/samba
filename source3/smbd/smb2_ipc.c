/*
   Unix SMB/CIFS implementation.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1998

   SMB Version handling
   Copyright (C) John H Terpstra 1995-1998

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
/*
   This file handles the named pipe and mailslot calls
   in the SMBtrans protocol
   */

#include "includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"

NTSTATUS nt_status_np_pipe(NTSTATUS status)
{
	if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_DISCONNECTED)) {
		status = NT_STATUS_PIPE_DISCONNECTED;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_CONNECTION_RESET)) {
		status = NT_STATUS_PIPE_BROKEN;
	}

	return status;
}
