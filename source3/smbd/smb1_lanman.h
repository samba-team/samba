/*
   Unix SMB/CIFS implementation.
   Inter-process communication and named pipe handling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 2007.

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

void api_reply(connection_struct *conn, uint64_t vuid,
	       struct smb_request *req,
	       char *data, char *params,
	       int tdscnt, int tpscnt,
	       int mdrcnt, int mprcnt);
