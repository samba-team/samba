/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008

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

#ifndef __LIBSMB_READ_SMB_H
#define __LIBSMB_READ_SMB_H

struct tevent_context;
struct tevent_req;

struct tevent_req *read_smb_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 int fd);

ssize_t read_smb_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		      uint8_t **pbuf, int *perrno);

#endif
