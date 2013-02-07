/*
   Unix SMB/CIFS implementation.
   smbd scavenger daemon

   Copyright (C) Gregor Beck                    2013

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

#ifndef _SCAVENGER_H_
#define _SCAVENGER_H_


bool smbd_scavenger_init(TALLOC_CTX *mem_ctx,
			 struct messaging_context *msg,
			 struct tevent_context *ev);

void scavenger_schedule_disconnected(struct files_struct *fsp);

#endif
