/*
   Unix SMB/CIFS implementation.

   Utility routines

   Copyright (C) 2020 Ralph Boehme <slow@samba.org>

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

#ifndef SAMBA_SERVER_UTIL_H
#define SAMBA_SERVER_UTIL_H

struct samba_tevent_trace_state;

struct samba_tevent_trace_state *create_samba_tevent_trace_state(
	TALLOC_CTX *mem_ctx);

void samba_tevent_trace_callback(enum tevent_trace_point point,
				 void *private_data);

#endif
