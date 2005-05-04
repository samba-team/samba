/* 
   Unix SMB/CIFS implementation.

   Definitions of composite function monitoring messages.

   Copyright (C) Rafal Szczesniak  2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
 * Monitor structure definition. Composite function monitoring allows client
 * application to be notified on function progress. This enables eg. gui
 * client to display progress bars, status messages, etc.
 */

enum monitor_type {
	rpc_open_user,
	rpc_query_user,
	rpc_close_user
};

struct monitor_msg {
	enum monitor_type type;
	union monitor_data {
		struct rpc_open_user {
			uint32_t rid, access_mask;
		} rpc_open_user;

		struct rpc_query_user {
			uint16_t level;
		} rpc_query_user;

		struct rpc_close_user {
			uint32_t rid;
		} rpc_close_user;
	} data;
};
