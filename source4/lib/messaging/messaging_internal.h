/*
   Unix SMB/CIFS implementation.

   Samba internal messaging functions

   Copyright (C) Andrew Tridgell 2004

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

struct imessaging_context {
	struct imessaging_context *prev, *next;
	struct tevent_context *ev;
	struct server_id server_id;
	const char *sock_dir;
	const char *lock_dir;
	struct dispatch_fn **dispatch;
	uint32_t num_types;
	struct idr_context *dispatch_tree;
	struct irpc_list *irpc;
	struct idr_context *idr;
	struct server_id_db *names;
	struct timeval start_time;
	void *msg_dgm_ref;
};

NTSTATUS imessaging_register_extra_handlers(struct imessaging_context *msg);
