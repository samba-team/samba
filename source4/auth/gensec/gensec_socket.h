/*
   Unix SMB/CIFS implementation.

   GENSEC socket interface

   Copyright (C) Andrew Bartlett 2006

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

NTSTATUS gensec_socket_init(struct gensec_security *gensec_security,
			    TALLOC_CTX *mem_ctx,
			    struct socket_context *current_socket,
			    struct tevent_context *ev,
			    void (*recv_handler)(void *, uint16_t),
			    void *recv_private,
			    struct socket_context **new_socket);
