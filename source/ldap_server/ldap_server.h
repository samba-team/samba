/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   
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

struct ldap_message_queue {
	struct ldap_message_queue *prev, *next;
	struct ldap_message *msg;
};

struct rw_buffer {
	uint8_t *data;
	size_t ofs, length;
};

struct ldapsrv_connection {
	struct server_connection *connection;

	struct gensec_security *gensec_ctx;

	struct auth_session_info *session_info;

	struct rw_buffer in_buffer;
	struct rw_buffer out_buffer;
	struct ldap_message_queue *in_queue;
	struct ldap_message_queue *out_queue;
};
