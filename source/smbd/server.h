/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan (metze) Metzmacher	2004
   
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

#ifndef _SERVER_H
#define _SERVER_H

struct server_service;
struct event_context;

struct server_context {
	TALLOC_CTX *mem_ctx;
	struct server_service *service_list;
	struct event_context *events;
};

/* size of listen() backlog in smbd */
#define SERVER_LISTEN_BACKLOG 10

/* the range of ports to try for dcerpc over tcp endpoints */
#define SERVER_TCP_LOW_PORT  1024
#define SERVER_TCP_HIGH_PORT 1300

/* the default idle time of a service */
#define SERVER_DEFAULT_IDLE_TIME 300

#endif /* _SERVER_H */
