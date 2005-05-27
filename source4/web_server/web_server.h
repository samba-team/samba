/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2005
   
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

#include "request.h"
#include "smbd/process_model.h"

/*
  context of one open web connection
*/
struct websrv_context {
	struct task_server *task;
	struct stream_connection *conn;
	struct {
		DATA_BLOB partial;
		BOOL end_of_headers;
		char *url;
		unsigned content_length;
		BOOL post_request;
		const char *content_type;
		const char *query_string;
		const char *user_agent;
		const char *referer;
		const char *host;
		const char *accept_encoding;
		const char *accept_language;
		const char *accept_charset;
		const char *cookie;
		const char *session_key;
	} input;
	struct {
		DATA_BLOB content;
		int fd;
		unsigned nsent;
		int response_code;
		const char **headers;
	} output;
	struct session_data *session;
};


