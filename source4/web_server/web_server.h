/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2005
   
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

#include "smbd/process_model.h"

/*
  context of one open web connection
*/
struct websrv_context {
	struct task_server *task;
	struct stream_connection *conn;
	struct {
		bool tls_detect;
		bool tls_first_char;
		uint8_t first_byte;
		DATA_BLOB partial;
		bool end_of_headers;
		char *url;
		unsigned content_length;
		bool post_request;
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
		bool output_pending;
		DATA_BLOB content;
		int fd;
		unsigned nsent;
		int response_code;
		const char **headers;
	} output;
	struct session_data *session;
};


/*
  context for long term storage in the web server, to support session[]
  and application[] data. Stored in task->private.
*/
struct esp_data {
	struct session_data {
		struct session_data *next, *prev;
		struct esp_data *edata;
		const char *id;
		struct MprVar *data;
		struct timed_event *te;
		int lifetime;
	} *sessions;
	struct MprVar *application_data;
	struct tls_params *tls_params;
};

#include "web_server/proto.h"

