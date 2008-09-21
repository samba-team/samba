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

struct web_server_data {
	struct tls_params *tls_params;
	void *private;	
};

struct http_header {
	char *name;
	char *value;
	struct http_header *prev, *next;
};

/*
  context of one open web connection
*/
struct websrv_context {
	struct task_server *task;
	struct stream_connection *conn;
	void (*http_process_input)(struct websrv_context *web);
	struct {
		bool tls_detect;
		bool tls_first_char;
		uint8_t first_byte;
		DATA_BLOB partial;
		bool end_of_headers;
		char *url;
		unsigned content_length;
		bool post_request;
		struct http_header *headers;
		const char *content_type;
	} input;
	struct {
		bool output_pending;
		DATA_BLOB content;
		int fd;
		unsigned nsent;
		int response_code;
		struct http_header *headers;
	} output;
	struct session_data *session;
};


#include "web_server/proto.h"

