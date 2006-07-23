/* 
   Unix SMB/CIFS Implementation.

   ldap client side header

   Copyright (C) Andrew Tridgell 2005
    
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


#include "libcli/ldap/ldap.h"

enum ldap_request_state { LDAP_REQUEST_SEND=1, LDAP_REQUEST_PENDING=2, LDAP_REQUEST_DONE=3, LDAP_REQUEST_ERROR=4 };

/* this is the handle that the caller gets when an async ldap message
   is sent */
struct ldap_request {
	struct ldap_request *next, *prev;
	struct ldap_connection *conn;

	enum ldap_request_tag type;
	int messageid;
	enum ldap_request_state state;

	int num_replies;
	struct ldap_message **replies;

	NTSTATUS status;
	DATA_BLOB data;
	struct {
		void (*fn)(struct ldap_request *);
		void *private_data;
	} async;

	struct timed_event *time_event;
};


/* main context for a ldap client connection */
struct ldap_connection {
	struct socket_context *sock;
	char *host;
	uint16_t port;
	BOOL ldaps;

	const char *auth_dn;
	const char *simple_pw;

	struct {
		char *url;
		int max_retries;
		int retries;
		time_t previous;
	} reconnect;

	struct {
		enum { LDAP_BIND_SIMPLE, LDAP_BIND_SASL } type;
		void *creds;
	} bind;

	/* next message id to assign */
	unsigned next_messageid;

	/* Outstanding LDAP requests that have not yet been replied to */
	struct ldap_request *pending;

	/* Let's support SASL */
	struct gensec_security *gensec;

	/* the default timeout for messages */
	int timeout;

	/* last error message */
	char *last_error;

	struct {
		struct event_context *event_ctx;
		struct fd_event *fde;
	} event;

	struct packet_context *packet;
};
