/*
   Unix SMB/CIFS implementation.

   a async CLDAP library

   Copyright (C) Andrew Tridgell 2005

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

#include "../lib/util/asn1.h"
#include "../libcli/netlogon.h"

struct ldap_message;

enum cldap_request_state {CLDAP_REQUEST_SEND, 
			  CLDAP_REQUEST_WAIT, 
			  CLDAP_REQUEST_DONE,
			  CLDAP_REQUEST_ERROR};

/*
  a cldap request packet
*/
struct cldap_request {
	struct cldap_request *next, *prev;

	struct cldap_socket *cldap;

	enum cldap_request_state state;
	NTSTATUS status;

	/* where to send the request */
	struct socket_address *dest;

	/* timeout between retries (seconds) */
	int timeout;
	int num_retries;

	bool is_reply;

	/* the ldap message_id */
	int message_id;

	struct tevent_timer *te;

	/* the encoded request */
	DATA_BLOB encoded;

	/* the reply data */
	struct asn1_data *asn1;

	/* information on what to do on completion */
	struct {
		void (*fn)(struct cldap_request *);
		void *private_data;
	} async;
};

/*
  context structure for operations on cldap packets
*/
struct cldap_socket {
	struct socket_context *sock;
	struct tevent_context *event_ctx;
	struct smb_iconv_convenience *iconv_convenience;

	/* the fd event */
	struct tevent_fd *fde;

	/* a queue of outgoing requests */
	struct cldap_request *send_queue;

	/* mapping from message_id to pending request */
	struct idr_context *idr;

	/* what to do with incoming request packets */
	struct {
		void (*handler)(struct cldap_socket *, struct ldap_message *, 
				struct socket_address *);
		void *private_data;
	} incoming;
};


/*
 a general cldap search request  
*/
struct cldap_search {
	struct {
		const char *dest_address;
		uint16_t dest_port;
		const char *filter;
		const char **attributes;
		int timeout;
		int retries;
	} in;
	struct {
		struct ldap_SearchResEntry *response;
		struct ldap_Result         *result;
	} out;
};

struct cldap_socket *cldap_socket_init(TALLOC_CTX *mem_ctx, 
				       struct tevent_context *event_ctx, 
				       struct smb_iconv_convenience *iconv_convenience);
NTSTATUS cldap_set_incoming_handler(struct cldap_socket *cldap,
				    void (*handler)(struct cldap_socket *, struct ldap_message *, 
						    struct socket_address *),
				    void *private_data);
struct cldap_request *cldap_search_send(struct cldap_socket *cldap, 
					struct cldap_search *io);
NTSTATUS cldap_search_recv(struct cldap_request *req, TALLOC_CTX *mem_ctx, 
			   struct cldap_search *io);
NTSTATUS cldap_search(struct cldap_socket *cldap, TALLOC_CTX *mem_ctx, 
		      struct cldap_search *io);


/*
  a general cldap reply
*/
struct cldap_reply {
	uint32_t messageid;
	struct socket_address *dest;
	struct ldap_SearchResEntry *response;
	struct ldap_Result         *result;
};

NTSTATUS cldap_reply_send(struct cldap_socket *cldap, struct cldap_reply *io);

NTSTATUS cldap_empty_reply(struct cldap_socket *cldap, 
			   uint32_t message_id,
			   struct socket_address *src);
NTSTATUS cldap_error_reply(struct cldap_socket *cldap, 
			   uint32_t message_id,
			   struct socket_address *src,
			   int resultcode,
			   const char *errormessage);

/*
  a netlogon cldap request  
*/
struct cldap_netlogon {
	struct {
		const char *dest_address;
		uint16_t dest_port;
		const char *realm;
		const char *host;
		const char *user;
		const char *domain_guid;
		const char *domain_sid;
		int acct_control;
		uint32_t version;
		bool map_response;
	} in;
	struct {
		struct netlogon_samlogon_response netlogon;
	} out;
};

struct cldap_request *cldap_netlogon_send(struct cldap_socket *cldap, 
					  struct cldap_netlogon *io);
NTSTATUS cldap_netlogon_recv(struct cldap_request *req, 
			     TALLOC_CTX *mem_ctx, 
			     struct cldap_netlogon *io);
NTSTATUS cldap_netlogon(struct cldap_socket *cldap, 
			TALLOC_CTX *mem_ctx, struct cldap_netlogon *io);
NTSTATUS cldap_netlogon_reply(struct cldap_socket *cldap, 
			      uint32_t message_id,
			      struct socket_address *src,
			      uint32_t version,
			      struct netlogon_samlogon_response *netlogon);
