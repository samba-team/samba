/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   Copyright (C) Jeremy Allison 1998
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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

#ifndef _SMBCLI_CONTEXT_H
#define _SMBCLI_CONTEXT_H

struct smbcli_tree;  /* forward declare */
struct smbcli_request;  /* forward declare */
struct smbcli_session;  /* forward declare */
struct smbcli_transport;  /* forward declare */

/* context that will be and has been negotiated between the client and server */
struct smbcli_negotiate {
	/* 
	 * negotiated maximum transmit size - this is given to us by the server
	 */
	uint32_t max_xmit;

	/* maximum number of requests that can be multiplexed */
	uint16_t max_mux;

	/* the negotiatiated protocol */
	enum protocol_types protocol;

	uint8_t sec_mode;		/* security mode returned by negprot */
	uint8_t key_len;
	DATA_BLOB server_guid;      /* server_guid */
	DATA_BLOB secblob;      /* cryptkey or negTokenInit blob */
	uint32_t sesskey;
	
	struct smb_signing_context sign_info;

	/* capabilities that the server reported */
	uint32_t capabilities;
	
	int server_zone;
	time_t server_time;
	uint_t readbraw_supported:1;
	uint_t writebraw_supported:1;

	const char *server_domain;
};
	
/* this is the context for a SMB socket associated with the socket itself */
struct smbcli_socket {
	TALLOC_CTX *mem_ctx;  	/* life of socket pool */

	/* when the reference count reaches zero then the socket is destroyed */
	int reference_count;

	struct in_addr dest_ip;
	/* dest hostname (which may or may not be a DNS name) */
	char *hostname;

	/* the port used */
	int port;
	
	/* the open file descriptor */
	int fd;

	/* a count of the number of packets we have received. We
	 * actually only care about zero/non-zero at this stage */
	uint_t pkt_count;

	/* the network address of the client */
	char *client_addr;
	
	/* timeout for socket operations in milliseconds. */
	int timeout;
};

/*
  this structure allows applications to control the behaviour of the
  client library
*/
struct smbcli_options {
	uint_t use_oplocks:1;
	uint_t use_level2_oplocks:1;
	uint_t use_spnego:1;
};

/* this is the context for the client transport layer */
struct smbcli_transport {
	TALLOC_CTX *mem_ctx;

	/* when the reference count reaches zero then the transport is destroyed */
	int reference_count;

	/* socket level info */
	struct smbcli_socket *socket;

	/* the next mid to be allocated - needed for signing and
	   request matching */
	uint16_t next_mid;
	
	/* negotiated protocol information */
	struct smbcli_negotiate negotiate;

	/* options to control the behaviour of the client code */
	struct smbcli_options options;

	/* is a readbraw pending? we need to handle that case
	   specially on receiving packets */
	uint_t readbraw_pending:1;
	
	/* an idle function - if this is defined then it will be
	   called once every period seconds while we are waiting
	   for a packet */
	struct {
		void (*func)(struct smbcli_transport *, void *);
		void *private;
		uint_t period;
	} idle;

	/* the error fields from the last message */
	struct {
		enum {ETYPE_NONE, ETYPE_DOS, ETYPE_NT, ETYPE_SOCKET, ETYPE_NBT} etype;
		union {
			struct {
				uint8_t eclass;
				uint16_t ecode;
			} dos;
			NTSTATUS nt_status;
			enum {SOCKET_READ_TIMEOUT,
			      SOCKET_READ_EOF,
			      SOCKET_READ_ERROR,
			      SOCKET_WRITE_ERROR,
			      SOCKET_READ_BAD_SIG} socket_error;
			uint_t nbt_error;
		} e;
	} error;

	struct {
		/* a oplock break request handler */
		BOOL (*handler)(struct smbcli_transport *transport, 
				uint16_t tid, uint16_t fnum, uint8_t level, void *private);
		/* private data passed to the oplock handler */
		void *private;
	} oplock;

	/* a list of async requests that are pending for send on this connection */
	struct smbcli_request *pending_send;

	/* a list of async requests that are pending for receive on this connection */
	struct smbcli_request *pending_recv;

	/* remember the called name - some sub-protocols require us to
	   know the server name */
	struct nmb_name called;

	/* a buffer for partially received SMB packets. */
	struct {
		uint8_t header[NBT_HDR_SIZE];
		size_t req_size;
		size_t received;
		uint8_t *buffer;
	} recv_buffer;

	/* the event handle for waiting for socket IO */
	struct {
		struct event_context *ctx;
		struct fd_event *fde;
		struct timed_event *te;
	} event;
};

/* this is the context for the user */

/* this is the context for the session layer */
struct smbcli_session {	
	TALLOC_CTX *mem_ctx;  	/* life of session */

	/* when the reference count reaches zero then the session is destroyed */
	int reference_count;	
	
	/* transport layer info */
	struct smbcli_transport *transport;
	
	/* after a session setup the server provides us with
	   a vuid identifying the security context */
	uint16_t vuid;

	/* default pid for this session */
	uint32_t pid;

	DATA_BLOB user_session_key;

	/* the spnego context if we use extented security */
	struct gensec_security *gensec;
};

/* 
   smbcli_tree context: internal state for a tree connection. 
 */
struct smbcli_tree {
	/* life of tree tree */
	TALLOC_CTX *mem_ctx;

	/* when the reference count reaches zero then the tree is destroyed */
	int reference_count;	

	/* session layer info */
	struct smbcli_session *session;

	uint16_t tid;			/* tree id, aka cnum */
	char *device;
	char *fs_type;
};


/*
  a client request moves between the following 4 states.
*/
enum smbcli_request_state {SMBCLI_REQUEST_INIT, /* we are creating the request */
			SMBCLI_REQUEST_SEND, /* the request is in the outgoing socket Q */
			SMBCLI_REQUEST_RECV, /* we are waiting for a matching reply */
			SMBCLI_REQUEST_DONE, /* the request is finished */
			SMBCLI_REQUEST_ERROR}; /* a packet or transport level error has occurred */

/* the context for a single SMB request. This is passed to any request-context 
 * functions (similar to context.h, the server version).
 * This will allow requests to be multi-threaded. */
struct smbcli_request {
	/* allow a request to be part of a list of requests */
	struct smbcli_request *next, *prev;

	/* each request is in one of 4 possible states */
	enum smbcli_request_state state;
	
	/* a request always has a transport context, nearly always has
	   a session context and usually has a tree context */
	struct smbcli_transport *transport;
	struct smbcli_session *session;
	struct smbcli_tree *tree;

	/* the flags2 from the SMB request, in raw form (host byte
	   order). Used to parse strings */
	uint16_t flags2;

	/* the NT status for this request. Set by packet receive code
	   or code detecting error. */
	NTSTATUS status;
	
	/* the sequence number of this packet - used for signing */
	uint_t seq_num;

	/* set if this is a one-way request, meaning we are not
	   expecting a reply from the server. */
	uint_t one_way_request:1;

	/* set this when the request should only increment the signing
	   counter by one */
	uint_t sign_single_increment:1;

	/* the mid of this packet - used to match replies */
	uint16_t mid;

	struct request_buffer in;
	struct request_buffer out;

	/* information on what to do with a reply when it is received
	   asyncronously. If this is not setup when a reply is received then
	   the reply is discarded

	   The private pointer is private to the caller of the client
	   library (the application), not private to the library
	*/
	struct {
		void (*fn)(struct smbcli_request *);
		void *private;
	} async;
};

/* 
   smbcli_state: internal state used in libcli library for single-threaded callers, 
   i.e. a single session on a single socket. 
 */
struct smbcli_state {
	TALLOC_CTX *mem_ctx;  	/* life of client pool */
	struct smbcli_transport *transport;
	struct smbcli_session *session;
	struct smbcli_tree *tree;
	struct substitute_context substitute;
};

/* useful way of catching wct errors with file and line number */
#define SMBCLI_CHECK_MIN_WCT(req, wcount) if ((req)->in.wct < (wcount)) { \
      DEBUG(1,("Unexpected WCT %d at %s(%d) - expected min %d\n", (req)->in.wct, __FILE__, __LINE__, wcount)); \
      req->status = NT_STATUS_INVALID_PARAMETER; \
      goto failed; \
}

#define SMBCLI_CHECK_WCT(req, wcount) if ((req)->in.wct != (wcount)) { \
      DEBUG(1,("Unexpected WCT %d at %s(%d) - expected %d\n", (req)->in.wct, __FILE__, __LINE__, wcount)); \
      req->status = NT_STATUS_INVALID_PARAMETER; \
      goto failed; \
}

#endif /* _SMBCLI_CONTEXT_H */
