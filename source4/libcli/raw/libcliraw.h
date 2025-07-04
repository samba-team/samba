/*
   Unix SMB/CIFS implementation.
   SMB parameters and setup

   Copyright (C) Andrew Tridgell 2002-2004
   Copyright (C) James Myers 2003 <myersjj@samba.org>

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

#ifndef __LIBCLI_RAW_H__
#define __LIBCLI_RAW_H__

#include "../libcli/smb/smb_common.h"
#include "libcli/raw/request.h"
#include "librpc/gen_ndr/nbt.h"
#include "libcli/raw/interfaces.h"
#include "libcli/smb/smb2_negotiate_context.h"

struct smbcli_tree;  /* forward declare */
struct smbcli_request;  /* forward declare */
struct smbcli_session;  /* forward declare */
struct smbcli_transport;  /* forward declare */

struct resolve_context;
struct cli_credentials;
struct gensec_settings;

/* default timeout for all smb requests */
#define SMB_REQUEST_TIMEOUT 60

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
	DATA_BLOB secblob;      /* cryptkey or negTokenInit blob */
	uint32_t sesskey;

	/* capabilities that the server reported */
	uint32_t capabilities;
	
	int server_zone;
	time_t server_time;

	unsigned int readbraw_supported:1;
	unsigned int writebraw_supported:1;
	unsigned int lockread_supported:1;
};
	
/* this is the context for a SMB socket associated with the socket itself */
struct smbcli_socket {
	struct smbXcli_transport *transport;

	/* the hostname we connected to */
	const char *hostname;

	/* the event handle for waiting for socket IO */
	struct {
		struct tevent_context *ctx;
	} event;
};

/*
  this structure allows applications to control the behaviour of the
  client library
*/
struct smbcli_options {
	unsigned int use_oplocks:1;
	unsigned int use_level2_oplocks:1;
	unsigned int use_spnego:1;
	unsigned int unicode:1;
	unsigned int ntstatus_support:1;
	int min_protocol;
	int max_protocol;
	uint32_t max_xmit;
	uint16_t max_mux;
	int request_timeout;
	enum smb_signing_setting signing;
	uint32_t smb2_capabilities;
	struct GUID client_guid;
	uint64_t max_credits;
	unsigned int only_negprot;
	struct smb_transports transports;
	struct smb311_capabilities smb3_capabilities;
};

/* this is the context for the client transport layer */
struct smbcli_transport {
	struct tevent_context *ev; /* TODO: remove this !!! */
	struct smbXcli_conn *conn;

	/* negotiated protocol information */
	struct smbcli_negotiate negotiate;

	/* options to control the behaviour of the client code */
	struct smbcli_options options;

	/* an idle function - if this is defined then it will be
	   called once every period microseconds while we are waiting
	   for a packet */
	struct {
		void (*func)(struct smbcli_transport *, void *);
		void *private_data;
		unsigned int period;
		struct tevent_timer *te;
	} idle;

	/* the error fields from the last message */
	struct {
		enum {ETYPE_NONE, ETYPE_SMB, ETYPE_SOCKET, ETYPE_NBT} etype;
		union {
			NTSTATUS nt_status;
			enum {SOCKET_READ_TIMEOUT,
			      SOCKET_READ_EOF,
			      SOCKET_READ_ERROR,
			      SOCKET_WRITE_ERROR,
			      SOCKET_READ_BAD_SIG} socket_error;
			unsigned int nbt_error;
		} e;
	} error;

	struct {
		/* a oplock break request handler */
		bool (*handler)(struct smbcli_transport *transport, 
				uint16_t tid, uint16_t fnum, uint8_t level, void *private_data);
		/* private data passed to the oplock handler */
		void *private_data;
	} oplock;
	struct tevent_req *break_subreq;
};

/* this is the context for the user */

/* this is the context for the session layer */
struct smbcli_session {	
	/* transport layer info */
	struct smbcli_transport *transport;
	
	/* after a session setup the server provides us with
	   a vuid identifying the security context */
	struct smbXcli_session *smbXcli;
	uint16_t vuid;

	/* default pid for this session */
	uint32_t pid;

	/* the flags2 for each packet - this allows
	   the user to control these for torture testing */
	uint16_t flags2;

	/* the spnego context if we use extended security */
	struct gensec_security *gensec;

	struct smbcli_session_options {
		unsigned int lanman_auth:1;
		unsigned int ntlmv2_auth:1;
		unsigned int plaintext_auth:1;
	} options;

	const char *os;
	const char *lanman;
};

/* 
   smbcli_tree context: internal state for a tree connection. 
 */
struct smbcli_tree {
	/* session layer info */
	struct smbcli_session *session;

	struct smbXcli_tcon *smbXcli;
	uint16_t tid;			/* tree id, aka cnum */
	char *device;
	char *fs_type;
};


/*
  a client request moves between the following 4 states.
*/
enum smbcli_request_state {SMBCLI_REQUEST_INIT, /* we are creating the request */
			SMBCLI_REQUEST_RECV, /* we are waiting for a matching reply */
			SMBCLI_REQUEST_DONE, /* the request is finished */
			SMBCLI_REQUEST_ERROR}; /* a packet or transport level error has occurred */

/* the context for a single SMB request. This is passed to any request-context 
 * functions (similar to context.h, the server version).
 * This will allow requests to be multi-threaded. */
struct smbcli_request {
	/* smbXcli_req */
	struct tevent_req *subreqs[2];

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

	/* the caller wants to do the signing check */
	bool sign_caller_checks;

	/* give the caller a chance to prevent the talloc_free() in the _recv() function */
	bool do_not_free;

	struct smb_request_buffer in;
	struct smb_request_buffer out;

	struct smb_trans2 trans2;
	struct smb_nttrans nttrans;

	/* information on what to do with a reply when it is received
	   asynchronously. If this is not setup when a reply is received then
	   the reply is discarded

	   The private pointer is private to the caller of the client
	   library (the application), not private to the library
	*/
	struct {
		void (*fn)(struct smbcli_request *);
		void *private_data;
	} async;
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

NTSTATUS smb_raw_read_recv(struct smbcli_request *req, union smb_read *parms);
struct smbcli_request *smb_raw_read_send(struct smbcli_tree *tree, union smb_read *parms);
NTSTATUS smb_raw_trans_recv(struct smbcli_request *req,
			     TALLOC_CTX *mem_ctx,
			     struct smb_trans2 *parms);
struct smbcli_request *smb_raw_trans_send(struct smbcli_tree *tree, struct smb_trans2 *parms);
NTSTATUS smbcli_request_destroy(struct smbcli_request *req);
struct smbcli_request *smb_raw_write_send(struct smbcli_tree *tree, union smb_write *parms);
NTSTATUS smb_raw_write_recv(struct smbcli_request *req, union smb_write *parms);
struct smbcli_request *smb_raw_close_send(struct smbcli_tree *tree, union smb_close *parms);
NTSTATUS smb_raw_open_recv(struct smbcli_request *req, TALLOC_CTX *mem_ctx, union smb_open *parms);
struct smbcli_request *smb_raw_open_send(struct smbcli_tree *tree, union smb_open *parms);

bool smbcli_transport_process(struct smbcli_transport *transport);
const char *smbcli_errstr(struct smbcli_tree *tree);
NTSTATUS smb_raw_fsinfo(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_fsinfo *fsinfo);
NTSTATUS smb_raw_setfsinfo(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_setfsinfo *set_fsinfo);
NTSTATUS smb_raw_pathinfo(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_fileinfo *parms);
NTSTATUS smb_raw_shadow_data(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, struct smb_shadow_copy *info);
NTSTATUS smb_raw_fileinfo(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_fileinfo *parms);
struct smbcli_tree *smbcli_tree_init(struct smbcli_session *session, TALLOC_CTX *parent_ctx, bool primary);
NTSTATUS smb_raw_tcon(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_tcon *parms);
void smbcli_oplock_handler(struct smbcli_transport *transport, 
			bool (*handler)(struct smbcli_transport *, uint16_t, uint16_t, uint8_t, void *),
			void *private_data);
void smbcli_transport_idle_handler(struct smbcli_transport *transport, 
				   void (*idle_func)(struct smbcli_transport *, void *),
				   uint64_t period,
				   void *private_data);
NTSTATUS smbcli_request_simple_recv(struct smbcli_request *req);
bool smbcli_oplock_ack(struct smbcli_tree *tree, uint16_t fnum, uint16_t ack_level);
NTSTATUS smb_raw_open(struct smbcli_tree *tree, TALLOC_CTX *mem_ctx, union smb_open *parms);
NTSTATUS smb_raw_close(struct smbcli_tree *tree, union smb_close *parms);
NTSTATUS smb_raw_unlink(struct smbcli_tree *tree, union smb_unlink *parms);
NTSTATUS smb_raw_chkpath(struct smbcli_tree *tree, union smb_chkpath *parms);
NTSTATUS smb_raw_mkdir(struct smbcli_tree *tree, union smb_mkdir *parms);
NTSTATUS smb_raw_rmdir(struct smbcli_tree *tree, struct smb_rmdir *parms);
NTSTATUS smb_raw_rename(struct smbcli_tree *tree, union smb_rename *parms);
NTSTATUS smb_raw_seek(struct smbcli_tree *tree, union smb_seek *parms);
NTSTATUS smb_raw_read(struct smbcli_tree *tree, union smb_read *parms);
NTSTATUS smb_raw_write(struct smbcli_tree *tree, union smb_write *parms);
NTSTATUS smb_raw_lock(struct smbcli_tree *tree, union smb_lock *parms);
NTSTATUS smb_raw_setpathinfo(struct smbcli_tree *tree, union smb_setfileinfo *parms);
NTSTATUS smb_raw_setfileinfo(struct smbcli_tree *tree, union smb_setfileinfo *parms);

struct smbcli_request *smb_raw_changenotify_send(struct smbcli_tree *tree, union smb_notify *parms);
NTSTATUS smb_raw_changenotify_recv(struct smbcli_request *req, TALLOC_CTX *mem_ctx, union smb_notify *parms);

NTSTATUS smb_tree_disconnect(struct smbcli_tree *tree);
NTSTATUS smbcli_nt_error(struct smbcli_tree *tree);
NTSTATUS smb_raw_exit(struct smbcli_session *session);
NTSTATUS smb_raw_pathinfo_recv(struct smbcli_request *req,
			       TALLOC_CTX *mem_ctx,
			       union smb_fileinfo *parms);
struct smbcli_request *smb_raw_pathinfo_send(struct smbcli_tree *tree,
					     union smb_fileinfo *parms);
struct smbcli_request *smb_raw_setpathinfo_send(struct smbcli_tree *tree,
					     union smb_setfileinfo *parms);
struct smbcli_request *smb_raw_echo_send(struct smbcli_transport *transport,
					 struct smb_echo *p);
NTSTATUS smb_raw_search_first(struct smbcli_tree *tree,
			      TALLOC_CTX *mem_ctx,
			      union smb_search_first *io, void *private_data,
			      smbcli_search_callback callback);
NTSTATUS smb_raw_flush(struct smbcli_tree *tree, union smb_flush *parms);

NTSTATUS smb_raw_trans(struct smbcli_tree *tree,
		       TALLOC_CTX *mem_ctx,
		       struct smb_trans2 *parms);

#endif /* __LIBCLI_RAW__H__ */
