/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2003
   Copyright (C) James J Myers 		      2003 <myersjj@samba.org>
   Copyright (C) Stefan Metzmacher            2004-2005
   
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
  this header declares the core context structures associated with smb
  sockets, tree connects, requests etc

  the idea is that we will eventually get rid of all our global
  variables and instead store our state from structures hanging off
  these basic elements
*/

struct smbsrv_tcons_context {
	/* an id tree used to allocate tids */
	struct idr_context *idtree_tid;

	/* this is the limit of vuid values for this connection */
	uint32_t idtree_limit;

	/* list of open tree connects */
	struct smbsrv_tcon *list;
};

struct smbsrv_sessions_context {
	/* an id tree used to allocate vuids */
	/* this holds info on session vuids that are already
	 * validated for this VC */
	struct idr_context *idtree_vuid;

	/* this is the limit of vuid values for this connection */
	uint64_t idtree_limit;

	/* also kept as a link list so it can be enumerated by
	   the management code */
	struct smbsrv_session *list;
} sessions;

/* the current user context for a request */
struct smbsrv_session {
	struct smbsrv_session *prev, *next;

	struct smbsrv_connection *smb_conn;

	struct smbsrv_tcons_context smb2_tcons;

	/* 
	 * an index passed over the wire:
	 * - 16 bit for smb
	 * - 64 bit for smb2
	 */
	uint64_t vuid;

	struct gensec_security *gensec_ctx;

	struct auth_session_info *session_info;

	/* some statictics for the management tools */
	struct {
		/* the time when the session setup started */
		struct timeval connect_time;
		/* the time when the session setup was finished */
		struct timeval auth_time;
	} statistics;
};

/* we need a forward declaration of the ntvfs_ops strucutre to prevent
   include recursion */
struct ntvfs_context;

struct smbsrv_tcon {
	struct smbsrv_tcon *next, *prev;

	/* the server context that this was created on */
	struct smbsrv_connection *smb_conn;

	/* 
	 * an index passed over the wire:
	 * - 16 bit for smb
	 * - 32 bit for smb2
	 */
	uint32_t tid; /* an index passed over the wire (the TID) */

	int service;
	BOOL read_only;
	BOOL admin_user;

	/* the NTVFS context - see source/ntvfs/ for details */
	struct ntvfs_context *ntvfs_ctx;

	/* the reported filesystem type */
	char *fs_type;

	/* the reported device type */
	char *dev_type;

	/* some stuff to support share level security */
	struct {
		/* in share level security we need to fake up a session */
		struct smbsrv_session *session;
	} sec_share;

	/* some stuff to support share level security */
	struct {
		/* in SMB2 a tcon always belongs to one session */
		struct smbsrv_session *session;
	} smb2;

	/* some statictics for the management tools */
	struct {
		struct timeval connect_time;
	} statistics;
};

/* a set of flags to control handling of request structures */
#define REQ_CONTROL_LARGE     (1<<1) /* allow replies larger than max_xmit */

/* the context for a single SMB request. This is passed to any request-context 
   functions */
struct smbsrv_request {
	/* the smbsrv_connection needs a list of requests queued for send */
	struct smbsrv_request *next, *prev;

	/* the server_context contains all context specific to this SMB socket */
	struct smbsrv_connection *smb_conn;

	/* conn is only set for operations that have a valid TID */
	struct smbsrv_tcon *tcon;

	/* the session context is derived from the vuid */
	struct smbsrv_session *session;

	/* a set of flags to control usage of the request. See REQ_CONTROL_* */
	unsigned control_flags;

	/* the smb pid is needed for locking contexts */
	uint16_t smbpid;

	/* the flags from the SMB request, in raw form (host byte order) */
	uint16_t flags, flags2;

	/* the system time when the request arrived */
	struct timeval request_time;

	/* this can contain a fnum from an earlier part of a chained
	 * message (such as an SMBOpenX), or -1 */
	int chained_fnum;

	/* how far through the chain of SMB commands have we gone? */
	unsigned chain_count;

	/* the sequence number for signing */
	uint64_t seq_num;

	/* ntvfs per request async states */
	struct ntvfs_async_state *async_states;

	struct request_buffer in;
	struct request_buffer out;
};

/* this contains variables that should be used in % substitutions for
 * smb.conf parameters */
struct substitute_context {
	char *remote_arch;

	/* our local netbios name, as give to us by the client */
	char *local_machine;

	/* the remote netbios name, as give to us by the client */
	char *remote_machine;

	/* the select remote protocol */
	char *remote_proto;	

	/* the name of the client as should be displayed in
	 * smbstatus. Can be an IP or a netbios name */
	char *client_name; 

	/* the username for %U */
	char *user_name;
};

/* Remote architectures we know about. */
enum remote_arch_types {RA_UNKNOWN, RA_WFWG, RA_OS2, RA_WIN95, RA_WINNT, RA_WIN2K, RA_WINXP, RA_SAMBA};

/* smb server context structure. This should contain all the state
 * information associated with a SMB server connection 
 */
struct smbsrv_connection {
	/* context that has been negotiated between the client and server */
	struct {
		/* have we already done the NBT session establishment? */
		BOOL done_nbt_session;
	
		/* only one negprot per connection is allowed */
		BOOL done_negprot;
	
		/* multiple session setups are allowed, but some parameters are
		   ignored in any but the first */
		BOOL done_sesssetup;
		
		/* 
		 * Size of data we can send to client. Set
		 *  by the client for all protocols above CORE.
		 *  Set by us for CORE protocol.
		 */
		unsigned max_send; /* init to BUFFER_SIZE */
	
		/*
		 * Size of the data we can receive. Set by us.
		 * Can be modified by the max xmit parameter.
		 */
		unsigned max_recv; /* init to BUFFER_SIZE */
	
		/* a guess at the remote architecture. Try not to rely on this - in almost
		   all cases using these values is the wrong thing to do */
		enum remote_arch_types ra_type;
	
		/* the negotiatiated protocol */
		enum protocol_types protocol;
	
		/* authentication context for multi-part negprot */
		struct auth_context *auth_context;
	
		/* reference to the kerberos keytab, or machine trust account */
		struct cli_credentials *server_credentials;
	
		/* did we tell the client we support encrypted passwords? */
		BOOL encrypted_passwords;
	
		/* did we send an extended security negprot reply? */
		BOOL spnego_negotiated;
	
		/* client capabilities */
		uint32_t client_caps;
	
		/* the timezone we sent to the client */
		int zone_offset;

		/* NBT names only set when done_nbt_session is true */
		struct nbt_name *called_name;
		struct nbt_name *calling_name;
	} negotiate;

	/* the context associated with open tree connects on a smb socket */
	struct smbsrv_tcons_context smb_tcons;

	/* context associated with currently valid session setups */
	struct smbsrv_sessions_context sessions;

	/* the server_context holds a linked list of pending requests,
	 * this is used for blocking locks and requests blocked due to oplock
	 * break requests */
	struct _smbsrv_pending_request {
		struct _smbsrv_pending_request *next, *prev;
	
		/* the request itself - needs to be freed */
		struct smbsrv_request *request;
	} *requests;

	struct smb_signing_context signing;
	
	struct stream_connection *connection;

	/* this holds a partially received request */
	struct packet_context *packet;

	/* a list of partially received transaction requests */
	struct smbsrv_trans_partial {
		struct smbsrv_trans_partial *next, *prev;
		struct smbsrv_request *req;
		struct smb_trans2 *trans;
		uint8_t command;
	} *trans_partial;

	/* configuration parameters */
	struct {
		enum security_types security;
		BOOL nt_status_support;
	} config;
};
