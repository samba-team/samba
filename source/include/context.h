/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Andrew Tridgell              2003
   Copyright (C) James J Myers 		      2003 <myersjj@samba.org>
   
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

/*
  this header declares the core context structures associated with smb
  sockets, tree connects, requests etc

  the idea is that we will eventually get rid of all our global
  variables and instead store our stang from structures hanging off
  these basic elements
*/

/* the current user context for a request */
struct user_context {
	/* the vuid is used to specify the security context for this
	   request. Note that this may not be the same vuid as we
	   received on the wire (for example, for share mode or guest
	   access) */
	uint16 vuid;

	/* the domain name, user name etc - mostly used in % substitutions */
	struct userdom_struct *user;

	struct user_struct *vuser;
};


/* each backend has to be one one of the following 3 basic types. In
 * earlier versions of Samba backends needed to handle all types, now
 * we implement them separately. */
enum ntvfs_type {NTVFS_DISK, NTVFS_PRINT, NTVFS_IPC};

/* we need a forward declaration of the ntvfs_ops strucutre to prevent
   include recursion */
struct ntvfs_ops;

struct tcon_context {
	struct tcon_context *next, *prev;

	/* the server context that this was created on */
	struct server_context *smb;

	/* a talloc context for all data in this structure */
	TALLOC_CTX *mem_ctx;

	/* a private structure used by the active NTVFS backend */
	void *ntvfs_private;

	uint16 cnum; /* an index passed over the wire (the TID) */
	int service;
	enum ntvfs_type type;
	BOOL read_only;
	BOOL admin_user;

	/* the NTVFS operations - see source/ntvfs/ and include/ntvfs.h for details */
	const struct ntvfs_ops *ntvfs_ops;

	/* the reported filesystem type */
	char *fs_type;

	/* the reported device type */
	char *dev_type;
};

/* the context for a single SMB request. This is passed to any request-context 
   functions */
struct request_context {
	/* the server_context contains all context specific to this SMB socket */
	struct server_context *smb;

	/* conn is only set for operations that have a valid TID */
	struct tcon_context *conn;

	/* the user context is derived from the vuid plus smb.conf options */
	struct user_context *user_ctx;

	/* a talloc context for the lifetime of this request */
	TALLOC_CTX *mem_ctx;

	/* a set of flags to control usage of the request. See REQ_CONTROL_* */
	unsigned control_flags;

	/* the smb pid is needed for locking contexts */
	uint16 smbpid;

	/* the flags from the SMB request, in raw form (host byte order) */
	uint16 flags, flags2;

	/* the system time when the request arrived */
	struct timeval request_time;

	/* this can contain a fnum from an earlier part of a chained
	 * message (such as an SMBOpenX), or -1 */
	int chained_fnum;

	/* how far through the chain of SMB commands have we gone? */
	unsigned chain_count;

	/* the sequence number for signing */
	uint64_t seq_num;

	/* the async structure allows backend functions to delay
	   replying to requests. To use this, the front end must set
	   async.send_fn to a function to be called by the backend
	   when the reply is finally ready to be sent. The backend
	   must set async.status to the status it wants in the
	   reply. The backend must set the REQ_CONTROL_ASYNC
	   control_flag on the request to indicate that it wishes to
	   delay the reply

	   If async.send_fn is NULL then the backend cannot ask for a
	   delayed reply for this request

	   note that the async.private pointer is private to the front
	   end not the backend. The backend must not change it.
	*/
	struct {
		void (*send_fn)(struct request_context *);
		void *private;
		NTSTATUS status;
	} async;

	struct {
		/* the raw SMB buffer, including the 4 byte length header */
		char *buffer;
		
		/* the size of the raw buffer, including 4 byte header */
		unsigned size;

		/* how much has been allocated - on reply the buffer is over-allocated to 
		   prevent too many realloc() calls 
		*/
		unsigned allocated;

		/* the start of the SMB header - this is always buffer+4 */
		char *hdr;

		/* the command words and command word count. vwv points
		   into the raw buffer */
		char *vwv;
		unsigned wct;

		/* the data buffer and size. data points into the raw buffer */
		char *data;
		unsigned data_size;

		/* ptr is used as a moving pointer into the data area
		 * of the packet. The reason its here and not a local
		 * variable in each function is that when a realloc of
		 * a reply packet is done we need to move this
		 * pointer */
		char *ptr;
	} in, out;
};



/* the context associated with open files on an smb socket */
struct files_context {
	struct files_struct *files; /* open files */
	struct bitmap *file_bmap; /* bitmap used to allocate file handles */

	/* a fsp to use when chaining */
	struct files_struct *chain_fsp;

	/* a fsp to use to save when breaking an oplock. */
	struct files_struct *oplock_save_chain_fsp;

	/* how many files are open */
	int files_used;

	/* limit for maximum open files */
	int real_max_open_files;
};


/* the context associated with open tree connects on a smb socket */
struct tree_context {
	struct tcon_context *connections;

	/* number of open connections */
	struct bitmap *bmap;
	int num_open;
};

/* context associated with currently valid session setups */
struct users_context {
	/* users from session setup */
	char *session_users; /* was a pstring */

	/* this holds info on user ids that are already validated for this VC */
	struct user_struct *validated_users;
	int next_vuid; /* initialise to VUID_OFFSET */
	int num_validated_vuids;
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

/* context that has been negotiated between the client and server */
struct negotiate_context {
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

	/* state of NTLMSSP auth */
	struct auth_ntlmssp_state *ntlmssp_state;

	/* did we tell the client we support encrypted passwords? */
	BOOL encrypted_passwords;

	/* did we send an extended security negprot reply? */
	BOOL spnego_negotiated;

	/* client capabilities */
	uint32 client_caps;

	/* the timezone we sent to the client */
	int zone_offset;
};
	
/* this is the context for a SMB socket associated with the socket itself */
struct socket_context {
	/* the open file descriptor */
	int fd; 

	/* the last read error on the socket, if any (replaces smb_read_error global) */
	int read_error;

	/* a count of the number of packets we have received. We
	 * actually only care about zero/non-zero at this stage */
	unsigned pkt_count;

	/* the network address of the client */
	char *client_addr;
};


/* this holds long term state specific to the printing subsystem */
struct printing_context {
	struct notify_queue *notify_queue_head;
};


/* the server_context holds a linked list of pending requests,
 * this is used for blocking locks and requests blocked due to oplock
 * break requests */
struct pending_request {
	struct pending_request *next, *prev;

	/* the request itself - needs to be freed */
	struct request_context *request;
};

/* the timers context contains info on when we last did various
 * functions */
struct timers_context {
	/* when did we last do timeout processing? */
	time_t last_timeout_processing;

	/* when did we last sent a keepalive */
	time_t last_keepalive_sent;
	
	/* when we last checked the smb.conf for auto-reload */
	time_t last_smb_conf_reload;
};


struct signing_context {
	DATA_BLOB mac_key;
	uint64_t next_seq_num;
	enum smb_signing_state signing_state;
};

#include "smbd/process_model.h"

/* smb context structure. This should contain all the state
 * information associated with a SMB server */
struct server_context {
	/* a talloc context for all data in this structure */
	TALLOC_CTX *mem_ctx;

	struct negotiate_context negotiate;

	struct substitute_context substitute;

	struct socket_context socket;

	struct files_context file;

	struct tree_context tree;

	struct users_context users;

	struct printing_context print;

	struct timers_context timers;

	struct dcesrv_context dcesrv;

	struct signing_context signing;

	/* the pid of the process handling this session */
	pid_t pid;
	
	/* pointer to list of events that we are waiting on */
	struct event_context *events;

	/* process model specific operations */
	const struct model_ops *model_ops;
};


