/* 
   Unix SMB/CIFS implementation.

   SMB2 client library header

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

#ifndef __LIBCLI_SMB2_SMB2_H__
#define __LIBCLI_SMB2_SMB2_H__

#include "libcli/raw/request.h"
#include "libcli/raw/libcliraw.h"

struct smb2_handle;

/*
  information returned from the negotiate process
*/
struct smb2_negotiate {
	DATA_BLOB secblob;
	NTTIME system_time;
	NTTIME server_start_time;
	uint16_t security_mode;
};

/* this is the context for the smb2 transport layer */
struct smb2_transport {
	/* socket level info */
	struct smbcli_socket *socket;

	struct smb2_negotiate negotiate;

	/* next seqnum to allocate */
	uint64_t seqnum;

	/* a list of requests that are pending for receive on this
	   connection */
	struct smb2_request *pending_recv;

	/* context of the stream -> packet parser */
	struct packet_context *packet;

	/* an idle function - if this is defined then it will be
	   called once every period microseconds while we are waiting
	   for a packet */
	struct {
		void (*func)(struct smb2_transport *, void *);
		void *private_data;
		uint_t period;
	} idle;

	struct {
		/* a oplock break request handler */
		bool (*handler)(struct smb2_transport *transport,
				const struct smb2_handle *handle,
				uint8_t level, void *private_data);
		/* private data passed to the oplock handler */
		void *private_data;
	} oplock;

	struct smbcli_options options;

	bool signing_required;
};


/*
  SMB2 tree context
*/
struct smb2_tree {
	struct smb2_session *session;
	uint32_t tid;
};

/*
  SMB2 session context
*/
struct smb2_session {
	struct smb2_transport *transport;
	struct gensec_security *gensec;
	uint64_t uid;
	DATA_BLOB session_key;
	bool signing_active;
};


struct smb2_request_buffer {
	/* the raw SMB2 buffer, including the 4 byte length header */
	uint8_t *buffer;
	
	/* the size of the raw buffer, including 4 byte header */
	size_t size;
	
	/* how much has been allocated - on reply the buffer is over-allocated to 
	   prevent too many realloc() calls 
	*/
	size_t allocated;
	
	/* the start of the SMB2 header - this is always buffer+4 */
	uint8_t *hdr;
	
	/* the packet body */
	uint8_t *body;
	size_t body_fixed;
	size_t body_size;

	/* this point to the next dynamic byte that can be used
	 * this will be moved when some dynamic data is pushed
	 */
	uint8_t *dynamic;

	/* this is used to range check and align strings and buffers */
	struct request_bufinfo bufinfo;
};


/*
  a client request moves between the following 4 states.
*/
enum smb2_request_state {SMB2_REQUEST_INIT, /* we are creating the request */
			SMB2_REQUEST_RECV, /* we are waiting for a matching reply */
			SMB2_REQUEST_DONE, /* the request is finished */
			SMB2_REQUEST_ERROR}; /* a packet or transport level error has occurred */

/* the context for a single SMB2 request */
struct smb2_request {
	/* allow a request to be part of a list of requests */
	struct smb2_request *next, *prev;

	/* each request is in one of 3 possible states */
	enum smb2_request_state state;
	
	struct smb2_transport *transport;
	struct smb2_session   *session;
	struct smb2_tree      *tree;

	uint64_t seqnum;

	struct {
		bool do_cancel;
		bool can_cancel;
		uint32_t pending_id;
	} cancel;

	/* the NT status for this request. Set by packet receive code
	   or code detecting error. */
	NTSTATUS status;
	
	struct smb2_request_buffer in;
	struct smb2_request_buffer out;

	/* information on what to do with a reply when it is received
	   asyncronously. If this is not setup when a reply is received then
	   the reply is discarded

	   The private pointer is private to the caller of the client
	   library (the application), not private to the library
	*/
	struct {
		void (*fn)(struct smb2_request *);
		void *private_data;
	} async;
};


#define SMB2_MIN_SIZE 0x42
#define SMB2_MIN_SIZE_NO_BODY 0x40

/* offsets into header elements for a sync SMB2 request */
#define SMB2_HDR_PROTOCOL_ID    0x00
#define SMB2_HDR_LENGTH		0x04
#define SMB2_HDR_EPOCH		0x06
#define SMB2_HDR_STATUS		0x08
#define SMB2_HDR_OPCODE		0x0c
#define SMB2_HDR_CREDIT 	0x0e
#define SMB2_HDR_FLAGS		0x10
#define SMB2_HDR_NEXT_COMMAND	0x14
#define SMB2_HDR_MESSAGE_ID     0x18
#define SMB2_HDR_PID		0x20
#define SMB2_HDR_TID		0x24
#define SMB2_HDR_SESSION_ID	0x28
#define SMB2_HDR_SIGNATURE	0x30 /* 16 bytes */
#define SMB2_HDR_BODY		0x40

/* header flags */
#define SMB2_HDR_FLAG_REDIRECT  0x01
#define SMB2_HDR_FLAG_ASYNC     0x02
#define SMB2_HDR_FLAG_CHAINED   0x04
#define SMB2_HDR_FLAG_SIGNED    0x08
#define SMB2_HDR_FLAG_DFS       0x10000000

/* SMB2 opcodes */
#define SMB2_OP_NEGPROT   0x00
#define SMB2_OP_SESSSETUP 0x01
#define SMB2_OP_LOGOFF    0x02
#define SMB2_OP_TCON      0x03
#define SMB2_OP_TDIS      0x04
#define SMB2_OP_CREATE    0x05
#define SMB2_OP_CLOSE     0x06
#define SMB2_OP_FLUSH     0x07
#define SMB2_OP_READ      0x08
#define SMB2_OP_WRITE     0x09
#define SMB2_OP_LOCK      0x0a
#define SMB2_OP_IOCTL     0x0b
#define SMB2_OP_CANCEL    0x0c
#define SMB2_OP_KEEPALIVE 0x0d
#define SMB2_OP_FIND      0x0e
#define SMB2_OP_NOTIFY    0x0f
#define SMB2_OP_GETINFO   0x10
#define SMB2_OP_SETINFO   0x11
#define SMB2_OP_BREAK     0x12

#define SMB2_MAGIC 0x424D53FE /* 0xFE 'S' 'M' 'B' */

/* the dialect we support */
#define SMB2_DIALECT_REVISION           0x202

/* SMB2 negotiate security_mode */
#define SMB2_NEGOTIATE_SIGNING_ENABLED   0x01
#define SMB2_NEGOTIATE_SIGNING_REQUIRED  0x02

/* SMB2 capabilities - only 1 so far. I'm sure more will be added */
#define SMB2_CAP_DFS                     0x0
/* so we can spot new caps as added */
#define SMB2_CAP_ALL                     SMB2_CAP_DFS 

/* SMB2 share flags */
#define SMB2_SHAREFLAG_MANUAL_CACHING                    0x0000
#define SMB2_SHAREFLAG_AUTO_CACHING                      0x0010
#define SMB2_SHAREFLAG_VDO_CACHING                       0x0020
#define SMB2_SHAREFLAG_NO_CACHING                        0x0030
#define SMB2_SHAREFLAG_DFS                               0x0001
#define SMB2_SHAREFLAG_DFS_ROOT                          0x0002
#define SMB2_SHAREFLAG_RESTRICT_EXCLUSIVE_OPENS          0x0100
#define SMB2_SHAREFLAG_FORCE_SHARED_DELETE               0x0200
#define SMB2_SHAREFLAG_ALLOW_NAMESPACE_CACHING           0x0400
#define SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM       0x0800
#define SMB2_SHAREFLAG_ALL                               0x0F33

/* SMB2 create security flags */
#define SMB2_SECURITY_DYNAMIC_TRACKING                   0x01
#define SMB2_SECURITY_EFFECTIVE_ONLY                     0x02

/* SMB2 requested oplock levels */
#define SMB2_OPLOCK_LEVEL_NONE                           0x00
#define SMB2_OPLOCK_LEVEL_II                             0x01
#define SMB2_OPLOCK_LEVEL_EXCLUSIVE                      0x08
#define SMB2_OPLOCK_LEVEL_BATCH                          0x09

/* SMB2 impersonation levels */
#define SMB2_IMPERSONATION_ANONYMOUS                     0x00
#define SMB2_IMPERSONATION_IDENTIFICATION                0x01
#define SMB2_IMPERSONATION_IMPERSONATION                 0x02
#define SMB2_IMPERSONATION_DELEGATE                      0x03

/* SMB2 create tags */
#define SMB2_CREATE_TAG_EXTA "ExtA"
#define SMB2_CREATE_TAG_MXAC "MxAc"
#define SMB2_CREATE_TAG_SECD "SecD"
#define SMB2_CREATE_TAG_DHNQ "DHnQ"
#define SMB2_CREATE_TAG_DHNC "DHnC"
#define SMB2_CREATE_TAG_ALSI "AlSi"
#define SMB2_CREATE_TAG_TWRP "TWrp"
#define SMB2_CREATE_TAG_QFID "QFid"

/* SMB2 Create ignore some more create_options */
#define SMB2_CREATE_OPTIONS_NOT_SUPPORTED_MASK	(NTCREATEX_OPTIONS_TREE_CONNECTION | \
						 NTCREATEX_OPTIONS_OPFILTER)

/*
  check that a body has the expected size
*/
#define SMB2_CHECK_PACKET_RECV(req, size, dynamic) do { \
	size_t is_size = req->in.body_size; \
	uint16_t field_size = SVAL(req->in.body, 0); \
	uint16_t want_size = ((dynamic)?(size)+1:(size)); \
	if (is_size < (size)) { \
		DEBUG(0,("%s: buffer too small 0x%x. Expected 0x%x\n", \
			 __location__, (unsigned)is_size, (unsigned)want_size)); \
		return NT_STATUS_BUFFER_TOO_SMALL; \
	}\
	if (field_size != want_size) { \
		DEBUG(0,("%s: unexpected fixed body size 0x%x. Expected 0x%x\n", \
			 __location__, (unsigned)field_size, (unsigned)want_size)); \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
} while (0)

#endif
