/* 
   Unix SMB/CIFS implementation.
   messages.c header
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001, 2002 by Martin Pool
   
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

#ifndef _MESSAGES_H_
#define _MESSAGES_H_

/* change the message version with any incompatible changes in the protocol */
#define MESSAGE_VERSION 2


#define MSG_TYPE_MASK			0xFFFF

/* general messages */
#define MSG_DEBUG			0x0001
#define MSG_PING			0x0002
#define MSG_PONG			0x0003
#define MSG_PROFILE			0x0004
#define MSG_REQ_DEBUGLEVEL		0x0005
#define MSG_DEBUGLEVEL			0x0006
#define MSG_REQ_PROFILELEVEL		0x0007
#define MSG_PROFILELEVEL		0x0008
#define MSG_REQ_POOL_USAGE		0x0009
#define MSG_POOL_USAGE			0x000A

/* If dmalloc is included, set a steady-state mark */
#define MSG_REQ_DMALLOC_MARK		0x000B

/* If dmalloc is included, dump to the dmalloc log a description of
 * what has changed since the last MARK */
#define MSG_REQ_DMALLOC_LOG_CHANGED	0x000C

#define MSG_SHUTDOWN			0x000D

/* nmbd messages */
#define MSG_FORCE_ELECTION		0x0101
#define MSG_WINS_NEW_ENTRY		0x0102
#define MSG_SEND_PACKET			0x0103

/* printing messages */
/* #define MSG_PRINTER_NOTIFY  2001*/ /* Obsolete */
#define MSG_PRINTER_NOTIFY2		0x0202

#define MSG_PRINTER_DRVUPGRADE		0x0203
#define MSG_PRINTERDATA_INIT_RESET	0x0204
#define MSG_PRINTER_UPDATE		0x0205
#define MSG_PRINTER_MOD			0x0206

/* smbd messages */
#define MSG_SMB_CONF_UPDATED		0x0301
#define MSG_SMB_FORCE_TDIS		0x0302
#define MSG_SMB_SAM_SYNC		0x0303
#define MSG_SMB_SAM_REPL		0x0304
#define MSG_SMB_UNLOCK			0x0305
#define MSG_SMB_BREAK_REQUEST		0x0306
#define MSG_SMB_BREAK_RESPONSE		0x0307
#define MSG_SMB_ASYNC_LEVEL2_BREAK	0x0308
#define MSG_SMB_OPEN_RETRY		0x0309
#define MSG_SMB_KERNEL_BREAK		0x030A
#define MSG_SMB_FILE_RENAME		0x030B
#define MSG_SMB_INJECT_FAULT		0x030C
#define MSG_SMB_BLOCKING_LOCK_CANCEL	0x030D
#define MSG_SMB_NOTIFY			0x030E
#define MSG_SMB_STAT_CACHE_DELETE	0x030F
/*
 * Samba4 compatibility
 */
#define MSG_PVFS_NOTIFY			0x0310
/*
 * cluster reconfigure events
 */
#define MSG_SMB_BRL_VALIDATE		0x0311
#define MSG_SMB_RELEASE_IP		0x0312
/*
 * Close a specific file given a share entry.
 */
#define MSG_SMB_CLOSE_FILE		0x0313

/* winbind messages */
#define MSG_WINBIND_FINISHED		0x0401
#define MSG_WINBIND_FORGET_STATE	0x0402
#define MSG_WINBIND_ONLINE		0x0403
#define MSG_WINBIND_OFFLINE		0x0404
#define MSG_WINBIND_ONLINESTATUS	0x0405
#define MSG_WINBIND_TRY_TO_GO_ONLINE	0x0406
#define MSG_WINBIND_FAILED_TO_GO_ONLINE 0x0407
#define MSG_WINBIND_VALIDATE_CACHE	0x0408
#define MSG_WINBIND_DUMP_DOMAIN_LIST	0x0409

/* event messages */
#define MSG_DUMP_EVENT_LIST		0x0500

/* dbwrap messages 4001-4999 */
#define MSG_DBWRAP_TDB2_CHANGES		4001

/*
 * Special flags passed to message_send. Allocated from the top, lets see when
 * it collides with the message types in the lower 16 bits :-)
 */

/*
 * Under high load, this message can be dropped. Use for notify-style
 * messages that are not critical for correct operation.
 */
#define MSG_FLAG_LOWPRIORITY		0x80000000


/* Flags to classify messages - used in message_send_all() */
/* Sender will filter by flag. */

#define FLAG_MSG_GENERAL		0x0001
#define FLAG_MSG_SMBD			0x0002
#define FLAG_MSG_NMBD			0x0004
#define FLAG_MSG_PRINT_NOTIFY		0x0008
#define FLAG_MSG_PRINT_GENERAL		0x0010
/* dbwrap messages 4001-4999 */
#define FLAG_MSG_DBWRAP			0x0020


/*
 * Virtual Node Numbers are identifying a node within a cluster. Ctdbd sets
 * this, we retrieve our vnn from it.
 */

#define NONCLUSTER_VNN (0xFFFFFFFF)

/*
 * ctdb gives us 64-bit server ids for messaging_send. This is done to avoid
 * pid clashes and to be able to register for special messages like "all
 * smbds".
 *
 * Normal individual server id's have the upper 32 bits to 0, I picked "1" for
 * Samba, other subsystems might use something else.
 */

#define MSG_SRVID_SAMBA 0x0000000100000000LL


struct server_id {
	pid_t pid;
#ifdef CLUSTER_SUPPORT
	uint32 vnn;
#endif
};

#ifdef CLUSTER_SUPPORT
#define MSG_BROADCAST_PID_STR	"0:0"
#else
#define MSG_BROADCAST_PID_STR	"0"
#endif

struct messaging_context;
struct messaging_rec;
struct data_blob;

/*
 * struct messaging_context belongs to messages.c, but because we still have
 * messaging_dispatch, we need it here. Once we get rid of signals for
 * notifying processes, this will go.
 */

struct messaging_context {
	struct server_id id;
	struct event_context *event_ctx;
	struct messaging_callback *callbacks;

	struct messaging_backend *local;
	struct messaging_backend *remote;
};

struct messaging_backend {
	NTSTATUS (*send_fn)(struct messaging_context *msg_ctx,
			    struct server_id pid, int msg_type,
			    const struct data_blob *data,
			    struct messaging_backend *backend);
	void *private_data;
};

NTSTATUS messaging_tdb_init(struct messaging_context *msg_ctx,
			    TALLOC_CTX *mem_ctx,
			    struct messaging_backend **presult);
void message_dispatch(struct messaging_context *msg_ctx);

NTSTATUS messaging_ctdbd_init(struct messaging_context *msg_ctx,
			      TALLOC_CTX *mem_ctx,
			      struct messaging_backend **presult);
struct ctdbd_connection *messaging_ctdbd_connection(void);

bool message_send_all(struct messaging_context *msg_ctx,
		      int msg_type,
		      const void *buf, size_t len,
		      int *n_sent);
struct event_context *messaging_event_context(struct messaging_context *msg_ctx);
struct messaging_context *messaging_init(TALLOC_CTX *mem_ctx, 
					 struct server_id server_id, 
					 struct event_context *ev);

/*
 * re-init after a fork
 */
NTSTATUS messaging_reinit(struct messaging_context *msg_ctx);

NTSTATUS messaging_register(struct messaging_context *msg_ctx,
			    void *private_data,
			    uint32_t msg_type,
			    void (*fn)(struct messaging_context *msg,
				       void *private_data, 
				       uint32_t msg_type, 
				       struct server_id server_id,
				       struct data_blob *data));
void messaging_deregister(struct messaging_context *ctx, uint32_t msg_type,
			  void *private_data);
NTSTATUS messaging_send(struct messaging_context *msg_ctx,
			struct server_id server, 
			uint32_t msg_type, const struct data_blob *data);
NTSTATUS messaging_send_buf(struct messaging_context *msg_ctx,
			    struct server_id server, uint32_t msg_type,
			    const uint8 *buf, size_t len);
void messaging_dispatch_rec(struct messaging_context *msg_ctx,
			    struct messaging_rec *rec);

#endif
