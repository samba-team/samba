/* 
   Unix SMB/CIFS implementation.
   process incoming packets - main loop
   Copyright (C) Andrew Tridgell 1992-2003
   Copyright (C) James J Myers 2003 <myersjj@samba.org>
   Copyright (C) Stefan Metzmacher 2004
   
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

#include "includes.h"


/*
  send an oplock break request to a client
*/
BOOL req_send_oplock_break(struct smbsrv_tcon *tcon, uint16_t fnum, uint8_t level)
{
	struct smbsrv_request *req;

	req = init_smb_request(tcon->smb_conn);

	req_setup_reply(req, 8, 0);
	
	SCVAL(req->out.hdr,HDR_COM,SMBlockingX);
	SSVAL(req->out.hdr,HDR_TID,tcon->cnum);
	SSVAL(req->out.hdr,HDR_PID,0xFFFF);
	SSVAL(req->out.hdr,HDR_UID,0);
	SSVAL(req->out.hdr,HDR_MID,0xFFFF);
	SCVAL(req->out.hdr,HDR_FLG,0);
	SSVAL(req->out.hdr,HDR_FLG2,0);

	SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
	SSVAL(req->out.vwv, VWV(1), 0);
	SSVAL(req->out.vwv, VWV(2), fnum);
	SCVAL(req->out.vwv, VWV(3), LOCKING_ANDX_OPLOCK_RELEASE);
	SCVAL(req->out.vwv, VWV(3)+1, level);
	SIVAL(req->out.vwv, VWV(4), 0);
	SSVAL(req->out.vwv, VWV(6), 0);
	SSVAL(req->out.vwv, VWV(7), 0);

	req_send_reply(req);
	return True;
}

/****************************************************************************
receive a SMB request from the wire, forming a request_context from the result
****************************************************************************/
static struct smbsrv_request *receive_smb_request(struct smbsrv_connection *smb_conn)
{
	NTSTATUS status;
	ssize_t len, len2;
	DATA_BLOB tmp_blob;
	struct smbsrv_request *req;

	status = socket_recv(smb_conn->connection->socket, smb_conn, &tmp_blob, 4, SOCKET_FLAG_BLOCK|SOCKET_FLAG_PEEK);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	if (tmp_blob.length != 4) {
		return NULL;
	}

	len = smb_len(tmp_blob.data);
	talloc_free(tmp_blob.data);

	req = init_smb_request(smb_conn);

	GetTimeOfDay(&req->request_time);
	req->chained_fnum = -1;

	len2 = len + NBT_HDR_SIZE;

	status = socket_recv(smb_conn->connection->socket, req, &tmp_blob, len2, SOCKET_FLAG_BLOCK);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	if (tmp_blob.length != len2) {
		return NULL;
	}

	/* fill in the rest of the req->in structure */
	req->in.buffer = tmp_blob.data;
	req->in.size = len2;
	req->in.allocated = req->in.size;
	req->in.hdr = req->in.buffer + NBT_HDR_SIZE;
	req->in.vwv = req->in.hdr + HDR_VWV;
	req->in.wct = CVAL(req->in.hdr, HDR_WCT);
	if (req->in.vwv + VWV(req->in.wct) <= req->in.buffer + req->in.size) {
		req->in.data = req->in.vwv + VWV(req->in.wct) + 2;
		req->in.data_size = SVAL(req->in.vwv, VWV(req->in.wct));

		/* the bcc length is only 16 bits, but some packets
		   (such as SMBwriteX) can be much larger than 64k. We
		   detect this by looking for a large non-chained NBT
		   packet (at least 64k bigger than what is
		   specified). If it is detected then the NBT size is
		   used instead of the bcc size */
		if (req->in.data_size + 0x10000 <= 
		    req->in.size - PTR_DIFF(req->in.data, req->in.buffer) &&
		    (req->in.wct < 1 || SVAL(req->in.vwv, VWV(0)) == SMB_CHAIN_NONE)) {
			/* its an oversized packet! fun for all the family */
			req->in.data_size = req->in.size - PTR_DIFF(req->in.data,req->in.buffer);
		}
	}

	return req;
}

/*
These flags determine some of the permissions required to do an operation 

Note that I don't set NEED_WRITE on some write operations because they
are used by some brain-dead clients when printing, and I don't want to
force write permissions on print services.
*/
#define AS_USER (1<<0)
#define NEED_WRITE (1<<1)
#define TIME_INIT (1<<2)
#define CAN_IPC (1<<3)
#define AS_GUEST (1<<5)
#define USE_MUTEX (1<<7)

/* 
   define a list of possible SMB messages and their corresponding
   functions. Any message that has a NULL function is unimplemented -
   please feel free to contribute implementations!
*/
static const struct smb_message_struct
{
	const char *name;
	void (*fn)(struct smbsrv_request *);
	int flags;
}
 smb_messages[256] = {
/* 0x00 */ { "SMBmkdir",reply_mkdir,AS_USER | NEED_WRITE},
/* 0x01 */ { "SMBrmdir",reply_rmdir,AS_USER | NEED_WRITE},
/* 0x02 */ { "SMBopen",reply_open,AS_USER },
/* 0x03 */ { "SMBcreate",reply_mknew,AS_USER},
/* 0x04 */ { "SMBclose",reply_close,AS_USER | CAN_IPC },
/* 0x05 */ { "SMBflush",reply_flush,AS_USER},
/* 0x06 */ { "SMBunlink",reply_unlink,AS_USER | NEED_WRITE },
/* 0x07 */ { "SMBmv",reply_mv,AS_USER | NEED_WRITE },
/* 0x08 */ { "SMBgetatr",reply_getatr,AS_USER},
/* 0x09 */ { "SMBsetatr",reply_setatr,AS_USER | NEED_WRITE},
/* 0x0a */ { "SMBread",reply_read,AS_USER},
/* 0x0b */ { "SMBwrite",reply_write,AS_USER | CAN_IPC },
/* 0x0c */ { "SMBlock",reply_lock,AS_USER},
/* 0x0d */ { "SMBunlock",reply_unlock,AS_USER},
/* 0x0e */ { "SMBctemp",reply_ctemp,AS_USER },
/* 0x0f */ { "SMBmknew",reply_mknew,AS_USER}, 
/* 0x10 */ { "SMBchkpth",reply_chkpth,AS_USER},
/* 0x11 */ { "SMBexit",reply_exit,0},
/* 0x12 */ { "SMBlseek",reply_lseek,AS_USER},
/* 0x13 */ { "SMBlockread",reply_lockread,AS_USER},
/* 0x14 */ { "SMBwriteunlock",reply_writeunlock,AS_USER},
/* 0x15 */ { NULL, NULL, 0 },
/* 0x16 */ { NULL, NULL, 0 },
/* 0x17 */ { NULL, NULL, 0 },
/* 0x18 */ { NULL, NULL, 0 },
/* 0x19 */ { NULL, NULL, 0 },
/* 0x1a */ { "SMBreadbraw",reply_readbraw,AS_USER},
/* 0x1b */ { "SMBreadBmpx",reply_readbmpx,AS_USER},
/* 0x1c */ { "SMBreadBs",NULL,0 },
/* 0x1d */ { "SMBwritebraw",reply_writebraw,AS_USER},
/* 0x1e */ { "SMBwriteBmpx",reply_writebmpx,AS_USER},
/* 0x1f */ { "SMBwriteBs",reply_writebs,AS_USER},
/* 0x20 */ { "SMBwritec",NULL,0},
/* 0x21 */ { NULL, NULL, 0 },
/* 0x22 */ { "SMBsetattrE",reply_setattrE,AS_USER | NEED_WRITE },
/* 0x23 */ { "SMBgetattrE",reply_getattrE,AS_USER },
/* 0x24 */ { "SMBlockingX",reply_lockingX,AS_USER },
/* 0x25 */ { "SMBtrans",reply_trans,AS_USER | CAN_IPC },
/* 0x26 */ { "SMBtranss",NULL,AS_USER | CAN_IPC},
/* 0x27 */ { "SMBioctl",reply_ioctl,0},
/* 0x28 */ { "SMBioctls",NULL,AS_USER},
/* 0x29 */ { "SMBcopy",reply_copy,AS_USER | NEED_WRITE },
/* 0x2a */ { "SMBmove",NULL,AS_USER | NEED_WRITE },
/* 0x2b */ { "SMBecho",reply_echo,0},
/* 0x2c */ { "SMBwriteclose",reply_writeclose,AS_USER},
/* 0x2d */ { "SMBopenX",reply_open_and_X,AS_USER | CAN_IPC },
/* 0x2e */ { "SMBreadX",reply_read_and_X,AS_USER | CAN_IPC },
/* 0x2f */ { "SMBwriteX",reply_write_and_X,AS_USER | CAN_IPC },
/* 0x30 */ { NULL, NULL, 0 },
/* 0x31 */ { NULL, NULL, 0 },
/* 0x32 */ { "SMBtrans2", reply_trans2, AS_USER | CAN_IPC },
/* 0x33 */ { "SMBtranss2", reply_transs2, AS_USER},
/* 0x34 */ { "SMBfindclose", reply_findclose,AS_USER},
/* 0x35 */ { "SMBfindnclose", reply_findnclose, AS_USER},
/* 0x36 */ { NULL, NULL, 0 },
/* 0x37 */ { NULL, NULL, 0 },
/* 0x38 */ { NULL, NULL, 0 },
/* 0x39 */ { NULL, NULL, 0 },
/* 0x3a */ { NULL, NULL, 0 },
/* 0x3b */ { NULL, NULL, 0 },
/* 0x3c */ { NULL, NULL, 0 },
/* 0x3d */ { NULL, NULL, 0 },
/* 0x3e */ { NULL, NULL, 0 },
/* 0x3f */ { NULL, NULL, 0 },
/* 0x40 */ { NULL, NULL, 0 },
/* 0x41 */ { NULL, NULL, 0 },
/* 0x42 */ { NULL, NULL, 0 },
/* 0x43 */ { NULL, NULL, 0 },
/* 0x44 */ { NULL, NULL, 0 },
/* 0x45 */ { NULL, NULL, 0 },
/* 0x46 */ { NULL, NULL, 0 },
/* 0x47 */ { NULL, NULL, 0 },
/* 0x48 */ { NULL, NULL, 0 },
/* 0x49 */ { NULL, NULL, 0 },
/* 0x4a */ { NULL, NULL, 0 },
/* 0x4b */ { NULL, NULL, 0 },
/* 0x4c */ { NULL, NULL, 0 },
/* 0x4d */ { NULL, NULL, 0 },
/* 0x4e */ { NULL, NULL, 0 },
/* 0x4f */ { NULL, NULL, 0 },
/* 0x50 */ { NULL, NULL, 0 },
/* 0x51 */ { NULL, NULL, 0 },
/* 0x52 */ { NULL, NULL, 0 },
/* 0x53 */ { NULL, NULL, 0 },
/* 0x54 */ { NULL, NULL, 0 },
/* 0x55 */ { NULL, NULL, 0 },
/* 0x56 */ { NULL, NULL, 0 },
/* 0x57 */ { NULL, NULL, 0 },
/* 0x58 */ { NULL, NULL, 0 },
/* 0x59 */ { NULL, NULL, 0 },
/* 0x5a */ { NULL, NULL, 0 },
/* 0x5b */ { NULL, NULL, 0 },
/* 0x5c */ { NULL, NULL, 0 },
/* 0x5d */ { NULL, NULL, 0 },
/* 0x5e */ { NULL, NULL, 0 },
/* 0x5f */ { NULL, NULL, 0 },
/* 0x60 */ { NULL, NULL, 0 },
/* 0x61 */ { NULL, NULL, 0 },
/* 0x62 */ { NULL, NULL, 0 },
/* 0x63 */ { NULL, NULL, 0 },
/* 0x64 */ { NULL, NULL, 0 },
/* 0x65 */ { NULL, NULL, 0 },
/* 0x66 */ { NULL, NULL, 0 },
/* 0x67 */ { NULL, NULL, 0 },
/* 0x68 */ { NULL, NULL, 0 },
/* 0x69 */ { NULL, NULL, 0 },
/* 0x6a */ { NULL, NULL, 0 },
/* 0x6b */ { NULL, NULL, 0 },
/* 0x6c */ { NULL, NULL, 0 },
/* 0x6d */ { NULL, NULL, 0 },
/* 0x6e */ { NULL, NULL, 0 },
/* 0x6f */ { NULL, NULL, 0 },
/* 0x70 */ { "SMBtcon",reply_tcon,USE_MUTEX},
/* 0x71 */ { "SMBtdis",reply_tdis,0},
/* 0x72 */ { "SMBnegprot",reply_negprot,USE_MUTEX},
/* 0x73 */ { "SMBsesssetupX",reply_sesssetup,USE_MUTEX},
/* 0x74 */ { "SMBulogoffX", reply_ulogoffX, 0}, /* ulogoff doesn't give a valid TID */
/* 0x75 */ { "SMBtconX",reply_tcon_and_X,USE_MUTEX},
/* 0x76 */ { NULL, NULL, 0 },
/* 0x77 */ { NULL, NULL, 0 },
/* 0x78 */ { NULL, NULL, 0 },
/* 0x79 */ { NULL, NULL, 0 },
/* 0x7a */ { NULL, NULL, 0 },
/* 0x7b */ { NULL, NULL, 0 },
/* 0x7c */ { NULL, NULL, 0 },
/* 0x7d */ { NULL, NULL, 0 },
/* 0x7e */ { NULL, NULL, 0 },
/* 0x7f */ { NULL, NULL, 0 },
/* 0x80 */ { "SMBdskattr",reply_dskattr,AS_USER},
/* 0x81 */ { "SMBsearch",reply_search,AS_USER},
/* 0x82 */ { "SMBffirst",reply_search,AS_USER},
/* 0x83 */ { "SMBfunique",reply_search,AS_USER},
/* 0x84 */ { "SMBfclose",reply_fclose,AS_USER},
/* 0x85 */ { NULL, NULL, 0 },
/* 0x86 */ { NULL, NULL, 0 },
/* 0x87 */ { NULL, NULL, 0 },
/* 0x88 */ { NULL, NULL, 0 },
/* 0x89 */ { NULL, NULL, 0 },
/* 0x8a */ { NULL, NULL, 0 },
/* 0x8b */ { NULL, NULL, 0 },
/* 0x8c */ { NULL, NULL, 0 },
/* 0x8d */ { NULL, NULL, 0 },
/* 0x8e */ { NULL, NULL, 0 },
/* 0x8f */ { NULL, NULL, 0 },
/* 0x90 */ { NULL, NULL, 0 },
/* 0x91 */ { NULL, NULL, 0 },
/* 0x92 */ { NULL, NULL, 0 },
/* 0x93 */ { NULL, NULL, 0 },
/* 0x94 */ { NULL, NULL, 0 },
/* 0x95 */ { NULL, NULL, 0 },
/* 0x96 */ { NULL, NULL, 0 },
/* 0x97 */ { NULL, NULL, 0 },
/* 0x98 */ { NULL, NULL, 0 },
/* 0x99 */ { NULL, NULL, 0 },
/* 0x9a */ { NULL, NULL, 0 },
/* 0x9b */ { NULL, NULL, 0 },
/* 0x9c */ { NULL, NULL, 0 },
/* 0x9d */ { NULL, NULL, 0 },
/* 0x9e */ { NULL, NULL, 0 },
/* 0x9f */ { NULL, NULL, 0 },
/* 0xa0 */ { "SMBnttrans", reply_nttrans, AS_USER | CAN_IPC },
/* 0xa1 */ { "SMBnttranss", reply_nttranss, AS_USER | CAN_IPC },
/* 0xa2 */ { "SMBntcreateX", reply_ntcreate_and_X, AS_USER | CAN_IPC },
/* 0xa3 */ { NULL, NULL, 0 },
/* 0xa4 */ { "SMBntcancel", reply_ntcancel, 0 },
/* 0xa5 */ { "SMBntrename", reply_ntrename, 0 },
/* 0xa6 */ { NULL, NULL, 0 },
/* 0xa7 */ { NULL, NULL, 0 },
/* 0xa8 */ { NULL, NULL, 0 },
/* 0xa9 */ { NULL, NULL, 0 },
/* 0xaa */ { NULL, NULL, 0 },
/* 0xab */ { NULL, NULL, 0 },
/* 0xac */ { NULL, NULL, 0 },
/* 0xad */ { NULL, NULL, 0 },
/* 0xae */ { NULL, NULL, 0 },
/* 0xaf */ { NULL, NULL, 0 },
/* 0xb0 */ { NULL, NULL, 0 },
/* 0xb1 */ { NULL, NULL, 0 },
/* 0xb2 */ { NULL, NULL, 0 },
/* 0xb3 */ { NULL, NULL, 0 },
/* 0xb4 */ { NULL, NULL, 0 },
/* 0xb5 */ { NULL, NULL, 0 },
/* 0xb6 */ { NULL, NULL, 0 },
/* 0xb7 */ { NULL, NULL, 0 },
/* 0xb8 */ { NULL, NULL, 0 },
/* 0xb9 */ { NULL, NULL, 0 },
/* 0xba */ { NULL, NULL, 0 },
/* 0xbb */ { NULL, NULL, 0 },
/* 0xbc */ { NULL, NULL, 0 },
/* 0xbd */ { NULL, NULL, 0 },
/* 0xbe */ { NULL, NULL, 0 },
/* 0xbf */ { NULL, NULL, 0 },
/* 0xc0 */ { "SMBsplopen",reply_printopen,AS_USER },
/* 0xc1 */ { "SMBsplwr",reply_printwrite,AS_USER},
/* 0xc2 */ { "SMBsplclose",reply_printclose,AS_USER},
/* 0xc3 */ { "SMBsplretq",reply_printqueue,AS_USER},
/* 0xc4 */ { NULL, NULL, 0 },
/* 0xc5 */ { NULL, NULL, 0 },
/* 0xc6 */ { NULL, NULL, 0 },
/* 0xc7 */ { NULL, NULL, 0 },
/* 0xc8 */ { NULL, NULL, 0 },
/* 0xc9 */ { NULL, NULL, 0 },
/* 0xca */ { NULL, NULL, 0 },
/* 0xcb */ { NULL, NULL, 0 },
/* 0xcc */ { NULL, NULL, 0 },
/* 0xcd */ { NULL, NULL, 0 },
/* 0xce */ { NULL, NULL, 0 },
/* 0xcf */ { NULL, NULL, 0 },
/* 0xd0 */ { "SMBsends",reply_sends,AS_GUEST},
/* 0xd1 */ { "SMBsendb",NULL,AS_GUEST},
/* 0xd2 */ { "SMBfwdname",NULL,AS_GUEST},
/* 0xd3 */ { "SMBcancelf",NULL,AS_GUEST},
/* 0xd4 */ { "SMBgetmac",NULL,AS_GUEST},
/* 0xd5 */ { "SMBsendstrt",reply_sendstrt,AS_GUEST},
/* 0xd6 */ { "SMBsendend",reply_sendend,AS_GUEST},
/* 0xd7 */ { "SMBsendtxt",reply_sendtxt,AS_GUEST},
/* 0xd8 */ { NULL, NULL, 0 },
/* 0xd9 */ { NULL, NULL, 0 },
/* 0xda */ { NULL, NULL, 0 },
/* 0xdb */ { NULL, NULL, 0 },
/* 0xdc */ { NULL, NULL, 0 },
/* 0xdd */ { NULL, NULL, 0 },
/* 0xde */ { NULL, NULL, 0 },
/* 0xdf */ { NULL, NULL, 0 },
/* 0xe0 */ { NULL, NULL, 0 },
/* 0xe1 */ { NULL, NULL, 0 },
/* 0xe2 */ { NULL, NULL, 0 },
/* 0xe3 */ { NULL, NULL, 0 },
/* 0xe4 */ { NULL, NULL, 0 },
/* 0xe5 */ { NULL, NULL, 0 },
/* 0xe6 */ { NULL, NULL, 0 },
/* 0xe7 */ { NULL, NULL, 0 },
/* 0xe8 */ { NULL, NULL, 0 },
/* 0xe9 */ { NULL, NULL, 0 },
/* 0xea */ { NULL, NULL, 0 },
/* 0xeb */ { NULL, NULL, 0 },
/* 0xec */ { NULL, NULL, 0 },
/* 0xed */ { NULL, NULL, 0 },
/* 0xee */ { NULL, NULL, 0 },
/* 0xef */ { NULL, NULL, 0 },
/* 0xf0 */ { NULL, NULL, 0 },
/* 0xf1 */ { NULL, NULL, 0 },
/* 0xf2 */ { NULL, NULL, 0 },
/* 0xf3 */ { NULL, NULL, 0 },
/* 0xf4 */ { NULL, NULL, 0 },
/* 0xf5 */ { NULL, NULL, 0 },
/* 0xf6 */ { NULL, NULL, 0 },
/* 0xf7 */ { NULL, NULL, 0 },
/* 0xf8 */ { NULL, NULL, 0 },
/* 0xf9 */ { NULL, NULL, 0 },
/* 0xfa */ { NULL, NULL, 0 },
/* 0xfb */ { NULL, NULL, 0 },
/* 0xfc */ { NULL, NULL, 0 },
/* 0xfd */ { NULL, NULL, 0 },
/* 0xfe */ { NULL, NULL, 0 },
/* 0xff */ { NULL, NULL, 0 }
};

/****************************************************************************
return a string containing the function name of a SMB command
****************************************************************************/
static const char *smb_fn_name(uint8_t type)
{
	const char *unknown_name = "SMBunknown";

	if (smb_messages[type].name == NULL)
		return unknown_name;

	return smb_messages[type].name;
}


/****************************************************************************
 Do a switch on the message type and call the specific reply function for this 
message. Unlike earlier versions of Samba the reply functions are responsible
for sending the reply themselves, rather than returning a size to this function
The reply functions may also choose to delay the processing by pushing the message
onto the message queue
****************************************************************************/
static void switch_message(int type, struct smbsrv_request *req)
{
	int flags;
	struct smbsrv_connection *smb_conn = req->smb_conn;
	uint16_t session_tag;

	type &= 0xff;

	errno = 0;

	if (smb_messages[type].fn == NULL) {
		DEBUG(0,("Unknown message type %d!\n",type));
		reply_unknown(req);
		return;
	}

	flags = smb_messages[type].flags;

	req->tcon = conn_find(smb_conn, SVAL(req->in.hdr,HDR_TID));

	if (req->session == NULL) {
		/* setup the user context for this request if it
		   hasn't already been initialised (to cope with SMB
		   chaining) */

		/* In share mode security we must ignore the vuid. */
		if (lp_security() == SEC_SHARE) {
			session_tag = UID_FIELD_INVALID;
		} else {
			session_tag = SVAL(req->in.hdr,HDR_UID);
		}

		req->session = smbsrv_session_find(req->smb_conn, session_tag);
		if (req->session) {
			req->session->vuid = session_tag;
		}
	} else {
		session_tag = req->session->vuid;
	}

	DEBUG(3,("switch message %s (task_id %d)\n",smb_fn_name(type), smb_conn->connection->service->model_ops->get_id(req)));

	/* does this protocol need to be run as root? */
	if (!(flags & AS_USER)) {
		change_to_root_user();
	}
	
	/* does this protocol need a valid tree connection? */
	if ((flags & AS_USER) && !req->tcon) {
		req_reply_error(req, NT_STATUS_INVALID_HANDLE);
		return;
	}

	/* see if the vuid is valid */
	if ((flags & AS_USER) && !req->session) {
		if (!(flags & AS_GUEST)) {
			req_reply_error(req, NT_STATUS_INVALID_HANDLE);
			return;
		}
	}

	/* does this protocol need to be run as the connected user? */
#if HACK_REWRITE
	if ((flags & AS_USER) && !change_to_user(req->tcon,session_tag)) {
		if (!(flags & AS_GUEST)) {
			req_reply_error(req, NT_STATUS_ACCESS_DENIED);
			return;
		}

		/* we'll run it as guest */
		flags &= ~AS_USER;
	}
#endif

	/* this code is to work around a bug is MS client 3 without
	   introducing a security hole - it needs to be able to do
	   print queue checks as guest if it isn't logged in properly */
	if (flags & AS_USER) {
		flags &= ~AS_GUEST;
	}
	
	/* does it need write permission? */
	if ((flags & NEED_WRITE) && !CAN_WRITE(req->tcon)) {
		req_reply_error(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	
	/* ipc services are limited */
	if (req->tcon && req->tcon->ntvfs_ctx->type == NTVFS_IPC && (flags & AS_USER) && !(flags & CAN_IPC)) {
		req_reply_error(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	
	/* load service specific parameters */
	if (req->tcon && !set_current_service(req->tcon,(flags & AS_USER)?True:False)) {
		req_reply_error(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
	
	/* does this protocol need to be run as guest? */
#if HACK_REWRITE
	if ((flags & AS_GUEST) && 
	    !change_to_guest()) {
		req_reply_error(req, NT_STATUS_ACCESS_DENIED);
		return;
	}
#endif
	/* THREAD TESTING: use mutex to serialize calls to critical functions with global state */
	if (flags & USE_MUTEX) {
		MUTEX_LOCK_BY_ID(MUTEX_SMBD);
	}
	smb_messages[type].fn(req);
	if (flags & USE_MUTEX) {
		MUTEX_UNLOCK_BY_ID(MUTEX_SMBD);
	}
}


/****************************************************************************
 Construct a reply to the incoming packet.
****************************************************************************/
static void construct_reply(struct smbsrv_request *req)
{
	uint8_t type = CVAL(req->in.hdr,HDR_COM);

	/* see if its a special NBT packet */
	if (CVAL(req->in.buffer,0) != 0) {
		reply_special(req);
		return;
	}

	/* Make sure this is an SMB packet */	
	if (memcmp(req->in.hdr,"\377SMB",4) != 0) {
		DEBUG(2,("Non-SMB packet of length %d. Terminating connection\n", 
			 req->in.size));
		smbsrv_terminate_connection(req->smb_conn, "Non-SMB packet");
		return;
	}

	if (NBT_HDR_SIZE + MIN_SMB_SIZE + 2*req->in.wct > req->in.size) {
		DEBUG(2,("Invalid SMB word count %d\n", req->in.wct));
		smbsrv_terminate_connection(req->smb_conn, "Invalid SMB packet");
		return;
	}

	if (NBT_HDR_SIZE + MIN_SMB_SIZE + 2*req->in.wct + req->in.data_size > req->in.size) {
		DEBUG(2,("Invalid SMB buffer length count %d\n", req->in.data_size));
		smbsrv_terminate_connection(req->smb_conn, "Invalid SMB packet");
		return;
	}


	req->smbpid = SVAL(req->in.hdr,HDR_PID);	
	req->flags = CVAL(req->in.hdr, HDR_FLG);
	req->flags2 = SVAL(req->in.hdr, HDR_FLG2);

	if (!req_signing_check_incoming(req)) {
		req_reply_error(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	switch_message(type, req);
}


/*
  we call this when first first part of a possibly chained request has been completed
  and we need to call the 2nd part, if any
*/
void chain_reply(struct smbsrv_request *req)
{
	uint16_t chain_cmd, chain_offset;
	char *vwv, *data;
	uint16_t wct;
	uint16_t data_size;

	if (req->in.wct < 2 || req->out.wct < 2) {
		req_reply_dos_error(req, ERRSRV, ERRerror);
		return;
	}

	chain_cmd    = CVAL(req->in.vwv, VWV(0));
	chain_offset = SVAL(req->in.vwv, VWV(1));

	if (chain_cmd == SMB_CHAIN_NONE) {
		/* end of chain */
		SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
		SSVAL(req->out.vwv, VWV(1), 0);
		req_send_reply(req);
		return;
	}

	if (chain_offset + req->in.hdr >= req->in.buffer + req->in.size) {
		goto error;
	}

	wct = CVAL(req->in.hdr, chain_offset);
	vwv = req->in.hdr + chain_offset + 1;

	if (vwv + VWV(wct) + 2 > req->in.buffer + req->in.size) {
		goto error;
	}

	data_size = SVAL(vwv, VWV(wct));
	data = vwv + VWV(wct) + 2;

	if (data + data_size > req->in.buffer + req->in.size) {
		goto error;
	}

	/* all seems legit */
	req->in.vwv = vwv;
	req->in.wct = wct;
	req->in.data = data;
	req->in.data_size = data_size;
	req->in.ptr = data;

	req->chain_count++;

	SSVAL(req->out.vwv, VWV(0), chain_cmd);
	SSVAL(req->out.vwv, VWV(1), req->out.size - NBT_HDR_SIZE);

	/* the current request in the chain might have used an async reply,
	   but that doesn't mean the next element needs to */
	ZERO_STRUCT(req->async);
	req->control_flags &= ~REQ_CONTROL_ASYNC;

	switch_message(chain_cmd, req);
	return;

error:
	SSVAL(req->out.vwv, VWV(0), SMB_CHAIN_NONE);
	SSVAL(req->out.vwv, VWV(1), 0);
	req_reply_dos_error(req, ERRSRV, ERRerror);
}


/*
  close the socket and shutdown a server_context
*/
void smbsrv_terminate_connection(struct smbsrv_connection *smb_conn, const char *reason)
{
	server_terminate_connection(smb_conn->connection, reason);
}

/*
  called on a fatal error that should cause this server to terminate
*/
static void smbsrv_exit(struct server_service *service, const char *reason)
{
	DEBUG(1,("smbsrv_exit\n"));
	return;
}

/*
  add a socket address to the list of events, one event per port
*/
static void add_socket(struct server_service *service, 
		       const struct model_ops *model_ops,
		       struct socket_context *socket_ctx, 
		       struct in_addr *ifip)
{
	const char **ports = lp_smb_ports();
	int i;
	char *ip_str = talloc_strdup(service, inet_ntoa(*ifip));

	for (i=0;ports[i];i++) {
		uint16_t port = atoi(ports[i]);
		if (port == 0) continue;
		service_setup_socket(service, model_ops, ip_str, &port);
	}

	talloc_free(ip_str);
}

/****************************************************************************
 Open the socket communication.
****************************************************************************/
static void smbsrv_init(struct server_service *service, const struct model_ops *model_ops)
{	
	DEBUG(1,("smbsrv_init\n"));

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			struct in_addr *ifip = iface_n_ip(i);

			if (ifip == NULL) {
				DEBUG(0,("open_sockets_smbd: interface %d has NULL IP address !\n", i));
				continue;
			}

			add_socket(service, model_ops, NULL, ifip);
		}
	} else {
		struct in_addr *ifip;
		TALLOC_CTX *mem_ctx = talloc_init("open_sockets_smbd");

		if (!mem_ctx) {
			smb_panic("No memory");
		}	

		/* Just bind to lp_socket_address() (usually 0.0.0.0) */
		ifip = interpret_addr2(mem_ctx, lp_socket_address());
		add_socket(service, model_ops, NULL, ifip);

		talloc_free(mem_ctx);
	}
}

/*
  called when a SMB socket becomes readable
*/
static void smbsrv_recv(struct server_connection *conn, time_t t, uint16_t flags)
{
	struct smbsrv_request *req;
	struct smbsrv_connection *smb_conn = conn->private_data;

	DEBUG(10,("smbsrv_recv\n"));

	req = receive_smb_request(smb_conn);
	if (!req) {
		conn->event.fde->flags = 0;
		smbsrv_terminate_connection(smb_conn, "receive error");
		return;
	}

	construct_reply(req);

	/* free up temporary memory */
	lp_talloc_free();
	return;
}

/*
  called when a SMB socket becomes writable
*/
static void smbsrv_send(struct server_connection *conn, time_t t, uint16_t flags)
{
	DEBUG(10,("smbsrv_send\n"));
	return;
}

/*
  called when connection is idle
*/
static void smbsrv_idle(struct server_connection *conn, time_t t)
{
	DEBUG(10,("smbsrv_idle: not implemented!\n"));
	conn->event.idle->next_event = t + 5;

	return;
}

static void smbsrv_close(struct server_connection *conn, const char *reason)
{
	struct smbsrv_connection *smb_conn = conn->private_data;

	DEBUG(5,("smbsrv_close: %s\n",reason));

	conn_close_all(smb_conn);

	talloc_free(smb_conn);

	return;
}

/*
  process a message from an SMB socket while still processing a
  previous message this is used by backends who need to ensure that
  new messages from clients are still processed while they are
  performing long operations
*/
void smbd_process_async(struct smbsrv_connection *smb_conn)
{
	struct smbsrv_request *req;
	
	req = receive_smb_request(smb_conn);
	if (!req) {
		smbsrv_terminate_connection(smb_conn, "receive error");
		return;
	}

	construct_reply(req);
}


/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
void smbsrv_accept(struct server_connection *conn)
{
	struct smbsrv_connection *smb_conn;
	int fd;

	DEBUG(5,("smbsrv_accept\n"));

	smb_conn = talloc_p(conn, struct smbsrv_connection);
	if (!smb_conn) return;

	ZERO_STRUCTP(smb_conn);

	smb_conn->pid = getpid();

	sub_set_context(&smb_conn->substitute);

	/* now initialise a few default values associated with this smb socket */
	smb_conn->negotiate.max_send = 0xFFFF;

	/* this is the size that w2k uses, and it appears to be important for
	   good performance */
	smb_conn->negotiate.max_recv = lp_max_xmit();

	smb_conn->negotiate.zone_offset = get_time_zone(time(NULL));

	smb_conn->sessions.next_vuid = VUID_OFFSET;

	srv_init_signing(smb_conn);

	conn_init(smb_conn);

	smb_conn->connection = conn;

	conn->private_data = smb_conn;

	fd = socket_get_fd(conn->socket);
	set_blocking(fd, True);

	/* setup the DCERPC server subsystem */
	dcesrv_init_context(smb_conn, &smb_conn->dcesrv);

	return;
}

static const struct server_service_ops smb_server_ops = {
	.name			= "smb",
	.service_init		= smbsrv_init,
	.accept_connection	= smbsrv_accept,
	.recv_handler		= smbsrv_recv,
	.send_handler		= smbsrv_send,
	.idle_handler		= smbsrv_idle,
	.close_connection	= smbsrv_close,
	.service_exit		= smbsrv_exit,	
};

const struct server_service_ops *smbsrv_get_ops(void)
{
	return &smb_server_ops;
}

NTSTATUS server_service_smb_init(void)
{
	return NT_STATUS_OK;	
}
