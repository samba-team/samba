/*
   Unix SMB/Netbios implementation.
   Version 3.0
   change notify handling
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Jeremy Allison 1994-1998

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

static struct cnotify_fns *cnotify;

/****************************************************************************
 This is the structure to queue to implement NT change
 notify. It consists of smb_size bytes stored from the
 transact command (to keep the mid, tid etc around).
 Plus the fid to examine and notify private data.
*****************************************************************************/

struct change_notify {
	struct change_notify *next, *prev;
	files_struct *fsp;
	connection_struct *conn;
	uint32 flags;
	char request_buf[smb_size];
	void *change_data;
};

static struct change_notify *change_notify_list;

/****************************************************************************
 Setup the common parts of the return packet and send it.
*****************************************************************************/
static void change_notify_reply_packet(char *inbuf, NTSTATUS error_code)
{
	char outbuf[smb_size+38];

	memset(outbuf, '\0', sizeof(outbuf));
	construct_reply_common(inbuf, outbuf);

	ERROR_NT(error_code);

	/*
	 * Seems NT needs a transact command with an error code
	 * in it. This is a longer packet than a simple error.
	 */
	set_message(outbuf,18,0,False);

	if (!send_smb(smbd_server_fd(),outbuf))
		exit_server("change_notify_reply_packet: send_smb failed.");
}

/****************************************************************************
 Remove an entry from the list and free it, also closing any
 directory handle if necessary.
*****************************************************************************/

static void change_notify_remove(struct change_notify *cnbp)
{
	cnotify->remove_notify(cnbp->change_data);
	DLIST_REMOVE(change_notify_list, cnbp);
	ZERO_STRUCTP(cnbp);
	SAFE_FREE(cnbp);
}

/****************************************************************************
 Delete entries by fnum from the change notify pending queue.
*****************************************************************************/

void remove_pending_change_notify_requests_by_fid(files_struct *fsp)
{
	struct change_notify *cnbp, *next;

	for (cnbp=change_notify_list; cnbp; cnbp=next) {
		next=cnbp->next;
		if (cnbp->fsp->fnum == fsp->fnum) {
			change_notify_remove(cnbp);
		}
	}
}

/****************************************************************************
 Delete entries by mid from the change notify pending queue. Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_mid(int mid)
{
	struct change_notify *cnbp, *next;

	for (cnbp=change_notify_list; cnbp; cnbp=next) {
		next=cnbp->next;
		if(SVAL(cnbp->request_buf,smb_mid) == mid) {
			change_notify_reply_packet(cnbp->request_buf,NT_STATUS_CANCELLED);
			change_notify_remove(cnbp);
		}
	}
}

/****************************************************************************
 Delete entries by filename and cnum from the change notify pending queue.
 Always send reply.
*****************************************************************************/

void remove_pending_change_notify_requests_by_filename(files_struct *fsp)
{
	struct change_notify *cnbp, *next;

	for (cnbp=change_notify_list; cnbp; cnbp=next) {
		next=cnbp->next;
		/*
		 * We know it refers to the same directory if the connection number and
		 * the filename are identical.
		 */
		if((cnbp->fsp->conn == fsp->conn) && strequal(cnbp->fsp->fsp_name,fsp->fsp_name)) {
			change_notify_reply_packet(cnbp->request_buf,NT_STATUS_CANCELLED);
			change_notify_remove(cnbp);
		}
	}
}

/****************************************************************************
 Return true if there are pending change notifies.
****************************************************************************/

int change_notify_timeout(void)
{
	return cnotify->select_time;
}

/****************************************************************************
 Process the change notify queue. Note that this is only called as root.
 Returns True if there are still outstanding change notify requests on the
 queue.
*****************************************************************************/

BOOL process_pending_change_notify_queue(time_t t)
{
	struct change_notify *cnbp, *next;
	uint16 vuid;

	for (cnbp=change_notify_list; cnbp; cnbp=next) {
		next=cnbp->next;

		vuid = (lp_security() == SEC_SHARE) ? UID_FIELD_INVALID : SVAL(cnbp->request_buf,smb_uid);

		if (cnotify->check_notify(cnbp->conn, vuid, cnbp->fsp->fsp_name, cnbp->flags, cnbp->change_data, t)) {
			DEBUG(10,("process_pending_change_notify_queue: dir %s changed !\n", cnbp->fsp->fsp_name ));
			change_notify_reply_packet(cnbp->request_buf,STATUS_NOTIFY_ENUM_DIR);
			change_notify_remove(cnbp);
		}
	}

	return (change_notify_list != NULL);
}

/****************************************************************************
 Now queue an entry on the notify change list.
 We only need to save smb_size bytes from this incoming packet
 as we will always by returning a 'read the directory yourself'
 error.
****************************************************************************/

BOOL change_notify_set(char *inbuf, files_struct *fsp, connection_struct *conn, uint32 flags)
{
	struct change_notify *cnbp;

	if((cnbp = (struct change_notify *)malloc(sizeof(*cnbp))) == NULL) {
		DEBUG(0,("call_nt_transact_notify_change: malloc fail !\n" ));
		return -1;
	}

	ZERO_STRUCTP(cnbp);

	memcpy(cnbp->request_buf, inbuf, smb_size);
	cnbp->fsp = fsp;
	cnbp->conn = conn;
	cnbp->flags = flags;
	cnbp->change_data = cnotify->register_notify(conn, fsp->fsp_name, flags);
	
	if (!cnbp->change_data) {
		SAFE_FREE(cnbp);
		return False;
	}

	DLIST_ADD(change_notify_list, cnbp);

	return True;
}

/****************************************************************************
 Initialise the change notify subsystem.
****************************************************************************/

BOOL init_change_notify(void)
{
#if HAVE_KERNEL_CHANGE_NOTIFY
	cnotify = kernel_notify_init();
#endif
	if (!cnotify) cnotify = hash_notify_init();
	
	if (!cnotify) {
		DEBUG(0,("Failed to init change notify system\n"));
		return False;
	}

	return True;
}
