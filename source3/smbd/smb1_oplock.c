/*
   Unix SMB/CIFS implementation.
   oplock processing
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1998 - 2001
   Copyright (C) Volker Lendecke 2005

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

#include "includes.h"
#include "lib/util/server_id.h"
#include "locking/share_mode_lock.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "messages.h"
#include "locking/leases_db.h"
#include "../librpc/gen_ndr/ndr_open_files.h"

/****************************************************************************
 Set up an oplock break message.
****************************************************************************/

void new_break_message_smb1(files_struct *fsp, int cmd,
			    char result[SMB1_BREAK_MESSAGE_LENGTH])
{
	memset(result,'\0',smb_size);
	srv_smb1_set_message(result,8,0,true);
	SCVAL(result,smb_com,SMBlockingX);
	SSVAL(result,smb_tid,fsp->conn->cnum);
	SSVAL(result,smb_pid,0xFFFF);
	SSVAL(result,smb_uid,0);
	SSVAL(result,smb_mid,0xFFFF);
	SCVAL(result,smb_vwv0,0xFF);
	SSVAL(result,smb_vwv2,fsp->fnum);
	SCVAL(result,smb_vwv3,LOCKING_ANDX_OPLOCK_RELEASE);
	SCVAL(result,smb_vwv3+1,cmd);
}

void send_break_message_smb1(files_struct *fsp, int level)
{
	struct smbXsrv_connection *xconn = NULL;
	char break_msg[SMB1_BREAK_MESSAGE_LENGTH];

	/*
	 * For SMB1 we only have one connection
	 */
	xconn = fsp->conn->sconn->client->connections;

	new_break_message_smb1(fsp, level, break_msg);

	show_msg(break_msg);
	if (!smb1_srv_send(xconn,
			   break_msg,
			   false,
			   0,
			   IS_CONN_ENCRYPTED(fsp->conn))) {
		exit_server_cleanly("send_break_message_smb1: "
			"smb1_srv_send failed.");
	}
}
