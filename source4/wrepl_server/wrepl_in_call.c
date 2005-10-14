/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"

static NTSTATUS wreplsrv_in_start_association(struct wreplsrv_in_call *call)
{
	struct wrepl_stop *stop;

	call->rep_packet.opcode		= WREPL_OPCODE_BITS;
	call->rep_packet.assoc_ctx	= 0;
	call->rep_packet.mess_type	= WREPL_STOP_ASSOCIATION;
	stop				= &call->rep_packet.message.stop;
	stop->reason			= 4;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_in_replication(struct wreplsrv_in_call *call)
{
	struct wrepl_replication *repl_in = &call->req_packet.message.replication;
	struct wrepl_stop *stop_out;

	switch (repl_in->command) {
		case WREPL_REPL_TABLE_QUERY:
			break;
		case WREPL_REPL_TABLE_REPLY:
			break;
		case WREPL_REPL_SEND_REQUEST:
			break;
		case WREPL_REPL_SEND_REPLY:
			break;
		case WREPL_REPL_UPDATE:
			break;
		case WREPL_REPL_5:
			break;
		case WREPL_REPL_INFORM:
			break;
		case WREPL_REPL_9:
			break;
	}

	call->rep_packet.opcode		= WREPL_OPCODE_BITS;
	call->rep_packet.assoc_ctx	= 0;
	call->rep_packet.mess_type	= WREPL_STOP_ASSOCIATION;
	stop_out			= &call->rep_packet.message.stop;
	stop_out->reason		= 4;

	return NT_STATUS_OK;
}

NTSTATUS wreplsrv_in_call(struct wreplsrv_in_call *call)
{
	struct wrepl_stop *stop_out;

	/* TODO: check opcode and assoc_ctx */

	switch (call->req_packet.mess_type) {
		case WREPL_START_ASSOCIATION:
			return wreplsrv_in_start_association(call);

		case WREPL_START_ASSOCIATION_REPLY:
			/* this is not valid here */
			break;
		case WREPL_STOP_ASSOCIATION:
			/* this is not valid here */
			break;

		case WREPL_REPLICATION:
			return wreplsrv_in_replication(call);
	}

	call->rep_packet.opcode		= WREPL_OPCODE_BITS;
	call->rep_packet.assoc_ctx	= 0;
	call->rep_packet.mess_type	= WREPL_STOP_ASSOCIATION;
	call->rep_packet.padding	= data_blob(NULL, 0);
	stop_out			= &call->rep_packet.message.stop;
	stop_out->reason		= 4;

	return NT_STATUS_OK;
}

