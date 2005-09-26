/* 
   Unix SMB/CIFS implementation.

   NBT server task

   Copyright (C) Andrew Tridgell	2005
   
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
#include "lib/events/events.h"
#include "smbd/service_task.h"
#include "nbt_server/nbt_server.h"


/*
  serve out the nbt statistics
*/
static NTSTATUS nbtd_information(struct irpc_message *msg, 
				 struct nbtd_information *r)
{
	struct nbtd_server *server = talloc_get_type(msg->private, struct nbtd_server);

	switch (r->in.level) {
	case NBTD_INFO_STATISTICS:
		r->out.info.stats = &server->stats;
		break;
	}

	return NT_STATUS_OK;
}

struct getdc_state {
	struct irpc_message *msg;
	struct nbtd_getdcname *req;
};

static void getdc_recv_ntlogon_reply(struct dgram_mailslot_handler *dgmslot, 
				     struct nbt_dgram_packet *packet, 
				     const char *src_address, int src_port)
{
	struct getdc_state *s =
		talloc_get_type(dgmslot->private, struct getdc_state);

	struct nbt_ntlogon_packet ntlogon;
	NTSTATUS status;

	status = dgram_mailslot_ntlogon_parse(dgmslot, packet, packet,
					      &ntlogon);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(5, ("dgram_mailslot_ntlogon_parse failed: %s\n",
			  nt_errstr(status)));
		goto done;
	}

	status = NT_STATUS_NO_LOGON_SERVERS;

	DEBUG(10, ("reply: command=%d\n", ntlogon.command));

	switch (ntlogon.command) {
	case NTLOGON_SAM_LOGON:
		DEBUG(0, ("Huh -- got NTLOGON_SAM_LOGON as reply\n"));
		break;
	case NTLOGON_SAM_LOGON_REPLY:
		DEBUG(10, ("NTLOGON_SAM_LOGON_REPLY: server: %s, user: %s, "
			   "domain: %s\n", ntlogon.req.reply.server,
			   ntlogon.req.reply.user_name,
			   ntlogon.req.reply.domain));
		s->req->out.dcname =
			talloc_strdup(s->req, ntlogon.req.reply.server);
		if (s->req->out.dcname == NULL) {
			DEBUG(0, ("talloc failed\n"));
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
		status = NT_STATUS_OK;
		break;
	default:
		DEBUG(0, ("Got unknown packet: %d\n", ntlogon.command));
		break;
	}

 done:
	irpc_send_reply(s->msg, status);
}

static NTSTATUS nbtd_getdcname(struct irpc_message *msg, 
			       struct nbtd_getdcname *req)
{
	struct nbtd_server *server =
		talloc_get_type(msg->private, struct nbtd_server);

	struct getdc_state *s;
	struct nbt_ntlogon_packet p;
	struct nbt_ntlogon_sam_logon *r;
	struct nbt_dgram_socket *sock;
	struct nbt_name src, dst;
	struct dgram_mailslot_handler *handler;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	DEBUG(0, ("nbtd_getdcname called\n"));

	sock = server->interfaces[0].dgmsock;

	s = talloc(msg, struct getdc_state);
        NT_STATUS_HAVE_NO_MEMORY(s);

	s->msg = msg;
	s->req = req;
	
	handler = dgram_mailslot_temp(sock, NBT_MAILSLOT_GETDC,
				      getdc_recv_ntlogon_reply, s);
        NT_STATUS_HAVE_NO_MEMORY(handler);
	
	ZERO_STRUCT(p);
	p.command = NTLOGON_SAM_LOGON;
	r = &p.req.logon;
	r->request_count = 0;
	r->computer_name = req->in.my_computername;
	r->user_name = req->in.my_accountname;
	r->mailslot_name = handler->mailslot_name;
	r->acct_control = req->in.account_control;
	r->sid = *req->in.domain_sid;
	r->nt_version = 1;
	r->lmnt_token = 0xffff;
	r->lm20_token = 0xffff;

	make_nbt_name_client(&src, req->in.my_computername);
	make_nbt_name(&dst, req->in.domainname, 0x1c);

	status = dgram_mailslot_ntlogon_send(sock, DGRAM_DIRECT_GROUP,
					     &dst, req->in.ip_address, 138,
					     &src, &p);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("dgram_mailslot_ntlogon_send failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	msg->defer_reply = True;
	return NT_STATUS_OK;
}


/*
  startup the nbtd task
*/
static void nbtd_task_init(struct task_server *task)
{
	struct nbtd_server *nbtsrv;
	NTSTATUS status;

	if (iface_count() == 0) {
		task_server_terminate(task, "nbtd: no network interfaces configured");
		return;
	}

	nbtsrv = talloc(task, struct nbtd_server);
	if (nbtsrv == NULL) {
		task_server_terminate(task, "nbtd: out of memory");
		return;
	}

	nbtsrv->task            = task;
	nbtsrv->interfaces      = NULL;
	nbtsrv->bcast_interface = NULL;
	nbtsrv->wins_interface  = NULL;

	/* start listening on the configured network interfaces */
	status = nbtd_startup_interfaces(nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to setup interfaces");
		return;
	}

	/* start the WINS server, if appropriate */
	status = nbtd_winsserver_init(nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to start WINS server");
		return;
	}

	/* setup monitoring */
	status = IRPC_REGISTER(task->msg_ctx, irpc, NBTD_INFORMATION, 
			       nbtd_information, nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to setup monitoring");
		return;
	}

	/* Setup handler for getdcname call */
	status = IRPC_REGISTER(task->msg_ctx, irpc, NBTD_GETDCNAME,
			       nbtd_getdcname, nbtsrv);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "nbtd failed to setup getdcname "
				      "handler");
		return;
	}

	/* start the process of registering our names on all interfaces */
	nbtd_register_names(nbtsrv);

	irpc_add_name(task->msg_ctx, "nbt_server");
}


/*
  initialise the nbt server
 */
static NTSTATUS nbtd_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, nbtd_task_init);
}


/*
  register ourselves as a available server
*/
NTSTATUS server_service_nbtd_init(void)
{
	return register_server_service("nbt", nbtd_init);
}
