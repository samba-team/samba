/* 
   Unix SMB/CIFS implementation.

   CLDAP server task

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
#include "libcli/ldap/ldap.h"
#include "lib/socket/socket.h"
#include "lib/messaging/irpc.h"
#include "smbd/service_task.h"
#include "cldap_server/cldap_server.h"

/*
  handle incoming cldap requests
*/
static void cldapd_request_handler(struct cldap_socket *cldap, 
				   struct ldap_message *ldap_msg, 
				   const char *src_address, int src_port)
{
	struct ldap_SearchRequest *search;
	if (ldap_msg->type != LDAP_TAG_SearchRequest) {
		DEBUG(0,("Invalid CLDAP request type %d from %s:%d\n", 
			 ldap_msg->type, src_address, src_port));
		return;
	}

	search = &ldap_msg->r.SearchRequest;

	if (search->num_attributes == 1 &&
	    strcasecmp(search->attributes[0], "netlogon") == 0) {
		cldapd_netlogon_request(cldap, ldap_msg->messageid,
					search->tree, src_address, src_port);
	} else {
		DEBUG(0,("Unknown CLDAP search for '%s'\n", 
			 ldb_filter_from_tree(ldap_msg, 
					      ldap_msg->r.SearchRequest.tree)));
		cldap_empty_reply(cldap, ldap_msg->messageid, src_address, src_port);
	}
}


/*
  start listening on the given address
*/
static NTSTATUS cldapd_add_socket(struct cldapd_server *cldapd, const char *address)
{
	struct cldap_socket *cldapsock;
	NTSTATUS status;

	/* listen for unicasts on the CLDAP port (389) */
	cldapsock = cldap_socket_init(cldapd, cldapd->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(cldapsock);

	status = socket_listen(cldapsock->sock, address, lp_cldap_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_cldap_port(), nt_errstr(status)));
		talloc_free(cldapsock);
		return status;
	}

	cldap_set_incoming_handler(cldapsock, cldapd_request_handler, cldapd);

	return NT_STATUS_OK;
}


/*
  setup our listening sockets on the configured network interfaces
*/
NTSTATUS cldapd_startup_interfaces(struct cldapd_server *cldapd)
{
	int num_interfaces = iface_count();
	TALLOC_CTX *tmp_ctx = talloc_new(cldapd);
	NTSTATUS status;

	/* if we are allowing incoming packets from any address, then
	   we need to bind to the wildcard address */
	if (!lp_bind_interfaces_only()) {
		status = cldapd_add_socket(cldapd, "0.0.0.0");
		NT_STATUS_NOT_OK_RETURN(status);
	} else {
		int i;

		for (i=0; i<num_interfaces; i++) {
			const char *address = talloc_strdup(tmp_ctx, iface_n_ip(i));
			status = cldapd_add_socket(cldapd, address);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

/*
  startup the cldapd task
*/
static void cldapd_task_init(struct task_server *task)
{
	struct cldapd_server *cldapd;
	NTSTATUS status;

	if (iface_count() == 0) {
		task_server_terminate(task, "cldapd: no network interfaces configured");
		return;
	}

	cldapd = talloc(task, struct cldapd_server);
	if (cldapd == NULL) {
		task_server_terminate(task, "cldapd: out of memory");
		return;
	}

	cldapd->task = task;
	cldapd->samctx = NULL;

	/* start listening on the configured network interfaces */
	status = cldapd_startup_interfaces(cldapd);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "cldapd failed to setup interfaces");
		return;
	}

	irpc_add_name(task->msg_ctx, "cldap_server");
}


/*
  initialise the cldapd server
 */
static NTSTATUS cldapd_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, cldapd_task_init);
}


/*
  register ourselves as a available server
*/
NTSTATUS server_service_cldapd_init(void)
{
	return register_server_service("cldap", cldapd_init);
}
