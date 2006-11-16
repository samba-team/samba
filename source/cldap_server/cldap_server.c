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
#include "smbd/service.h"
#include "cldap_server/cldap_server.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "dsdb/samdb/samdb.h"
#include "db_wrap.h"
#include "auth/auth.h"

/*
  handle incoming cldap requests
*/
static void cldapd_request_handler(struct cldap_socket *cldap, 
				   struct ldap_message *ldap_msg, 
				   struct socket_address *src)
{
	struct ldap_SearchRequest *search;
	if (ldap_msg->type != LDAP_TAG_SearchRequest) {
		DEBUG(0,("Invalid CLDAP request type %d from %s:%d\n", 
			 ldap_msg->type, src->addr, src->port));
		cldap_error_reply(cldap, ldap_msg->messageid, src,
				  LDAP_OPERATIONS_ERROR, "Invalid CLDAP request");
		return;
	}

	search = &ldap_msg->r.SearchRequest;

	if (strcmp("", search->basedn) != 0) {
		DEBUG(0,("Invalid CLDAP basedn '%s' from %s:%d\n", 
			 search->basedn, src->addr, src->port));
		cldap_error_reply(cldap, ldap_msg->messageid, src,
				  LDAP_OPERATIONS_ERROR, "Invalid CLDAP basedn");
		return;
	}

	if (search->scope != LDAP_SEARCH_SCOPE_BASE) {
		DEBUG(0,("Invalid CLDAP scope %d from %s:%d\n", 
			 search->scope, src->addr, src->port));
		cldap_error_reply(cldap, ldap_msg->messageid, src,
				  LDAP_OPERATIONS_ERROR, "Invalid CLDAP scope");
		return;
	}

	if (search->num_attributes == 1 &&
	    strcasecmp(search->attributes[0], "netlogon") == 0) {
		cldapd_netlogon_request(cldap, ldap_msg->messageid,
					search->tree, src);
		return;
	}

	cldapd_rootdse_request(cldap, ldap_msg->messageid,
			       search, src);
}


/*
  start listening on the given address
*/
static NTSTATUS cldapd_add_socket(struct cldapd_server *cldapd, const char *address)
{
	struct cldap_socket *cldapsock;
	struct socket_address *socket_address;
	NTSTATUS status;

	/* listen for unicasts on the CLDAP port (389) */
	cldapsock = cldap_socket_init(cldapd, cldapd->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(cldapsock);

	socket_address = socket_address_from_strings(cldapsock, cldapsock->sock->backend_name, 
						     address, lp_cldap_port());
	if (!socket_address) {
		talloc_free(cldapsock);
		return NT_STATUS_NO_MEMORY;
	}

	status = socket_listen(cldapsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_cldap_port(), nt_errstr(status)));
		talloc_free(cldapsock);
		return status;
	}

	talloc_free(socket_address);

	cldap_set_incoming_handler(cldapsock, cldapd_request_handler, cldapd);

	return NT_STATUS_OK;
}


/*
  setup our listening sockets on the configured network interfaces
*/
static NTSTATUS cldapd_startup_interfaces(struct cldapd_server *cldapd)
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

	task_server_set_title(task, "task[cldapd]");

	cldapd = talloc(task, struct cldapd_server);
	if (cldapd == NULL) {
		task_server_terminate(task, "cldapd: out of memory");
		return;
	}

	cldapd->task = task;
	cldapd->samctx = samdb_connect(cldapd, anonymous_session(cldapd));
	if (cldapd->samctx == NULL) {
		task_server_terminate(task, "cldapd failed to open samdb");
		return;
	}

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
