/* 
   Unix SMB/CIFS implementation.

   CLDAP server task

   Copyright (C) Andrew Tridgell	2005
   
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
#include "ldb_wrap.h"
#include "auth/auth.h"
#include "param/param.h"

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
static NTSTATUS cldapd_add_socket(struct cldapd_server *cldapd, struct loadparm_context *lp_ctx,
				  const char *address)
{
	struct cldap_socket *cldapsock;
	struct socket_address *socket_address;
	NTSTATUS status;

	/* listen for unicasts on the CLDAP port (389) */
	cldapsock = cldap_socket_init(cldapd, cldapd->task->event_ctx, lp_iconv_convenience(cldapd->task->lp_ctx));
	NT_STATUS_HAVE_NO_MEMORY(cldapsock);

	socket_address = socket_address_from_strings(cldapsock, cldapsock->sock->backend_name, 
						     address, lp_cldap_port(lp_ctx));
	if (!socket_address) {
		talloc_free(cldapsock);
		return NT_STATUS_NO_MEMORY;
	}

	status = socket_listen(cldapsock->sock, socket_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_cldap_port(lp_ctx), nt_errstr(status)));
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
static NTSTATUS cldapd_startup_interfaces(struct cldapd_server *cldapd, struct loadparm_context *lp_ctx,
					  struct interface *ifaces)
{
	int num_interfaces;
	TALLOC_CTX *tmp_ctx = talloc_new(cldapd);
	NTSTATUS status;
	int i;

	num_interfaces = iface_count(ifaces);

	/* if we are allowing incoming packets from any address, then
	   we need to bind to the wildcard address */
	if (!lp_bind_interfaces_only(lp_ctx)) {
		status = cldapd_add_socket(cldapd, lp_ctx, "0.0.0.0");
		NT_STATUS_NOT_OK_RETURN(status);
	}

	/* now we have to also listen on the specific interfaces,
	   so that replies always come from the right IP */
	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, iface_n_ip(ifaces, i));
		status = cldapd_add_socket(cldapd, lp_ctx, address);
		NT_STATUS_NOT_OK_RETURN(status);
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
	struct interface *ifaces;
	
	load_interfaces(task, lp_interfaces(task->lp_ctx), &ifaces);

	if (iface_count(ifaces) == 0) {
		task_server_terminate(task, "cldapd: no network interfaces configured");
		return;
	}

	switch (lp_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "cldap_server: no CLDAP server required in standalone configuration");
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "cldap_server: no CLDAP server required in member server configuration");
		return;
	case ROLE_DOMAIN_CONTROLLER:
		/* Yes, we want an CLDAP server */
		break;
	}

	task_server_set_title(task, "task[cldapd]");

	cldapd = talloc(task, struct cldapd_server);
	if (cldapd == NULL) {
		task_server_terminate(task, "cldapd: out of memory");
		return;
	}

	cldapd->task = task;
	cldapd->samctx = samdb_connect(cldapd, task->event_ctx, task->lp_ctx, system_session(cldapd, task->lp_ctx));
	if (cldapd->samctx == NULL) {
		task_server_terminate(task, "cldapd failed to open samdb");
		return;
	}

	/* start listening on the configured network interfaces */
	status = cldapd_startup_interfaces(cldapd, task->lp_ctx, ifaces);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "cldapd failed to setup interfaces");
		return;
	}

	irpc_add_name(task->msg_ctx, "cldap_server");
}


/*
  register ourselves as a available server
*/
NTSTATUS server_service_cldapd_init(void)
{
	return register_server_service("cldap", cldapd_task_init);
}
