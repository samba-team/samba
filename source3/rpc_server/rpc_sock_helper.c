/*
 *  Unix SMB/CIFS implementation.
 *
 *  RPC Socket Helper
 *
 *  Copyright (c) 2011      Andreas Schneider <asn@samba.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "ntdomain.h"

#include "../lib/tsocket/tsocket.h"
#include "librpc/rpc/dcerpc_ep.h"
#include "rpc_server/rpc_server.h"
#include "rpc_server/rpc_sock_helper.h"
#include "lib/server_prefork.h"
#include "librpc/ndr/ndr_table.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

NTSTATUS dcesrv_create_ncacn_ip_tcp_sockets(
				const struct ndr_interface_table *iface,
				struct dcerpc_binding_vector *bvec,
				uint16_t port,
				struct pf_listen_fd *listen_fd,
				int *listen_fd_size)
{
	uint32_t num_ifs = iface_count();
	uint32_t i;
	uint16_t p = port;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	int rc;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		/*
		 * We have been given an interfaces line, and been told to only
		 * bind to those interfaces. Create a socket per interface and
		 * bind to only these.
		 */

		/* Now open a listen socket for each of the interfaces. */
		for (i = 0; i < num_ifs; i++) {
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);
			struct tsocket_address *bind_addr;
			const char *addr;
			int fd;

			status = dcesrv_create_ncacn_ip_tcp_socket(ifss,
								   &p,
								   &fd);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
			listen_fd[*listen_fd_size].fd = fd;
			listen_fd[*listen_fd_size].fd_data = NULL;
			(*listen_fd_size)++;

			if (bvec != NULL) {
				rc = tsocket_address_bsd_from_sockaddr(tmp_ctx,
								       (const struct sockaddr *)ifss,
								       sizeof(struct sockaddr_storage),
								       &bind_addr);
				if (rc < 0) {
					close(fd);
					status = NT_STATUS_NO_MEMORY;
					goto done;
				}

				addr = tsocket_address_inet_addr_string(bind_addr,
									tmp_ctx);
				if (addr == NULL) {
					close(fd);
					status = NT_STATUS_NO_MEMORY;
					goto done;
				}

				status = dcerpc_binding_vector_add_port(iface,
									bvec,
									addr,
									p);
				if (!NT_STATUS_IS_OK(status)) {
					close(fd);
					goto done;
				}
			}
		}
	} else {
		const char *sock_addr;
		const char *sock_ptr;
		char *sock_tok;

#ifdef HAVE_IPV6
		sock_addr = "::,0.0.0.0";
#else
		sock_addr = "0.0.0.0";
#endif

		for (sock_ptr = sock_addr;
		     next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,");
		    ) {
			struct sockaddr_storage ss;
			int fd;

			/* open an incoming socket */
			if (!interpret_string_addr(&ss,
						   sock_tok,
						   AI_NUMERICHOST|AI_PASSIVE)) {
				continue;
			}

			status = dcesrv_create_ncacn_ip_tcp_socket(&ss,
								   &p,
								   &fd);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}
			listen_fd[*listen_fd_size].fd = fd;
			listen_fd[*listen_fd_size].fd_data = NULL;
			(*listen_fd_size)++;

			if (bvec != NULL) {
				status = dcerpc_binding_vector_add_port(iface,
									bvec,
									sock_tok,
									p);
				if (!NT_STATUS_IS_OK(status)) {
					close(fd);
					goto done;
				}
			}
		}
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

NTSTATUS dcesrv_setup_ncacn_ip_tcp_sockets(struct tevent_context *ev_ctx,
					   struct messaging_context *msg_ctx,
					   struct dcesrv_context *dce_ctx,
					   struct dcesrv_endpoint *e,
					   struct dcerpc_binding_vector *bvec,
					   dcerpc_ncacn_termination_fn t_fn,
					   void *t_data)
{
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	int rc;

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		uint32_t num_ifs = iface_count();
		uint32_t i;

		/*
		 * We have been given an interfaces line, and been told to only
		 * bind to those interfaces. Create a socket per interface and
		 * bind to only these.
		 */

		/* Now open a listen socket for each of the interfaces. */
		for (i = 0; i < num_ifs; i++) {
			const struct sockaddr_storage *ifss =
					iface_n_sockaddr_storage(i);
			struct tsocket_address *bind_addr;
			const char *addr;
			const char *endpoint;
			uint16_t port = 0;

			status = dcesrv_setup_ncacn_ip_tcp_socket(ev_ctx,
								  msg_ctx,
								  dce_ctx,
								  e,
								  ifss,
								  t_fn,
								  t_data);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}

			if (bvec != NULL) {
				struct dcesrv_if_list *if_list = NULL;

				rc = tsocket_address_bsd_from_sockaddr(tmp_ctx,
								       (const struct sockaddr*)ifss,
								       sizeof(struct sockaddr_storage),
								       &bind_addr);
				if (rc < 0) {
					status = NT_STATUS_NO_MEMORY;
					goto done;
				}

				addr = tsocket_address_inet_addr_string(bind_addr,
									tmp_ctx);
				if (addr == NULL) {
					status = NT_STATUS_NO_MEMORY;
					goto done;
				}

				endpoint = dcerpc_binding_get_string_option(e->ep_description,
									    "endpoint");
				if (endpoint != NULL) {
					port = atoi(endpoint);
				}

				for (if_list = e->interface_list; if_list; if_list = if_list->next) {
					const struct ndr_interface_table *iface = NULL;
					iface = ndr_table_by_syntax(&if_list->iface->syntax_id);
					if (iface != NULL) {
						status = dcerpc_binding_vector_add_port(iface,
											bvec,
											addr,
											port);
						if (!NT_STATUS_IS_OK(status)) {
							goto done;
						}
					}
				}
			}
		}
	} else {
		const char *sock_addr;
		const char *sock_ptr;
		char *sock_tok;

#ifdef HAVE_IPV6
		sock_addr = "::,0.0.0.0";
#else
		sock_addr = "0.0.0.0";
#endif

		for (sock_ptr = sock_addr;
		     next_token_talloc(talloc_tos(), &sock_ptr, &sock_tok, " \t,");
		    ) {
			struct sockaddr_storage ss;

			/* open an incoming socket */
			if (!interpret_string_addr(&ss,
						   sock_tok,
						   AI_NUMERICHOST|AI_PASSIVE)) {
				continue;
			}

			status = dcesrv_setup_ncacn_ip_tcp_socket(ev_ctx,
								  msg_ctx,
								  dce_ctx,
								  e,
								  &ss,
								  t_fn,
								  t_data);
			if (!NT_STATUS_IS_OK(status)) {
				goto done;
			}

			if (bvec != NULL) {
				struct dcesrv_if_list *if_list = NULL;
				const char *endpoint;
				uint16_t port = 0;

				endpoint = dcerpc_binding_get_string_option(e->ep_description,
									    "endpoint");
				if (endpoint != NULL) {
					port = atoi(endpoint);
				}

				for (if_list = e->interface_list; if_list; if_list = if_list->next) {
					const struct ndr_interface_table *iface = NULL;
					iface = ndr_table_by_syntax(&if_list->iface->syntax_id);
					if (iface != NULL) {
						status = dcerpc_binding_vector_add_port(iface,
											bvec,
											sock_tok,
											port);
						if (!NT_STATUS_IS_OK(status)) {
							goto done;
						}
					}
				}
			}
		}
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
