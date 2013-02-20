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

NTSTATUS rpc_create_tcpip_sockets(const struct ndr_interface_table *iface,
				  struct dcerpc_binding_vector *bvec,
				  uint16_t port,
				  int *listen_fd,
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

			fd = create_tcpip_socket(ifss, &p);
			if (fd < 0 || p == 0) {
				status = NT_STATUS_UNSUCCESSFUL;
				if (fd != -1) {
					close(fd);
				}
				goto done;
			}
			listen_fd[*listen_fd_size] = fd;
			(*listen_fd_size)++;

			if (bvec != NULL) {
				rc = tsocket_address_bsd_from_sockaddr(tmp_ctx,
								       (struct sockaddr *)ifss,
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

#if HAVE_IPV6
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

			fd = create_tcpip_socket(&ss, &p);
			if (fd < 0 || p == 0) {
				status = NT_STATUS_UNSUCCESSFUL;
				if (fd != -1) {
					close(fd);
				}
				goto done;
			}
			listen_fd[*listen_fd_size] = fd;
			(*listen_fd_size)++;

			if (bvec != NULL) {
				status = dcerpc_binding_vector_add_port(iface,
									bvec,
									sock_ptr,
									p);
				if (!NT_STATUS_IS_OK(status)) {
					close(fd);
					return status;
				}
			}
		}
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

NTSTATUS rpc_setup_tcpip_sockets(struct tevent_context *ev_ctx,
				 struct messaging_context *msg_ctx,
				 const struct ndr_interface_table *iface,
				 struct dcerpc_binding_vector *bvec,
				 uint16_t port)
{
	uint32_t num_ifs = iface_count();
	uint32_t i;
	uint16_t p = 0;
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

			p = setup_dcerpc_ncacn_tcpip_socket(ev_ctx,
							    msg_ctx,
							    ifss,
							    port);
			if (p == 0) {
				status = NT_STATUS_UNSUCCESSFUL;
				goto done;
			}

			if (bvec != NULL) {
				rc = tsocket_address_bsd_from_sockaddr(tmp_ctx,
								       (struct sockaddr*)ifss,
								       sizeof(struct sockaddr_storage),
								       &bind_addr);
				if (rc < 0) {
					return NT_STATUS_NO_MEMORY;
				}

				addr = tsocket_address_inet_addr_string(bind_addr,
									tmp_ctx);
				if (addr == NULL) {
					return NT_STATUS_NO_MEMORY;
				}

				status = dcerpc_binding_vector_add_port(iface,
									bvec,
									addr,
									p);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
				}
			}
		}
	} else {
		const char *sock_addr;
		const char *sock_ptr;
		char *sock_tok;

#if HAVE_IPV6
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

			p = setup_dcerpc_ncacn_tcpip_socket(ev_ctx,
							    msg_ctx,
							    &ss,
							    port);
			if (p == 0) {
				return NT_STATUS_UNSUCCESSFUL;
			}

			if (bvec != NULL) {
				status = dcerpc_binding_vector_add_port(iface,
									bvec,
									sock_tok,
									p);
				if (!NT_STATUS_IS_OK(status)) {
					return status;
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
