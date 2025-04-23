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
#include "librpc/rpc/dcesrv_core.h"
#include "rpc_server/rpc_sock_helper.h"
#include "librpc/ndr/ndr_table.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

static NTSTATUS dcesrv_create_ncacn_np_socket(
	struct dcerpc_binding *b, int *out_fd)
{
	char *np_dir = NULL;
	int fd = -1;
	NTSTATUS status;
	const char *endpoint;
	char *endpoint_normalized = NULL;
	char *p = NULL;

	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	if (endpoint == NULL) {
		DBG_ERR("Endpoint mandatory for named pipes\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* The endpoint string from IDL can be mixed uppercase and case is
	 * normalized by smbd on connection */
	endpoint_normalized = strlower_talloc(talloc_tos(), endpoint);
	if (endpoint_normalized == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* The endpoint string from IDL can be prefixed by \pipe\ */
	p = endpoint_normalized;
	if (strncmp(p, "\\pipe\\", 6) == 0) {
		p += 6;
	}

	/*
	 * As lp_ncalrpc_dir() should have 0755, but
	 * lp_ncalrpc_dir()/np should have 0700, we need to
	 * create lp_ncalrpc_dir() first.
	 */
	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create pipe directory %s - %s\n",
			lp_ncalrpc_dir(), strerror(errno));
		goto out;
	}

	np_dir = talloc_asprintf(talloc_tos(), "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		status = NT_STATUS_NO_MEMORY;
		DBG_ERR("Out of memory\n");
		goto out;
	}

	if (!directory_create_or_exist_strict(np_dir, geteuid(), 0700)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create pipe directory %s - %s\n",
			np_dir, strerror(errno));
		goto out;
	}

	fd = create_pipe_sock(np_dir, p, 0700);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncacn_np socket! '%s/%s': %s\n",
			np_dir, p, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened pipe socket fd %d for %s\n", fd, p);

	*out_fd = fd;

	status = NT_STATUS_OK;

out:
	TALLOC_FREE(endpoint_normalized);
	TALLOC_FREE(np_dir);
	return status;
}

/********************************************************************
 * Start listening on the tcp/ip socket
 ********************************************************************/

static NTSTATUS dcesrv_create_ncacn_ip_tcp_socket(
	const struct sockaddr_storage *ifss,
	uint16_t port,
	bool rebind,
	int *out_fd)
{
	int fd = -1;

	fd = open_socket_in(SOCK_STREAM, ifss, port, rebind);
	if (fd < 0) {
		DBG_ERR("Failed to create socket on port %u!\n", port);
		return map_nt_error_from_unix(-fd);
	}

	/* ready to listen */
	set_socket_options(fd, "SO_KEEPALIVE");
	set_socket_options(fd, lp_socket_options());

	DBG_DEBUG("Opened ncacn_ip_tcp socket fd %d for port %u\n", fd, port);

	*out_fd = fd;

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_create_ncacn_ip_tcp_sockets(
	struct dcerpc_binding *b,
	TALLOC_CTX *mem_ctx,
	size_t *pnum_fds,
	int **pfds)
{
	static uint16_t next_low_port;
	static uint16_t conf_high_port;
	uint16_t port = 0;
	uint16_t highest_port = 0;
	char port_str[11];
	const char *endpoint = NULL;
	size_t i = 0, num_fds;
	int *fds = NULL;
	struct samba_sockaddr *addrs = NULL;
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	bool rebind = false;
	bool ok;

	if (next_low_port == 0) {
		next_low_port = lp_rpc_low_port();
		conf_high_port = lp_rpc_high_port();
	}

	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	if (endpoint != NULL) {
		port = atoi(endpoint);
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		num_fds = iface_count();
	} else {
		num_fds = 1;
#ifdef HAVE_IPV6
		num_fds += 1;
#endif
	}

	addrs = talloc_array(mem_ctx, struct samba_sockaddr, num_fds);
	if (addrs == NULL) {
		num_fds = 0; /* nothing to close */
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	fds = talloc_array(mem_ctx, int, num_fds);
	if (fds == NULL) {
		num_fds = 0; /* nothing to close */
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	for (i=0; i<num_fds; i++) {
		fds[i] = -1;
	}

	/*
	 * Fill "addrs"
	 */

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		for (i=0; i<num_fds; i++) {
			const struct sockaddr_storage *ifss =
				iface_n_sockaddr_storage(i);

			ok = sockaddr_storage_to_samba_sockaddr(
				&addrs[i], ifss);
			if (!ok) {
				goto fail;
			}
		}
	} else {
		struct sockaddr_storage ss = { .ss_family = 0 };

#ifdef HAVE_IPV6
		ok = interpret_string_addr(
			&ss, "::", AI_NUMERICHOST|AI_PASSIVE);
		if (!ok) {
			goto fail;
		}
		ok = sockaddr_storage_to_samba_sockaddr(&addrs[0], &ss);
		if (!ok) {
			goto fail;
		}
#endif
		ok = interpret_string_addr(
			&ss, "0.0.0.0", AI_NUMERICHOST|AI_PASSIVE);
		if (!ok) {
			goto fail;
		}

		/* num_fds set above depending on HAVE_IPV6 */
		ok = sockaddr_storage_to_samba_sockaddr(
			&addrs[num_fds-1], &ss);
		if (!ok) {
			goto fail;
		}
	}

	if (port != 0) {
		rebind = true;
		highest_port = port;
	} else {
		rebind = false;
		port = next_low_port;
		highest_port = conf_high_port;
	}

	for (; port <= highest_port; port += 1) {
		for (i=0; i<num_fds; i++) {
			status = dcesrv_create_ncacn_ip_tcp_socket(
						&addrs[i].u.ss,
						port,
						rebind,
						&fds[i]);
			if (NT_STATUS_EQUAL(status,
			    NT_STATUS_ADDRESS_ALREADY_ASSOCIATED))
			{
				break;
			}
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
			samba_sockaddr_set_port(&addrs[i], port);
		}

		if (port == next_low_port) {
			next_low_port += 1;
		}

		if (i == num_fds) {
			/*
			 * We were able to bind to the same port on all
			 * addresses
			 */
			break;
		}

		/*
		 * The port was not available on at least one address, so close
		 * them all and try the next port or return the error.
		 */
		for (i=0; i<num_fds; i++) {
			if (fds[i] == -1) {
				continue;
			}
			close(fds[i]);
			fds[i] = -1;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	/* Set the port in the endpoint */
	snprintf(port_str, sizeof(port_str), "%"PRIu16, port);

	status = dcerpc_binding_set_string_option(b, "endpoint", port_str);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("Failed to set binding endpoint '%s': %s\n",
			port_str, nt_errstr(status));
		goto fail;
	}

	TALLOC_FREE(addrs);

	*pfds = fds;
	*pnum_fds = num_fds;

	return NT_STATUS_OK;

fail:
	for (i=0; i<num_fds; i++) {
		if (fds[i] == -1) {
			continue;
		}
		close(fds[i]);
		fds[i] = -1;
	}
	TALLOC_FREE(fds);
	TALLOC_FREE(addrs);
	return status;
}

/********************************************************************
 * Start listening on the ncalrpc socket
 ********************************************************************/

static NTSTATUS dcesrv_create_ncalrpc_socket(
	struct dcerpc_binding *b, int *out_fd)
{
	int fd = -1;
	const char *endpoint = NULL;
	NTSTATUS status;

	endpoint = dcerpc_binding_get_string_option(b, "endpoint");
	if (endpoint == NULL) {
		/*
		 * No identifier specified: use DEFAULT or SMBD.
		 *
		 * When role is AD DC we run two rpc server instances, the one
		 * started by 'samba' and the one embedded in 'smbd'.
		 * Avoid listening in DEFAULT socket for NCALRPC as both
		 * servers will race to accept connections. In this case smbd
		 * will listen in SMBD socket and rpcint binding handle
		 * implementation will pick the right socket to use.
		 *
		 * TODO: DO NOT hardcode this value anywhere else. Rather,
		 * specify no endpoint and let the epmapper worry about it.
		 */
		if (lp_server_role() == ROLE_ACTIVE_DIRECTORY_DC) {
			endpoint = "SMBD";
		} else {
			endpoint = "DEFAULT";
		}
		status = dcerpc_binding_set_string_option(
			b, "endpoint", endpoint);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("Failed to set ncalrpc 'endpoint' binding "
				"string option to '%s': %s\n",
				endpoint, nt_errstr(status));
			return status;
		}
	}

	if (!directory_create_or_exist(lp_ncalrpc_dir(), 0755)) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc directory '%s': %s\n",
			lp_ncalrpc_dir(), strerror(errno));
		goto out;
	}

	fd = create_pipe_sock(lp_ncalrpc_dir(), endpoint, 0755);
	if (fd == -1) {
		status = map_nt_error_from_unix_common(errno);
		DBG_ERR("Failed to create ncalrpc socket '%s/%s': %s\n",
			lp_ncalrpc_dir(), endpoint, strerror(errno));
		goto out;
	}

	DBG_DEBUG("Opened ncalrpc socket fd '%d' for '%s/%s'\n",
		  fd, lp_ncalrpc_dir(), endpoint);

	*out_fd = fd;

	return NT_STATUS_OK;

out:
	return status;
}

NTSTATUS dcesrv_create_binding_sockets(
	struct dcerpc_binding *b,
	TALLOC_CTX *mem_ctx,
	size_t *pnum_fds,
	int **pfds)
{
	enum dcerpc_transport_t transport = dcerpc_binding_get_transport(b);
	size_t i, num_fds = 1;
	int *fds = NULL;
	NTSTATUS status;

	if ((transport == NCALRPC) || (transport == NCACN_NP)) {
		fds = talloc(mem_ctx, int);
		if (fds == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	switch(transport) {
	case NCALRPC:
		status = dcesrv_create_ncalrpc_socket(b, fds);
		break;
	case NCACN_NP:
		status = dcesrv_create_ncacn_np_socket(b, fds);
		break;
	case NCACN_IP_TCP:
		status = dcesrv_create_ncacn_ip_tcp_sockets(
			b, talloc_tos(), &num_fds, &fds);
		break;
	default:
		status = NT_STATUS_NOT_SUPPORTED;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(fds);
		return status;
	}

	for (i=0; i<num_fds; i++) {
		bool ok = smb_set_close_on_exec(fds[i]);
		if (!ok) {
			status = map_nt_error_from_unix(errno);
			break;
		}
	}
	if (i < num_fds) {
		for (i=0; i<num_fds; i++) {
			close(fds[i]);
		}
		TALLOC_FREE(fds);
		return status;
	}

	*pfds = fds;
	*pnum_fds = num_fds;
	return NT_STATUS_OK;
}

/* vim: set ts=8 sw=8 noet cindent syntax=c.doxygen: */
