/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Stefan Metzmacher 2025
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LIBSMB_SMBSOCK_CONNECT_H_
#define _LIBSMB_SMBSOCK_CONNECT_H_

struct smbXcli_transport;

/* The following definitions come from libsmb/smbsock_connect.c */

struct smb_transports smbsock_transports_from_port(uint16_t port);

struct tevent_req *smbsock_connect_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct loadparm_context *lp_ctx,
					const struct sockaddr_storage *addr,
					const struct smb_transports *transports,
					const char *called_name,
					int called_type,
					const char *calling_name,
					int calling_type)
	NONNULL(2) NONNULL(3) NONNULL(4) NONNULL(5);
NTSTATUS smbsock_connect_recv(struct tevent_req *req, int *sock,
			      uint16_t *ret_port);
NTSTATUS smbsock_connect(const struct sockaddr_storage *addr,
			 struct loadparm_context *lp_ctx,
			 const struct smb_transports *transports,
			 const char *called_name, int called_type,
			 const char *calling_name, int calling_type,
			 int *pfd, uint16_t *ret_port, int sec_timeout)
	NONNULL(1) NONNULL(2) NONNULL(3) NONNULL(8);

struct tevent_req *smbsock_any_connect_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct loadparm_context *lp_ctx,
					    const struct sockaddr_storage *addrs,
					    const char **called_names,
					    int *called_types,
					    const char **calling_names,
					    int *calling_types,
					    size_t num_addrs,
					    const struct smb_transports *transports)
	NONNULL(2) NONNULL(3) NONNULL(4) NONNULL(10);
NTSTATUS smbsock_any_connect_recv(struct tevent_req *req, int *pfd,
				  size_t *chosen_index, uint16_t *chosen_port);
NTSTATUS smbsock_any_connect(const struct sockaddr_storage *addrs,
			     const char **called_names,
			     int *called_types,
			     const char **calling_names,
			     int *calling_types,
			     size_t num_addrs,
			     struct loadparm_context *lp_ctx,
			     const struct smb_transports *transports,
			     int sec_timeout,
			     TALLOC_CTX *mem_ctx,
			     struct smbXcli_transport **ptransport,
			     size_t *chosen_index)
	NONNULL(1) NONNULL(7) NONNULL(8) NONNULL(11);

#endif /* _LIBSMB_SMBSOCK_CONNECT_H_ */
