/*
 * Unix SMB/CIFS implementation.
 *
 * block SMB2 transports using iptables
 *
 * Copyright (C) Guenther Deschner, 2017
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

bool torture_list_tcp_transport_name(struct torture_context *tctx,
				    const char *name,
				    uint32_t *packets);

bool torture_block_tcp_transport_name(struct torture_context *tctx,
				      struct smb2_transport *t,
				      const char *name);

bool torture_unblock_tcp_transport_name(struct torture_context *tctx,
					struct smb2_transport *t,
					const char *name);

void torture_unblock_cleanup(struct torture_context *tctx);

uint16_t torture_get_local_port_from_transport(struct smb2_transport *t);

#define torture_block_tcp_transport(_tctx, _t) \
	torture_block_tcp_transport_name(_tctx, _t, #_t)

#define torture_unblock_tcp_transport(_tctx, _t) \
	torture_unblock_tcp_transport_name(_tctx, _t, #_t)

#define torture_list_tcp_transport(_tctx, _t, _packets) \
	torture_list_tcp_transport_name(_tctx, #_t, _packets)
