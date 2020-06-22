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

uint16_t torture_get_local_port_from_transport(struct smb2_transport *t);

bool torture_block_tcp_output_port(struct torture_context *tctx,
				   const char *name,
				   uint16_t port);
bool torture_unblock_tcp_output_port(struct torture_context *tctx,
				     const char *name,
				     uint16_t port);
bool torture_block_tcp_output_setup(struct torture_context *tctx);
bool torture_unblock_tcp_output_cleanup(struct torture_context *tctx);

bool test_setup_blocked_transports(struct torture_context *tctx);
void test_cleanup_blocked_transports(struct torture_context *tctx);

#define test_block_smb2_transport(_tctx, _t) _test_block_smb2_transport(_tctx, _t, #_t)
bool _test_block_smb2_transport(struct torture_context *tctx,
				struct smb2_transport *transport,
				const char *name);
#define test_unblock_smb2_transport(_tctx, _t) _test_unblock_smb2_transport(_tctx, _t, #_t)
bool _test_unblock_smb2_transport(struct torture_context *tctx,
				  struct smb2_transport *transport,
				  const char *name);
