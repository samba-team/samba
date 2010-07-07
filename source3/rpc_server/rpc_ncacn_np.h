/*
   Unix SMB/Netbios implementation.
   RPC Server Headers
   Copyright (C) Simo Sorce 2010

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

#ifndef _RPC_NCACN_NP_H_
#define _RPC_NCACN_NP_H_

struct np_proxy_state {
	uint16_t file_type;
	uint16_t device_state;
	uint64_t allocation_size;
	struct tstream_context *npipe;
	struct tevent_queue *read_queue;
	struct tevent_queue *write_queue;
};

struct np_proxy_state *make_external_rpc_pipe_p(TALLOC_CTX *mem_ctx,
				const char *pipe_name,
				const struct tsocket_address *local_address,
				const struct tsocket_address *remote_address,
				struct auth_serversupplied_info *server_info);

#endif /* _RPC_NCACN_NP_H_ */
