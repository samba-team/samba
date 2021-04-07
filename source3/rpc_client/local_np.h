/*
 *  Unix SMB/CIFS implementation.
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

#ifndef _LOCAL_NP_H_
#define _LOCAL_NP_H_

#include <replace.h>
#include "lib/tsocket/tsocket.h"
#include "librpc/rpc/rpc_common.h"

struct auth_session_info;

struct tevent_req *local_np_connect_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const char *pipename,
	enum dcerpc_transport_t transport,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	bool need_idle_server);

int local_np_connect_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	struct tstream_context **pstream);

int local_np_connect(
	const char *pipename,
	enum dcerpc_transport_t transport,
	const char *remote_client_name,
	const struct tsocket_address *remote_client_addr,
	const char *local_server_name,
	const struct tsocket_address *local_server_addr,
	const struct auth_session_info *session_info,
	bool need_idle_server,
	TALLOC_CTX *mem_ctx,
	struct tstream_context **stream);

#endif /* _LOCAL_NP_H_ */
