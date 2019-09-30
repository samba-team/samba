/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

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

#ifndef NPA_TSTREAM_H
#define NPA_TSTREAM_H

struct tevent_req;
struct tevent_context;
struct auth_session_info_transport;
struct tsocket_address;

struct tevent_req *tstream_npa_connect_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    const char *directory,
					    const char *npipe,
					    const struct tsocket_address *remote_client_addr,
					    const char *remote_client_name_in,
					    const struct tsocket_address *local_server_addr,
					    const char *local_server_name_in,
					    const struct auth_session_info_transport *session_info);
int _tstream_npa_connect_recv(struct tevent_req *req,
			      int *perrno,
			      TALLOC_CTX *mem_ctx,
			      struct tstream_context **stream,
			      uint16_t *file_type,
			      uint16_t *device_state,
			      uint64_t *allocation_size,
			      const char *location);
#define tstream_npa_connect_recv(req, perrno, mem_ctx, stream, f, d, a) \
	_tstream_npa_connect_recv(req, perrno, mem_ctx, stream, f, d, a, \
				  __location__)

int _tstream_npa_existing_socket(TALLOC_CTX *mem_ctx,
				 int fd,
				 uint16_t file_type,
				 struct tstream_context **_stream,
				 const char *location);
#define tstream_npa_existing_socket(mem_ctx, fd, ft, stream) \
	_tstream_npa_existing_socket(mem_ctx, fd, ft, stream, \
				     __location__)


/**
 * @brief Accepts a connection for authenticated named pipes
 *
 * @param[in]  mem_ctx          The memory context for the operation
 * @param[in]  ev               The tevent_context for the operation
 * @param[in]  plain            The plain tstream_context of the bsd unix
 *                              domain socket.
 *                              This must be valid for the whole life of the
 *                              resulting npa tstream_context!
 * @param[in]  file_type        The file_type, message mode or byte mode
 * @param[in]  device_state     The reported device state
 * @param[in]  allocation_size  The reported allocation size
 *
 * @return the tevent_req handle
 */
struct tevent_req *tstream_npa_accept_existing_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *plain,
					uint16_t file_type,
					uint16_t device_state,
					uint64_t allocation_size);

/**
 * @brief The receive end of the previous async function
 *
 * @param[in]  req		The tevent_req handle
 * @param[out] perrno		Pointer to store the errno in case of error
 * @param[in]  mem_ctx		The memory context for the results
 * @param[out] stream		The resulting stream
 * @param[out] client		The resulting client address
 * @param[out] client_name	The resulting client name
 * @param[out] server		The resulting server address
 * @param[out] server_name	The resulting server name
 * @param[out] info3		The info3 auth for the connecting user.
 * @param[out] session_key	The resulting session key
 * @param[out] delegated_creds	Delegated credentials
 *
 * @return  0 if successful, -1 on failure with *perror filled.
 */
int _tstream_npa_accept_existing_recv(struct tevent_req *req,
				      int *perrno,
				      TALLOC_CTX *mem_ctx,
				      struct tstream_context **stream,
				      struct tsocket_address **remote_client_addr,
				      char **_remote_client_name,
				      struct tsocket_address **local_server_addr,
				      char **local_server_name,
				      struct auth_session_info_transport **session_info,
				      const char *location);
#define tstream_npa_accept_existing_recv(req, perrno, \
					 mem_ctx, stream, \
					 remote_client_addr, \
					 remote_client_name,  \
					 local_server_addr, \
					 local_server_name, \
					 session_info) \
	_tstream_npa_accept_existing_recv(req, perrno, \
					  mem_ctx, stream, \
					  remote_client_addr, \
					  remote_client_name,  \
					  local_server_addr, \
					  local_server_name, \
					  session_info, \
					  __location__)

int _tstream_npa_socketpair(uint16_t file_type,
			    TALLOC_CTX *mem_ctx1,
			    struct tstream_context **pstream1,
			    TALLOC_CTX *mem_ctx2,
			    struct tstream_context **pstream2,
			    const char *location);
#define tstream_npa_socketpair(ft, mem1, stream1, mem2, stream2) \
	_tstream_npa_socketpair(ft, mem1, stream1, mem2, stream2, \
				__location__)

#endif /* NPA_TSTREAM_H */
