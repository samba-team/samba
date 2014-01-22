/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010

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

#ifndef _CLI_NP_TSTREAM_H_
#define _CLI_NP_TSTREAM_H_

struct tevent_context;
struct tevent_req;
struct tstream_context;
struct smbXcli_conn;
struct smbXcli_session;
struct smbXcli_tcon;

struct tevent_req *tstream_smbXcli_np_open_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon,
						uint16_t pid,
						unsigned int timeout,
						const char *npipe);
NTSTATUS _tstream_smbXcli_np_open_recv(struct tevent_req *req,
				       TALLOC_CTX *mem_ctx,
				       struct tstream_context **_stream,
				       const char *location);
#define tstream_smbXcli_np_open_recv(req, mem_ctx, stream) \
		_tstream_smbXcli_np_open_recv(req, mem_ctx, stream, __location__)

bool tstream_is_smbXcli_np(struct tstream_context *stream);

NTSTATUS tstream_smbXcli_np_use_trans(struct tstream_context *stream);

unsigned int tstream_smbXcli_np_set_timeout(struct tstream_context *stream,
					    unsigned int timeout);

/*
 * Windows uses 4280 (the max xmit/recv size negotiated on DCERPC).
 * This is fits into the max_xmit negotiated at the SMB layer.
 *
 * On the sending side they may use SMBtranss if the request does not
 * fit into a single SMBtrans call.
 *
 * Windows uses 1024 as max data size of a SMBtrans request and then
 * possibly reads the rest of the DCERPC fragment (up to 3256 bytes)
 * via a SMBreadX.
 *
 * For now we just ask for the full 4280 bytes (max data size) in the SMBtrans
 * request to get the whole fragment at once (like samba 3.5.x and below did.
 *
 * It is important that we use do SMBwriteX with the size of a full fragment,
 * otherwise we may get NT_STATUS_PIPE_BUSY on the SMBtrans request
 * from NT4 servers. (See bug #8195)
 */
#define TSTREAM_SMBXCLI_NP_MAX_BUF_SIZE 4280

#endif /*  _CLI_NP_TSTREAM_H_ */
