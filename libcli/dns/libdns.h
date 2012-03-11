/*
   Unix SMB/CIFS implementation.

   Small async DNS library for Samba with socketwrapper support

   Copyright (C) 2012 Kai Blin  <kai@samba.org>

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

#ifndef __LIBDNS_H__
#define __LIBDNS_H__

/** Send an dns request to a dns server using UDP
 *
 *@param mem_ctx        talloc memory context to use
 *@param ev             tevent context to use
 *@param server_address address of the server as a string
 *@param query          dns query to send
 *@param query_len      length of the query
 *@return tevent_req with the active request or NULL on out-of-memory
 */
struct tevent_req *dns_udp_request_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					const char *server_address,
					const uint8_t *query,
					size_t query_len);

/** Get the dns response from a dns server via UDP
 *
 *@param req       tevent_req struct returned from dns_request_send
 *@param mem_ctx   talloc memory context to use for the reply string
 *@param reply     buffer that will be allocated and filled with the dns reply
 *@param reply_len length of the reply buffer
 *@return WERROR code depending on the async request result
 */
WERROR dns_udp_request_recv(struct tevent_req *req,
			    TALLOC_CTX *mem_ctx,
			    uint8_t **reply,
			    size_t *reply_len);

#endif /*__LIBDNS_H__*/
