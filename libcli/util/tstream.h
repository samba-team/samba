/*
 *  Unix SMB/CIFS implementation.
 *
 *  Copyright (C) Stefan Metzmacher 2009
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

#ifndef _LIBCLI_UTIL_TSTREAM_H_
#define _LIBCLI_UTIL_TSTREAM_H_

/**
 * @brief A helper function to read a full PDU from a stream
 *
 * This function is designed for simple PDUs and as compat layer
 * for the Samba4 packet interface.
 *
 * tstream_readv_pdu_send() is a more powerful interface,
 * which is part of the main (non samba specific) tsocket code.
 *
 * @param[in] mem_ctx		The memory context for the result.
 *
 * @param[in] ev		The event context the operation should work on.
 *
 * @param[in] stream		The stream to read data from.
 *
 * @param[in] inital_read_size	The initial byte count that is needed to workout
 *				the full pdu size.
 *
 * @param[in] full_fn		The callback function that will report the size
 *				of the full pdu.
 *
 * @param[in] full_private	The private data for the callback function.
 *
 * @return			The async request handle. NULL on fatal error.
 *
 * @see tstream_read_pdu_blob_recv()
 * @see tstream_readv_pdu_send()
 * @see tstream_readv_pdu_queue_send()
 *
 */
struct tevent_req *tstream_read_pdu_blob_send(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct tstream_context *stream,
				size_t inital_read_size,
				NTSTATUS (*full_fn)(void *private_data,
						    DATA_BLOB blob,
						    size_t *packet_size),
				void *full_private);
/**
 * @brief Receive the result of the tstream_read_pdu_blob_send() call.
 *
 * @param[in] req	The tevent request from tstream_read_pdu_blob_send().
 *
 * @param[in] mem_ctx	The memory context for returned pdu DATA_BLOB.
 *
 * @param[in] pdu_blob	The DATA_BLOB with the full pdu.
 *
 * @return		The NTSTATUS result, NT_STATUS_OK on success
 *			and others on failure.
 *
 * @see tstream_read_pdu_blob_send()
 */
NTSTATUS tstream_read_pdu_blob_recv(struct tevent_req *req,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *pdu_blob);

#endif /* _LIBCLI_UTIL_TSTREAM_H_ */
