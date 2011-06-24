/*
   Unix SMB/CIFS implementation.
   CTDB Packet handling
   Copyright (C) Volker Lendecke 2007

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

/*
 * A ctdb_packet context is a wrapper around a bidirectional file descriptor,
 * hiding the handling of individual requests.
 */

struct ctdb_packet_context;

/*
 * Initialize a ctdb_packet context. The fd is given to the ctdb_packet context, meaning
 * that it is automatically closed when the ctdb_packet context is freed.
 */
struct ctdb_packet_context *ctdb_packet_init(TALLOC_CTX *mem_ctx, int fd);

/*
 * Pull data from the fd
 */
NTSTATUS ctdb_packet_fd_read(struct ctdb_packet_context *ctx);

/*
 * Sync read, wait for the next chunk
 */
NTSTATUS ctdb_packet_fd_read_sync_timeout(struct ctdb_packet_context *ctx, int timeout);

/*
 * Handle an incoming ctdb_packet:
 * Return False if none is available
 * Otherwise return True and store the callback result in *status
 * Callback must either talloc_move or talloc_free buf
 */
bool ctdb_packet_handler(struct ctdb_packet_context *ctx,
		    bool (*full_req)(const uint8_t *buf,
				     size_t available,
				     size_t *length,
				     void *private_data),
		    NTSTATUS (*callback)(uint8_t *buf, size_t length,
					 void *private_data),
		    void *private_data,
		    NTSTATUS *status);

/*
 * How many bytes of outgoing data do we have pending?
 */
size_t ctdb_packet_outgoing_bytes(struct ctdb_packet_context *ctx);

/*
 * Push data to the fd
 */
NTSTATUS ctdb_packet_fd_write(struct ctdb_packet_context *ctx);

/*
 * Sync flush all outgoing bytes
 */
NTSTATUS ctdb_packet_flush(struct ctdb_packet_context *ctx);

/*
 * Send a list of DATA_BLOBs
 *
 * Example:  ctdb_packet_send(ctx, 2, data_blob_const(&size, sizeof(size)),
 *			 data_blob_const(buf, size));
 */
NTSTATUS ctdb_packet_send(struct ctdb_packet_context *ctx, int num_blobs, ...);

/*
 * Get the ctdb_packet context's file descriptor
 */
int ctdb_packet_get_fd(struct ctdb_packet_context *ctx);
