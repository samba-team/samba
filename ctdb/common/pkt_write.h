/*
   API for writing a packet

   Copyright (C) Amitay Isaacs 2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_PKT_WRITE_H__
#define __CTDB_PKT_WRITE_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file pkt_write.h
 *
 * @brief Write a packet.
 *
 * Write a complete packet with possibly multiple system calls.
 */

/**
 * @brief Start async computation to write a packet
 *
 * This returns a tevent request to write a packet to given fd.  The fd
 * should be nonblocking. Freeing this request will free all the memory
 * associated with the request.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] fd The non-blocking file/socket descriptor to write to
 * @param[in] buf The data
 * @param[in] buflen The size of the data
 * @return new tevent request or NULL on failure
 */
struct tevent_req *pkt_write_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  int fd, uint8_t *buf, size_t buflen);

/**
 * @brief Function to actually write data to the socket
 *
 * This function should be called, when tevent fd event is triggered
 * for TEVENT_FD_WRITE event.  This function has the syntax of
 * tevent_fd_handler_t.  The private_data for this function is the tevent
 * request created by pkt_write_send function.
 *
 * @param[in] ev Tevent context
 * @param[in] fde Tevent fd context
 * @param[in] flags Tevent fd flags
 * @param[in] req The active tevent request
 */
void pkt_write_handler(struct tevent_context *ev, struct tevent_fd *fde,
		       uint16_t flags, struct tevent_req *req);

/**
 * @brief Packet is sent
 *
 * This function returns the number of bytes written.
 *
 * @param[in] req Tevent request
 * @param[out] perrno errno in case of failure
 * @return the number of bytes written, or -1 on failure
 */
ssize_t pkt_write_recv(struct tevent_req *req, int *perrno);

#endif /* __CTDB_PKT_WRITE_H__ */
