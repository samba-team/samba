/*
   API for reading packets using fixed and dynamic buffer

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

#ifndef __CTDB_PKT_READ_H__
#define __CTDB_PKT_READ_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file pkt_read.h
 *
 * @brief Read a packet using fixed size buffer or allocated memory.
 *
 * CTDB communication uses lots of small packets.  This abstraction avoids the
 * need to allocate memory for small packets.  Only if the received packet is
 * larger than the fixed memory buffer, use talloc to allocate memory.
 */

/**
 * @brief Start async computation to read a packet
 *
 * This returns a tevent request to read a packet from given fd.  The fd
 * should be nonblocking. Freeing this request will free all the memory
 * associated with the request.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] fd The non-blocking file/socket descriptor to read from
 * @param[in] initial Initial amount of data to read
 * @param[in] buf The static buffer to read data in
 * @param[in] buflen The size of the static buffer
 * @param[in] more The function to check if the bytes read forms a packet
 * @param[in] private_data Private data to pass to more function
 * @return new tevent request or NULL on failure
 */
struct tevent_req *pkt_read_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 int fd, size_t initial,
				 uint8_t *buf, size_t buflen,
				 ssize_t (*more)(uint8_t *buf,
						 size_t buflen,
						 void *private_data),
				 void *private_data);

/**
 * @brief Function to actually read data from the socket
 *
 * This function should be called, when tevent fd event is triggered.  This
 * function has the syntax of tevent_fd_handler_t.  The private_data for this
 * function is the tevent request created by pkt_read_send function.
 *
 * @param[in] ev Tevent context
 * @param[in] fde Tevent fd context
 * @param[in] flags Tevent fd flags
 * @param[in] req The active tevent request
 */
void pkt_read_handler(struct tevent_context *ev, struct tevent_fd *fde,
		      uint16_t flags, struct tevent_req *req);

/**
 * @brief Retrieve a packet
 *
 * This function returns the pkt read from fd.
 *
 * @param[in] req Tevent request
 * @param[in] mem_ctx Talloc memory context
 * @param[out] pbuf The pointer to the buffer
 * @param[out] free_buf Boolean to indicate that caller should free buffer
 * @param[out] perrno errno in case of failure
 * @return the size of the pkt, or -1 on failure
 *
 * If the pkt data is dynamically allocated, then it is moved under the
 * specified talloc memory context and free_buf is set to true.  It is the
 * responsibility of the caller to the free the memory returned.
 *
 * If the pkt data is stored in the fixed buffer, then free_buf is set to false.
 */
ssize_t pkt_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		      uint8_t **pbuf, bool *free_buf, int *perrno);

#endif /* __CTDB_PKT_READ_H__ */
