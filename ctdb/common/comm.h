/*
   Communication endpoint API

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

#ifndef __CTDB_COMM_H__
#define __CTDB_COMM_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file comm.h
 *
 * @brief Communication over a socket or file descriptor
 *
 * This abstraction is a wrapper around a socket or file descriptor to
 * send/receive complete packets.
 */

/**
 * @brief Packet handler function
 *
 * This function is registered while setting up communication endpoint.  Any
 * time packets are read, this function is called.
 */
typedef void (*comm_read_handler_fn)(uint8_t *buf, size_t buflen,
				     void *private_data);

/**
 * @brief Communication endpoint dead handler function
 *
 * This function is called when the communication endpoint is closed.
 */
typedef void (*comm_dead_handler_fn)(void *private_data);

/**
 * @brief Abstract struct to store communication endpoint details
 */
struct comm_context;

/**
 * @brief Initialize the communication endpoint
 *
 * This return a new communication context. Freeing this context will free all
 * memory associated with it.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] fd The socket or file descriptor
 * @param[in] read_handler The packet handler function
 * @param[in] read_private_data Private data for read handler function
 * @param[in] dead_handler The communication dead handler function
 * @param[in] dead_private_data Private data for dead handler function
 * @param[out] result The new comm_context structure
 * @return 0 on success, errno on failure
 */
int comm_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev, int fd,
	       comm_read_handler_fn read_handler, void *read_private_data,
	       comm_dead_handler_fn dead_handler, void *dead_private_data,
	       struct comm_context **result);

/**
 * @brief Async computation start to send a packet
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] comm Communication context
 * @param[in] buf The packet data
 * @param[in] buflen The size of the packet
 * @return new tevent request, or NULL on failure
 */
struct tevent_req *comm_write_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct comm_context *comm,
				   uint8_t *buf, size_t buflen);

/**
 * @brief Async computation end to send a packet
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool comm_write_recv(struct tevent_req *req, int *perr);

#endif /* __CTDB_COMM_H__ */
