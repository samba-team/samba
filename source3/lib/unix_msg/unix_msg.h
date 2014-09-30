/*
 * Unix SMB/CIFS implementation.
 * Copyright (C) Volker Lendecke 2013
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __UNIX_DGRAM_H__
#define __UNIX_DGRAM_H__

#include "replace.h"
#include "poll_funcs/poll_funcs.h"
#include "system/network.h"

/**
 * @file unix_msg.h
 *
 * @brief Send large messages over unix domain datagram sockets
 *
 * A unix_msg_ctx represents a unix domain datagram socket.
 *
 * Unix domain datagram sockets have some unique properties compared with UDP
 * sockets:
 *
 * - They are reliable, i.e. as long as both sender and receiver are processes
 *   that are alive, nothing is lost.
 *
 * - They preserve sequencing
 *
 * Based on these two properties, this code implements sending of large
 * messages. It aims at being maximally efficient for short, single-datagram
 * messages. Ideally, if the receiver queue is not full, sending a message
 * should be a single syscall without malloc. Receiving a message should also
 * not malloc anything before the data is shipped to the user.
 *
 * If unix_msg_send meets a full receive buffer, more effort is required: The
 * socket behind unix_msg_send is not pollable for POLLOUT, it will always be
 * writable: A datagram socket can send anywhere, the full queue is a property
 * of of the receiving socket. unix_msg_send creates a new unnamed socket that
 * it will connect(2) to the target socket. This unnamed socket is then
 * pollable for POLLOUT. The socket will be writable when the destination
 * socket's queue is drained sufficiently.
 *
 * If unix_msg_send is asked to send a message larger than fragment_size, it
 * will try sending the message in pieces with proper framing, the receiving
 * side will reassemble the messages.
 *
 * fd-passing is supported.
 * Note that by default the fds passed to recv_callback are closed by
 * the receive handler in order to avoid fd-leaks. If the provider of
 * the recv_callback wants to use a passed file descriptor after the
 * callback returns, it must copy the fd away and set the corresponding
 * entry in the "fds" array to -1.
 */

/**
 * @brief Abstract structure representing a unix domain datagram socket
 */
struct unix_msg_ctx;

/**
 * @brief Initialize a struct unix_msg_ctx
 *
 * @param[in] path The socket path
 * @param[in] ev_funcs The event callback functions to use
 * @param[in] fragment_size Maximum datagram size to send/receive
 * @param[in] cookie Random number to identify this context
 * @param[in] recv_callback Function called when a message is received
 * @param[in] private_data Private pointer for recv_callback
 * @param[out] result The new struct unix_msg_ctx
 * @return 0 on success, errno on failure
 */


int unix_msg_init(const struct sockaddr_un *addr,
		  const struct poll_funcs *ev_funcs,
		  size_t fragment_size, uint64_t cookie,
		  void (*recv_callback)(struct unix_msg_ctx *ctx,
					uint8_t *msg, size_t msg_len,
					int *fds, size_t num_fds,
					void *private_data),
		  void *private_data,
		  struct unix_msg_ctx **result);

/**
 * @brief Send a message
 *
 * @param[in] ctx The context to send across
 * @param[in] dst_sock The destination socket path
 * @param[in] iov The message
 * @param[in] iovlen The number of iov structs
 * @param[in] fds - optional fd array
 * @param[in] num_fds - fd array size
 * @return 0 on success, errno on failure
 */

int unix_msg_send(struct unix_msg_ctx *ctx, const struct sockaddr_un *dst,
		  const struct iovec *iov, int iovlen,
		  const int *fds, size_t num_fds);

/**
 * @brief Free a unix_msg_ctx
 *
 * @param[in] ctx The message context to free
 * @return 0 on success, errno on failure (EBUSY)
 */
int unix_msg_free(struct unix_msg_ctx *ctx);

#endif
