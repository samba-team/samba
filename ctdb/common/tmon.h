/*
   Trivial FD monitoring

   Copyright (C) Martin Schwenke & Amitay Isaacs, DataDirect Networks  2022

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

#ifndef __CTDB_TMON_H__
#define __CTDB_TMON_H__

#include <talloc.h>
#include <tevent.h>

/**
 * @file tmon.h
 *
 * @brief Interprocess file descriptor (pipe and socketpair) monitoring
 *
 * Assumes 2 processes connected by a pipe(2) or a socketpair(2).  A
 * simple protocol is defined to allow sending various types of status
 * information.  When a pipe(2) is used the reader can monitor for
 * close and read packets, while the sender can write packets. When a
 * socketpair(2) is used then both ends can monitor for close, and
 * read and write packets.  A read timeout can be specified,
 * terminating the computation if no packets are received.
 *
 * A simplified interface is provided to monitor for close and allow
 * sending/monitoring of one-way ping packets.  A ping timeout occurs
 * when one end is expecting pings but none are received during the
 * timeout interval - no response is sent to pings, they merely reset
 * a timer on the receiving end.
 */

struct tmon_pkt;

struct tmon_actions {
	int (*write_callback)(void *private_data, struct tmon_pkt *pkt);
	int (*timeout_callback)(void *private_data);
	int (*read_callback)(void *private_data, struct tmon_pkt *pkt);
	int (*close_callback)(void *private_data);
};

/*
 * Return value from write_callback() and read_callback() to cause the
 * computation to exit successfully.  For consistency this can also be
 * used with timeout_callback() and close_callback().
 */
#define TMON_STATUS_EXIT (-1)

/* Return value from write_callback() to skip write */
#define TMON_STATUS_SKIP (-2)

/* For direction, below */
#define TMON_FD_READ  0x1
#define TMON_FD_WRITE 0x2
#define TMON_FD_BOTH  (TMON_FD_READ | TMON_FD_WRITE)

/**
 * @brief Async computation to start FD monitoring
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] fd File descriptor for "this" end of pipe/socketpair
 * @param[in] direction Read, write or both - for sanity checking
 * @param[in] read_timeout Seconds to trigger timeout when no packets received
 * @param[in] write_interval Seconds to trigger write_callback
 * @param[in] actions struct containing callbacks
 * @param[in] private_data Passed to callbacks
 * @return new tevent request or NULL on failure
 *
 * @note read_timeout implies monitor_close
 *
 * @note The computation will complete when:
 *
 * - The writing end closes (e.g. writer process terminates) - EPIPE
 * - read_timeout is non-zero and timeout occurs - ETIMEDOUT
 * - Packets received with no read_callback defined - EIO
 * - Invalid or unexpected packet received - EPROTO
 * - File descriptor readable but no bytes to read - error: EPIPE
 * - Invalid combination of direction, callbacks, timeouts: EINVAL
 * - An unexpected error occurs - other
 *
 * @note action callbacks return an int that can be used to trigger
 * other errors or override an error.  For example:
 *
 * - write_callback() can return non-zero errno, causing an error
 * - close_callback() can return zero, overriding the default EPIPE error
 * - timeout_callback() can return something other than ETIMEDOUT
 * - read_callback() can return EPROTO for unexpected packet types
 *
 * Reading of exit and errno packets is handled internally (read
 * callback is never called).  Write callback can return special
 * value TMON_STATUS_SKIP to avoid sending any data.
 */
struct tevent_req *tmon_send(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev,
			     int fd,
			     int direction,
			     unsigned long read_timeout,
			     unsigned long write_interval,
			     struct tmon_actions *actions,
			     void *private_data);

/**
 * @brief Async computation to end FD monitoring
 *
 * @param[in] req Tevent request
 * @param[out] perr errno in case of failure
 * @return true on success, false on failure
 */
bool tmon_recv(struct tevent_req *req, int *perr);

/**
 * @brief Fill in an exit packet
 *
 * @param[in,out] pkt An exit packet
 * @return true on success, false on failure
 */
bool tmon_set_exit(struct tmon_pkt *pkt);
/**
 * @brief Fill in an errno packet
 *
 * @param[in,out] pkt An errno packet
 * @param[in] err An errno to send in packet
 * @return true on success, false on failure
 */
bool tmon_set_errno(struct tmon_pkt *pkt, int err);
/**
 * @brief Fill in a ping packet
 *
 * @param[in,out] pkt A ping packet
 * @return true on success, false on failure
 */
bool tmon_set_ping(struct tmon_pkt *pkt);
/**
 * @brief Fill in an ASCII packet
 *
 * @param[in,out] pkt An ASCII packet
 * @param[in] c An ASCII character to send in packet
 * @return true on success, false on failure
 */
bool tmon_set_ascii(struct tmon_pkt *pkt, char c);
/**
 * @brief Fill in a custom packet
 *
 * @param[in,out] pkt A custom packet
 * @param[in] val A uint16_t to send in a custom packet
 * @return true on success, false on failure
 */
bool tmon_set_custom(struct tmon_pkt *pkt, uint16_t val);

/**
 * @brief Validate a ping packet
 *
 * @param[in] pkt A ping packet
 * @return true on success, false on failure
 */
bool tmon_parse_ping(struct tmon_pkt *pkt);

/**
 * @brief Validate ASCII packet and parse out character
 *
 * @param[in] pkt An ASCII packet
 * @param[out] c An ASCII character value from packet
 * @return true on success, false on failure
 */
bool tmon_parse_ascii(struct tmon_pkt *pkt, char *c);

/**
 * @brief Validate custom packet and parse out value
 *
 * @param[in] pkt A custom packet
 * @param[out] val A uint16_t value from packet
 * @return true on success, false on failure
 */
bool tmon_parse_custom(struct tmon_pkt *pkt, uint16_t *val);

/**
 * @brief Write a packet
 *
 * @param[in] req Tevent request created by tmon_send
 * @param[in] pkt Packet to write
 * @return true on success, false on failure
 */
bool tmon_write(struct tevent_req *req, struct tmon_pkt *pkt);

/**
 * @brief Async computation to start ping monitoring
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] ev Tevent context
 * @param[in] fd File descriptor for "this" end of pipe/socketpair
 * @param[in] direction Read, write or both - for sanity checking
 * @param[in] timeout Timeout for pings on receiving end
 * @param[in] interval Send a ping packet every interval seconds
 */
struct tevent_req *tmon_ping_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  int fd,
				  int direction,
				  unsigned long timeout,
				  unsigned long interval);

bool tmon_ping_recv(struct tevent_req *req, int *perr);

#endif /* __CTDB_TMON_H__ */
