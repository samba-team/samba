/*
   Message handler database based on srvid

   Copyright (C) Amitay Isaacs  2015

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

#ifndef __CTDB_SRVID_H__
#define __CTDB_SRVID_H__

#include <talloc.h>
#include <tdb.h>

/**
 * @file srvid.h
 *
 * @brief Database of message handlers based on srvid
 *
 * CTDB can be used to send messages between clients across nodes using
 * CTDB_REQ_MESSAGE. Clients register for messages based on srvid. CTDB itself
 * uses a small set of srvid messages. A large range (2^56) of srvid messages
 * is reserved for Samba.
 */

/**
 * @brief Message handler function
 *
 * To receive messages for a specific srvid, register a message handler function
 * for the srvid.
 */
typedef void (*srvid_handler_fn)(uint64_t srvid, TDB_DATA data,
				 void *private_data);

/**
 * @brief Abstract struct to store srvid message handler database
 */
struct srvid_context;

/**
 * @brief Initialize srvid message handler database
 *
 * This returns a new srvid message handler database context. Freeing
 * this context will free all the memory associated with the hash table.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[out] result The new db_hash_context structure
 * @return 0 on success, errno on failure
 */
int srvid_init(TALLOC_CTX *mem_ctx, struct srvid_context **result);

/**
 * @brief Register a message handler for a srvid
 *
 * The message handler is allocated using the specified talloc context. Freeing
 * this talloc context, removes the message handler.
 *
 * @param[in] srv The srvid message handler database context
 * @param[in] mem_ctx Talloc memory context for message handler
 * @param[in] srvid The srvid
 * @param[in] handler The message handler function for srvid
 * @param[in] private_data Private data for message handler function
 * @return 0 on success, errno on failure
 */
int srvid_register(struct srvid_context *srv, TALLOC_CTX *mem_ctx,
		   uint64_t srvid, srvid_handler_fn handler,
		   void *private_data);

/**
 * @brief Unregister a message handler for a srvid
 *
 * @param[in] srv The srvid message handler database context
 * @param[in] srvid The srvid
 * @param[in] private_data Private data of message handler function
 * @return 0 on success, errno on failure
 */
int srvid_deregister(struct srvid_context *srv, uint64_t srvid,
		     void *private_data);

/**
 * @brief Check if any message handler is registered for srvid
 *
 * If private_data is NULL, then check if there is any registration
 * for * specified srvid.  If private_data is not NULL, then check for
 * registration that matches the specified private data.
 *
 * @param[in] srv The srvid message handler database context
 * @param[in] srvid The srvid
 * @param[in] private_data Private data
 * @return 0 on success, errno on failure
 */
int srvid_exists(struct srvid_context *srv, uint64_t srvid,
		 void *private_data);

/**
 * @brief Call message handlers for given srvid
 *
 * @param[in] srv The srvid message handler database context
 * @param[in] srvid The srvid
 * @param[in] srvid_all The srvid that gets all messages
 * @param[in] data The data passed to each message handler
 * @return 0 on success, errno on failure
 *
 * If srvid_all passed is 0, the message is not sent to message handlers
 * registered with special srvid to receive all messages.
 */
int srvid_dispatch(struct srvid_context *srv, uint64_t srvid,
		   uint64_t srvid_all, TDB_DATA data);

#endif /* __CTDB_SRVID_H__ */
