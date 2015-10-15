/*
   Request id database

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

#ifndef __CTDB_REQID_H__
#define __CTDB_REQID_H__

#include <talloc.h>

/**
 * @file reqid.h
 *
 * @brief Request id database
 *
 * CTDB tracks messsages using request id. CTDB stores client state for each
 * request id to process the replies correctly.
 */

/**
 * @brief Abstract struct to store request id database
 */
struct reqid_context;

#define REQID_INVALID	0xffffffff

/**
 * @brief Initialize request id database
 *
 * This returns a new request id context. Freeing this context will free
 * all the memory associated with request id database.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] start_id The initial id
 * @param[out] result The new talloc_context structure
 * @return 0 on success, errno on failure
 */
int reqid_init(TALLOC_CTX *mem_ctx, int start_id,
	       struct reqid_context **result);

/**
 * @brief Generate new request id and associate given data with the request id
 *
 * @param[in] reqid_ctx The request id context
 * @param[in] private_data The state to associate with new request id
 * @return new request id, REQID_INVALID on failure
 */
uint32_t reqid_new(struct reqid_context *reqid_ctx, void *private_data);

#ifdef DOXYGEN
/**
 * @brief Fetch the data associated with the request id
 *
 * @param[in] reqid_ctx The request id context
 * @param[in] reqid The request id
 * @param[in] type The data type of the stored data
 * @return the data stored for the reqid, NULL on failure
 */
type *reqid_find(struct reqid_context *reqid_ctx, uint32_t reqid, #type);
#else
void *_reqid_find(struct reqid_context *reqid_ctx, uint32_t reqid);
#define reqid_find(ctx, reqid, type) \
	(type *)talloc_check_name(_reqid_find(ctx, reqid), #type)
#endif

/**
 * @brief Remove the data associated with the request id
 *
 * @param[in] reqid_ctx The request id context
 * @param[in] reqid The request id
 * @return 0 on success, errno on failure
 */
int reqid_remove(struct reqid_context *reqid_ctx, uint32_t reqid);

#endif /* __CTDB_REQID_H__ */
