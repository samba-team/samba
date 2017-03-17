/*
   Using tdb as a hash table

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

#ifndef __CTDB_DB_HASH_H__
#define __CTDB_DB_HASH_H__

#include <talloc.h>
#include <tdb.h>

/**
 * @file db_hash.h
 *
 * @brief Use tdb database as a hash table
 *
 * This uses in-memory tdb databases to create a fixed sized hash table.
 */

/**
 * @brief Hash type to indicate the hashing function to use.
 *
 * DB_HASH_SIMPLE uses default hashing function
 * DB_HASH_COMPLEX uses jenkins hashing function
 */
enum db_hash_type {
	DB_HASH_SIMPLE,
	DB_HASH_COMPLEX,
};

/**
 * @brief Parser callback function called when fetching a record
 *
 * This function is called when fetching a record. This function should
 * not modify key and data arguments.
 *
 * The function should return 0 on success and errno on error.
 */
typedef int (*db_hash_record_parser_fn)(uint8_t *keybuf, size_t keylen,
					uint8_t *databuf, size_t datalen,
					void *private_data);

/**
 * @brief Abstract structure representing tdb hash table
 */
struct db_hash_context;

/**
 * @brief Initialize tdb hash table
 *
 * This returns a new tdb hash table context which is a talloc context.  Freeing
 * this context will free all the memory associated with the hash table.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] name The name for the hash table
 * @param[in] hash_size The size of the hash table
 * @param[in] type The type of hashing function to use
 * @param[out] result The new db_hash_context structure
 * @return 0 on success, errno on failure
 */
int db_hash_init(TALLOC_CTX *mem_ctx, const char *name, int hash_size,
		 enum db_hash_type type, struct db_hash_context **result);

/**
 * @brief Insert a record into the hash table
 *
 * The key and data can be any binary data.  Insert only if the record does not
 * exist.  If the record already exists, return error.
 *
 * @param[in] dh The tdb hash table context
 * @param[in] keybuf The key buffer
 * @param[in] keylen The key length
 * @param[in] databuf The data buffer
 * @param[in] datalen The data length
 * @return 0 on success, errno on failure
 */
int db_hash_insert(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		   uint8_t *databuf, size_t datalen);

/**
 * @brief Add a record into the hash table
 *
 * The key and data can be any binary data.  If the record does not exist,
 * insert the record.  If the record already exists, replace the record.
 *
 * @param[in] dh The tdb hash table context
 * @param[in] keybuf The key buffer
 * @param[in] keylen The key length
 * @param[in] databuf The data buffer
 * @param[in] datalen The data length
 * @return 0 on success, errno on failure
 */
int db_hash_add(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		uint8_t *databuf, size_t datalen); 
/**
 * @brief Delete a record from the hash table
 *
 * @param[in] dh The tdb hash table context
 * @param[in] keybuf The key buffer
 * @param[in] keylen The key length
 * @return 0 on success, errno on failure
 */
int db_hash_delete(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen);

/**
 * @brief Fetch a record from the hash table
 *
 * The key and data can be any binary data.
 *
 * @param[in] dh The tdb hash table context
 * @param[in] keybuf The key buffer
 * @param[in] keylen The key length
 * @param[in] parser Function called when the matching record is found
 * @param[in] private_data Private data to parser function
 * @return 0 on success, errno on failure
 */
int db_hash_fetch(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen,
		  db_hash_record_parser_fn parser, void *private_data);

/**
 * @brief Check if a record exists in the hash table
 *
 * @param[in] dh The tdb hash table context
 * @param[in] keybuf The key buffer
 * @param[in] keylen The key length
 * @return 0 if the record exists, errno on failure
 */
int db_hash_exists(struct db_hash_context *dh, uint8_t *keybuf, size_t keylen);

/**
 * @brief Traverse the database without modification
 *
 * The parser function should return non-zero value to stop traverse.
 *
 * @param[in] dh The tdb hash table context
 * @param[in] parser Function called for each record
 * @param[in] private_data Private data to parser function
 * @param[out] count Number of records traversed
 * @return 0 on success, errno on failure
 */
int db_hash_traverse(struct db_hash_context *dh,
		     db_hash_record_parser_fn parser, void *private_data,
		     int *count);

/**
 * @brief Traverse the database for modifications
 *
 * The parser function should return non-zero value to stop traverse.
 *
 * @param[in] dh The tdb hash table context
 * @param[in] parser Function called for each record
 * @param[in] private_data Private data to parser function
 * @param[out] count Number of records traversed
 * @return 0 on success, errno on failure
 */
int db_hash_traverse_update(struct db_hash_context *dh,
			    db_hash_record_parser_fn parser,
			    void *private_data, int *count);

#endif /* __CTDB_DB_HASH_H__ */
