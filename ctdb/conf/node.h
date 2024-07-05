/*
   Node file loading

   Copyright (C) Martin Andrew Tridgell  2007
   Copyright (C) Martin Ronnie Sahlberg  2008, 2009
   Copyright (C) Martin Schwenke  2015
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

#ifndef __CTDB_COMMON_NODES_H__
#define __CTDB_COMMON_NODES_H__

#include <talloc.h>

#include "protocol/protocol.h"

/**
 * @brief Parse node address string, setting CTDB port
 *
 * Parse a node address string.  Set the port number to the CTDB port.
 *
 * @param[in] str Text node address
 * @param[out] address Socket address structure, already allocated
 * @return true on success, false on failure
 */
bool ctdb_parse_node_address(const char *str, ctdb_sock_addr *address);

/**
 * @brief Load node list into a node map
 *
 * Load nodes from location, into a node map, allocated off the given
 * talloc context.  Location must be a filename.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] location Location of nodes list
 * @return node map on success, NULL on failure
 */
struct ctdb_node_map *ctdb_read_nodes(TALLOC_CTX *mem_ctx,
				      const char *location);

#endif /* __CTDB_COMMON_NODES_H__ */
