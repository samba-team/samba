/*
   CTDB cluster config handling

   Copyright (C) Martin Schwenke  2018

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

#ifndef __CTDB_CLUSTER_CONF_H__
#define __CTDB_CLUSTER_CONF_H__

#include <talloc.h>

#include "conf/conf.h"

#define CLUSTER_CONF_SECTION "cluster"

#define CLUSTER_CONF_TRANSPORT       "transport"
#define CLUSTER_CONF_NODE_ADDRESS    "node address"
#define CLUSTER_CONF_CLUSTER_LOCK    "cluster lock"
#define CLUSTER_CONF_RECOVERY_LOCK   "recovery lock"
#define CLUSTER_CONF_NODES_LIST      "nodes list"
#define CLUSTER_CONF_LEADER_TIMEOUT  "leader timeout"
#define CLUSTER_CONF_LEADER_CAPABILITY "leader capability"

void cluster_conf_init(struct conf_context *conf);

/**
 * @brief Return the value of the nodes list configuration parameter.
 *
 * This function is used to fetch the value set in the ctdb.conf (or equivalent)
 * for 'nodes list' a value that is then used to fetch the actual nodes list
 * of private node addresses. If a value is not present in the configuration
 * file a backwards compatible default value will be returned.
 *
 * @param[in] mem_ctx  TALLOC memory context
 * @param[in] conf  A configuration context
 * @return string or NULL on memory allocation error
 */
char *cluster_conf_nodes_list(TALLOC_CTX *mem_ctx, struct conf_context *conf);

#endif /* __CTDB_CLUSTER_CONF_H__ */
