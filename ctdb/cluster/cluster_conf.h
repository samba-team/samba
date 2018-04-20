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

#include "common/conf.h"

#define CLUSTER_CONF_SECTION "cluster"

#define CLUSTER_CONF_TRANSPORT       "transport"
#define CLUSTER_CONF_NODE_ADDRESS    "node address"
#define CLUSTER_CONF_RECOVERY_LOCK   "recovery lock"

void cluster_conf_init(struct conf_context *conf);

#endif /* __CTDB_CLUSTER_CONF_H__ */
