/*
   CTDB failover config handling

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

#ifndef __CTDB_FAILOVER_CONF_H__
#define __CTDB_FAILOVER_CONF_H__

#include "conf/conf.h"

#define FAILOVER_CONF_SECTION "failover"

#define FAILOVER_CONF_DISABLED "disabled"
#define FAILOVER_CONF_SHUTDOWN_EXTRA_TIMEOUT "shutdown extra timeout"
#define FAILOVER_CONF_SHUTDOWN_FAILOVER_TIMEOUT "shutdown failover timeout"


void failover_conf_init(struct conf_context *conf);

#endif /* __CTDB_FAILOVER_CONF_H__ */
