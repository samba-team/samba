/*
   CTDB cluster mutex handling

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Martin Schwenke  2016

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

#ifndef __CTDB_CLUSTER_MUTEX_H__
#define __CTDB_CLUSTER_MUTEX_H__

#include <talloc.h>

#include "replace.h"
#include "system/network.h"

#include "ctdb_private.h"

struct ctdb_cluster_mutex_handle;

typedef void (*cluster_mutex_handler_t) (
	char status,
	double latency,
	void *private_data);

typedef void (*cluster_mutex_lost_handler_t) (void *private_data);

struct ctdb_cluster_mutex_handle *
ctdb_cluster_mutex(TALLOC_CTX *mem_ctx,
		   struct ctdb_context *ctdb,
		   const char *argstring,
		   int timeout,
		   cluster_mutex_handler_t handler,
		   void *private_data,
		   cluster_mutex_lost_handler_t lost_handler,
		   void *lost_data);

#endif /* __CTDB_CLUSTER_MUTEX_H__ */
