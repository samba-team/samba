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

#include "replace.h"
#include "system/network.h"

#include "ctdb_private.h"

struct ctdb_cluster_mutex_handle;

typedef void (*cluster_mutex_handler_t) (
	struct ctdb_context *ctdb,
	char status,
	double latency,
	struct ctdb_cluster_mutex_handle *h,
	void *private_data);

void ctdb_cluster_mutex_set_handler(struct ctdb_cluster_mutex_handle *h,
				    cluster_mutex_handler_t handler,
				    void *private_data);

struct ctdb_cluster_mutex_handle *
ctdb_cluster_mutex(struct ctdb_context *ctdb,
		   const char *argstring,
		   int timeout);

#endif /* __CTDB_IPALLOC_H__ */
