/*
   Tests support for CTDB IP allocation

   Copyright (C) Martin Schwenke 2011

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

#ifndef __IPALLOC_READ_KNOWN_IPS_H__
#define __IPALLOC_READ_KNOWN_IPS_H__

#include <stdbool.h>
#include <talloc.h>

#include "protocol/protocol.h"

struct ctdb_public_ip_list * ipalloc_read_known_ips(TALLOC_CTX *ctx,
						    int numnodes,
						    bool multi);

#endif /* __IPALLOC_READ_KNOWN_IPS_H__ */
