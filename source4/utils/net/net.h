/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) Stefan Metzmacher 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _UTIL_NET_H
#define _UTIL_NET_H

struct net_context {
	TALLOC_CTX *mem_ctx;
	struct cli_credentials *credentials;
};

struct net_functable {
	const char *name;
	const char *desc;
	int (*fn)(struct net_context *ctx, int argc, const char **argv);
	int (*usage)(struct net_context *ctx, int argc, const char **argv);
};

#include "utils/net/net_proto.h"

#endif /* _UTIL_NET_H */
