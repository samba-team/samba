/* 
   Samba Unix/Linux SMB client library 
   Distributed SMB/CIFS Server Management Utility 

   Copyright (C) Stefan Metzmacher 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _UTIL_NET_H
#define _UTIL_NET_H

struct net_context {
	TALLOC_CTX *mem_ctx;
	struct {
		const char *account_name;
		const char *domain_name;
		const char *password;
	} user;
};

struct net_functable {
	const char *name;
	int (*fn)(struct net_context *ctx, int argc, const char **argv);
	int (*usage)(struct net_context *ctx, int argc, const char **argv);
	int (*help)(struct net_context *ctx, int argc, const char **argv);
};

#endif /* _UTIL_NET_H */
