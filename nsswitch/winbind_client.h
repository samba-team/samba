/*
   Unix SMB/CIFS implementation.

   winbind client common code

   Copyright (C) Tim Potter 2000
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Andrew Bartlett 2002
   Copyright (C) Matthew Newton 2015


   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _NSSWITCH_WINBIND_CLIENT_H_
#define _NSSWITCH_WINBIND_CLIENT_H_

#include "winbind_nss_config.h"
#include "winbind_struct_protocol.h"

struct winbindd_context;

struct winbindd_context *winbindd_ctx_create(void);
void winbindd_ctx_free(struct winbindd_context *ctx);

void winbindd_free_response(struct winbindd_response *response);
NSS_STATUS winbindd_request_response(struct winbindd_context *ctx,
				     int req_type,
				     struct winbindd_request *request,
				     struct winbindd_response *response);
NSS_STATUS winbindd_priv_request_response(struct winbindd_context *ctx,
					  int req_type,
					  struct winbindd_request *request,
					  struct winbindd_response *response);

void winbind_set_client_name(const char *name);

#define winbind_env_set() \
	(strcmp(getenv(WINBINDD_DONT_ENV)?getenv(WINBINDD_DONT_ENV):"0","1") == 0)

#define winbind_off() \
	(setenv(WINBINDD_DONT_ENV, "1", 1) == 0)

#define winbind_on() \
	(setenv(WINBINDD_DONT_ENV, "0", 1) == 0)

#endif /* _NSSWITCH_WINBIND_CLIENT_H_ */
