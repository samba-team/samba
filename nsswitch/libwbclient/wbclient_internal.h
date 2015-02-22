/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

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

#ifndef _WBCLIENT_INTERNAL_H
#define _WBCLIENT_INTERNAL_H

struct wbcContext {
	struct winbindd_context *winbindd_ctx;
	uint32_t pw_cache_size; /* Number of cached passwd structs */
	uint32_t pw_cache_idx;  /* Position of the pwent context */
	uint32_t gr_cache_size; /* Number of cached group structs */
	uint32_t gr_cache_idx;  /* Position of the grent context */
};

/* Private functions */

wbcErr wbcRequestResponse(struct wbcContext *ctx, int cmd,
			  struct winbindd_request *request,
			  struct winbindd_response *response);

wbcErr wbcRequestResponsePriv(struct wbcContext *ctx, int cmd,
			      struct winbindd_request *request,
			      struct winbindd_response *response);

void *wbcAllocateMemory(size_t nelem, size_t elsize,
			void (*destructor)(void *ptr));

char *wbcStrDup(const char *str);
const char **wbcAllocateStringArray(int num_strings);
struct wbcContext *wbcGetGlobalCtx(void);

#endif      /* _WBCLIENT_INTERNAL_H */
