/* 
   Unix SMB/CIFS implementation.

   Winbind daemon - WINS related functions

   Copyright (C) Andrew Tridgell 1999
   Copyright (C) Herb Lewis 2002
   
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

#include "includes.h"
#include "winbindd.h"
#include "libsmb/nmblib.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static struct sockaddr_storage *lookup_byname_backend(TALLOC_CTX *mem_ctx,
						      const char *name,
						      int *count)
{
	struct sockaddr_storage *return_ss = NULL;
	int j;
	NTSTATUS status;

	*count = 0;

	/* always try with wins first */
	status = resolve_wins(name, 0x20, mem_ctx, &return_ss, count);
	if (NT_STATUS_IS_OK(status)) {
		if ( *count == 0 )
			return NULL;
		return return_ss;
	}

	/* uggh, we have to broadcast to each interface in turn */
	for (j=iface_count() - 1;
	     j >= 0;
	     j--) {
		const struct sockaddr_storage *bcast_ss = iface_n_bcast(j);
		if (!bcast_ss) {
			continue;
		}
		status = name_query(name, 0x20, True, True,bcast_ss,
				    mem_ctx, &return_ss, count, NULL);
		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	}

	return return_ss;
}

/* Get IP from hostname */

void winbindd_wins_byname(struct winbindd_cli_state *state)
{
	struct sockaddr_storage *ip_list = NULL;
	int i, count, maxlen, size;
	fstring response;
	char addr[INET6_ADDRSTRLEN];

	/* Ensure null termination */
	state->request->data.winsreq[sizeof(state->request->data.winsreq)-1]='\0';

	DEBUG(3, ("[%5lu]: wins_byname %s\n", (unsigned long)state->pid,
		state->request->data.winsreq));

	*response = '\0';
	maxlen = sizeof(response) - 1;

	ip_list = lookup_byname_backend(
		state->mem_ctx, state->request->data.winsreq, &count);
	if (ip_list != NULL){
		for (i = count; i ; i--) {
			print_sockaddr(addr, sizeof(addr), &ip_list[i-1]);
			size = strlen(addr);
			if (size > maxlen) {
				TALLOC_FREE(ip_list);
				request_error(state);
				return;
			}
			if (i != 0) {
				/* Clear out the newline character */
				/* But only if there is something in there,
				otherwise we clobber something in the stack */
				if (strlen(response)) {
					response[strlen(response)-1] = ' ';
				}
			}
			strlcat(response,addr,sizeof(response));
			strlcat(response,"\t",sizeof(response));
		}
		size = strlen(state->request->data.winsreq) + strlen(response);
		if (size > maxlen) {
		    TALLOC_FREE(ip_list);
		    request_error(state);
		    return;
		}
		strlcat(response,state->request->data.winsreq,sizeof(response));
		strlcat(response,"\n",sizeof(response));
		TALLOC_FREE(ip_list);
	} else {
		request_error(state);
		return;
	}

	strlcpy(state->response->data.winsresp,
		response,
		sizeof(state->response->data.winsresp));

	request_ok(state);
}
