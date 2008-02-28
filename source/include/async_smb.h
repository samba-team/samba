/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008

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

/*
 * Create a fresh async smb request
 */

struct async_req *cli_request_new(TALLOC_CTX *mem_ctx,
				  struct event_context *ev,
				  struct cli_state *cli,
				  uint8_t num_words, size_t num_bytes,
				  struct cli_request **preq);

/*
 * Convenience function to get the SMB part out of an async_req
 */

struct cli_request *cli_request_get(struct async_req *req);

/*
 * Fetch an error out of a NBT packet
 */

NTSTATUS cli_pull_error(char *buf);

/*
 * Compatibility helper for the sync APIs: Fake NTSTATUS in cli->inbuf
 */

void cli_set_error(struct cli_state *cli, NTSTATUS status);

/*
 * Create a temporary event context for use in the sync helper functions
 */

struct cli_tmp_event *cli_tmp_event_ctx(TALLOC_CTX *mem_ctx,
					struct cli_state *cli);

/*
 * Attach an event context permanently to a cli_struct
 */

NTSTATUS cli_add_event_ctx(struct cli_state *cli,
			   struct event_context *event_ctx);
