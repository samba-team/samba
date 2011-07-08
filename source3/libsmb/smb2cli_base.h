/*
   Unix SMB/CIFS implementation.
   smb2 client routines
   Copyright (C) Volker Lendecke 2011

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

#ifndef __SMB2CLI_BASE_H__
#define __SMB2CLI_BASE_H__

struct tevent_req *smb2cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint16_t cmd,
				      uint32_t flags,
				      const uint8_t *fixed,
				      uint16_t fixed_len,
				      const uint8_t *dyn,
				      uint16_t dyn_len);
NTSTATUS smb2cli_req_compound_submit(struct tevent_req **reqs,
				     int num_reqs);
struct tevent_req *smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    uint16_t cmd,
				    uint32_t flags,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint16_t dyn_len);
NTSTATUS smb2cli_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct iovec **piov, int body_size);

#endif
