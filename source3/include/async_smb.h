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

#ifndef __ASYNC_SMB_H__
#define __ASYNC_SMB_H__

struct cli_state;

struct tevent_req *cli_smb_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct cli_state *cli,
				      uint8_t smb_command,
				      uint8_t additional_flags,
				      uint8_t wct, uint16_t *vwv,
				      int iov_count,
				      struct iovec *bytes_iov);
struct tevent_req *cli_smb_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
				struct cli_state *cli,
				uint8_t smb_command, uint8_t additional_flags,
				uint8_t wct, uint16_t *vwv,
				uint32_t num_bytes,
				const uint8_t *bytes);
NTSTATUS cli_smb_recv(struct tevent_req *req,
		      TALLOC_CTX *mem_ctx, uint8_t **pinbuf,
		      uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
		      uint32_t *pnum_bytes, uint8_t **pbytes);

#endif
