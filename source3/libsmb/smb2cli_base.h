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

#include "../libcli/smb/smbXcli_base.h"

static inline struct tevent_req *cli_state_smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct cli_state *cli,
				    uint16_t cmd,
				    uint32_t additional_flags,
				    uint32_t clear_flags,
				    uint32_t timeout_msec,
				    uint32_t pid,
				    uint32_t tid,
				    uint64_t uid,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint32_t dyn_len)
{
	if (cli->smb2.conn == NULL) {
		cli->smb2.conn = smbXcli_conn_create(cli,
						     cli->conn.fd,
						     cli->conn.remote_name,
						     SMB_SIGNING_OFF,
						     0,  /* smb1_capabilities */
						     NULL); /* client guid */
		if (cli->smb2.conn == NULL) {
			return NULL;
		}
	}

	return smb2cli_req_send(mem_ctx, ev,
				cli->smb2.conn, cmd,
				additional_flags, clear_flags,
				timeout_msec,
				pid, tid, uid,
				fixed, fixed_len,
				dyn, dyn_len);
}

#define smb2cli_req_send(mem_ctx, ev, cli, cmd, \
			 additional_flags, clear_flags, \
			 timeout_msec, \
			 pid, tid, uid, \
			 fixed, fixed_len, dyn, dyn_len) \
	cli_state_smb2cli_req_send(mem_ctx, ev, cli, cmd, \
			 additional_flags, clear_flags, \
			 timeout_msec, \
			 pid, tid, uid, \
			 fixed, fixed_len, dyn, dyn_len)

#endif
