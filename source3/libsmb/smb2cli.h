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

#ifndef __SMB2CLI_H__
#define __SMB2CLI_H__

struct smbXcli_conn;
struct smbXcli_session;
struct cli_state;

struct tevent_req *smb2cli_tcon_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli,
				     const char *share);
NTSTATUS smb2cli_tcon_recv(struct tevent_req *req);
NTSTATUS smb2cli_tcon(struct cli_state *cli, const char *share);

struct tevent_req *smb2cli_tdis_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     struct cli_state *cli);
NTSTATUS smb2cli_tdis_recv(struct tevent_req *req);
NTSTATUS smb2cli_tdis(struct cli_state *cli);

#endif /* __SMB2CLI_H__ */
