/*
   Unix SMB/CIFS implementation.
   SMB Signing Code
   Copyright (C) Jeremy Allison 2003.
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2002-2003
   Copyright (C) Stefan Metzmacher 2009

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

struct smbXsrv_connection;

bool smb1_srv_check_sign_mac(struct smbXsrv_connection *conn,
			const char *inbuf, uint32_t *seqnum, bool trusted_channel);
NTSTATUS smb1_srv_calculate_sign_mac(struct smbXsrv_connection *conn,
				char *outbuf, uint32_t seqnum);
void smb1_srv_cancel_sign_response(struct smbXsrv_connection *conn);
void smb1_srv_set_signing_negotiated(struct smbXsrv_connection *conn,
			        bool allowed, bool mandatory);
bool smb1_srv_is_signing_active(struct smbXsrv_connection *conn);
bool smb1_srv_is_signing_negotiated(struct smbXsrv_connection *conn);
void smb1_srv_set_signing(struct smbXsrv_connection *conn,
		     const DATA_BLOB user_session_key,
		     const DATA_BLOB response);
bool smb1_srv_init_signing(struct loadparm_context *lp_ctx,
			   struct smbXsrv_connection *conn);
