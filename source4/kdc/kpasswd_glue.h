/*
   Unix SMB/CIFS implementation.

   kpasswd Server implementation

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell	2005

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

NTSTATUS samdb_kpasswd_change_password(TALLOC_CTX *mem_ctx,
				       struct loadparm_context *lp_ctx,
				       struct tevent_context *event_ctx,
				       struct ldb_context *samdb,
				       struct auth_session_info *session_info,
				       const DATA_BLOB *password,
				       enum samPwdChangeReason *reject_reason,
				       struct samr_DomInfo1 **dominfo,
				       const char **error_string,
				       NTSTATUS *result);
