/*
   Unix SMB/CIFS implementation.

   Samba kpasswd implementation

   Copyright (c) 2016      Andreas Schneider <asn@samba.org>

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

#ifndef _KPASSWD_HELPER_H
#define _KPASSWD_HELPER_H

bool kpasswd_make_error_reply(TALLOC_CTX *mem_ctx,
			      krb5_error_code error_code,
			      const char *error_string,
			      DATA_BLOB *error_data);

bool kpasswd_make_pwchange_reply(TALLOC_CTX *mem_ctx,
				 NTSTATUS status,
				 enum samPwdChangeReason reject_reason,
				 struct samr_DomInfo1 *dominfo,
				 DATA_BLOB *error_blob);

NTSTATUS kpasswd_samdb_set_password(TALLOC_CTX *mem_ctx,
				    struct tevent_context *event_ctx,
				    struct loadparm_context *lp_ctx,
				    struct auth_session_info *session_info,
				    bool is_service_principal,
				    const char *target_principal_name,
				    DATA_BLOB *password,
				    enum samPwdChangeReason *reject_reason,
				    struct samr_DomInfo1 **dominfo);

#endif /* _KPASSWD_HELPER_H */
