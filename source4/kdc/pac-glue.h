/*
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2009
   Copyright (C) Simo Sorce <idra@samba.org> 2010

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


NTSTATUS samba_get_logon_info_pac_blob(TALLOC_CTX *mem_ctx,
				       struct smb_iconv_convenience *ic,
				       struct auth_serversupplied_info *info,
				       DATA_BLOB *pac_data);

krb5_error_code samba_make_krb5_pac(krb5_context context,
				    DATA_BLOB *pac_blob,
				    krb5_pac *pac);

bool samba_princ_needs_pac(struct hdb_entry_ex *princ);

NTSTATUS samba_kdc_get_pac_blob(TALLOC_CTX *mem_ctx,
				struct hdb_entry_ex *client,
				DATA_BLOB **_pac_blob);

NTSTATUS samba_kdc_update_pac_blob(TALLOC_CTX *mem_ctx,
				   krb5_context context,
				   struct smb_iconv_convenience *ic,
				   krb5_pac *pac, DATA_BLOB *pac_blob);

void samba_kdc_build_edata_reply(TALLOC_CTX *tmp_ctx, krb5_data *e_data,
				 NTSTATUS nt_status);
