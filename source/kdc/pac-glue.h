/* 
   Unix SMB/CIFS implementation.

   PAC Glue between Samba and the KDC
   
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

 struct hdb_ldb_private {
	struct ldb_context *samdb;
	struct ldb_message *msg;
	struct ldb_message *realm_ref_msg;
	hdb_entry_ex *entry_ex;
 };

 krb5_error_code hdb_ldb_authz_data_as_req(krb5_context context, struct hdb_entry_ex *entry_ex, 
					   METHOD_DATA* pa_data_seq,
					   time_t authtime,
					   const EncryptionKey *tgtkey,
					   const EncryptionKey *sessionkey,
					   AuthorizationData **out);

 krb5_error_code hdb_ldb_authz_data_tgs_req(krb5_context context, struct hdb_entry_ex *entry_ex, 
					    krb5_principal client, 
					    AuthorizationData *in, 
					    time_t authtime,
					    const EncryptionKey *tgtkey,
					    const EncryptionKey *servicekey,
					    const EncryptionKey *sessionkey,
					    AuthorizationData **out);
 krb5_error_code hdb_ldb_check_client_access(krb5_context context, hdb_entry_ex *entry_ex, 
					     HostAddresses *addresses);
