/* 
   Unix SMB/CIFS implementation.
   simple kerberos5 routines for active directory
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Luke Howard 2002-2003
   
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

#if defined(HAVE_KRB5)

#ifndef HAVE_KRB5_SET_REAL_TIME
krb5_error_code krb5_set_real_time(krb5_context context, int32_t seconds, int32_t microseconds);
#endif

#ifndef HAVE_KRB5_SET_DEFAULT_TGS_KTYPES
krb5_error_code krb5_set_default_tgs_ktypes(krb5_context ctx, const krb5_enctype *enc);
#endif

#if defined(HAVE_KRB5_AUTH_CON_SETKEY) && !defined(HAVE_KRB5_AUTH_CON_SETUSERUSERKEY)
krb5_error_code krb5_auth_con_setuseruserkey(krb5_context context, krb5_auth_context auth_context, krb5_keyblock *keyblock);
#endif

#ifndef HAVE_KRB5_FREE_UNPARSED_NAME
void krb5_free_unparsed_name(krb5_context ctx, char *val);
#endif

/* Samba wrapper function for krb5 functionality. */
void setup_kaddr( krb5_address *pkaddr, struct sockaddr *paddr);
int create_kerberos_key_from_string(krb5_context context, krb5_principal host_princ, krb5_data *password, krb5_keyblock *key, krb5_enctype enctype);
void get_auth_data_from_tkt(DATA_BLOB *auth_data, krb5_ticket *tkt);
krb5_const_principal get_principal_from_tkt(krb5_ticket *tkt);
krb5_error_code krb5_locate_kdc(krb5_context ctx, const krb5_data *realm, struct sockaddr **addr_pp, int *naddrs, int get_masters);
krb5_error_code get_kerberos_allowed_etypes(krb5_context context, krb5_enctype **enctypes);
void free_kerberos_etypes(krb5_context context, krb5_enctype *enctypes);
BOOL get_krb5_smb_session_key(krb5_context context, krb5_auth_context auth_context, DATA_BLOB *session_key, BOOL remote);
#endif /* HAVE_KRB5 */

