/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2004
   
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

/*
  this file contains pre-declarations of private structures to avoid the
  "scope is only this definition or declaration" warning
*/

union spoolss_PrinterInfo;
union spoolss_FormInfo;
union spoolss_JobInfo;
union spoolss_DriverInfo;
union spoolss_PortInfo;

struct MULTI_QI;
struct COSERVERINFO;


struct epm_floor;
struct epm_tower;

struct drsuapi_DsCrackNames;

struct samr_ChangePasswordUser;
struct samr_OemChangePasswordUser2;
struct samr_ChangePasswordUser3;
struct samr_ChangePasswordUser2;
struct samr_CryptPassword;
struct samr_CryptPasswordEx;
struct samr_LogonHours;

struct netr_Authenticator;
union netr_Validation;

struct iface_struct;

struct tm;
struct utimbuf;


struct auth_usersupplied_info;
struct auth_serversupplied_info;
struct auth_session_info;

struct creds_CredentialState;
struct ntlmssp_state;
struct auth_methods;
struct schannel_state;
struct spnego_data;
struct gensec_security;
typedef NTSTATUS (*gensec_password_callback)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx, 
					     char **password);

struct asn1_data;

struct ldapsrv_call;
struct ldapsrv_connection;
struct rw_buffer;
struct registry_context;
struct registry_key;
struct registry_value;

struct rap_NetShareEnum;
struct rap_NetServerEnum2;

struct smbsrv_request;
struct smbsrv_tcon;
struct smb_signing_context;
struct smbsrv_connection;
struct auth_context;
struct request_buffer;

struct pvfs_dir;
struct pvfs_filename;
struct pvfs_state;
struct pvfs_file;
struct pvfs_file_handle;

struct dcesrv_context;
struct dcesrv_interface;
struct dcesrv_connection;
struct dcesrv_endpoint;
struct dcesrv_call_state;
struct dcesrv_auth;

union libnet_ChangePassword;
union libnet_SetPassword;
union libnet_find_pdc;
union libnet_rpc_connect;
union libnet_RemoteTOD;
struct net_functable;
struct net_context;

struct file_info;

struct xattr_DosEAs;
struct xattr_DosStreams;
struct xattr_NTACL;

struct test_join;

struct test_join_ads_dc;

struct netr_LMSessionKey;

struct ldb_message;

struct security_token;
struct security_acl;
struct security_ace;

typedef struct security_descriptor SEC_DESC;
