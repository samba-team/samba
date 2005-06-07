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

struct spoolss_EnumPrinters;
struct spoolss_EnumForms;
struct spoolss_EnumJobs;
struct spoolss_EnumPrinterDrivers;
struct spoolss_EnumPorts;
struct spoolss_EnumMonitors;
struct spoolss_EnumPrintProcessors;
union spoolss_PrinterInfo;
union spoolss_JobInfo;
union spoolss_DriverInfo;
union spoolss_FormInfo;
union spoolss_PortInfo;
union spoolss_MonitorInfo;
union spoolss_PrintProcessorInfo;
struct spoolss_GetPrinterData;
struct spoolss_SetPrinterData;

struct drsuapi_DsReplicaObjectListItem;
struct drsuapi_DsReplicaObjectListItemEx;

struct MULTI_QI;
struct COSERVERINFO;


struct epm_floor;
struct epm_tower;

struct drsuapi_DsCrackNames;

struct samr_ChangePasswordUser;
struct samr_OemChangePasswordUser2;
struct samr_ChangePasswordUser3;
struct samr_ChangePasswordUser2;
struct samr_Password;
struct samr_CryptPassword;
struct samr_CryptPasswordEx;
struct samr_LogonHours;

struct netr_Credential;
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
struct gensec_security_ops;
typedef NTSTATUS (*gensec_password_callback)(struct gensec_security *gensec_security, TALLOC_CTX *mem_ctx, 
					     char **password);
struct gensec_ntlmssp_state;

struct asn1_data;

struct ldapsrv_call;
struct ldapsrv_connection;
struct ldap_connection;
struct ldap_message;
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
struct auth_method_context;
struct request_buffer;

struct ntvfs_context;
struct ntvfs_module_context;

struct pvfs_dir;
struct pvfs_filename;
struct pvfs_state;
struct pvfs_file;
struct pvfs_file_handle;

struct stat;

struct dcesrv_context;
struct dcesrv_interface;
struct dcesrv_connection;
struct dcesrv_connection_context;
struct dcesrv_endpoint;
struct dcesrv_call_state;
struct dcesrv_auth;

union libnet_Join;
union libnet_JoinDomain;
union libnet_ChangePassword;
union libnet_SetPassword;
union libnet_find_pdc;
union libnet_rpc_connect;
union libnet_RemoteTOD;
union libnet_JoinDomain;
struct libnet_CreateUser;
struct libnet_ListShares;
struct libnet_AddShare;
struct libnet_DelShare;
struct net_functable;
struct net_context;

struct clilist_file_info;

struct xattr_DosEAs;
struct xattr_DosStreams;
struct xattr_NTACL;

struct test_join;

struct test_join_ads_dc;

struct netr_LMSessionKey;

struct ldb_val;
struct ldb_message;
struct ldb_context;

struct dom_sid;
struct security_token;
struct security_acl;
struct security_ace;

struct lsa_RightSet;

struct composite_context;
struct monitor_msg;

struct smb_composite_loadfile;
struct smb_composite_savefile;
struct smb_composite_connect;
struct smb_composite_sesssetup;
struct smb_composite_fetchfile;
struct smb_composite_appendacl;
struct smb_composite_fsinfo;
struct rpc_composite_userinfo;
struct rpc_composite_useradd;
struct rpc_composite_userdel;
struct rpc_composite_domain_open;

struct nbt_name;
struct nbt_name_packet;
struct nbt_name_socket;
struct nbt_name_query;
struct nbt_name_status;
struct nbt_name_register;
struct nbt_name_refresh;
struct nbt_name_release;
struct nbt_name_register_bcast;
struct nbt_name_refresh_wins;
struct nbt_name_register_wins;

struct nbt_dgram_packet;
struct nbt_dgram_socket;
struct dgram_mailslot_handler;

struct messaging_context;
struct stream_connection;
struct task_server;
struct model_ops;
struct stream_server_ops;

struct nbtd_server;
struct nbtd_interface;
struct wins_server;

struct cldap_socket;
struct cldapd_server;

struct mutex_ops;

struct ads_struct;

struct wrepl_packet;
struct wrepl_associate;
struct wrepl_pull_table;
struct wrepl_pull_names;

struct arcfour_state;

union libnet_SamDump;
struct websrv_context;
struct EspRequest;

struct kdc_server;
