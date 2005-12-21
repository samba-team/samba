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
struct spoolss_OpenPrinterEx;
struct spoolss_EnumPrinterData;
struct spoolss_DeletePrinterData;
struct spoolss_AddForm;
struct spoolss_GetForm;
struct spoolss_SetForm;
struct spoolss_DeleteForm;
struct spoolss_AddPrinterDriver;
struct spoolss_DeletePrinterDriver;
struct spoolss_GetPrinterDriverDirectory;
struct spoolss_AddPrinter;
struct spoolss_GetPrinter;
struct spoolss_SetPrinter;
struct spoolss_DeletePrinter;
struct spoolss_GetPrinterDriver;
struct spoolss_EnumPrinterData;
struct spoolss_DeletePrinterData;
struct spoolss_AddForm;
struct spoolss_GetForm;
struct spoolss_SetForm;
struct spoolss_DeleteForm;
struct spoolss_AddJob;
struct spoolss_ScheduleJob;
struct spoolss_GetJob;
struct spoolss_SetJob;
struct spoolss_StartDocPrinter;
struct spoolss_EndDocPrinter;
struct spoolss_StartPagePrinter;
struct spoolss_EndPagePrinter;
struct spoolss_WritePrinter;
struct spoolss_ReadPrinter;

struct spoolss_DeviceMode;

struct ntptr_context;
struct ntptr_GenericHandle;

struct drsuapi_DsCrackNames;
struct drsuapi_DsNameInfo1;
struct drsuapi_DsReplicaObjectListItem;
struct drsuapi_DsReplicaObjectListItemEx;

struct DsPrivate;

struct MULTI_QI;
struct COSERVERINFO;


struct epm_floor;
struct epm_tower;

struct PAC_BUFFER;
struct PAC_DATA;

struct samr_ChangePasswordUser;
struct samr_OemChangePasswordUser2;
struct samr_ChangePasswordUser3;
struct samr_ChangePasswordUser2;
struct samr_Password;
struct samr_CryptPassword;
struct samr_CryptPasswordEx;
struct samr_LogonHours;
struct samr_DomInfo1;

struct netr_Credential;
struct netr_Authenticator;
union netr_Validation;
struct netr_SamBaseInfo;
struct netr_SamInfo3;
struct netr_UserSessionKey;
struct netr_LogonSamLogon;

struct iface_struct;

struct tm;
struct utimbuf;


struct auth_usersupplied_info;
struct auth_serversupplied_info;
struct auth_session_info;

struct creds_CredentialState;
struct auth_methods;
struct schannel_state;
struct spnego_data;
struct gensec_security;
struct gensec_security_ops;
struct gensec_ntlmssp_state;

struct asn1_data;

struct ldapsrv_call;
struct ldapsrv_connection;
struct ldap_connection;
struct ldap_message;
struct ldap_Result;
struct rw_buffer;
struct registry_context;
struct registry_key;
struct registry_value;
struct reg_diff_file;

struct rap_NetShareEnum;
struct rap_NetServerEnum2;

struct auth_context;
struct auth_method_context;

struct smb_signing_context;

struct smbsrv_session;
struct smbsrv_tcon;
struct smbsrv_connection;

struct smbsrv_request;
struct request_buffer;

struct smb2srv_request;
struct smb2_request_buffer;

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

struct libnet_Join;
struct libnet_JoinDomain;
union libnet_ChangePassword;
union libnet_SetPassword;
union libnet_RemoteTOD;
struct libnet_RpcConnect;
struct libnet_CreateUser;
struct libnet_ListShares;
struct libnet_AddShare;
struct libnet_DelShare;
struct libnet_Lookup;
struct libnet_SamDump;
struct libnet_SamDump_keytab;
struct libnet_SamSync;
struct libnet_samsync_ldb;
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
struct ldb_dn;
struct ldb_message;
struct ldb_context;
struct ldb_parse_tree;
struct ldb_message_element;
struct ldap_mod;

struct dom_sid;
struct security_token;
struct security_acl;
struct security_ace;

struct lsa_RightSet;

struct composite_context;
struct monitor_msg;
struct irpc_request;
struct rpc_request;

struct smb_composite_loadfile;
struct smb_composite_savefile;
struct smb_composite_connect;
struct smb_composite_connectmulti;
struct smb_composite_sesssetup;
struct smb_composite_fetchfile;
struct smb_composite_appendacl;
struct smb_composite_fsinfo;
struct libnet_rpc_userinfo;
struct libnet_rpc_useradd;
struct libnet_rpc_userdel;
struct libnet_rpc_usermod;
struct libnet_rpc_domain_open;

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
struct nbt_name_request;

struct nbt_peer_socket;

struct nbt_dgram_packet;
struct nbt_dgram_socket;
struct dgram_mailslot_handler;

struct messaging_context;
struct irpc_message;
struct stream_connection;
struct task_server;
struct model_ops;
struct stream_server_ops;

struct nbtd_server;
struct nbtd_interface;
struct wins_server;
struct nbtd_proxy_wins_challenge;
struct nbtd_proxy_wins_release_demand;

struct nbt_dc_name;
struct wb_sid_object;
struct wb_dom_info;

struct cldap_socket;
struct cldapd_server;

struct mutex_ops;

struct ads_struct;

struct wreplsrv_service;
struct wreplsrv_partner;
struct wreplsrv_owner;
struct wreplsrv_in_connection;
struct wreplsrv_in_call;
struct wreplsrv_out_connection;
struct wreplsrv_pull_table_io;
struct wreplsrv_pull_names_io;
struct wreplsrv_pull_cycle_io;
struct wreplsrv_push_notify_io;

struct winsdb_record;

struct wrepl_packet;
struct wrepl_send_ctrl;
struct wrepl_associate;
struct wrepl_associate_stop;
struct wrepl_pull_table;
struct wrepl_pull_names;
struct wrepl_table;

struct arcfour_state;

struct websrv_context;
struct EspRequest;
struct PAC_LOGON_INFO;
struct kdc_server;
struct smb_krb5_context;

struct samba3_samaccount;
struct samba3_idmapdb;
struct samba3_groupdb;
struct samba3_winsdb_entry;
struct samba3_policy;
struct samba3_regdb;
struct samba3_secrets;
struct samba3_share_info;
struct samba3;

struct wbsrv_service;
struct wbsrv_domain;
struct wbsrv_protocol_ops;
struct wbsrv_listen_socket;
struct wbsrv_connection;
struct wbsrv_call;
struct wbsrv_samba3_call;

struct ldb_map_attribute;
struct ldb_map_objectclass;

struct param_context;
struct param_section;
struct param;

struct socket_context;
struct packet_context;

struct smbcli_socket;
struct smbcli_request;

struct _krb5_krb_auth_data;

struct smb2_request;
struct smb2_transport;
struct smb2_session;
struct smb2_negprot;
struct smb2_session_setup;
struct smb2_tree;
struct smb2_tree_connect;
struct smb2_create;
struct smb2_close;
struct smb2_getinfo;
struct smb2_setinfo;
struct smb2_read;
struct smb2_write;
struct smb2_find;
struct smb2_ioctl;
struct smb2_flush;
struct smb2_handle;

struct com_context;
struct IUnknown;
struct IUnknown_vtable;
