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

struct spoolss_DeviceMode;

struct drsuapi_DsNameInfo1;
struct drsuapi_DsCrackNames;
struct drsuapi_DsReplicaObjectListItem;
struct drsuapi_DsReplicaObjectListItemEx;

struct DsPrivate;

struct PAC_LOGON_INFO;
struct PAC_DATA;
struct PAC_BUFFER;

struct samr_ChangePasswordUser;
struct samr_OemChangePasswordUser2;
struct samr_ChangePasswordUser3;
struct samr_ChangePasswordUser2;
struct samr_CryptPassword;
struct samr_CryptPasswordEx;
struct samr_DomInfo1;

struct netr_Credential;
struct netr_Authenticator;
union netr_Validation;

struct iface_struct;

struct utimbuf;

struct auth_serversupplied_info;
struct auth_session_info;

struct spnego_data;
struct gensec_ntlmssp_state;

struct asn1_data;

struct ldapsrv_call;
struct ldapsrv_connection;
struct ldap_connection;

struct rap_NetShareEnum;
struct rap_NetServerEnum2;

struct smbsrv_tcon;
struct smbsrv_connection;

struct smbsrv_request;

struct ntvfs_module_context;

struct dcesrv_context;
struct dcesrv_call_state;

struct libnet_context;
struct libnet_JoinDomain;

struct clilist_file_info;

struct netr_LMSessionKey;

struct ldb_dn;
struct ldb_message;
struct ldb_context;
struct ldb_parse_tree;

struct lsa_RightSet;

struct irpc_request;

struct smb_composite_loadfile;
struct smb_composite_savefile;
struct smb_composite_connect;
struct smb_composite_sesssetup;
struct smb_composite_fetchfile;
struct smb_composite_appendacl;
struct smb_composite_fsinfo;

struct nbt_dgram_socket;
struct dgram_mailslot_handler;

struct messaging_context;
struct stream_connection;
struct task_server;
struct stream_server_ops;

struct nbt_dc_name;
struct wb_sid_object;

struct cldap_socket;
struct cldapd_server;

struct mutex_ops;

struct websrv_context;

struct wbsrv_call;

struct ldb_map_attribute;
struct ldb_map_objectclass;

struct param_context;

struct smbcli_request;
struct smbcli_tree;

struct smb2_tree;

struct com_context;
struct IUnknown;
struct IUnknown_vtable;

struct MprVar;

struct registry_context;
struct nbtd_interface;
struct smbcli_session;
struct smbcli_state;

struct substitute_context;

