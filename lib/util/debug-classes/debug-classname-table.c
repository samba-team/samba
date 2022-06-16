/*
   Unix SMB/CIFS implementation.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Elrond               2002
   Copyright (C) Simo Sorce           2002

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


static const char *default_classname_table[] = {	
	[DBGC_ALL] =			"all",
	[DBGC_TDB] =			"tdb",
	[DBGC_PRINTDRIVERS] =		"printdrivers",
	[DBGC_LANMAN] =			"lanman",
	[DBGC_SMB] =			"smb",
	[DBGC_RPC_PARSE] =		"rpc_parse",
	[DBGC_RPC_SRV] =		"rpc_srv",
	[DBGC_RPC_CLI] =		"rpc_cli",
	[DBGC_PASSDB] =			"passdb",
	[DBGC_SAM] =			"sam",
	[DBGC_AUTH] =			"auth",
	[DBGC_WINBIND] =		"winbind",
	[DBGC_VFS] =			"vfs",
	[DBGC_IDMAP] =			"idmap",
	[DBGC_QUOTA] =			"quota",
	[DBGC_ACLS] =			"acls",
	[DBGC_LOCKING] =		"locking",
	[DBGC_MSDFS] =			"msdfs",
	[DBGC_DMAPI] =			"dmapi",
	[DBGC_REGISTRY] =		"registry",
	[DBGC_SCAVENGER] =		"scavenger",
	[DBGC_DNS] =			"dns",
	[DBGC_LDB] =			"ldb",
	[DBGC_TEVENT] =			"tevent",
	[DBGC_AUTH_AUDIT] =		"auth_audit",
	[DBGC_AUTH_AUDIT_JSON] =	"auth_json_audit",
	[DBGC_KERBEROS] =       	"kerberos",
	[DBGC_DRS_REPL] =       	"drs_repl",
	[DBGC_SMB2] =           	"smb2",
	[DBGC_SMB2_CREDITS] =   	"smb2_credits",
	[DBGC_DSDB_AUDIT] =		"dsdb_audit",
	[DBGC_DSDB_AUDIT_JSON] =	"dsdb_json_audit",
	[DBGC_DSDB_PWD_AUDIT]  =	"dsdb_password_audit",
	[DBGC_DSDB_PWD_AUDIT_JSON] =	"dsdb_password_json_audit",
	[DBGC_DSDB_TXN_AUDIT]  =	"dsdb_transaction_audit",
	[DBGC_DSDB_TXN_AUDIT_JSON] =	"dsdb_transaction_json_audit",
	[DBGC_DSDB_GROUP_AUDIT] =	"dsdb_group_audit",
	[DBGC_DSDB_GROUP_AUDIT_JSON] =	"dsdb_group_json_audit",
};
