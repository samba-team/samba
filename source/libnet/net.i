/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007
   
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

%module(package="samba.net") net

%{
#include "includes.h"
#include "libnet/libnet.h"
#include "lib/events/events.h"
#include "param/param.h"
typedef struct libnet_context libnet;
%}

%import "../libcli/util/errors.i"
%import "../lib/events/events.i"
%import "../lib/talloc/talloc.i"
%import "../param/param.i"

%talloctype(libnet_context);

typedef struct libnet_context {
    struct cli_credentials *cred;
    %extend { 
        libnet(struct event_context *ev, struct loadparm_context *lp_ctx) {
            return libnet_context_init(ev, lp_ctx);
        }
        NTSTATUS samsync_ldb(TALLOC_CTX *mem_ctx, struct libnet_samsync_ldb *r);
        NTSTATUS DomainList(TALLOC_CTX *mem_ctx, struct libnet_DomainList *io);
        NTSTATUS DomainClose(TALLOC_CTX *mem_ctx, struct libnet_DomainClose *io);
        NTSTATUS DomainOpen(TALLOC_CTX *mem_ctx, struct libnet_DomainOpen *io);
        NTSTATUS LookupName(TALLOC_CTX *mem_ctx, struct libnet_LookupName *io);
        NTSTATUS LookupDCs(TALLOC_CTX *mem_ctx, struct libnet_LookupDCs *io);
        NTSTATUS LookupHost(TALLOC_CTX *mem_ctx, struct libnet_Lookup *io);
        NTSTATUS Lookup(TALLOC_CTX *mem_ctx, struct libnet_Lookup *io);
        NTSTATUS ListShares(TALLOC_CTX *mem_ctx, struct libnet_ListShares *r);
        NTSTATUS AddShare(TALLOC_CTX *mem_ctx, struct libnet_AddShare *r);
        NTSTATUS DelShare(TALLOC_CTX *mem_ctx, struct libnet_DelShare *r);
        NTSTATUS GroupList(TALLOC_CTX *mem_ctx, struct libnet_GroupList *io);
        NTSTATUS GroupInfo(TALLOC_CTX *mem_ctx, struct libnet_GroupInfo *io);
        NTSTATUS UserList(TALLOC_CTX *mem_ctx, struct libnet_UserList *r);
        NTSTATUS UserInfo(TALLOC_CTX *mem_ctx, struct libnet_UserInfo *r);
        NTSTATUS ModifyUser(TALLOC_CTX *mem_ctx, struct libnet_ModifyUser *r);
        NTSTATUS DeleteUser(TALLOC_CTX *mem_ctx, struct libnet_DeleteUser *r);
        NTSTATUS CreateUser(TALLOC_CTX *mem_ctx, struct libnet_CreateUser *r);
        NTSTATUS SamDump_keytab(TALLOC_CTX *mem_ctx, struct libnet_SamDump_keytab *r);
        NTSTATUS SamDump(TALLOC_CTX *mem_ctx, struct libnet_SamDump *r);
        NTSTATUS SamSync_netlogon(TALLOC_CTX *mem_ctx, struct libnet_SamSync *r);
        NTSTATUS UnbecomeDC(TALLOC_CTX *mem_ctx, struct libnet_UnbecomeDC *r);
        NTSTATUS BecomeDC(TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r);
        NTSTATUS JoinSite(struct ldb_context *remote_ldb, struct libnet_JoinDomain *libnet_r);
        NTSTATUS JoinDomain(TALLOC_CTX *mem_ctx, struct libnet_JoinDomain *r);
        NTSTATUS Join(TALLOC_CTX *mem_ctx, struct libnet_Join *r);
        NTSTATUS RpcConnect(TALLOC_CTX *mem_ctx, struct libnet_RpcConnect *r);
        NTSTATUS RemoteTOD(TALLOC_CTX *mem_ctx, union libnet_RemoteTOD *r);
        NTSTATUS ChangePassword(TALLOC_CTX *mem_ctx, union libnet_ChangePassword *r);
        NTSTATUS SetPassword(TALLOC_CTX *mem_ctx, union libnet_SetPassword *r);
    }
} libnet;
