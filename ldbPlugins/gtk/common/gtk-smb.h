/* 
   Unix SMB/CIFS implementation.
   SMB-related GTK+ functions
   
   Copyright (C) Jelmer Vernooij 2004

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

#ifndef __GTK_SMB_H__
#define __GTK_SMB_H__

#ifdef HAVE_GTK

#include <gtk/gtk.h>

typedef struct _GtkRpcBindingDialog GtkRpcBindingDialog;

struct _GtkRpcBindingDialog 
{
	GtkDialog dialog;
	GtkWidget *chk_sign;
	GtkWidget *chk_seal;
	GtkWidget *transport_tcp_ip;
	GtkWidget *transport_ncalrpc;
	GtkWidget *transport_smb;
	GtkWidget *frame_host;
	GtkWidget *entry_host;
	GtkWidget *entry_username;
	GtkWidget *entry_password;
	GtkWidget *krb5_chk_button;
	GtkWidget *frame_credentials;
	TALLOC_CTX *mem_ctx;
	struct sam_pipe *sam_pipe;
};

typedef struct _GtkRpcBindingDialogClass GtkRpcBindingDialogClass;

struct _GtkRpcBindingDialogClass
{
	GtkDialogClass parent_class;
};

#define GTK_RPC_BINDING_DIALOG(obj)          GTK_CHECK_CAST (obj, gtk_rpc_binding_dialog_get_type (), GtkRpcBindingDialog)
#define GTK_RPC_BINDING_DIALOG_CLASS(klass)  GTK_CHECK_CLASS_CAST (klass, gtk_rpc_binding_dialog_class_get_type (), GtkRpcBindingDialogClass)
#define IS_GTK_RPC_BINDING_DIALOG(obj)       GTK_CHECK_TYPE (obj, gtk_rpc_binding_dialog_get_type ())

#endif

/* subsystem prototypes */
GtkWidget *create_gtk_samba_about_dialog (const char *appname);
void gtk_show_ntstatus(GtkWidget *win, NTSTATUS status);
GtkWidget *gtk_rpc_binding_dialog_new (BOOL nocredentials, struct sam_pipe *sam_pipe);
GType gtk_rpc_binding_dialog_get_type (void);
struct dcerpc_binding *gtk_rpc_binding_dialog_get_binding(GtkRpcBindingDialog *d, TALLOC_CTX *mem_ctx);
GtkWidget *gtk_select_host_dialog_new (struct sam_pipe *sam_pipe, BOOL nocredentials);
const char *gtk_select_host_dialog_get_host (GtkSelectHostDialog *d);
GType gtk_select_host_dialog_get_type (void);
void gtk_show_werror(GtkWidget *win, WERROR err);
const char *gtk_rpc_binding_dialog_get_binding_string(GtkRpcBindingDialog *d, TALLOC_CTX *mem_ctx);
const char *gtk_rpc_binding_dialog_get_username(GtkRpcBindingDialog *d);
const char *gtk_rpc_binding_dialog_get_password(GtkRpcBindingDialog *d);
const char *gtk_rpc_binding_dialog_get_host(GtkRpcBindingDialog *d);
GtkWidget *gtk_select_domain_dialog_new (struct dcerpc_pipe *sam_pipe);
GType gtk_select_domain_dialog_get_type (void);
struct policy_handle gtk_select_domain_dialog_get_handle(GtkSelectDomainDialog *d);


#endif
