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
	GtkWidget *transport_smb;
	GtkWidget *entry_host;
	GtkWidget *entry_username;
	GtkWidget *entry_password;
	TALLOC_CTX *mem_ctx;
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

#endif
