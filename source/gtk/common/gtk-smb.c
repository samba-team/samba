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

#include "includes.h"
#include "gtk-smb.h"

void gtk_show_werror(GtkWidget *win, WERROR err) 
{
	GtkWidget *dialog = gtk_message_dialog_new( GTK_WINDOW(win), 
		 GTK_DIALOG_DESTROY_WITH_PARENT,
         GTK_MESSAGE_ERROR,
         GTK_BUTTONS_CLOSE,
		 "Windows error: %s\n", win_errstr(err));
	gtk_dialog_run (GTK_DIALOG (dialog));
 	gtk_widget_destroy (dialog);
}
                   
void gtk_show_ntstatus(GtkWidget *win, NTSTATUS status) 
{
	GtkWidget *dialog = gtk_message_dialog_new( GTK_WINDOW(win), 
		 GTK_DIALOG_DESTROY_WITH_PARENT,
         GTK_MESSAGE_ERROR,
         GTK_BUTTONS_CLOSE,
		 "Windows error: %s\n", nt_errstr(status));
	gtk_dialog_run (GTK_DIALOG (dialog));
 	gtk_widget_destroy (dialog);
}

static void on_browse_activate  (GtkButton     *button,  gpointer         user_data)
{
	GtkRpcBindingDialog *rbd = user_data;
	GtkWidget *shd = gtk_select_host_dialog_new(rbd->sam_pipe, TRUE);
	if(gtk_dialog_run(GTK_DIALOG(shd)) == GTK_RESPONSE_ACCEPT) {
		gtk_entry_set_text(GTK_ENTRY(rbd->entry_host), gtk_select_host_dialog_get_host(GTK_SELECT_HOST_DIALOG(shd)));
	}
	
	gtk_widget_destroy(GTK_WIDGET(shd));
}

static void on_krb5_toggled(GtkToggleButton *togglebutton, GtkRpcBindingDialog *d)
{
	gtk_widget_set_sensitive(d->entry_password, !gtk_toggle_button_get_active(togglebutton));
}

static void on_ncalrpc_toggled(GtkToggleButton *tb, GtkRpcBindingDialog *d)
{
	gtk_widget_set_sensitive(d->frame_host, !gtk_toggle_button_get_active(tb));
}

static void gtk_rpc_binding_dialog_init (GtkRpcBindingDialog *gtk_rpc_binding_dialog)
{
	GtkWidget *dialog_vbox1;
	GtkWidget *vbox1;
	GtkWidget *vbox6;
	GtkWidget *frame_transport;
	GtkWidget *label1;
	GtkWidget *hbox1;
	GtkWidget *lbl_name;
	GtkWidget *label2;
	GtkWidget *frame_security;
	GtkWidget *vbox2;
	GtkWidget *label3;
	GtkWidget *frame_credentials;
	GtkWidget *table1;
	GtkWidget *lbl_username;
	GtkWidget *lbl_password;
	GtkWidget *btn_browse;
	GtkWidget *label9;
	GtkWidget *lbl_credentials;
	GtkWidget *dialog_action_area1;
	GtkWidget *btn_cancel;
	GtkWidget *btn_connect;
	GSList *transport_smb_group = NULL;

	gtk_rpc_binding_dialog->mem_ctx = talloc_init("gtk_rcp_binding_dialog");
	
	gtk_window_set_title (GTK_WINDOW (gtk_rpc_binding_dialog), "Connect");

	dialog_vbox1 = GTK_DIALOG (gtk_rpc_binding_dialog)->vbox;
	gtk_widget_show (dialog_vbox1);

	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_widget_show (vbox1);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), vbox1, TRUE, TRUE, 0);

	frame_transport = gtk_frame_new (NULL);
	gtk_widget_show (frame_transport);
	gtk_box_pack_start (GTK_BOX (vbox1), frame_transport, TRUE, TRUE, 0);

	vbox6 = gtk_vbox_new (FALSE, 0);
	gtk_widget_show (vbox6);
	gtk_container_add (GTK_CONTAINER (frame_transport), vbox6);

	gtk_rpc_binding_dialog->transport_ncalrpc = gtk_radio_button_new_with_mnemonic (NULL, "Local Host");
	gtk_widget_show (gtk_rpc_binding_dialog->transport_ncalrpc);
	gtk_box_pack_start (GTK_BOX (vbox6), gtk_rpc_binding_dialog->transport_ncalrpc, FALSE, FALSE, 0);
	gtk_radio_button_set_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_ncalrpc), transport_smb_group);
	transport_smb_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_ncalrpc));


	gtk_rpc_binding_dialog->transport_smb = gtk_radio_button_new_with_mnemonic (NULL, "RPC over SMB over TCP/IP");
	gtk_widget_show (gtk_rpc_binding_dialog->transport_smb);
	gtk_box_pack_start (GTK_BOX (vbox6), gtk_rpc_binding_dialog->transport_smb, FALSE, FALSE, 0);
	gtk_radio_button_set_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_smb), transport_smb_group);
	transport_smb_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_smb));
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (gtk_rpc_binding_dialog->transport_smb), TRUE);

	gtk_rpc_binding_dialog->transport_tcp_ip = gtk_radio_button_new_with_mnemonic (NULL, "RPC over TCP/IP");
	gtk_widget_show (gtk_rpc_binding_dialog->transport_tcp_ip);
	gtk_box_pack_start (GTK_BOX (vbox6), gtk_rpc_binding_dialog->transport_tcp_ip, FALSE, FALSE, 0);
	gtk_radio_button_set_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_tcp_ip), transport_smb_group);
	transport_smb_group = gtk_radio_button_get_group (GTK_RADIO_BUTTON (gtk_rpc_binding_dialog->transport_tcp_ip));



	label1 = gtk_label_new ("Transport");
	gtk_widget_show (label1);
	gtk_frame_set_label_widget (GTK_FRAME (frame_transport), label1);

	gtk_rpc_binding_dialog->frame_host = gtk_frame_new (NULL);
	gtk_widget_show (gtk_rpc_binding_dialog->frame_host);
	gtk_box_pack_start (GTK_BOX (vbox1), gtk_rpc_binding_dialog->frame_host, TRUE, TRUE, 0);

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_widget_show (hbox1);
	gtk_container_add (GTK_CONTAINER (gtk_rpc_binding_dialog->frame_host), hbox1);

	lbl_name = gtk_label_new ("Name");
	gtk_widget_show (lbl_name);
	gtk_box_pack_start (GTK_BOX (hbox1), lbl_name, TRUE, TRUE, 0);

	gtk_rpc_binding_dialog->entry_host = gtk_entry_new ();
	gtk_widget_show (gtk_rpc_binding_dialog->entry_host);
	gtk_box_pack_start (GTK_BOX (hbox1), gtk_rpc_binding_dialog->entry_host, TRUE, TRUE, 0);

	if(gtk_rpc_binding_dialog->sam_pipe)
	{
		btn_browse = gtk_button_new_with_label ("Browse");
		gtk_widget_show (btn_browse);
		gtk_box_pack_start (GTK_BOX (hbox1), btn_browse, TRUE, TRUE, 0);

		g_signal_connect ((gpointer) btn_browse, "pressed",
						  G_CALLBACK (on_browse_activate),
						  gtk_rpc_binding_dialog);
	}

	label2 = gtk_label_new ("Host");
	gtk_widget_show (label2);
	gtk_frame_set_label_widget (GTK_FRAME (gtk_rpc_binding_dialog->frame_host), label2);

	frame_security = gtk_frame_new (NULL);
	gtk_widget_show (frame_security);
	gtk_box_pack_start (GTK_BOX (vbox1), frame_security, TRUE, TRUE, 0);

	vbox2 = gtk_vbox_new (FALSE, 0);
	gtk_widget_show (vbox2);
	gtk_container_add (GTK_CONTAINER (frame_security), vbox2);

	gtk_rpc_binding_dialog->chk_sign = gtk_check_button_new_with_mnemonic ("S_ign");
	gtk_widget_show (gtk_rpc_binding_dialog->chk_sign);
	gtk_box_pack_start (GTK_BOX (vbox2), gtk_rpc_binding_dialog->chk_sign, FALSE, FALSE, 0);

	gtk_rpc_binding_dialog->chk_seal = gtk_check_button_new_with_mnemonic ("_Seal");
	gtk_widget_show (gtk_rpc_binding_dialog->chk_seal);
	gtk_box_pack_start (GTK_BOX (vbox2), gtk_rpc_binding_dialog->chk_seal, FALSE, FALSE, 0);

	label3 = gtk_label_new ("Security");
	gtk_widget_show (label3);
	gtk_frame_set_label_widget (GTK_FRAME (frame_security), label3);

	frame_credentials = gtk_frame_new (NULL);
	gtk_widget_show (frame_credentials);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), frame_credentials, TRUE, TRUE, 0);

	table1 = gtk_table_new (3, 2, FALSE);
	gtk_widget_show (table1);
	gtk_container_add (GTK_CONTAINER (frame_credentials), table1);

	lbl_username = gtk_label_new ("Username:");
	gtk_widget_show (lbl_username);
	gtk_table_attach (GTK_TABLE (table1), lbl_username, 0, 1, 0, 1,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (lbl_username), 0, 0.5);

	lbl_password = gtk_label_new ("Password:");
	gtk_widget_show (lbl_password);
	gtk_table_attach (GTK_TABLE (table1), lbl_password, 0, 1, 1, 2,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (lbl_password), 0, 0.5);

	label9 = gtk_label_new ("");
	gtk_widget_show (label9);
	gtk_table_attach (GTK_TABLE (table1), label9, 0, 1, 2, 3,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label9), 0, 0.5);

	gtk_rpc_binding_dialog->entry_password = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (gtk_rpc_binding_dialog->entry_password), FALSE);
	gtk_widget_show (gtk_rpc_binding_dialog->entry_password);
	gtk_table_attach (GTK_TABLE (table1), gtk_rpc_binding_dialog->entry_password, 1, 2, 1, 2,
			(GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

	gtk_rpc_binding_dialog->entry_username = gtk_entry_new ();
	gtk_widget_show (gtk_rpc_binding_dialog->entry_username);
	gtk_table_attach (GTK_TABLE (table1), gtk_rpc_binding_dialog->entry_username, 1, 2, 0, 1,
			(GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

	gtk_entry_set_text(GTK_ENTRY(gtk_rpc_binding_dialog->entry_username), getenv("LOGNAME"));

	gtk_rpc_binding_dialog->krb5_chk_button = gtk_check_button_new_with_mnemonic ("_Use kerberos");
	gtk_widget_show (gtk_rpc_binding_dialog->krb5_chk_button);
	gtk_table_attach (GTK_TABLE (table1), gtk_rpc_binding_dialog->krb5_chk_button, 1, 2, 2, 3,
			(GtkAttachOptions) (GTK_FILL),
			(GtkAttachOptions) (0), 0, 0);

    g_signal_connect ((gpointer) gtk_rpc_binding_dialog->krb5_chk_button, "toggled",
               G_CALLBACK (on_krb5_toggled),
               gtk_rpc_binding_dialog);

	/* Poor man's autodetection */
	if(getenv("KRB5CCNAME")) {
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_rpc_binding_dialog->krb5_chk_button), TRUE);
	}

	lbl_credentials = gtk_label_new ("Credentials");
	gtk_widget_show (lbl_credentials);
	gtk_frame_set_label_widget (GTK_FRAME (frame_credentials), lbl_credentials);

	dialog_action_area1 = GTK_DIALOG (gtk_rpc_binding_dialog)->action_area;
	gtk_widget_show (dialog_action_area1);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

	btn_cancel = gtk_button_new_from_stock ("gtk-cancel");
	gtk_widget_show (btn_cancel);
	gtk_dialog_add_action_widget (GTK_DIALOG (gtk_rpc_binding_dialog), btn_cancel, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (btn_cancel, GTK_CAN_DEFAULT);

	btn_connect = gtk_button_new_with_mnemonic ("_Connect");
	gtk_widget_show (btn_connect);
	gtk_dialog_add_action_widget (GTK_DIALOG (gtk_rpc_binding_dialog), btn_connect, GTK_RESPONSE_ACCEPT);
	gtk_container_set_border_width (GTK_CONTAINER (btn_connect), 1);
	GTK_WIDGET_SET_FLAGS (btn_connect, GTK_CAN_DEFAULT);

	g_signal_connect ((gpointer) gtk_rpc_binding_dialog->transport_ncalrpc, "toggled",
						  G_CALLBACK (on_ncalrpc_toggled),
						  gtk_rpc_binding_dialog);


	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON(gtk_rpc_binding_dialog->transport_ncalrpc), TRUE);

	gtk_widget_grab_focus (btn_connect);
	gtk_widget_grab_default (btn_connect);
}

GType gtk_rpc_binding_dialog_get_type (void)
{
  static GType mytype = 0;

  if (!mytype)
    {
      static const GTypeInfo myinfo =
      {
	sizeof (GtkRpcBindingDialogClass),
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	sizeof(GtkRpcBindingDialog),
	0,
	(GInstanceInitFunc) gtk_rpc_binding_dialog_init,
      };

      mytype = g_type_register_static (GTK_TYPE_DIALOG, 
		"GtkRpcBindingDialog", &myinfo, 0);
    }

  return mytype;
}

GtkWidget *gtk_rpc_binding_dialog_new (BOOL nocredentials, struct sam_pipe *sam_pipe)
{
	GtkRpcBindingDialog *d = GTK_RPC_BINDING_DIALOG ( gtk_type_new (gtk_rpc_binding_dialog_get_type ()));
	d->sam_pipe = sam_pipe;
	return GTK_WIDGET(d);
}

const char *gtk_rpc_binding_dialog_get_username(GtkRpcBindingDialog *d)
{
	return gtk_entry_get_text(GTK_ENTRY(d->entry_username));
}

const char *gtk_rpc_binding_dialog_get_password(GtkRpcBindingDialog *d)
{
	return gtk_entry_get_text(GTK_ENTRY(d->entry_password));
}

const char *gtk_rpc_binding_dialog_get_host(GtkRpcBindingDialog *d)
{
	return gtk_entry_get_text(GTK_ENTRY(d->entry_host));
}

struct dcerpc_binding *gtk_rpc_binding_dialog_get_binding(GtkRpcBindingDialog *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_binding *binding = talloc_p(mem_ctx, struct dcerpc_binding);

	ZERO_STRUCT(binding->object);

	/* Format: TRANSPORT:host[\pipe\foo,foo,foo] */

	binding->host = talloc_strdup(mem_ctx, gtk_entry_get_text(GTK_ENTRY(d->entry_host)));
	if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->transport_tcp_ip))) {
		binding->transport = NCACN_IP_TCP;
	} else if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->transport_ncalrpc))) {
		binding->transport = NCALRPC;
	} else {
		binding->transport = NCACN_NP;
	}

	binding->options = NULL;
	binding->flags = 0;
	binding->endpoint = NULL;

	if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->chk_seal))) {
		binding->flags |= DCERPC_SEAL;
	}

	if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(d->chk_sign))) {
		binding->flags |= DCERPC_SIGN;
	}

	return binding;
}

const char *gtk_rpc_binding_dialog_get_binding_string(GtkRpcBindingDialog *d, TALLOC_CTX *mem_ctx)
{
	return dcerpc_binding_string(mem_ctx, gtk_rpc_binding_dialog_get_binding(d, mem_ctx));
}

GtkWidget *create_gtk_samba_about_dialog (const char *appname)
{
  GtkWidget *samba_about_dialog;
  GtkWidget *dialog_vbox1;
  GtkWidget *label1;
  GtkWidget *label3;
  GtkWidget *label2;
  GtkWidget *dialog_action_area1;
  GtkWidget *okbutton1;

  samba_about_dialog = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (samba_about_dialog), "About");

  dialog_vbox1 = GTK_DIALOG (samba_about_dialog)->vbox;
  gtk_widget_show (dialog_vbox1);

/* FIXME image1 = create_pixmap (samba_about_dialog, "slmed.png");
  gtk_widget_show (image1);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), image1, TRUE, TRUE, 0);*/

  label1 = gtk_label_new (appname);
  gtk_widget_show (label1);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), label1, FALSE, FALSE, 0);

  label3 = gtk_label_new_with_mnemonic ("Part of Samba <http://www.samba.org/>");
  gtk_widget_show (label3);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), label3, FALSE, FALSE, 0);

  label2 = gtk_label_new ("\302\251 1992-2004 The Samba Team");
  gtk_widget_show (label2);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), label2, FALSE, FALSE, 0);

  dialog_action_area1 = GTK_DIALOG (samba_about_dialog)->action_area;
  gtk_widget_show (dialog_action_area1);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

  okbutton1 = gtk_button_new_from_stock ("gtk-ok");
  gtk_widget_show (okbutton1);
  gtk_dialog_add_action_widget (GTK_DIALOG (samba_about_dialog), okbutton1, GTK_RESPONSE_OK);
  GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

  return samba_about_dialog;
}
