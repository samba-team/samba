/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Jelmer Vernooij 2005

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
#include "gtk/common/gtk-smb.h"

static const char *gtk_get_userpassword(struct cli_credentials *credentials)
{
	char *prompt;
	const char *ret;
	GtkWidget *dialog;
	GtkWidget *dialog_vbox1;
	GtkWidget *hbox;
	GtkWidget *label;
	GtkWidget *entry_password;
	GtkWidget *dialog_action_area1;
	GtkWidget *cancelbutton1;
	GtkWidget *okbutton1;

	dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (dialog), "Enter Password");
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_type_hint (GTK_WINDOW (dialog), GDK_WINDOW_TYPE_HINT_DIALOG);

	dialog_vbox1 = GTK_DIALOG (dialog)->vbox;

	hbox = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), hbox, TRUE, TRUE, 0);

	prompt = talloc_asprintf(NULL, "Password for [%s\\%s]:", 
							 cli_credentials_get_domain(credentials),
							 cli_credentials_get_username(credentials));

	label = gtk_label_new (prompt);

	gtk_box_pack_start (GTK_BOX (hbox), label, FALSE, FALSE, 0);

	entry_password = gtk_entry_new ();
	gtk_box_pack_start (GTK_BOX (hbox), entry_password, TRUE, TRUE, 0);
	gtk_entry_set_visibility (GTK_ENTRY (entry_password), FALSE);
	gtk_entry_set_activates_default (GTK_ENTRY (entry_password), TRUE);

	dialog_action_area1 = GTK_DIALOG (dialog)->action_area;
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

	cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
	gtk_dialog_add_action_widget (GTK_DIALOG (dialog), cancelbutton1, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

	okbutton1 = gtk_button_new_from_stock ("gtk-ok");
	gtk_dialog_add_action_widget (GTK_DIALOG (dialog), okbutton1, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

	gtk_widget_show_all (dialog);

    switch (gtk_dialog_run (GTK_DIALOG (dialog))) {
	case GTK_RESPONSE_OK:
		ret = talloc_strdup(credentials, gtk_entry_get_text(GTK_ENTRY(entry_password)));
		break;
	default:
		ret = NULL;
		break;
	}

	gtk_widget_destroy (dialog);

	talloc_free(prompt);
	
	return ret;
}

void cli_credentials_set_gtk_callbacks(struct cli_credentials *cred)
{
	if (cred->password_obtained <= CRED_CALLBACK) {
		cred->password_cb = gtk_get_userpassword;
		cred->password_obtained = CRED_CALLBACK;
	}
}
