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
#include "auth/credentials/credentials.h"

static void gtk_get_credentials(struct cli_credentials *credentials)
{
	const char *ret;
	GtkWidget *dialog;
	GtkWidget *label;
	GtkWidget *table;
	GtkWidget *entry_username;
	GtkWidget *entry_password;
	GtkWidget *entry_domain;
	GtkWidget *dialog_action_area1;
	GtkWidget *cancelbutton1;
	GtkWidget *okbutton1;
	GtkWidget *anonymous;

	dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (dialog), "Credentials");
	gtk_window_set_resizable (GTK_WINDOW (dialog), FALSE);
	gtk_window_set_type_hint (GTK_WINDOW (dialog), GDK_WINDOW_TYPE_HINT_DIALOG);

	table = gtk_table_new(4, 2, FALSE);
	gtk_container_add(GTK_CONTAINER(GTK_DIALOG(dialog)->vbox), table);

	label = gtk_label_new ("Domain:");

	gtk_table_attach(GTK_TABLE(table),label,0,1,0,1,GTK_FILL,0,0,0);

	entry_domain = gtk_entry_new ();
	gtk_table_attach(GTK_TABLE(table), entry_domain, 1,2,0,1, GTK_FILL, 0,0,0);
	gtk_entry_set_activates_default (GTK_ENTRY (entry_domain), TRUE);

	if (credentials->domain_obtained != CRED_UNINITIALISED) {
		gtk_entry_set_text(GTK_ENTRY(entry_domain), credentials->domain);
	}

	label = gtk_label_new ("Username:");

	gtk_table_attach(GTK_TABLE(table),label,0,1,1,2,GTK_FILL,0,0,0);

	entry_username = gtk_entry_new ();
	gtk_table_attach(GTK_TABLE(table),entry_username,1,2,1,2,GTK_FILL,0,0,0);
	gtk_entry_set_activates_default (GTK_ENTRY (entry_username), TRUE);
	if (credentials->username_obtained != CRED_UNINITIALISED) {
		gtk_entry_set_text(GTK_ENTRY(entry_username), credentials->username);
	}

	label = gtk_label_new ("Password:");

	gtk_table_attach(GTK_TABLE(table),label,0,1,3,4,GTK_FILL,0,0,0);

	entry_password = gtk_entry_new ();
	gtk_table_attach(GTK_TABLE(table),entry_password,1,2,3,4,GTK_FILL,0,0,0);
	gtk_entry_set_visibility (GTK_ENTRY (entry_password), FALSE);
	gtk_entry_set_activates_default (GTK_ENTRY (entry_password), TRUE);
	if (credentials->password_obtained != CRED_UNINITIALISED) {
		gtk_entry_set_text(GTK_ENTRY(entry_password), credentials->password);
	}

	anonymous = gtk_check_button_new_with_mnemonic("_Anonymous");
	gtk_table_attach(GTK_TABLE(table),anonymous,0,2,4,5,GTK_FILL,0,0,0);

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
		cli_credentials_set_username(credentials, gtk_entry_get_text(GTK_ENTRY(entry_username)), CRED_SPECIFIED);
		cli_credentials_set_password(credentials, gtk_entry_get_text(GTK_ENTRY(entry_password)), CRED_SPECIFIED);
		cli_credentials_set_domain(credentials, gtk_entry_get_text(GTK_ENTRY(entry_domain)), CRED_SPECIFIED);

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(anonymous))) {
			cli_credentials_set_anonymous(credentials);
		}
		break;
	default:
		ret = NULL;
		break;
	}

	gtk_widget_destroy (dialog);
}

static const char *gtk_get_username(struct cli_credentials *credentials)
{
	gtk_get_credentials(credentials);
	return credentials->username;
}

static const char *gtk_get_userpassword(struct cli_credentials *credentials)
{
	gtk_get_credentials(credentials);
	return credentials->password;
}

static const char *gtk_get_domain(struct cli_credentials *credentials)
{
	gtk_get_credentials(credentials);
	return credentials->domain;
}

void cli_credentials_set_gtk_callbacks(struct cli_credentials *cred)
{
	cli_credentials_set_username_callback(cred, gtk_get_username);
	cli_credentials_set_domain_callback(cred, gtk_get_domain);
	cli_credentials_set_password_callback(cred, gtk_get_userpassword);
}
