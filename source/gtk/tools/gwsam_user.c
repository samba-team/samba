/* 
   Unix SMB/CIFS implementation.
   GTK+ SAM frontend
   
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
#include "gtk/common/gtk-smb.h"


GtkWidget*
create_user_edit_dialog (void)
{
	GtkWidget *user_edit_dialog;
	GtkWidget *dialog_vbox1;
	GtkWidget *notebook;
	GtkWidget *table1;
	GtkWidget *label4;
	GtkWidget *label5;
	GtkWidget *label6;
	GtkWidget *label7;
	int i;
	GtkWidget *label8;
	GtkWidget *chk_mustchange;
	GtkWidget *entry_fullname;
	GtkWidget *entry_description;
	GtkWidget *lbl_username;
	GtkWidget *entry_password;
	GtkWidget *entry_confirm_password;
	GtkWidget *chk_cannotchange;
	GtkWidget *chk_cannotexpire;
	GtkWidget *chk_disabled;
	GtkWidget *chk_lockedout;
	GtkWidget *label1;
	GtkWidget *hbox1;
	GtkWidget *scrolledwindow3;
	GtkWidget *treeview3;
	GtkWidget *vbox2;
	GtkWidget *btn_groupadd;
	GtkWidget *btn_groupdel;
	GtkWidget *scrolledwindow4;
	GtkWidget *treeview4;
	GtkWidget *label2;
	GtkWidget *vbox3;
	GtkWidget *frame1;
	GtkWidget *table2;
	GtkWidget *label12;
	GtkWidget *label13;
	GtkWidget *entry_profilepath;
	GtkWidget *entry_scriptname;
	GtkWidget *label10;
	GtkWidget *frame2;
	GtkWidget *table3;
	GtkWidget *label14;
	GtkWidget *entry_homedir;
	GtkWidget *chk_mapdrive;
	GtkWidget *combo_homedrive;
	GtkWidget *label11;
	GtkWidget *label3;
	GtkWidget *dialog_action_area1;
	GtkWidget *cancelbutton1;
	GtkWidget *applybutton1;
	GtkWidget *okbutton1;

	user_edit_dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (user_edit_dialog), "Edit User");

	dialog_vbox1 = GTK_DIALOG (user_edit_dialog)->vbox;
	gtk_widget_show (dialog_vbox1);

	notebook = gtk_notebook_new ();
	gtk_widget_show (notebook);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), notebook, TRUE, TRUE, 0);

	table1 = gtk_table_new (10, 2, FALSE);
	gtk_widget_show (table1);
	gtk_container_add (GTK_CONTAINER (notebook), table1);

	label4 = gtk_label_new ("Username");
	gtk_widget_show (label4);
	gtk_table_attach (GTK_TABLE (table1), label4, 0, 1, 0, 1,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label4), 0, 0.5);

	label5 = gtk_label_new ("Full name");
	gtk_widget_show (label5);
	gtk_table_attach (GTK_TABLE (table1), label5, 0, 1, 1, 2,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label5), 0, 0.5);

	label6 = gtk_label_new ("Description");
	gtk_widget_show (label6);
	gtk_table_attach (GTK_TABLE (table1), label6, 0, 1, 2, 3,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label6), 0, 0.5);

	label7 = gtk_label_new ("Password");
	gtk_widget_show (label7);
	gtk_table_attach (GTK_TABLE (table1), label7, 0, 1, 3, 4,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label7), 0, 0.5);

	label8 = gtk_label_new ("Confirm password");
	gtk_widget_show (label8);
	gtk_table_attach (GTK_TABLE (table1), label8, 0, 1, 4, 5,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label8), 0, 0.5);

	chk_mustchange = gtk_check_button_new_with_mnemonic ("_User Must Change Password at Next Logon");
	gtk_widget_show (chk_mustchange);
	gtk_table_attach (GTK_TABLE (table1), chk_mustchange, 1, 2, 5, 6,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_fullname = gtk_entry_new ();
	gtk_widget_show (entry_fullname);
	gtk_table_attach (GTK_TABLE (table1), entry_fullname, 1, 2, 1, 2,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_description = gtk_entry_new ();
	gtk_widget_show (entry_description);
	gtk_table_attach (GTK_TABLE (table1), entry_description, 1, 2, 2, 3,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	lbl_username = gtk_label_new ("");
	gtk_widget_show (lbl_username);
	gtk_table_attach (GTK_TABLE (table1), lbl_username, 1, 2, 0, 1,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (lbl_username), 0, 0.5);

	entry_password = gtk_entry_new ();
	gtk_widget_show (entry_password);
	gtk_table_attach (GTK_TABLE (table1), entry_password, 1, 2, 3, 4,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_confirm_password = gtk_entry_new ();
	gtk_widget_show (entry_confirm_password);
	gtk_table_attach (GTK_TABLE (table1), entry_confirm_password, 1, 2, 4, 5,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_cannotchange = gtk_check_button_new_with_mnemonic ("User Cannot Change Password");
	gtk_widget_show (chk_cannotchange);
	gtk_table_attach (GTK_TABLE (table1), chk_cannotchange, 1, 2, 6, 7,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_cannotexpire = gtk_check_button_new_with_mnemonic ("Password Never Expires");
	gtk_widget_show (chk_cannotexpire);
	gtk_table_attach (GTK_TABLE (table1), chk_cannotexpire, 1, 2, 7, 8,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_disabled = gtk_check_button_new_with_mnemonic ("Account Disabled");
	gtk_widget_show (chk_disabled);
	gtk_table_attach (GTK_TABLE (table1), chk_disabled, 1, 2, 8, 9,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_lockedout = gtk_check_button_new_with_mnemonic ("Account Locked Out");
	gtk_widget_show (chk_lockedout);
	gtk_table_attach (GTK_TABLE (table1), chk_lockedout, 1, 2, 9, 10,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	label1 = gtk_label_new ("Main");
	gtk_widget_show (label1);
	gtk_notebook_set_tab_label (GTK_NOTEBOOK (notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (notebook), 0), label1);

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_widget_show (hbox1);
	gtk_container_add (GTK_CONTAINER (notebook), hbox1);

	scrolledwindow3 = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow3);
	gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow3, TRUE, TRUE, 0);

	treeview3 = gtk_tree_view_new ();
	gtk_widget_show (treeview3);
	gtk_container_add (GTK_CONTAINER (scrolledwindow3), treeview3);

	vbox2 = gtk_vbox_new (TRUE, 0);
	gtk_widget_show (vbox2);
	gtk_box_pack_start (GTK_BOX (hbox1), vbox2, TRUE, TRUE, 0);

	btn_groupadd = gtk_button_new_from_stock ("gtk-add");
	gtk_widget_show (btn_groupadd);
	gtk_box_pack_start (GTK_BOX (vbox2), btn_groupadd, FALSE, FALSE, 0);

	btn_groupdel = gtk_button_new_from_stock ("gtk-remove");
	gtk_widget_show (btn_groupdel);
	gtk_box_pack_start (GTK_BOX (vbox2), btn_groupdel, FALSE, FALSE, 0);

	scrolledwindow4 = gtk_scrolled_window_new (NULL, NULL);
	gtk_widget_show (scrolledwindow4);
	gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow4, TRUE, TRUE, 0);

	treeview4 = gtk_tree_view_new ();
	gtk_widget_show (treeview4);
	gtk_container_add (GTK_CONTAINER (scrolledwindow4), treeview4);

	label2 = gtk_label_new ("Groups");
	gtk_widget_show (label2);
	gtk_notebook_set_tab_label (GTK_NOTEBOOK (notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (notebook), 1), label2);

	vbox3 = gtk_vbox_new (FALSE, 0);
	gtk_widget_show (vbox3);
	gtk_container_add (GTK_CONTAINER (notebook), vbox3);

	frame1 = gtk_frame_new (NULL);
	gtk_widget_show (frame1);
	gtk_box_pack_start (GTK_BOX (vbox3), frame1, TRUE, TRUE, 0);

	table2 = gtk_table_new (2, 2, FALSE);
	gtk_widget_show (table2);
	gtk_container_add (GTK_CONTAINER (frame1), table2);

	label12 = gtk_label_new ("User Profile Path:");
	gtk_widget_show (label12);
	gtk_table_attach (GTK_TABLE (table2), label12, 0, 1, 0, 1,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label12), 0, 0.5);

	label13 = gtk_label_new ("Logon Script Name:");
	gtk_widget_show (label13);
	gtk_table_attach (GTK_TABLE (table2), label13, 0, 1, 1, 2,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label13), 0, 0.5);

	entry_profilepath = gtk_entry_new ();
	gtk_widget_show (entry_profilepath);
	gtk_table_attach (GTK_TABLE (table2), entry_profilepath, 1, 2, 0, 1,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_scriptname = gtk_entry_new ();
	gtk_widget_show (entry_scriptname);
	gtk_table_attach (GTK_TABLE (table2), entry_scriptname, 1, 2, 1, 2,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	label10 = gtk_label_new ("User Profiles");
	gtk_widget_show (label10);
	gtk_frame_set_label_widget (GTK_FRAME (frame1), label10);

	frame2 = gtk_frame_new (NULL);
	gtk_widget_show (frame2);
	gtk_box_pack_start (GTK_BOX (vbox3), frame2, TRUE, TRUE, 0);

	table3 = gtk_table_new (2, 2, FALSE);
	gtk_widget_show (table3);
	gtk_container_add (GTK_CONTAINER (frame2), table3);

	label14 = gtk_label_new ("Path");
	gtk_widget_show (label14);
	gtk_table_attach (GTK_TABLE (table3), label14, 0, 1, 0, 1,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label14), 0, 0.5);

	entry_homedir = gtk_entry_new ();
	gtk_widget_show (entry_homedir);
	gtk_table_attach (GTK_TABLE (table3), entry_homedir, 1, 2, 0, 1,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_mapdrive = gtk_check_button_new_with_mnemonic ("Map homedir to drive");
	gtk_widget_show (chk_mapdrive);
	gtk_table_attach (GTK_TABLE (table3), chk_mapdrive, 0, 1, 1, 2,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	combo_homedrive = gtk_combo_new();
	gtk_widget_show (combo_homedrive);
	gtk_table_attach (GTK_TABLE (table3), combo_homedrive, 1, 2, 1, 2,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (GTK_FILL), 0, 0);
	for(i = 'C'; i <= 'Z'; i++)
	{
		char drive[3];
		snprintf(drive, 3, "%c:", i);
		gtk_combo_box_append_text (GTK_COMBO_BOX (combo_homedrive), drive);
	}

	label11 = gtk_label_new ("Home Directory");
	gtk_widget_show (label11);
	gtk_frame_set_label_widget (GTK_FRAME (frame2), label11);

	label3 = gtk_label_new ("Profile");
	gtk_widget_show (label3);
	gtk_notebook_set_tab_label (GTK_NOTEBOOK (notebook), gtk_notebook_get_nth_page (GTK_NOTEBOOK (notebook), 2), label3);

	dialog_action_area1 = GTK_DIALOG (user_edit_dialog)->action_area;
	gtk_widget_show (dialog_action_area1);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

	cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
	gtk_widget_show (cancelbutton1);
	gtk_dialog_add_action_widget (GTK_DIALOG (user_edit_dialog), cancelbutton1, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

	applybutton1 = gtk_button_new_from_stock ("gtk-apply");
	gtk_widget_show (applybutton1);
	gtk_dialog_add_action_widget (GTK_DIALOG (user_edit_dialog), applybutton1, GTK_RESPONSE_APPLY);
	GTK_WIDGET_SET_FLAGS (applybutton1, GTK_CAN_DEFAULT);

	okbutton1 = gtk_button_new_from_stock ("gtk-ok");
	gtk_widget_show (okbutton1);
	gtk_dialog_add_action_widget (GTK_DIALOG (user_edit_dialog), okbutton1, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

	return user_edit_dialog;
}
