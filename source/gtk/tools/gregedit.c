/* 
   Unix SMB/CIFS implementation.
   GTK+ registry frontend
   
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
#include "gtk/common/select.h"
#include "gtk/common/gtk-smb.h"

GtkWidget *openfilewin;
GtkWidget *savefilewin;
GtkTreeStore *store_keys;
GtkListStore *store_vals;
GtkWidget *tree_keys;
GtkWidget *mainwin;
GtkWidget *mnu_add_key, *mnu_add_value, *mnu_del_key, *mnu_del_value, *mnu_find;
TALLOC_CTX *mem_ctx; /* FIXME: Split up */

GtkWidget *save;
GtkWidget *save_as;
static GtkWidget* create_openfilewin (void);
static GtkWidget* create_savefilewin (void);
struct registry_context *registry = NULL;

static GtkWidget* create_FindDialog (void)
{
  GtkWidget *FindDialog;
  GtkWidget *dialog_vbox2;
  GtkWidget *vbox1;
  GtkWidget *hbox1;
  GtkWidget *label6;
  GtkWidget *entry_pattern;
  GtkWidget *frame3;
  GtkWidget *alignment3;
  GtkWidget *vbox2;
  GtkWidget *checkbutton1;
  GtkWidget *checkbutton2;
  GtkWidget *checkbutton3;
  GtkWidget *label7;
  GtkWidget *dialog_action_area2;
  GtkWidget *cancelbutton2;
  GtkWidget *okbutton2;

  FindDialog = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (FindDialog), "Find Key or Value");
  gtk_window_set_type_hint (GTK_WINDOW (FindDialog), GDK_WINDOW_TYPE_HINT_DIALOG);

  dialog_vbox2 = GTK_DIALOG (FindDialog)->vbox;

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (dialog_vbox2), vbox1, TRUE, TRUE, 0);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

  label6 = gtk_label_new ("Find String");
  gtk_box_pack_start (GTK_BOX (hbox1), label6, FALSE, FALSE, 0);

  entry_pattern = gtk_entry_new ();
  gtk_box_pack_start (GTK_BOX (hbox1), entry_pattern, TRUE, TRUE, 0);

  frame3 = gtk_frame_new (NULL);
  gtk_box_pack_start (GTK_BOX (vbox1), frame3, TRUE, TRUE, 0);
  gtk_frame_set_shadow_type (GTK_FRAME (frame3), GTK_SHADOW_NONE);

  alignment3 = gtk_alignment_new (0.5, 0.5, 1, 1);
  gtk_container_add (GTK_CONTAINER (frame3), alignment3);
  gtk_alignment_set_padding (GTK_ALIGNMENT (alignment3), 0, 0, 12, 0);

  vbox2 = gtk_vbox_new (FALSE, 0);
  gtk_container_add (GTK_CONTAINER (alignment3), vbox2);

  checkbutton1 = gtk_check_button_new_with_mnemonic ("_Key Names");
  gtk_box_pack_start (GTK_BOX (vbox2), checkbutton1, FALSE, FALSE, 0);

  checkbutton2 = gtk_check_button_new_with_mnemonic ("_Value Names");
  gtk_box_pack_start (GTK_BOX (vbox2), checkbutton2, FALSE, FALSE, 0);

  checkbutton3 = gtk_check_button_new_with_mnemonic ("Value _Data");
  gtk_box_pack_start (GTK_BOX (vbox2), checkbutton3, FALSE, FALSE, 0);

  label7 = gtk_label_new ("<b>Search in</b>");
  gtk_frame_set_label_widget (GTK_FRAME (frame3), label7);
  gtk_label_set_use_markup (GTK_LABEL (label7), TRUE);

  dialog_action_area2 = GTK_DIALOG (FindDialog)->action_area;
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area2), GTK_BUTTONBOX_END);

  cancelbutton2 = gtk_button_new_from_stock ("gtk-cancel");
  gtk_dialog_add_action_widget (GTK_DIALOG (FindDialog), cancelbutton2, GTK_RESPONSE_CANCEL);
  GTK_WIDGET_SET_FLAGS (cancelbutton2, GTK_CAN_DEFAULT);

  okbutton2 = gtk_button_new_from_stock ("gtk-ok");
  gtk_dialog_add_action_widget (GTK_DIALOG (FindDialog), okbutton2, GTK_RESPONSE_OK);
  GTK_WIDGET_SET_FLAGS (okbutton2, GTK_CAN_DEFAULT);

  gtk_widget_show_all (dialog_vbox2);

  return FindDialog;
}

static GtkWidget* create_SetValueDialog (void)
{
  GtkWidget *SetValueDialog;
  GtkWidget *dialog_vbox1;
  GtkWidget *table1;
  GtkWidget *label3;
  GtkWidget *label4;
  GtkWidget *label5;
  GtkWidget *entry_value_name;
  GtkWidget *value_data;
  GtkWidget *combo_data_type;
  GtkWidget *dialog_action_area1;
  GtkWidget *cancelbutton1;
  GtkWidget *okbutton1;

  SetValueDialog = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (SetValueDialog), "Set Registry Value");
  GTK_WINDOW (SetValueDialog)->type = GTK_WINDOW_POPUP;
  gtk_window_set_position (GTK_WINDOW (SetValueDialog), GTK_WIN_POS_CENTER);
  gtk_window_set_resizable (GTK_WINDOW (SetValueDialog), FALSE);
  gtk_window_set_type_hint (GTK_WINDOW (SetValueDialog), GDK_WINDOW_TYPE_HINT_DIALOG);

  dialog_vbox1 = GTK_DIALOG (SetValueDialog)->vbox;

  table1 = gtk_table_new (3, 2, FALSE);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), table1, TRUE, TRUE, 0);

  label3 = gtk_label_new ("Value name:");
  gtk_table_attach (GTK_TABLE (table1), label3, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label3), 0, 0.5);

  label4 = gtk_label_new ("Data Type:");
  gtk_table_attach (GTK_TABLE (table1), label4, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label4), 0, 0.5);

  label5 = gtk_label_new ("Data:");
  gtk_table_attach (GTK_TABLE (table1), label5, 0, 1, 2, 3,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label5), 0, 0.5);

  entry_value_name = gtk_entry_new ();
  gtk_table_attach (GTK_TABLE (table1), entry_value_name, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  value_data = gtk_entry_new ();
  gtk_table_attach (GTK_TABLE (table1), value_data, 1, 2, 2, 3,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  combo_data_type = gtk_combo_box_entry_new_text ();
  gtk_table_attach (GTK_TABLE (table1), combo_data_type, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (GTK_FILL), 0, 0);

  dialog_action_area1 = GTK_DIALOG (SetValueDialog)->action_area;
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

  cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
  gtk_dialog_add_action_widget (GTK_DIALOG (SetValueDialog), cancelbutton1, GTK_RESPONSE_CANCEL);
  GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

  okbutton1 = gtk_button_new_from_stock ("gtk-ok");
  gtk_dialog_add_action_widget (GTK_DIALOG (SetValueDialog), okbutton1, GTK_RESPONSE_OK);
  GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

  gtk_widget_show_all (dialog_vbox1);

  return SetValueDialog;
}

static GtkWidget* create_NewKeyDialog (void)
{
  GtkWidget *NewKeyDialog;
  GtkWidget *dialog_vbox2;
  GtkWidget *hbox1;
  GtkWidget *label6;
  GtkWidget *entry_key_name;
  GtkWidget *dialog_action_area2;
  GtkWidget *cancelbutton2;
  GtkWidget *okbutton2;

  NewKeyDialog = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (NewKeyDialog), "New Registry Key");
  GTK_WINDOW (NewKeyDialog)->type = GTK_WINDOW_POPUP;
  gtk_window_set_position (GTK_WINDOW (NewKeyDialog), GTK_WIN_POS_CENTER);
  gtk_window_set_resizable (GTK_WINDOW (NewKeyDialog), FALSE);
  gtk_window_set_type_hint (GTK_WINDOW (NewKeyDialog), GDK_WINDOW_TYPE_HINT_DIALOG);

  dialog_vbox2 = GTK_DIALOG (NewKeyDialog)->vbox;

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_box_pack_start (GTK_BOX (dialog_vbox2), hbox1, TRUE, TRUE, 0);

  label6 = gtk_label_new ("Name:");
  gtk_box_pack_start (GTK_BOX (hbox1), label6, FALSE, FALSE, 0);

  entry_key_name = gtk_entry_new ();
  gtk_box_pack_start (GTK_BOX (hbox1), entry_key_name, TRUE, TRUE, 0);

  dialog_action_area2 = GTK_DIALOG (NewKeyDialog)->action_area;
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area2), GTK_BUTTONBOX_END);

  cancelbutton2 = gtk_button_new_from_stock ("gtk-cancel");
  gtk_dialog_add_action_widget (GTK_DIALOG (NewKeyDialog), cancelbutton2, GTK_RESPONSE_CANCEL);
  GTK_WIDGET_SET_FLAGS (cancelbutton2, GTK_CAN_DEFAULT);

  okbutton2 = gtk_button_new_from_stock ("gtk-ok");
  gtk_dialog_add_action_widget (GTK_DIALOG (NewKeyDialog), okbutton2, GTK_RESPONSE_OK);
  GTK_WIDGET_SET_FLAGS (okbutton2, GTK_CAN_DEFAULT);

  gtk_widget_show_all (dialog_vbox2);

  return NewKeyDialog;
}


static void expand_key(GtkTreeView *treeview, GtkTreeIter *parent, GtkTreePath *arg2)
{
	GtkTreeIter firstiter, iter, tmpiter;
	struct registry_key *k, *sub;
	char *name;
	WERROR error;
	int i;

    gtk_tree_model_iter_children(GTK_TREE_MODEL(store_keys), &firstiter, parent);

    /* See if this row has ever had a name gtk_tree_store_set()'ed to it.
       If not, read the directory contents */
    gtk_tree_model_get(GTK_TREE_MODEL(store_keys), &firstiter, 0, &name, -1);

	if(name) return;

	gtk_tree_model_get(GTK_TREE_MODEL(store_keys), parent, 1, &k, -1);

	g_assert(k);
	
	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(mem_ctx, k, i, &sub)); i++) {
		int count;
		/* Replace the blank child with the first directory entry
           You may be tempted to remove the blank child node and then 
           append a new one.  Don't.  If you remove the blank child 
           node GTK gets confused and won't expand the parent row. */

		if(i == 0) {
			iter = firstiter;
		} else {
			gtk_tree_store_append(store_keys, &iter, parent);
		}
		gtk_tree_store_set (store_keys,
					    &iter, 
						0,
						sub->name,
						1, 
						sub,
						-1);
		
		if(W_ERROR_IS_OK(reg_key_num_subkeys(sub, &count)) && count > 0) 
			gtk_tree_store_append(store_keys, &tmpiter, &iter);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) gtk_show_werror(mainwin, error);
}

static void registry_load_root(void) 
{
	struct registry_key *root;
	GtkTreeIter iter, tmpiter;
	int i = 0;
	if(!registry) return;

	gtk_tree_store_clear(store_keys);

	for(i = 0; i < registry->num_hives; i++) 
	{
		root = registry->hives[i]->root;

		/* Add the root */
		gtk_tree_store_append(store_keys, &iter, NULL);
		gtk_tree_store_set (store_keys,
					    &iter, 
						0,
						root->hive->name?root->hive->name:"",
						1,
						root,
						-1);

		gtk_tree_store_append(store_keys, &tmpiter, &iter);
	}

  	gtk_widget_set_sensitive( save, True );
  	gtk_widget_set_sensitive( save_as, True );
}

static void on_open_file_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	gint result = gtk_dialog_run(GTK_DIALOG(create_openfilewin()));
	char *filename, *tmp;
	WERROR error;
	switch(result) {
	case GTK_RESPONSE_OK:
		filename = strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(openfilewin)));
		error = reg_open(&registry, user_data, filename, NULL);
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(mainwin, error);
			break;
		}

		tmp = g_strdup_printf("Registry Editor - %s", filename);
		gtk_window_set_title (GTK_WINDOW (mainwin), tmp);
		g_free(tmp);
		registry_load_root();
		break;
	default:
		break;
	}

	gtk_widget_destroy(openfilewin);
}

static void on_open_gconf_activate                       (GtkMenuItem     *menuitem,
  		                                      gpointer         user_data)
{
	WERROR error = reg_open(&registry, "gconf", NULL, NULL);
	if(!W_ERROR_IS_OK(error)) {
		gtk_show_werror(mainwin, error);
		return;
	}

	gtk_window_set_title (GTK_WINDOW (mainwin), "Registry Editor - GConf");

	registry_load_root();
}

static void on_open_remote_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	char *credentials;
	const char *location;
	char *tmp;
	GtkWidget *rpcwin = GTK_WIDGET(gtk_rpc_binding_dialog_new(FALSE, NULL));
	gint result = gtk_dialog_run(GTK_DIALOG(rpcwin));
	WERROR error;
	
	if(result != GTK_RESPONSE_ACCEPT)
	{
		gtk_widget_destroy(rpcwin);
		return;
	}

	location = gtk_rpc_binding_dialog_get_binding_string(GTK_RPC_BINDING_DIALOG(rpcwin), mem_ctx);
	asprintf(&credentials, "%s%%%s", gtk_rpc_binding_dialog_get_username(GTK_RPC_BINDING_DIALOG(rpcwin)), gtk_rpc_binding_dialog_get_password(GTK_RPC_BINDING_DIALOG(rpcwin)));
	error = reg_open(&registry, "rpc", location, credentials);

	if(!W_ERROR_IS_OK(error)) {
		gtk_show_werror(mainwin, error);
		gtk_widget_destroy(rpcwin);
		return;
	}
	free(credentials);

	tmp = g_strdup_printf("Registry Editor - Remote Registry at %s", gtk_rpc_binding_dialog_get_host(GTK_RPC_BINDING_DIALOG(rpcwin)));
	gtk_window_set_title (GTK_WINDOW (mainwin), tmp);
	g_free(tmp);

	registry_load_root();


	gtk_widget_destroy(rpcwin);
}


static void on_save_activate                       (GtkMenuItem     *menuitem,
													gpointer         user_data)
{
	WERROR error = reg_save(registry, NULL);
	if(!W_ERROR_IS_OK(error)) {
		gtk_show_werror(mainwin, error);
	}
}


static void on_save_as_activate                    (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	gint result;
	WERROR error;
	create_savefilewin();
	result = gtk_dialog_run(GTK_DIALOG(savefilewin));
	switch(result) {
	case GTK_RESPONSE_OK:
		error = reg_save(registry, gtk_file_selection_get_filename(GTK_FILE_SELECTION(savefilewin)));
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(mainwin, error);
		}
		break;

	default:
		break;

	}
	gtk_widget_destroy(savefilewin);
}


static void on_quit_activate                       (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	gtk_main_quit();
}


static void on_delete_activate                     (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	/* FIXME */
}

static void on_add_key_activate                     (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
        GtkDialog *addwin = GTK_DIALOG(create_NewKeyDialog());
        gtk_dialog_run(addwin);
	/* FIXME */
        gtk_widget_destroy(GTK_WIDGET(addwin));
}

static void on_add_value_activate                     (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
        GtkDialog *addwin = GTK_DIALOG(create_SetValueDialog());
        gtk_dialog_run(addwin);
	/* FIXME */
        gtk_widget_destroy(GTK_WIDGET(addwin));
}

static void on_find_activate                     (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
        GtkDialog *findwin = GTK_DIALOG(create_FindDialog());
        gtk_dialog_run(findwin);
	/* FIXME */
        gtk_widget_destroy(GTK_WIDGET(findwin));
}

static void on_about_activate                      (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
        GtkDialog *aboutwin = GTK_DIALOG(create_gtk_samba_about_dialog("gregedit"));
        gtk_dialog_run(aboutwin);
        gtk_widget_destroy(GTK_WIDGET(aboutwin));
}

gboolean on_key_activate(GtkTreeSelection *selection,
                                             GtkTreeModel *model,
                                             GtkTreePath *path,
                                             gboolean path_currently_selected,
                                             gpointer data)
{
	int i;
	struct registry_key *k;
	struct registry_value *val;
	WERROR error;
	GtkTreeIter parent;

	gtk_widget_set_sensitive(mnu_add_key, !path_currently_selected);
	gtk_widget_set_sensitive(mnu_add_value, !path_currently_selected);
	gtk_widget_set_sensitive(mnu_del_key, !path_currently_selected);
	gtk_widget_set_sensitive(mnu_del_value, !path_currently_selected);
	gtk_widget_set_sensitive(mnu_find, !path_currently_selected);

	if(path_currently_selected) { return TRUE; }

	gtk_tree_model_get_iter(GTK_TREE_MODEL(store_keys), &parent, path);
	gtk_tree_model_get(GTK_TREE_MODEL(store_keys), &parent, 1, &k, -1);

	g_assert(k);

	gtk_list_store_clear(store_vals);

	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_value_by_index(mem_ctx, k, i, &val)); i++) {
		GtkTreeIter iter;
		gtk_list_store_append(store_vals, &iter);
		gtk_list_store_set (store_vals,
					    &iter, 
						0,
						val->name,
						1,
						str_regtype(val->data_type),
						2,
						reg_val_data_string(mem_ctx, val),
						3, 
						val,
						-1);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
		 gtk_show_werror(mainwin, error);
		 return FALSE;
	}
	return TRUE;
}

static GtkWidget* create_mainwin (void)
{
	GtkWidget *vbox1;
	GtkWidget *menubar;
	GtkWidget *menu_file;
	GtkWidget *menu_file_menu;
	GtkWidget *open_nt4;
	GtkWidget *open_ldb;
	GtkWidget *open_w95;
	GtkWidget *open_gconf;
	GtkWidget *open_remote;
	GtkWidget *separatormenuitem1;
	GtkWidget *quit;
	GtkWidget *men_key;
	GtkWidget *men_key_menu;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *curcol;
	GtkWidget *help;
	GtkWidget *help_menu;
	GtkWidget *about;
	GtkWidget *hbox1;
	GtkWidget *scrolledwindow1;
	GtkWidget *scrolledwindow2;
	GtkWidget *tree_vals;
	GtkWidget *statusbar;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();

	mainwin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (mainwin), "Registry editor");
	gtk_window_set_default_size (GTK_WINDOW (mainwin), 642, 562);

	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (mainwin), vbox1);

	menubar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), menubar, FALSE, FALSE, 0);

	menu_file = gtk_menu_item_new_with_mnemonic ("_File");
	gtk_container_add (GTK_CONTAINER (menubar), menu_file);

	menu_file_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_file), menu_file_menu);

	if(reg_has_backend("nt4")) {
		open_nt4 = gtk_image_menu_item_new_with_mnemonic("Open _NT4 file");
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_nt4);

		g_signal_connect ((gpointer) open_nt4, "activate",
						  G_CALLBACK (on_open_file_activate),
						  (gconstpointer)"nt4");
	}

	if(reg_has_backend("w95")) {
		open_w95 = gtk_image_menu_item_new_with_mnemonic("Open Win_9x file");
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_w95);

		g_signal_connect ((gpointer) open_w95, "activate",
						  G_CALLBACK (on_open_file_activate),
						  (gconstpointer)"w95");
	}

	if(reg_has_backend("gconf")) {
		open_gconf = gtk_image_menu_item_new_with_mnemonic ("Open _GConf");
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_gconf);

		g_signal_connect ((gpointer) open_gconf, "activate",
						  G_CALLBACK (on_open_gconf_activate),
						  NULL);
	}

	if(reg_has_backend("rpc")) {
		open_remote = gtk_menu_item_new_with_mnemonic ("Open _Remote");
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_remote);

		g_signal_connect ((gpointer) open_remote, "activate",
						  G_CALLBACK (on_open_remote_activate),
						  NULL);
	}

	if(reg_has_backend("ldb")) {
		open_ldb = gtk_image_menu_item_new_with_mnemonic("Open _LDB file");
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_ldb);

		g_signal_connect ((gpointer) open_ldb, "activate",
						  G_CALLBACK (on_open_file_activate),
						  (gconstpointer)"ldb");
	}

	save = gtk_image_menu_item_new_from_stock ("gtk-save", accel_group);
	gtk_widget_set_sensitive( save, False );
	gtk_container_add (GTK_CONTAINER (menu_file_menu), save);

	save_as = gtk_image_menu_item_new_from_stock ("gtk-save-as", accel_group);
	gtk_widget_set_sensitive( save_as, False );
	gtk_container_add (GTK_CONTAINER (menu_file_menu), save_as);

	separatormenuitem1 = gtk_menu_item_new ();
	gtk_container_add (GTK_CONTAINER (menu_file_menu), separatormenuitem1);
	gtk_widget_set_sensitive (separatormenuitem1, FALSE);

	quit = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
	gtk_container_add (GTK_CONTAINER (menu_file_menu), quit);

	men_key = gtk_menu_item_new_with_mnemonic ("_Key");
	gtk_container_add (GTK_CONTAINER (menubar), men_key);

	men_key_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (men_key), men_key_menu);

	mnu_add_key = gtk_image_menu_item_new_with_mnemonic("Add _Subkey");
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (mnu_add_key), gtk_image_new_from_stock ("gtk-add", GTK_ICON_SIZE_MENU));

	gtk_widget_set_sensitive(mnu_add_key, False);
	gtk_container_add (GTK_CONTAINER (men_key_menu), mnu_add_key);

	mnu_add_value = gtk_image_menu_item_new_with_mnemonic("Add _Value");
	gtk_widget_set_sensitive(mnu_add_value, False);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (mnu_add_value), gtk_image_new_from_stock ("gtk-add", GTK_ICON_SIZE_MENU));
	gtk_container_add (GTK_CONTAINER (men_key_menu), mnu_add_value);

	mnu_find = gtk_image_menu_item_new_from_stock ("gtk-find", accel_group);
	gtk_widget_set_sensitive(mnu_find, False);
	gtk_container_add (GTK_CONTAINER (men_key_menu), mnu_find);

	mnu_del_key = gtk_image_menu_item_new_with_mnemonic ("Delete Key"); 
	gtk_widget_set_sensitive(mnu_del_key, False);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (mnu_del_value), gtk_image_new_from_stock ("gtk-delete", GTK_ICON_SIZE_MENU));
	gtk_container_add (GTK_CONTAINER (men_key_menu), mnu_del_key);

	mnu_del_value = gtk_image_menu_item_new_with_mnemonic ("Delete Value"); 
	gtk_widget_set_sensitive(mnu_del_value, False);
	gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (mnu_del_value), gtk_image_new_from_stock ("gtk-delete", GTK_ICON_SIZE_MENU));
	gtk_container_add (GTK_CONTAINER (men_key_menu), mnu_del_value);


	help = gtk_menu_item_new_with_mnemonic ("_Help");
	gtk_container_add (GTK_CONTAINER (menubar), help);

	help_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (help), help_menu);

	about = gtk_menu_item_new_with_mnemonic ("_About");
	gtk_container_add (GTK_CONTAINER (help_menu), about);

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

	scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow1, TRUE, TRUE, 0);

	tree_keys = gtk_tree_view_new ();

	/* Column names */
	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Name");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);

	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_keys), curcol);

	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), tree_keys);
	store_keys = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree_keys), GTK_TREE_MODEL(store_keys));
	g_object_unref(store_keys);

	gtk_tree_selection_set_select_function (gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_keys)), on_key_activate, NULL, NULL);

	g_signal_connect ((gpointer) tree_keys, "row-expanded",
					  G_CALLBACK (expand_key),
					  NULL);


	scrolledwindow2 = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow2, TRUE, TRUE, 0);

	tree_vals = gtk_tree_view_new ();
	/* Column names */

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Name");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_vals), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Type");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_vals), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 1);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Value");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_vals), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 2);


	gtk_container_add (GTK_CONTAINER (scrolledwindow2), tree_vals);

	store_vals = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree_vals), GTK_TREE_MODEL(store_vals));
	g_object_unref(store_vals);

	statusbar = gtk_statusbar_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), statusbar, FALSE, FALSE, 0);
	gtk_statusbar_set_has_resize_grip (GTK_STATUSBAR (statusbar), FALSE);

	g_signal_connect ((gpointer) save, "activate",
					  G_CALLBACK (on_save_activate),
					  NULL);
	g_signal_connect ((gpointer) save_as, "activate",
					  G_CALLBACK (on_save_as_activate),
					  NULL);
	g_signal_connect ((gpointer) quit, "activate",
					  G_CALLBACK (on_quit_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_add_key, "activate",
					  G_CALLBACK (on_add_key_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_add_value, "activate",
					  G_CALLBACK (on_add_value_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_find, "activate",
					  G_CALLBACK (on_find_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_del_key, "activate",
					  G_CALLBACK (on_delete_activate),
					  NULL);
	g_signal_connect ((gpointer) about, "activate",
					  G_CALLBACK (on_about_activate),
					  NULL);

	gtk_window_add_accel_group (GTK_WINDOW (mainwin), accel_group);

	return mainwin;
}

static GtkWidget* create_openfilewin (void)
{
	GtkWidget *ok_button;
	GtkWidget *cancel_button;

	openfilewin = gtk_file_selection_new ("Select File");
	gtk_container_set_border_width (GTK_CONTAINER (openfilewin), 10);

	ok_button = GTK_FILE_SELECTION (openfilewin)->ok_button;
	GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);

	cancel_button = GTK_FILE_SELECTION (openfilewin)->cancel_button;
	GTK_WIDGET_SET_FLAGS (cancel_button, GTK_CAN_DEFAULT);

	return openfilewin;
}

static GtkWidget* create_savefilewin (void)
{
	GtkWidget *ok_button;
	GtkWidget *cancel_button;

	savefilewin = gtk_file_selection_new ("Select File");
	gtk_container_set_border_width (GTK_CONTAINER (savefilewin), 10);

	ok_button = GTK_FILE_SELECTION (savefilewin)->ok_button;
	GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);

	cancel_button = GTK_FILE_SELECTION (savefilewin)->cancel_button;
	GTK_WIDGET_SET_FLAGS (cancel_button, GTK_CAN_DEFAULT);

	return savefilewin;
}

 int main(int argc, char *argv[])
{
	poptContext pc;
	const char *backend = NULL;
	const char *credentials = NULL;
	const char *location;
	int opt;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"backend", 'b', POPT_ARG_STRING, &backend, 0, "backend to use", NULL},
		{"credentials", 'c', POPT_ARG_STRING, &credentials, 0, "credentials (user%%password)", NULL},
		POPT_TABLEEND
	};

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();

	gtk_init (&argc, &argv);
	mem_ctx = talloc_init("gregedit");

	pc = poptGetContext(argv[0], argc, (const char **) argv, long_options,0);

	while((opt = poptGetNextOpt(pc)) != -1) {
	}

	location = poptGetArg(pc);

	if(location) {
		WERROR error;

		if(!backend) {
			if(credentials)backend = "rpc";
			else backend = "nt4";
		}

		error = reg_open(&registry, backend, location, credentials);
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(mainwin, error);
			return -1;
		}
		mainwin = create_mainwin ();
		registry_load_root();
	} else {
		mainwin = create_mainwin ();
	}

	gtk_widget_show_all (mainwin);

	gtk_main ();

	if(registry)talloc_destroy(registry->mem_ctx);
	talloc_destroy(mem_ctx);
	return 0;
}


