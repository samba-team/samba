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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>
#include "includes.h"

GtkWidget *openfilewin;
GtkWidget *savefilewin;
GtkTreeStore *store_keys;
GtkListStore *store_vals;
GtkWidget *tree_keys;
GtkWidget *aboutwin;
GtkWidget *mainwin;

GtkWidget *rpcwin;
GtkWidget *rpcwin_host;
GtkWidget *rpcwin_user;
GtkWidget *rpcwin_password;
GtkWidget *save;
GtkWidget *save_as;
static GtkWidget* create_openfilewin (void);
static GtkWidget* create_savefilewin (void);
static GtkWidget* create_aboutwin (void);
REG_HANDLE *registry = NULL;

static void gtk_show_werror(WERROR err) 
{
	GtkWidget *dialog = gtk_message_dialog_new( GTK_WINDOW(mainwin), 
		 GTK_DIALOG_DESTROY_WITH_PARENT,
         GTK_MESSAGE_ERROR,
         GTK_BUTTONS_CLOSE,
		 "Registry error: %s\n", win_errstr(err));
	gtk_dialog_run (GTK_DIALOG (dialog));
 	gtk_widget_destroy (dialog);
}

static void expand_key(GtkTreeView *treeview, GtkTreeIter *parent, GtkTreePath *arg2)
{
	GtkTreeIter firstiter, iter, tmpiter;
	REG_KEY *k, *sub;
	char *name;
	GValue value;
	WERROR error;
	int i;

    gtk_tree_model_iter_children(GTK_TREE_MODEL(store_keys), &firstiter, parent);

    /* See if this row has ever had a name gtk_tree_store_set()'ed to it.
       If not, read the directory contents */
    gtk_tree_model_get(GTK_TREE_MODEL(store_keys), &firstiter, 0, &name, -1);

	if(name) return;

	gtk_tree_model_get(GTK_TREE_MODEL(store_keys), parent, 1, &k, -1);

	g_assert(k);
	
	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_subkey_by_index(k, i, &sub)); i++) {
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
						reg_key_name(sub),
						1, 
						sub,
						-1);
		
		if(W_ERROR_IS_OK(reg_key_num_subkeys(sub, &count)) && count > 0) 
			gtk_tree_store_append(store_keys, &tmpiter, &iter);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) gtk_show_werror(error);
}

static void registry_load_root() 
{
	REG_KEY *root;
	GtkTreeIter iter, tmpiter;
	WERROR error = WERR_OK;
	int i = 0;
	if(!registry) return;

	gtk_tree_store_clear(store_keys);

	while(1) {
		error = reg_get_hive(registry, i, &root);
		if(W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) {
			return;
		}
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(error);
			return;
		}

		/* Add the root */
		gtk_tree_store_append(store_keys, &iter, NULL);
		gtk_tree_store_set (store_keys,
					    &iter, 
						0,
						reg_key_name(root),
						1,
						root,
						-1);

		gtk_tree_store_append(store_keys, &tmpiter, &iter);
		i++;
	}

  	gtk_widget_set_sensitive( save, True );
  	gtk_widget_set_sensitive( save_as, True );
}

static GtkWidget* create_rpcwin (void)
{
  GtkWidget *dialog_vbox1;
  GtkWidget *table1;
  GtkWidget *label1;
  GtkWidget *label2;
  GtkWidget *label3;
  GtkWidget *dialog_action_area1;
  GtkWidget *cancelbutton1;
  GtkWidget *okbutton1;

  rpcwin = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (rpcwin), "Connect to remote server");

  dialog_vbox1 = GTK_DIALOG (rpcwin)->vbox;
  gtk_widget_show (dialog_vbox1);

  table1 = gtk_table_new (3, 2, FALSE);
  gtk_widget_show (table1);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), table1, TRUE, TRUE, 0);

  label1 = gtk_label_new ("Host:");
  gtk_widget_show (label1);
  gtk_table_attach (GTK_TABLE (table1), label1, 0, 1, 0, 1,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label1), 0, 0.5);

  label2 = gtk_label_new ("User:");
  gtk_widget_show (label2);
  gtk_table_attach (GTK_TABLE (table1), label2, 0, 1, 1, 2,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label2), 0, 0.5);

  label3 = gtk_label_new ("Password:");
  gtk_widget_show (label3);
  gtk_table_attach (GTK_TABLE (table1), label3, 0, 1, 2, 3,
                    (GtkAttachOptions) (GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_misc_set_alignment (GTK_MISC (label3), 0, 0.5);

  rpcwin_host = gtk_entry_new ();
  gtk_widget_show (rpcwin_host);
  gtk_table_attach (GTK_TABLE (table1), rpcwin_host, 1, 2, 0, 1,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  rpcwin_user = gtk_entry_new ();
  gtk_widget_show (rpcwin_user);
  gtk_table_attach (GTK_TABLE (table1), rpcwin_user, 1, 2, 1, 2,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);

  rpcwin_password = gtk_entry_new ();
  gtk_widget_show (rpcwin_password);
  gtk_table_attach (GTK_TABLE (table1), rpcwin_password, 1, 2, 2, 3,
                    (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
                    (GtkAttachOptions) (0), 0, 0);
  gtk_entry_set_visibility (GTK_ENTRY (rpcwin_password), FALSE);

  dialog_action_area1 = GTK_DIALOG (rpcwin)->action_area;
  gtk_widget_show (dialog_action_area1);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

  cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
  gtk_widget_show (cancelbutton1);
  gtk_dialog_add_action_widget (GTK_DIALOG (rpcwin), cancelbutton1, GTK_RESPONSE_CANCEL);
  GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

  okbutton1 = gtk_button_new_from_stock ("gtk-ok");
  gtk_widget_show (okbutton1);
  gtk_dialog_add_action_widget (GTK_DIALOG (rpcwin), okbutton1, GTK_RESPONSE_OK);
  GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

  return rpcwin;
}

static void on_open_file_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	gint result = gtk_dialog_run(GTK_DIALOG(create_openfilewin()));
	char *filename;
	WERROR error;
	switch(result) {
	case GTK_RESPONSE_OK:
		filename = strdup(gtk_file_selection_get_filename(GTK_FILE_SELECTION(openfilewin)));
		error = reg_open(user_data, filename, NULL, &registry);
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(error);
			break;
		}
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
	WERROR error = reg_open("gconf", NULL, NULL, &registry);
	if(!W_ERROR_IS_OK(error)) {
		gtk_show_werror(error);
		return;
	}

	registry_load_root();
}

static void on_open_remote_activate                (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	char *location, *credentials;
	gint result = gtk_dialog_run(GTK_DIALOG(create_rpcwin()));
	WERROR error;
	switch(result) {
	case GTK_RESPONSE_OK:
		asprintf(&location, "ncacn_np:%s", gtk_entry_get_text(GTK_ENTRY(rpcwin_host)));
		asprintf(&credentials, "%s%%%s", gtk_entry_get_text(GTK_ENTRY(rpcwin_user)), gtk_entry_get_text(GTK_ENTRY(rpcwin_password)));
		error = reg_open("rpc", location, credentials, &registry);
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(error);
			break;
		}
		free(location); free(credentials);
		registry_load_root();
		break;
	default:
		break;
	}

	gtk_widget_destroy(rpcwin);
}


static void on_save_activate                       (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	WERROR error = reg_save(registry, NULL);
	if(!W_ERROR_IS_OK(error)) {
		gtk_show_werror(error);
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
			gtk_show_werror(error);
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


static void on_cut_activate                        (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	/* FIXME */
}


static void on_copy_activate                       (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	/* FIXME */
}


static void on_paste_activate                      (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	/* FIXME */
}


static void on_delete_activate                     (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	/* FIXME */
}


static void on_about_activate                      (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	gtk_dialog_run(GTK_DIALOG(create_aboutwin()));
	gtk_widget_destroy(aboutwin);
}

static void on_key_activate (GtkTreeView *treeview,
					  GtkTreePath *path,
					  gpointer user_data)
{
	int i;
	REG_KEY *k;
	REG_VAL *val;
	WERROR error;
	GtkTreeIter parent;

	gtk_tree_model_get_iter(GTK_TREE_MODEL(store_keys), &parent, path);
	gtk_tree_model_get(GTK_TREE_MODEL(store_keys), &parent, 1, &k, -1);

	g_assert(k);

	gtk_list_store_clear(store_vals);

	for(i = 0; W_ERROR_IS_OK(error = reg_key_get_value_by_index(k, i, &val)); i++) {
		GtkTreeIter iter;
		gtk_list_store_append(store_vals, &iter);
		gtk_list_store_set (store_vals,
					    &iter, 
						0,
						reg_val_name(val),
						1,
						str_regtype(reg_val_type(val)),
						2,
						reg_val_data_string(val),
						3, 
						val,
						-1);
	}

	if(!W_ERROR_EQUAL(error, WERR_NO_MORE_ITEMS)) gtk_show_werror(error);
}

static GtkWidget* create_mainwin (void)
{
	GtkWidget *vbox1;
	GtkWidget *menubar;
	GtkWidget *menu_file;
	GtkWidget *menu_file_menu;
	GtkWidget *open_nt4;
	GtkWidget *open_w95;
	GtkWidget *open_gconf;
	GtkWidget *open_remote;
	GtkWidget *separatormenuitem1;
	GtkWidget *quit;
	GtkWidget *men_edit;
	GtkWidget *men_edit_menu;
	GtkWidget *cut;
	GtkWidget *copy;
	GtkWidget *paste;
	GtkWidget *delete;
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
	GtkTreeIter iter, child;

	accel_group = gtk_accel_group_new ();

	mainwin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (mainwin), "Registry editor");
	gtk_window_set_default_size (GTK_WINDOW (mainwin), 642, 562);

	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_widget_show (vbox1);
	gtk_container_add (GTK_CONTAINER (mainwin), vbox1);

	menubar = gtk_menu_bar_new ();
	gtk_widget_show (menubar);
	gtk_box_pack_start (GTK_BOX (vbox1), menubar, FALSE, FALSE, 0);

	menu_file = gtk_menu_item_new_with_mnemonic ("_File");
	gtk_widget_show (menu_file);
	gtk_container_add (GTK_CONTAINER (menubar), menu_file);

	menu_file_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menu_file), menu_file_menu);

	if(reg_has_backend("nt4")) {
		open_nt4 = gtk_image_menu_item_new_with_mnemonic("_Open NT4 file");
		gtk_widget_show (open_nt4);
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_nt4);

  		g_signal_connect ((gpointer) open_nt4, "activate",
                    G_CALLBACK (on_open_file_activate),
                    "nt4");
	}

	if(reg_has_backend("w95")) {
		open_w95 = gtk_image_menu_item_new_with_mnemonic("_Open Win9x file");
		gtk_widget_show (open_w95);
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_w95);

  		g_signal_connect ((gpointer) open_w95, "activate",
                    G_CALLBACK (on_open_file_activate),
                    "w95");
	}

	if(reg_has_backend("gconf")) {
		open_gconf = gtk_image_menu_item_new_with_mnemonic ("_Open GConf");
		gtk_widget_show (open_gconf);
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_gconf);

  		g_signal_connect ((gpointer) open_gconf, "activate",
                    G_CALLBACK (on_open_gconf_activate),
                    NULL);
	}

	if(reg_has_backend("rpc")) {
		open_remote = gtk_menu_item_new_with_mnemonic ("_Open Remote");
		gtk_widget_show (open_remote);
		gtk_container_add (GTK_CONTAINER (menu_file_menu), open_remote);

  		g_signal_connect ((gpointer) open_remote, "activate",
                    G_CALLBACK (on_open_remote_activate),
                    NULL);
	}

	save = gtk_image_menu_item_new_from_stock ("gtk-save", accel_group);
	gtk_widget_show (save);
	gtk_widget_set_sensitive( save, False );
	gtk_container_add (GTK_CONTAINER (menu_file_menu), save);

	save_as = gtk_image_menu_item_new_from_stock ("gtk-save-as", accel_group);
	gtk_widget_show (save_as);
	gtk_widget_set_sensitive( save_as, False );
	gtk_container_add (GTK_CONTAINER (menu_file_menu), save_as);

	separatormenuitem1 = gtk_menu_item_new ();
	gtk_widget_show (separatormenuitem1);
	gtk_container_add (GTK_CONTAINER (menu_file_menu), separatormenuitem1);
	gtk_widget_set_sensitive (separatormenuitem1, FALSE);

	quit = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
	gtk_widget_show (quit);
	gtk_container_add (GTK_CONTAINER (menu_file_menu), quit);

	men_edit = gtk_menu_item_new_with_mnemonic ("_Edit");
	gtk_widget_show (men_edit);
	gtk_container_add (GTK_CONTAINER (menubar), men_edit);

  men_edit_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (men_edit), men_edit_menu);

  cut = gtk_image_menu_item_new_from_stock ("gtk-cut", accel_group);
  gtk_widget_show (cut);
  gtk_widget_set_sensitive(cut, False);
  gtk_container_add (GTK_CONTAINER (men_edit_menu), cut);

  copy = gtk_image_menu_item_new_from_stock ("gtk-copy", accel_group);
  gtk_widget_show (copy);
  gtk_widget_set_sensitive(copy, False);
  gtk_container_add (GTK_CONTAINER (men_edit_menu), copy);

  paste = gtk_image_menu_item_new_from_stock ("gtk-paste", accel_group);
  gtk_widget_show (paste);
  gtk_widget_set_sensitive(paste, False);
  gtk_container_add (GTK_CONTAINER (men_edit_menu), paste);

  delete = gtk_image_menu_item_new_from_stock ("gtk-delete", accel_group);
  gtk_widget_show (delete);
  gtk_widget_set_sensitive(delete, False);
  gtk_container_add (GTK_CONTAINER (men_edit_menu), delete);

  help = gtk_menu_item_new_with_mnemonic ("_Help");
  gtk_widget_show (help);
  gtk_container_add (GTK_CONTAINER (menubar), help);

  help_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (help), help_menu);

  about = gtk_menu_item_new_with_mnemonic ("_About");
  gtk_widget_show (about);
  gtk_container_add (GTK_CONTAINER (help_menu), about);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox1);
  gtk_box_pack_start (GTK_BOX (vbox1), hbox1, TRUE, TRUE, 0);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (hbox1), scrolledwindow1, TRUE, TRUE, 0);

  tree_keys = gtk_tree_view_new ();

  /* Column names */
  curcol = gtk_tree_view_column_new ();
  gtk_tree_view_column_set_title(curcol, "Name");
  renderer = gtk_cell_renderer_text_new();
  gtk_tree_view_column_pack_start(curcol, renderer, True);

  gtk_tree_view_append_column(GTK_TREE_VIEW(tree_keys), curcol);

  gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);
  gtk_widget_show (tree_keys);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), tree_keys);
  store_keys = gtk_tree_store_new(2, G_TYPE_STRING, G_TYPE_POINTER);
  gtk_tree_view_set_model(GTK_TREE_VIEW(tree_keys), GTK_TREE_MODEL(store_keys));
  g_object_unref(store_keys);

  g_signal_connect ((gpointer) tree_keys, "row-activated",
                    G_CALLBACK (on_key_activate),
                    NULL);

  g_signal_connect ((gpointer) tree_keys, "row-expanded",
                    G_CALLBACK (expand_key),
                    NULL);

  scrolledwindow2 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (scrolledwindow2);
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

  
  gtk_widget_show (tree_vals);
  gtk_container_add (GTK_CONTAINER (scrolledwindow2), tree_vals);

  store_vals = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
  gtk_tree_view_set_model(GTK_TREE_VIEW(tree_vals), GTK_TREE_MODEL(store_vals));
  g_object_unref(store_vals);

  statusbar = gtk_statusbar_new ();
  gtk_widget_show (statusbar);
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
  g_signal_connect ((gpointer) cut, "activate",
                    G_CALLBACK (on_cut_activate),
                    NULL);
  g_signal_connect ((gpointer) copy, "activate",
                    G_CALLBACK (on_copy_activate),
                    NULL);
  g_signal_connect ((gpointer) paste, "activate",
                    G_CALLBACK (on_paste_activate),
                    NULL);
  g_signal_connect ((gpointer) delete, "activate",
                    G_CALLBACK (on_delete_activate),
                    NULL);
  g_signal_connect ((gpointer) about, "activate",
                    G_CALLBACK (on_about_activate),
                    NULL);

  gtk_window_add_accel_group (GTK_WINDOW (mainwin), accel_group);

  return mainwin;
}

static GtkWidget* create_aboutwin (void)
{
  GtkWidget *dialog_vbox1;
  GtkWidget *image1;
  GtkWidget *label1;
  GtkWidget *label2;
  GtkWidget *dialog_action_area1;
  GtkWidget *closebutton1;

  aboutwin = gtk_dialog_new ();
  gtk_window_set_title (GTK_WINDOW (aboutwin), "About GRegEdit");
  gtk_window_set_resizable (GTK_WINDOW (aboutwin), FALSE);

  dialog_vbox1 = GTK_DIALOG (aboutwin)->vbox;
  gtk_widget_show (dialog_vbox1);

  /* FIXME: Samba logo ? 
  image1 = create_pixmap (aboutwin, "samba.png");
  gtk_widget_show (image1);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), image1, FALSE, TRUE, 0); */

  label1 = gtk_label_new ("GRegEdit 0.1");
  gtk_widget_show (label1);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), label1, FALSE, FALSE, 0);
  gtk_label_set_use_markup (GTK_LABEL (label1), TRUE);

  label2 = gtk_label_new_with_mnemonic ("(C) 2004 Jelmer Vernooij <jelmer@samba.org>\nPart of Samba\nhttp://www.samba.org/\n");
  gtk_widget_show (label2);
  gtk_box_pack_start (GTK_BOX (dialog_vbox1), label2, TRUE, FALSE, 0);
  gtk_label_set_use_markup (GTK_LABEL (label2), TRUE);

  dialog_action_area1 = GTK_DIALOG (aboutwin)->action_area;
  gtk_widget_show (dialog_action_area1);
  gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

  closebutton1 = gtk_button_new_from_stock ("gtk-close");
  gtk_widget_show (closebutton1);
  gtk_dialog_add_action_widget (GTK_DIALOG (aboutwin), closebutton1, GTK_RESPONSE_CLOSE);
  GTK_WIDGET_SET_FLAGS (closebutton1, GTK_CAN_DEFAULT);

  return aboutwin;
}


static GtkWidget* create_openfilewin (void)
{
  GtkWidget *ok_button;
  GtkWidget *cancel_button;

  openfilewin = gtk_file_selection_new ("Select File");
  gtk_container_set_border_width (GTK_CONTAINER (openfilewin), 10);

  ok_button = GTK_FILE_SELECTION (openfilewin)->ok_button;
  gtk_widget_show (ok_button);
  GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);

  cancel_button = GTK_FILE_SELECTION (openfilewin)->cancel_button;
  gtk_widget_show (cancel_button);
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
  gtk_widget_show (ok_button);
  GTK_WIDGET_SET_FLAGS (ok_button, GTK_CAN_DEFAULT);

  cancel_button = GTK_FILE_SELECTION (savefilewin)->cancel_button;
  gtk_widget_show (cancel_button);
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
                                                                              
    gtk_init (&argc, &argv);

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
		
		error = reg_open(backend, location, credentials, &registry);
		if(!W_ERROR_IS_OK(error)) {
			gtk_show_werror(error);
			return -1;
		}
		mainwin = create_mainwin ();
		registry_load_root();
	} else 
		mainwin = create_mainwin ();

	gtk_widget_show (mainwin);

	gtk_main ();

	if(registry)reg_free(registry);
	return 0;
}
