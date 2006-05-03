/* 
   Unix SMB/CIFS implementation.
   GTK+ Windows services management
   
   Copyright (C) Jelmer Vernooij 2006

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
#include "librpc/gen_ndr/ndr_svcctl_c.h"
#include "gtk/common/gtk-smb.h"
#include "auth/credentials/credentials.h"
#include "gtk/common/select.h"

static struct dcerpc_pipe *svcctl_pipe = NULL;
static GtkWidget *mainwin;
static GtkListStore *store_services;
static GtkWidget *services;
static GtkWidget *new_service, *delete_service, *edit_service, *start_service, *stop_service;

static void on_connect_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	TALLOC_CTX *mem_ctx = talloc_init("gwsvcctl_connect");

	svcctl_pipe = gtk_connect_rpc_interface(mem_ctx, &dcerpc_table_svcctl);
	if (svcctl_pipe == NULL)
		return;

	gtk_widget_set_sensitive (new_service, TRUE);

	/* FIXME: Fetch list of services and display */
}

static void on_quit_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	talloc_free(svcctl_pipe);
	gtk_main_quit();
}

static void on_about_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkDialog *aboutwin = GTK_DIALOG(create_gtk_samba_about_dialog("gwcrontab"));
	gtk_dialog_run(aboutwin);
	gtk_widget_destroy(GTK_WIDGET(aboutwin));
}

static GtkWidget* create_mainwindow (void)
{
	GtkWidget *mainwindow;
	GtkWidget *vbox;
	GtkWidget *menubar;
	GtkWidget *menuitem4;
	GtkWidget *menuitem4_menu;
	GtkWidget *mnu_connect;
	GtkWidget *separatormenuitem1;
	GtkWidget *quit;
	GtkWidget *service;
	GtkWidget *service_menu;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *curcol;
	GtkWidget *menuitem7;
	GtkWidget *menuitem7_menu;
	GtkWidget *about;
	GtkWidget *scrolledwindow;
	GtkWidget *statusbar;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();

	mainwindow = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW (mainwindow), 642, 562);
	gtk_window_set_title (GTK_WINDOW (mainwindow), "Service Management");

	vbox = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (mainwindow), vbox);

	menubar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX (vbox), menubar, FALSE, FALSE, 0);

	menuitem4 = gtk_menu_item_new_with_mnemonic ("_File");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem4);

	menuitem4_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem4), menuitem4_menu);

	mnu_connect = gtk_menu_item_new_with_mnemonic ("_Connect");
	gtk_container_add (GTK_CONTAINER (menuitem4_menu), mnu_connect);
	g_signal_connect ((gpointer) mnu_connect, "activate",
	  G_CALLBACK (on_connect_activate), NULL);

	separatormenuitem1 = gtk_separator_menu_item_new ();
	gtk_container_add (GTK_CONTAINER (menuitem4_menu), separatormenuitem1);
	gtk_widget_set_sensitive (separatormenuitem1, FALSE);

	quit = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
	gtk_container_add (GTK_CONTAINER (menuitem4_menu), quit);

	service = gtk_menu_item_new_with_mnemonic ("_Service");
	gtk_container_add (GTK_CONTAINER (menubar), service);

	service_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (service), service_menu);

	new_service = gtk_menu_item_new_with_mnemonic ("_New");
	gtk_container_add (GTK_CONTAINER (service_menu), new_service);
	gtk_widget_set_sensitive (new_service, FALSE);

	start_service = gtk_menu_item_new_with_mnemonic ("_Start");
	gtk_container_add (GTK_CONTAINER (service_menu), start_service);
	gtk_widget_set_sensitive (start_service, FALSE);

	stop_service = gtk_menu_item_new_with_mnemonic ("St_op");
	gtk_container_add (GTK_CONTAINER (service_menu), stop_service);
	gtk_widget_set_sensitive (stop_service, FALSE);

	edit_service = gtk_menu_item_new_with_mnemonic ("_Edit");
	gtk_container_add (GTK_CONTAINER (service_menu), edit_service);
	gtk_widget_set_sensitive (edit_service, FALSE);

	delete_service = gtk_menu_item_new_with_mnemonic ("_Delete");
	gtk_widget_set_sensitive(delete_service, FALSE);
	gtk_container_add (GTK_CONTAINER (service_menu), delete_service);

	menuitem7 = gtk_menu_item_new_with_mnemonic ("_Help");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem7);

	menuitem7_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem7), menuitem7_menu);

	about = gtk_menu_item_new_with_mnemonic ("_About");
	gtk_container_add (GTK_CONTAINER (menuitem7_menu), about);

	scrolledwindow = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (vbox), scrolledwindow, TRUE, TRUE, 0);

	services = gtk_tree_view_new ();

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Status");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(services), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "ID");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(services), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 1);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Day");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(services), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 2);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Time");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(services), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 3);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Command Line");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(services), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 4);

	store_services = gtk_list_store_new(5, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(services), GTK_TREE_MODEL(store_services));
	g_object_unref(store_services);

	gtk_container_add (GTK_CONTAINER (scrolledwindow), services);

	statusbar = gtk_statusbar_new ();
	gtk_box_pack_start (GTK_BOX (vbox), statusbar, FALSE, FALSE, 0);

	g_signal_connect ((gpointer) quit, "activate",
	  G_CALLBACK (on_quit_activate), NULL);
	g_signal_connect ((gpointer) about, "activate",
	  G_CALLBACK (on_about_activate), NULL);

	gtk_window_add_accel_group (GTK_WINDOW (mainwindow), accel_group);

	return mainwindow;
}

int main(int argc, char **argv)
{
	lp_load();
	setup_logging(argv[0], DEBUG_STDERR);

	dcerpc_init();

	gtk_init(&argc, &argv);
	mainwin = create_mainwindow();
	gtk_widget_show_all(mainwin);

	return gtk_event_loop();
}
