/* 
   Unix SMB/CIFS implementation.
   GTK+ Endpoint Mapper frontend
   
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

GtkWidget *mainwin;
GtkWidget *entry_binding;
GtkTreeStore *store_eps;

static void on_quit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_main_quit();
}


static void on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	GtkDialog *aboutwin = GTK_DIALOG(create_gtk_samba_about_dialog("gsmbtorture"));
	gtk_dialog_run(aboutwin);
	gtk_widget_destroy(GTK_WIDGET(aboutwin));
}

static const char *get_protocol_name(enum epm_protocols protocol)
{
	switch (protocol) {
	case EPM_PROTOCOL_UUID: return "UUID";
	case EPM_PROTOCOL_NCACN: return "NCACN";
	case EPM_PROTOCOL_NCALRPC: return "NCALRPC";
	case EPM_PROTOCOL_NCADG: return "NCADG";
	case EPM_PROTOCOL_IP: return "IP";
	case EPM_PROTOCOL_TCP: return "TCP";
	case EPM_PROTOCOL_NETBIOS: return "NetBIOS";
	case EPM_PROTOCOL_SMB: return "SMB";
	case EPM_PROTOCOL_PIPE: return "PIPE";
	default: return "Unknown";
	}
}

static void add_epm_entry(TALLOC_CTX *mem_ctx, const char *annotation, struct epm_tower *t)
{
	struct dcerpc_binding bd;
	int i;
	NTSTATUS status;
	GtkTreeIter toweriter;

	status = dcerpc_binding_from_tower(mem_ctx, t, &bd);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, status);
		return;
	}
	
	/* Don't show UUID's */
	ZERO_STRUCT(bd.object);

	gtk_tree_store_append(store_eps, &toweriter, NULL);
	gtk_tree_store_set(store_eps, &toweriter, 0, strdup(annotation), 1, strdup(dcerpc_binding_string(mem_ctx, &bd)), -1);

	for (i = 0; i < t->num_floors; i++) {
		const char *data;
		GtkTreeIter iter;
		gtk_tree_store_append(store_eps, &iter, &toweriter);

		if (t->floors[i].lhs.protocol == EPM_PROTOCOL_UUID) {
			data = GUID_string(mem_ctx, &t->floors[i].lhs.info.uuid.uuid);
		} else {
			data = dcerpc_floor_get_rhs_data(mem_ctx, &t->floors[i]);
		}
		
		gtk_tree_store_set(store_eps, &iter, 0, get_protocol_name(t->floors[i].lhs.protocol), 1, data, -1);
	}
}

static void on_dump_clicked                     (GtkButton *btn, gpointer         user_data)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct GUID uuid;
	struct rpc_if_id_t iface;
	struct policy_handle handle;
	struct dcerpc_pipe *p;
	TALLOC_CTX *mem_ctx = talloc_init("dump");

	status = dcerpc_pipe_connect(&p, gtk_entry_get_text(GTK_ENTRY(entry_binding)), DCERPC_EPMAPPER_UUID, DCERPC_EPMAPPER_VERSION, lp_workgroup(), NULL, NULL);

	if (NT_STATUS_IS_ERR(status)) {
		gtk_show_ntstatus(mainwin, status);
		talloc_destroy(mem_ctx);
		return;
	}

	ZERO_STRUCT(uuid);
	ZERO_STRUCT(iface);
	ZERO_STRUCT(handle);

	r.in.inquiry_type = 0;
	r.in.object = &uuid;
	r.in.interface_id = &iface;
	r.in.vers_option = 0;
	r.in.entry_handle = &handle;
	r.out.entry_handle = &handle;
	r.in.max_ents = 10;

	gtk_tree_store_clear(store_eps);

	do {
		int i;
		status = dcerpc_epm_Lookup(p, mem_ctx, &r);
		if (!NT_STATUS_IS_OK(status) || r.out.result != 0) {
			break;
		}
		for (i=0;i<r.out.num_ents;i++) {
			add_epm_entry(mem_ctx, r.out.entries[i].annotation, &r.out.entries[i].tower->tower);
		}
	} while (NT_STATUS_IS_OK(status) && 
		 r.out.result == 0 && 
		 r.out.num_ents == r.in.max_ents);

	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, status);
		talloc_destroy(mem_ctx);
		return;
	}
	talloc_destroy(mem_ctx);
}

static void on_select_target_clicked(GtkButton *btn, gpointer         user_data)
{
	GtkRpcBindingDialog *d;
	TALLOC_CTX *mem_ctx;
	struct dcerpc_binding *bd;
	gint result;

	d = GTK_RPC_BINDING_DIALOG(gtk_rpc_binding_dialog_new(FALSE, NULL));
	result = gtk_dialog_run(GTK_DIALOG(d));
	switch(result) {
	case GTK_RESPONSE_ACCEPT:
		break;
	default:
		gtk_widget_destroy(GTK_WIDGET(d));
		return;
	}

	mem_ctx = talloc_init("select_target");
	bd = gtk_rpc_binding_dialog_get_binding (d, mem_ctx),
	gtk_entry_set_text(GTK_ENTRY(entry_binding), dcerpc_binding_string(mem_ctx, bd));
	talloc_destroy(mem_ctx);
	gtk_widget_destroy(GTK_WIDGET(d));
}

static GtkWidget* create_mainwindow (void)
{
  GtkWidget *mainwindow;
  GtkWidget *vbox1;
  GtkWidget *menubar1;
  GtkWidget *menuitem1;
  GtkWidget *menuitem1_menu;
  GtkWidget *quit1;
  GtkWidget *menuitem4;
  GtkWidget *menuitem4_menu;
  GtkWidget *about1;
  GtkWidget *handlebox1;
  GtkWidget *hbox1;
  GtkWidget *label1;
  GtkWidget *btn_select_target;
  GtkWidget *btn_dump;
  GtkWidget *scrolledwindow1;
  GtkWidget *tree_eps;
  GtkTreeViewColumn *curcol;
  GtkCellRenderer *renderer;
  GtkWidget *statusbar;
  GtkAccelGroup *accel_group;

  accel_group = gtk_accel_group_new ();

  mainwindow = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title (GTK_WINDOW (mainwindow), "Gtk+ Endpoint Mapper Viewer");

  vbox1 = gtk_vbox_new (FALSE, 0);
  gtk_widget_show (vbox1);
  gtk_container_add (GTK_CONTAINER (mainwindow), vbox1);

  menubar1 = gtk_menu_bar_new ();
  gtk_widget_show (menubar1);
  gtk_box_pack_start (GTK_BOX (vbox1), menubar1, FALSE, FALSE, 0);

  menuitem1 = gtk_menu_item_new_with_mnemonic ("_File");
  gtk_widget_show (menuitem1);
  gtk_container_add (GTK_CONTAINER (menubar1), menuitem1);

  menuitem1_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem1), menuitem1_menu);

  quit1 = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
  gtk_widget_show (quit1);
  gtk_container_add (GTK_CONTAINER (menuitem1_menu), quit1);

  menuitem4 = gtk_menu_item_new_with_mnemonic ("_Help");
  gtk_widget_show (menuitem4);
  gtk_container_add (GTK_CONTAINER (menubar1), menuitem4);

  menuitem4_menu = gtk_menu_new ();
  gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem4), menuitem4_menu);

  about1 = gtk_menu_item_new_with_mnemonic ("_About");
  gtk_widget_show (about1);
  gtk_container_add (GTK_CONTAINER (menuitem4_menu), about1);

  handlebox1 = gtk_handle_box_new ();
  gtk_widget_show (handlebox1);
  gtk_box_pack_start (GTK_BOX (vbox1), handlebox1, FALSE, TRUE, 0);

  hbox1 = gtk_hbox_new (FALSE, 0);
  gtk_widget_show (hbox1);
  gtk_container_add (GTK_CONTAINER (handlebox1), hbox1);

  label1 = gtk_label_new ("Location:");
  gtk_widget_show (label1);
  gtk_box_pack_start (GTK_BOX (hbox1), label1, FALSE, FALSE, 0);

  entry_binding = gtk_entry_new ();
  gtk_entry_set_text(GTK_ENTRY(entry_binding), "ncalrpc:");
  gtk_widget_show (entry_binding);
  gtk_box_pack_start (GTK_BOX (hbox1), entry_binding, FALSE, FALSE, 0);

  btn_select_target = gtk_button_new_with_mnemonic ("_Select Target");
  gtk_widget_show (btn_select_target);
  gtk_box_pack_start (GTK_BOX (hbox1), btn_select_target, FALSE, FALSE, 0);

  btn_dump = gtk_button_new_with_mnemonic ("_Dump");
  gtk_widget_show (btn_dump);
  gtk_box_pack_start (GTK_BOX (hbox1), btn_dump, FALSE, FALSE, 0);

  scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
  gtk_widget_show (scrolledwindow1);
  gtk_box_pack_start (GTK_BOX (vbox1), scrolledwindow1, TRUE, TRUE, 0);

  tree_eps = gtk_tree_view_new ();

  curcol = gtk_tree_view_column_new ();
  gtk_tree_view_column_set_title(curcol, "Name");
  renderer = gtk_cell_renderer_text_new();
  gtk_tree_view_column_pack_start(curcol, renderer, True);

  gtk_tree_view_append_column(GTK_TREE_VIEW(tree_eps), curcol);
  gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

  curcol = gtk_tree_view_column_new ();
  gtk_tree_view_column_set_title(curcol, "Binding String");
  renderer = gtk_cell_renderer_text_new();
  gtk_tree_view_column_pack_start(curcol, renderer, True);
  gtk_tree_view_column_add_attribute(curcol, renderer, "text", 1);


  gtk_tree_view_append_column(GTK_TREE_VIEW(tree_eps), curcol);

  store_eps = gtk_tree_store_new(2, GTK_TYPE_STRING, GTK_TYPE_STRING);
  gtk_tree_view_set_model(GTK_TREE_VIEW(tree_eps), GTK_TREE_MODEL(store_eps));
  g_object_unref(store_eps);
  
  gtk_widget_show (tree_eps);
  gtk_container_add (GTK_CONTAINER (scrolledwindow1), tree_eps);

  statusbar = gtk_statusbar_new ();
  gtk_widget_show (statusbar);
  gtk_box_pack_start (GTK_BOX (vbox1), statusbar, FALSE, FALSE, 0);

  g_signal_connect ((gpointer) quit1, "activate",
                    G_CALLBACK (on_quit1_activate),
                    NULL);
  g_signal_connect ((gpointer) about1, "activate",
                    G_CALLBACK (on_about1_activate),
                    NULL);
  g_signal_connect ((gpointer) btn_select_target, "clicked",
                    G_CALLBACK (on_select_target_clicked),
                    NULL);
  g_signal_connect ((gpointer) btn_dump, "clicked",
                    G_CALLBACK (on_dump_clicked),
                    NULL);

  gtk_window_add_accel_group (GTK_WINDOW (mainwindow), accel_group);

  return mainwindow;
}


 int main(int argc, char **argv)
{
	gtk_init(&argc, &argv);
	mainwin = create_mainwindow();
	gtk_widget_show(mainwin);
	gtk_main();
	return 0;
}
