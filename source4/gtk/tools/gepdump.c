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
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/gen_ndr/ndr_mgmt_c.h"
#include "gtk/common/gtk-smb.h"
#include "gtk/common/select.h"
#include "auth/gensec/gensec.h"

/* 
 * Show: 
 *  - RPC statistics
 *  - Available interfaces
 *   - Per interface: available endpoints
 *   - Per interface auth details
 */

static GtkWidget *mainwin;
static GtkTreeStore *store_eps;
static GtkWidget *table_statistics;
static GtkWidget *lbl_calls_in, *lbl_calls_out, *lbl_pkts_in, *lbl_pkts_out;
static GtkWidget *lbl_iface_version, *lbl_iface_uuid, *lbl_iface_name;
static GtkListStore *store_princ_names;
static GtkWidget *mnu_refresh;
TALLOC_CTX *eps_ctx = NULL;
TALLOC_CTX *conn_ctx = NULL;

static struct dcerpc_pipe *epmapper_pipe;
static struct dcerpc_pipe *mgmt_pipe;

static void on_quit1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	gtk_main_quit();
}


static void on_about1_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkDialog *aboutwin = GTK_DIALOG(create_gtk_samba_about_dialog("gepdump"));
	gtk_dialog_run(aboutwin);
	gtk_widget_destroy(GTK_WIDGET(aboutwin));
}

static const char *get_protocol_name(enum epm_protocol protocol)
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
	case EPM_PROTOCOL_UNIX_DS: return "Unix";
	default: return "Unknown";
	}
}

static void add_epm_entry(TALLOC_CTX *mem_ctx, const char *annotation, struct epm_tower *t)
{
	struct dcerpc_binding *bd;
	int i;
	NTSTATUS status;
	GtkTreeIter toweriter;

	status = dcerpc_binding_from_tower(mem_ctx, t, &bd);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, "Error creating binding from tower", status);
		return;
	}
	
	/* Don't show UUID's */
	ZERO_STRUCT(bd->object);

	gtk_tree_store_append(store_eps, &toweriter, NULL);
	gtk_tree_store_set(store_eps, &toweriter, 0, strdup(annotation), 1, strdup(dcerpc_binding_string(mem_ctx, bd)), 2, t, -1);

	for (i = 0; i < t->num_floors; i++) {
		const char *data;
		struct dcerpc_syntax_id syntax;
		GtkTreeIter iter;
		gtk_tree_store_append(store_eps, &iter, &toweriter);

		dcerpc_floor_get_lhs_data(&t->floors[i], &syntax);
		if (t->floors[i].lhs.protocol == EPM_PROTOCOL_UUID) {
			data = GUID_string(mem_ctx, &syntax.uuid);
		} else {
			data = dcerpc_floor_get_rhs_data(mem_ctx, &t->floors[i]);
		}
		
		gtk_tree_store_set(store_eps, &iter, 0, get_protocol_name(t->floors[i].lhs.protocol), 1, data, -1);
	}
}

static void refresh_eps(void)
{
	NTSTATUS status;
	struct epm_Lookup r;
	struct GUID uuid;
	struct rpc_if_id_t iface;
	struct policy_handle handle;
	TALLOC_CTX *mem_ctx = talloc_init("dump");

	talloc_free(eps_ctx);

	ZERO_STRUCT(handle);

	r.in.inquiry_type = 0;
	r.in.object = &uuid;
	r.in.interface_id = &iface;
	r.in.vers_option = 0;
	r.in.entry_handle = r.out.entry_handle = &handle;
	r.in.max_ents = 10;

	gtk_tree_store_clear(store_eps);

	eps_ctx = talloc_init("current endpoint list data");

	do {
		int i;
		ZERO_STRUCT(uuid);
		ZERO_STRUCT(iface);

		status = dcerpc_epm_Lookup(epmapper_pipe, eps_ctx, &r);
		if (!NT_STATUS_IS_OK(status) || r.out.result != 0) {
			break;
		}
		for (i=0;i<*r.out.num_ents;i++) {
			add_epm_entry(mem_ctx, r.out.entries[i].annotation, &r.out.entries[i].tower->tower);
		}

	} while (NT_STATUS_IS_OK(status) && 
		 r.out.result == 0 && 
		 *r.out.num_ents == r.in.max_ents);

	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, "Error adding endpoint mapper entry", status);
		talloc_free(mem_ctx);
		return;
	}
	talloc_free(mem_ctx);
}

static void on_refresh_clicked (GtkButton *btn, gpointer user_data)
{
	refresh_eps();
}

static void on_connect_clicked(GtkButton *btn, gpointer user_data)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_init("connect");

	epmapper_pipe = gtk_connect_rpc_interface(mem_ctx, &dcerpc_table_epmapper);
	if (epmapper_pipe == NULL)
		return;
	
	gtk_widget_set_sensitive( mnu_refresh, True );

	refresh_eps();

	status = dcerpc_secondary_context(epmapper_pipe, &mgmt_pipe, &dcerpc_table_mgmt);

	if (NT_STATUS_IS_ERR(status)) {
		mgmt_pipe = NULL;
		gtk_show_ntstatus(NULL, "Error connecting to mgmt interface over secondary connection", status);
	}
}

static gboolean on_eps_select(GtkTreeSelection *selection,
    GtkTreeModel *model, GtkTreePath *path, gboolean path_currently_selected, gpointer data)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	
	if (mgmt_pipe == NULL) 
		return FALSE;
	
	mem_ctx = talloc_init("eps");

	{
		/* Do an InqStats call */
		struct mgmt_inq_stats r;

		r.in.max_count = MGMT_STATS_ARRAY_MAX_SIZE;
		r.in.unknown = 0;

		status = dcerpc_mgmt_inq_stats(mgmt_pipe, mem_ctx, &r);
		if (NT_STATUS_IS_ERR(status)) {
			gtk_show_ntstatus(NULL, "Error inquiring statistics", status);
			return TRUE;
		}

		if (r.out.statistics->count != MGMT_STATS_ARRAY_MAX_SIZE) {
			printf("Unexpected array size %d\n", r.out.statistics->count);
			return False;
		}

		gtk_label_set_text(GTK_LABEL(lbl_calls_in), talloc_asprintf(mem_ctx, "%6d", r.out.statistics->statistics[MGMT_STATS_CALLS_IN]));
		gtk_label_set_text(GTK_LABEL(lbl_calls_out), talloc_asprintf(mem_ctx, "%6d", r.out.statistics->statistics[MGMT_STATS_CALLS_OUT]));
		gtk_label_set_text(GTK_LABEL(lbl_pkts_in), talloc_asprintf(mem_ctx, "%6d", r.out.statistics->statistics[MGMT_STATS_PKTS_IN]));
		gtk_label_set_text(GTK_LABEL(lbl_pkts_out), talloc_asprintf(mem_ctx, "%6d", r.out.statistics->statistics[MGMT_STATS_PKTS_OUT]));
	}

	{
		struct mgmt_inq_princ_name r;
		int i;

		gtk_list_store_clear(store_princ_names);

		for (i=0;i<100;i++) {
			r.in.authn_proto = i;  /* DCERPC_AUTH_TYPE_* */
			r.in.princ_name_size = 100;

			status = dcerpc_mgmt_inq_princ_name(mgmt_pipe, mem_ctx, &r);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			if (W_ERROR_IS_OK(r.out.result)) {
				GtkTreeIter iter;
				const char *name = gensec_get_name_by_authtype(i);
				char *protocol;
				if (name) {
					protocol = talloc_asprintf(mem_ctx, "%u (%s)", i, name);
				} else {
					protocol = talloc_asprintf(mem_ctx, "%u", i);
				}
				gtk_list_store_append(store_princ_names, &iter);
				gtk_list_store_set(store_princ_names, &iter, 
								   0, protocol,
								   1, r.out.princ_name,
								   -1);

			}
		}
	}

	return TRUE;
}


static GtkWidget* create_mainwindow (void)
{
	GtkWidget *mainwindow;
	GtkWidget *vbox1, *vbox2, *vbox3;
	GtkWidget *menubar1;
	GtkWidget *menuitem1;
	GtkWidget *menuitem1_menu;
	GtkWidget *quit1;
	GtkWidget *menuitem4;
	GtkWidget *menuitem4_menu;
	GtkWidget *mnu_connect;
	GtkWidget *treeview_princ_names;
	GtkWidget *about1;
	GtkWidget *hbox2;
	GtkWidget *scrolledwindow1;
	GtkWidget *frame1;
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

	mnu_connect = gtk_menu_item_new_with_mnemonic ("_Connect");
	gtk_container_add(GTK_CONTAINER(menuitem1_menu), mnu_connect);

	mnu_refresh = gtk_menu_item_new_with_mnemonic ("_Refresh");
	gtk_container_add(GTK_CONTAINER(menuitem1_menu), mnu_refresh);
	gtk_widget_set_sensitive( mnu_refresh, False );

	quit1 = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), quit1);

	menuitem4 = gtk_menu_item_new_with_mnemonic ("_Help");
	gtk_container_add (GTK_CONTAINER (menubar1), menuitem4);

	menuitem4_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem4), menuitem4_menu);

	about1 = gtk_menu_item_new_with_mnemonic ("_About");
	gtk_container_add (GTK_CONTAINER (menuitem4_menu), about1);

	hbox2 = gtk_hbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (vbox1), hbox2);

	scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX(hbox2), scrolledwindow1, TRUE, TRUE, 0);

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

	store_eps = gtk_tree_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tree_eps), GTK_TREE_MODEL(store_eps));
	g_object_unref(store_eps);

	gtk_container_add (GTK_CONTAINER (scrolledwindow1), tree_eps);

	gtk_tree_selection_set_select_function (gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_eps)), on_eps_select, NULL, NULL);

	vbox2 = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (hbox2), vbox2);

	frame1 = gtk_frame_new("Interface");
	gtk_container_add (GTK_CONTAINER(vbox2), frame1);

	vbox3 = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (frame1), vbox3);
	gtk_container_add (GTK_CONTAINER (vbox3), lbl_iface_uuid = gtk_label_new(""));
	gtk_container_add (GTK_CONTAINER (vbox3), lbl_iface_version = gtk_label_new(""));
	gtk_container_add (GTK_CONTAINER (vbox3), lbl_iface_name = gtk_label_new(""));

	frame1 = gtk_frame_new("Statistics");
	gtk_container_add (GTK_CONTAINER(vbox2), frame1);

	table_statistics = gtk_table_new(4, 2, TRUE);
	gtk_container_add (GTK_CONTAINER(frame1), table_statistics);

	gtk_table_attach_defaults (GTK_TABLE(table_statistics), gtk_label_new("Calls In: "), 0, 1, 0, 1);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), lbl_calls_in = gtk_label_new(""), 1, 2, 0, 1);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), gtk_label_new("Calls Out: "), 0, 1, 1, 2);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), lbl_calls_out = gtk_label_new(""), 1, 2, 1, 2);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), gtk_label_new("Packets In: "), 0, 1, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), lbl_pkts_in = gtk_label_new(""), 1, 2, 2, 3);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), gtk_label_new("Packets Out: "), 0, 1, 3, 4);
	gtk_table_attach_defaults (GTK_TABLE(table_statistics), lbl_pkts_out = gtk_label_new(""), 1, 2, 3, 4);
	
	frame1 = gtk_frame_new("Authentication");
	gtk_container_add (GTK_CONTAINER(vbox2), frame1);

	treeview_princ_names = gtk_tree_view_new();

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Protocol");
    renderer = gtk_cell_renderer_text_new();
    gtk_tree_view_column_pack_start(curcol, renderer, True);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview_princ_names), curcol);
    gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Principal Name");
    renderer = gtk_cell_renderer_text_new();
    gtk_tree_view_column_pack_start(curcol, renderer, True);
    gtk_tree_view_append_column(GTK_TREE_VIEW(treeview_princ_names), curcol);
    gtk_tree_view_column_add_attribute(curcol, renderer, "text", 1);

	gtk_container_add (GTK_CONTAINER(frame1), treeview_princ_names);

    store_princ_names = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
	gtk_tree_view_set_model(GTK_TREE_VIEW(treeview_princ_names), GTK_TREE_MODEL(store_princ_names));
    g_object_unref(store_princ_names);

	statusbar = gtk_statusbar_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), statusbar, FALSE, FALSE, 0);

	g_signal_connect ((gpointer) quit1, "activate",
					  G_CALLBACK (on_quit1_activate),
					  NULL);
	g_signal_connect ((gpointer) about1, "activate",
					  G_CALLBACK (on_about1_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_connect, "activate",
					  G_CALLBACK (on_connect_clicked),
					  NULL);
	g_signal_connect ((gpointer) mnu_refresh, "activate",
					  G_CALLBACK (on_refresh_clicked),
					  NULL);

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
