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
#include "librpc/gen_ndr/ndr_samr.h"
#include "gtk/common/gtk-smb.h"

struct policy_handle sam_handle;
struct dcerpc_pipe *sam_pipe = NULL;
struct policy_handle domain_handle;
GtkWidget *mainwin;
GtkWidget *seldomain;
GtkWidget *mnu_disconnect;

void update_grouplist(void)
{
	if(!sam_pipe) return;
	//FIXME
}

void update_userlist(void)
{
	NTSTATUS status;
	struct samr_EnumDomainUsers r;
	uint32_t resume_handle=0;
	int i;
	TALLOC_CTX *mem_ctx;

	if(!sam_pipe) return;

	mem_ctx = talloc_init("update_userlist");
	r.in.domain_handle = &domain_handle;
	r.in.resume_handle = &resume_handle;
	r.in.acct_flags = 0;
	r.in.max_size = (uint32_t)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomainUsers(sam_pipe, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, status);
		talloc_destroy(mem_ctx);
		return;
	}

	if (!r.out.sam || r.out.sam->count == 0) {
		talloc_destroy(mem_ctx);
		return;
	}

	for (i=0;i<r.out.sam->count;i++) {
		printf("Found: %s\n", r.out.sam->entries[i].name.name);
		/* FIXME: Query user info */

		//		if (!test_OpenUser(sam_pipe, mem_ctx, &sam_handle, r.out.sam->entries[i].idx)) {
		//			ret = False;
		//		}
	}
	talloc_destroy(mem_ctx);
}

void
on_new1_activate                       (GtkMenuItem     *menuitem,
										gpointer         user_data)
{

}

void
on_select_domain_activate                       (GtkMenuItem     *menuitem,
												 gpointer         user_data)
{
	GtkSelectDomainDialog *d;
	gint result;
	d = GTK_SELECT_DOMAIN_DIALOG(gtk_select_domain_dialog_new(sam_pipe));
	result = gtk_dialog_run(GTK_DIALOG(d));
	switch(result) {
	case GTK_RESPONSE_OK:
		break;
	default:
		gtk_widget_destroy(GTK_WIDGET(d));
		return;
	}
	domain_handle = gtk_select_domain_dialog_get_handle(d);

	update_userlist();
	update_grouplist();

	gtk_widget_destroy(GTK_WIDGET(d));
}

static void connect_sam(void)
{
	GtkRpcBindingDialog *d;
	NTSTATUS status;
	struct samr_Connect r;
	TALLOC_CTX *mem_ctx;
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

	mem_ctx = talloc_init("gwsam_connect");
	/* If connected, get list of jobs */
	status = dcerpc_pipe_connect_b(&sam_pipe, gtk_rpc_binding_dialog_get_binding(d, mem_ctx), DCERPC_SAMR_UUID, DCERPC_SAMR_VERSION, lp_workgroup(), gtk_rpc_binding_dialog_get_username(d), gtk_rpc_binding_dialog_get_password(d));

	if(!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, status);
		sam_pipe = NULL;
		gtk_widget_destroy(GTK_WIDGET(d));
		talloc_destroy(mem_ctx);
		return;
	}

	r.in.system_name = 0;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.connect_handle = &sam_handle;

	status = dcerpc_samr_Connect(sam_pipe, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, status);
		sam_pipe = NULL;
		gtk_widget_destroy(GTK_WIDGET(d));
		talloc_destroy(mem_ctx);
		return;
	}

	gtk_widget_set_sensitive (seldomain, TRUE);
	gtk_widget_set_sensitive (mnu_disconnect, TRUE);
	gtk_window_set_title (GTK_WINDOW (mainwin), talloc_asprintf(mem_ctx, "User Manager - Connected to %s", gtk_rpc_binding_dialog_get_host(d)));
	gtk_widget_destroy(GTK_WIDGET(d));
	talloc_destroy(mem_ctx);

}

void on_connect_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	connect_sam();
}

void on_disconnect_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	gtk_widget_set_sensitive (mnu_disconnect, FALSE);
	gtk_window_set_title (GTK_WINDOW (mainwin), "User Manager");
}

void
on_quit_activate                      (GtkMenuItem     *menuitem,
									   gpointer         user_data)
{
	if(sam_pipe)dcerpc_pipe_close(sam_pipe);
	gtk_main_quit();
}


void
on_account_activate                    (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	//FIXME
}


void
on_user_rights_activate                (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	//FIXME
}


void
on_audit_activate                      (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	//FIXME
}


void
on_trust_relations_activate            (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	//FIXME
}


void
on_refresh_activate                    (GtkMenuItem     *menuitem,
										gpointer         user_data)
{
	update_userlist();
	update_grouplist();
}


void
on_about_activate                     (GtkMenuItem     *menuitem,
									   gpointer         user_data)
{
	GtkDialog *aboutwin = GTK_DIALOG(create_gtk_samba_about_dialog("gwsam"));
	gtk_dialog_run(aboutwin);
	gtk_widget_destroy(GTK_WIDGET(aboutwin));
}

GtkWidget*
create_mainwindow (void)
{
	GtkWidget *vbox1;
	GtkWidget *mnu_connect;
	GtkWidget *menubar;
	GtkWidget *menuitem1;
	GtkWidget *menuitem1_menu;
	GtkWidget *new1;
	GtkWidget *separatormenuitem1;
	GtkWidget *quit;
	GtkWidget *policies;
	GtkWidget *policies_menu;
	GtkWidget *account;
	GtkWidget *user_rights;
	GtkWidget *audit;
	GtkWidget *separator1;
	GtkWidget *trust_relations;
	GtkWidget *menuitem3;
	GtkWidget *menuitem3_menu;
	GtkWidget *refresh;
	GtkWidget *menuitem4;
	GtkWidget *menuitem4_menu;
	GtkWidget *about;
	GtkWidget *vpaned;
	GtkWidget *scrolledwindow1;
	GtkWidget *user_list;
	GtkWidget *scrolledwindow2;
	GtkWidget *group_list;
	GtkWidget *statusbar;
	GtkAccelGroup *accel_group;

	accel_group = gtk_accel_group_new ();

	mainwin = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size (GTK_WINDOW (mainwin), 642, 562);
	gtk_window_set_title (GTK_WINDOW (mainwin), "User Manager");

	vbox1 = gtk_vbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (mainwin), vbox1);

	menubar = gtk_menu_bar_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), menubar, FALSE, FALSE, 0);

	menuitem1 = gtk_menu_item_new_with_mnemonic ("_File");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem1);

	menuitem1_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem1), menuitem1_menu);

	mnu_connect = gtk_menu_item_new_with_mnemonic ("_Connect");
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), mnu_connect);

	mnu_disconnect = gtk_menu_item_new_with_mnemonic ("_Disconnect");
	gtk_widget_set_sensitive (mnu_disconnect, FALSE);
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), mnu_disconnect);

	seldomain = gtk_menu_item_new_with_mnemonic("_Select Domain");
	gtk_widget_set_sensitive (seldomain, FALSE);
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), seldomain);

	separatormenuitem1 = gtk_separator_menu_item_new ();
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), separatormenuitem1);
	gtk_widget_set_sensitive (separatormenuitem1, FALSE);

	quit = gtk_image_menu_item_new_from_stock ("gtk-quit", accel_group);
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), quit);

	menuitem1 = gtk_menu_item_new_with_mnemonic ("_User");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem1);
	gtk_widget_set_sensitive (menuitem1, FALSE);

	menuitem1_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem1), menuitem1_menu);

	new1 = gtk_image_menu_item_new_from_stock ("gtk-new", accel_group);
	gtk_container_add (GTK_CONTAINER (menuitem1_menu), new1);



	policies = gtk_menu_item_new_with_mnemonic ("_Policies");
	gtk_container_add (GTK_CONTAINER (menubar), policies);
	gtk_widget_set_sensitive (policies, FALSE);

	policies_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (policies), policies_menu);

	account = gtk_menu_item_new_with_mnemonic ("_Account...");
	gtk_container_add (GTK_CONTAINER (policies_menu), account);

	user_rights = gtk_menu_item_new_with_mnemonic ("_User Rights...");
	gtk_container_add (GTK_CONTAINER (policies_menu), user_rights);

	audit = gtk_menu_item_new_with_mnemonic ("A_udit...");
	gtk_container_add (GTK_CONTAINER (policies_menu), audit);

	separator1 = gtk_separator_menu_item_new ();
	gtk_container_add (GTK_CONTAINER (policies_menu), separator1);
	gtk_widget_set_sensitive (separator1, FALSE);

	trust_relations = gtk_menu_item_new_with_mnemonic ("_Trust relations");
	gtk_container_add (GTK_CONTAINER (policies_menu), trust_relations);

	menuitem3 = gtk_menu_item_new_with_mnemonic ("_View");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem3);

	menuitem3_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem3), menuitem3_menu);

	refresh = gtk_image_menu_item_new_from_stock ("gtk-refresh", accel_group);
	gtk_container_add (GTK_CONTAINER (menuitem3_menu), refresh);
	gtk_widget_set_sensitive (refresh, FALSE);

	menuitem4 = gtk_menu_item_new_with_mnemonic ("_Help");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem4);

	menuitem4_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem4), menuitem4_menu);

	about = gtk_menu_item_new_with_mnemonic ("_About");
	gtk_container_add (GTK_CONTAINER (menuitem4_menu), about);

	vpaned = gtk_vpaned_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), vpaned, TRUE, TRUE, 0);

	scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
	gtk_paned_pack1 (GTK_PANED (vpaned), scrolledwindow1, FALSE, TRUE);

	user_list = gtk_tree_view_new ();
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), user_list);

	scrolledwindow2 = gtk_scrolled_window_new (NULL, NULL);
	gtk_paned_pack2 (GTK_PANED (vpaned), scrolledwindow2, TRUE, TRUE);

	group_list = gtk_tree_view_new ();
	gtk_container_add (GTK_CONTAINER (scrolledwindow2), group_list);

	statusbar = gtk_statusbar_new ();
	gtk_box_pack_start (GTK_BOX (vbox1), statusbar, FALSE, FALSE, 0);

	g_signal_connect ((gpointer) new1, "activate",
					  G_CALLBACK (on_new1_activate),
					  NULL);
	g_signal_connect ((gpointer) seldomain, "activate",
					  G_CALLBACK (on_select_domain_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_connect, "activate",
					  G_CALLBACK (on_connect_activate),
					  NULL);
	g_signal_connect ((gpointer) mnu_disconnect, "activate",
					  G_CALLBACK (on_disconnect_activate),
					  NULL);
	g_signal_connect ((gpointer) quit, "activate",
					  G_CALLBACK (on_quit_activate),
					  NULL);
	g_signal_connect ((gpointer) account, "activate",
					  G_CALLBACK (on_account_activate),
					  NULL);
	g_signal_connect ((gpointer) user_rights, "activate",
					  G_CALLBACK (on_user_rights_activate),
					  NULL);
	g_signal_connect ((gpointer) audit, "activate",
					  G_CALLBACK (on_audit_activate),
					  NULL);
	g_signal_connect ((gpointer) trust_relations, "activate",
					  G_CALLBACK (on_trust_relations_activate),
					  NULL);
	g_signal_connect ((gpointer) refresh, "activate",
					  G_CALLBACK (on_refresh_activate),
					  NULL);
	g_signal_connect ((gpointer) about, "activate",
					  G_CALLBACK (on_about_activate),
					  NULL);

	gtk_window_add_accel_group (GTK_WINDOW (mainwin), accel_group);

	return mainwin;
}



 int main(int argc, char **argv)
{
	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();
	setup_logging("gwsam", True);

	gtk_init(&argc, &argv);
	mainwin = create_mainwindow();
	connect_sam();
	gtk_widget_show_all(mainwin);
	gtk_main();

	return 0;
}
