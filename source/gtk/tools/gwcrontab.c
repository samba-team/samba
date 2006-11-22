/* 
   Unix SMB/CIFS implementation.
   GTK+ Windows crontab frontend
   
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
#include "librpc/gen_ndr/ndr_atsvc_c.h"
#include "gtk/common/gtk-smb.h"
#include "gtk/common/select.h"
#include "auth/credentials/credentials.h"

static struct dcerpc_pipe *at_pipe = NULL;
static GtkWidget *mainwin;
static GtkListStore *store_jobs;
static GtkWidget *tasks;
static GtkWidget *new_task;
static GtkWidget *entry_cmd;
static GtkWidget *entry_repeat_weekly;
static GtkWidget *entry_repeat_monthly;
static GtkWidget *delete;

static void update_joblist(void)
{
	TALLOC_CTX *mem_ctx = talloc_init("update_joblist");
	NTSTATUS status;
	struct atsvc_JobEnum r;
	struct atsvc_enum_ctr ctr;
	int i;
	uint32_t resume_handle = 0;

	gtk_list_store_clear(store_jobs);

	ctr.entries_read = 0;
	ctr.first_entry = NULL;
	r.in.servername = dcerpc_server_name(at_pipe);
	r.in.ctr = r.out.ctr = &ctr;
	r.in.preferred_max_len = 0xffffffff;
	r.in.resume_handle = r.out.resume_handle = &resume_handle;

	status = dcerpc_atsvc_JobEnum(at_pipe, mem_ctx, &r);
	if(!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(mainwin, "Error while enumerating first job", status);
		return;
	}

       	for (i = 0; i < r.out.ctr->entries_read; i++) {
                GtkTreeIter iter;
                gtk_list_store_append(store_jobs, &iter);
                gtk_list_store_set (store_jobs, &iter, 
			0, r.out.ctr->first_entry[i].flags,
			1, r.out.ctr->first_entry[i].job_id, 
			2, r.out.ctr->first_entry[i].days_of_week, /*FIXME: Nicer format */
			3, r.out.ctr->first_entry[i].job_time, /* FIXME: Nicer format */
			4, r.out.ctr->first_entry[i].command,
                        -1);

	}
	talloc_free(mem_ctx);
}

static void on_job_select(GtkTreeSelection *sel, gpointer data)
{
	gtk_widget_set_sensitive(delete, gtk_tree_selection_get_selected(sel, NULL, NULL));
}


static void on_connect_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	at_pipe = gtk_connect_rpc_interface(talloc_autofree_context(), &dcerpc_table_atsvc);

	if (!at_pipe)
		return;

	gtk_widget_set_sensitive (new_task, TRUE);
	update_joblist();
}

static void on_quit_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	talloc_free(at_pipe);
	gtk_main_quit();
}

static GtkWidget* create_new_job_dialog (void);

void on_new_activate (GtkMenuItem *menuitem, gpointer user_data)
{
	GtkWidget *d = create_new_job_dialog();
	gint result = gtk_dialog_run(GTK_DIALOG(d));
	struct atsvc_JobAdd r;
	struct atsvc_JobInfo job;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	switch(result) {
		case GTK_RESPONSE_OK:
			break;
		default:
			gtk_widget_destroy(d);
		        return;
	}
	mem_ctx = talloc_init("add_job");

	job.job_time = 0; /* FIXME */
	job.days_of_month = 0; /* FIXME */
	job.days_of_week = 0; /* FIXME */
	job.flags = 0; /* FIXME */
	job.command = gtk_entry_get_text(GTK_ENTRY(entry_cmd));
	r.in.servername = dcerpc_server_name(at_pipe);
	r.in.job_info = &job;

	status = dcerpc_atsvc_JobAdd(at_pipe, mem_ctx, &r);
	if(!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		gtk_show_ntstatus(mainwin, "Error while adding job", status);
		return;
	}
	
	talloc_free(mem_ctx);
	gtk_widget_destroy(d);
	
	d = gtk_message_dialog_new (GTK_WINDOW(mainwin), GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "Job Id: %d", *r.out.job_id);
	gtk_dialog_run(GTK_DIALOG(d));
	gtk_widget_destroy(d);
	update_joblist();
}


void on_delete_activate(GtkMenuItem *menuitem, gpointer user_data)
{
	GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(tasks));
	GtkTreeModel *model = GTK_TREE_MODEL(store_jobs);
	GtkTreeIter iter;
	gint id;

	if (gtk_tree_selection_get_selected (sel, &model, &iter))
	{
		struct atsvc_JobDel r;
		TALLOC_CTX *mem_ctx;
		NTSTATUS status;
		gtk_tree_model_get (model, &iter, 1, &id, -1);

		r.in.servername = dcerpc_server_name(at_pipe);
		r.in.min_job_id = r.in.max_job_id = id;

		mem_ctx = talloc_init("del_job");
		status = dcerpc_atsvc_JobDel(at_pipe, mem_ctx, &r);
		talloc_free(mem_ctx);
		if(!NT_STATUS_IS_OK(status)) {
			gtk_show_ntstatus(mainwin, "Error deleting job", status);
			return;
		}

		update_joblist();
	}
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
	GtkWidget *task;
	GtkWidget *task_menu;
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
	gtk_window_set_title (GTK_WINDOW (mainwindow), "Task Scheduler");

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

	task = gtk_menu_item_new_with_mnemonic ("_Task");
	gtk_container_add (GTK_CONTAINER (menubar), task);

	task_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (task), task_menu);

	new_task = gtk_menu_item_new_with_mnemonic ("_New");
	gtk_container_add (GTK_CONTAINER (task_menu), new_task);
	gtk_widget_set_sensitive (new_task, FALSE);

	delete = gtk_menu_item_new_with_mnemonic ("_Delete");
	gtk_widget_set_sensitive(delete, FALSE);
	gtk_container_add (GTK_CONTAINER (task_menu), delete);

	menuitem7 = gtk_menu_item_new_with_mnemonic ("_Help");
	gtk_container_add (GTK_CONTAINER (menubar), menuitem7);

	menuitem7_menu = gtk_menu_new ();
	gtk_menu_item_set_submenu (GTK_MENU_ITEM (menuitem7), menuitem7_menu);

	about = gtk_menu_item_new_with_mnemonic ("_About");
	gtk_container_add (GTK_CONTAINER (menuitem7_menu), about);

	scrolledwindow = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (vbox), scrolledwindow, TRUE, TRUE, 0);

	tasks = gtk_tree_view_new ();

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Status");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tasks), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "ID");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tasks), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 1);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Day");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tasks), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 2);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Time");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tasks), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 3);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Command Line");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tasks), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 4);

	store_jobs = gtk_list_store_new(5, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT, G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(tasks), GTK_TREE_MODEL(store_jobs));
	g_object_unref(store_jobs);

	gtk_container_add (GTK_CONTAINER (scrolledwindow), tasks);

	g_signal_connect (gtk_tree_view_get_selection(GTK_TREE_VIEW(tasks)) , "changed", G_CALLBACK (on_job_select), NULL);

	statusbar = gtk_statusbar_new ();
	gtk_box_pack_start (GTK_BOX (vbox), statusbar, FALSE, FALSE, 0);


	g_signal_connect ((gpointer) quit, "activate",
	  G_CALLBACK (on_quit_activate), NULL);
	g_signal_connect ((gpointer) new_task, "activate",
	  G_CALLBACK (on_new_activate), NULL);
	g_signal_connect ((gpointer) delete, "activate",
	  G_CALLBACK (on_delete_activate), NULL);
	g_signal_connect ((gpointer) about, "activate",
	  G_CALLBACK (on_about_activate), NULL);

	gtk_window_add_accel_group (GTK_WINDOW (mainwindow), accel_group);

	return mainwindow;
}

void on_chk_weekly_toggled(GtkToggleButton *togglebutton, gpointer user_data)
{
	gtk_widget_set_sensitive(entry_repeat_weekly, gtk_toggle_button_get_active(togglebutton));
}


void on_chk_monthly_toggled(GtkToggleButton *togglebutton, gpointer user_data)
{
	gtk_widget_set_sensitive(entry_repeat_monthly, gtk_toggle_button_get_active(togglebutton));
}


static GtkWidget *create_new_job_dialog (void)
{
	GtkWidget *new_job_dialog;
	GtkWidget *dialog_vbox1;
	GtkWidget *frame1;
	GtkWidget *table1;
	GtkWidget *label4;
	GtkWidget *cal_day;
	GtkWidget *label3;
	GtkWidget *entry_time;
	GtkWidget *chk_weekly;
	GtkWidget *chk_monthly;
	GtkWidget *label1;
	GtkWidget *frame2;
	GtkWidget *hbox1;
	GtkWidget *label5;
	GtkWidget *label2;
	GtkWidget *dialog_action_area1;
	GtkWidget *cancelbutton1;
	GtkWidget *okbutton1;

	new_job_dialog = gtk_dialog_new ();
	gtk_window_set_title (GTK_WINDOW (new_job_dialog), "New job");

	dialog_vbox1 = GTK_DIALOG (new_job_dialog)->vbox;

	frame1 = gtk_frame_new (NULL);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), frame1, TRUE, TRUE, 0);

	table1 = gtk_table_new (4, 2, FALSE);
	gtk_container_add (GTK_CONTAINER (frame1), table1);

	label4 = gtk_label_new ("Time:");
	gtk_table_attach (GTK_TABLE (table1), label4, 0, 1, 1, 2,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label4), 0, 0.5);

	cal_day = gtk_calendar_new ();
	gtk_table_attach (GTK_TABLE (table1), cal_day, 1, 2, 0, 1,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (GTK_FILL), 0, 0);
	gtk_calendar_set_display_options (GTK_CALENDAR (cal_day),
					  GTK_CALENDAR_SHOW_HEADING
					  | GTK_CALENDAR_SHOW_DAY_NAMES);

	label3 = gtk_label_new ("Date");
	gtk_table_attach (GTK_TABLE (table1), label3, 0, 1, 0, 1,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);
	gtk_misc_set_alignment (GTK_MISC (label3), 0, 0.5);

	entry_time = gtk_entry_new ();
	gtk_table_attach (GTK_TABLE (table1), entry_time, 1, 2, 1, 2,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_weekly = gtk_check_button_new_with_mnemonic ("Repeat weekly");
	gtk_table_attach (GTK_TABLE (table1), chk_weekly, 0, 1, 2, 3,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_repeat_weekly = gtk_entry_new ();
	gtk_table_attach (GTK_TABLE (table1), entry_repeat_weekly, 1, 2, 2, 3,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	chk_monthly = gtk_check_button_new_with_mnemonic ("Repeat monthly");
	gtk_table_attach (GTK_TABLE (table1), chk_monthly, 0, 1, 3, 4,
					  (GtkAttachOptions) (GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	entry_repeat_monthly = gtk_entry_new ();
	gtk_table_attach (GTK_TABLE (table1), entry_repeat_monthly, 1, 2, 3, 4,
					  (GtkAttachOptions) (GTK_EXPAND | GTK_FILL),
					  (GtkAttachOptions) (0), 0, 0);

	label1 = gtk_label_new ("Moment");
	gtk_frame_set_label_widget (GTK_FRAME (frame1), label1);

	frame2 = gtk_frame_new (NULL);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), frame2, TRUE, TRUE, 0);

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_container_add (GTK_CONTAINER (frame2), hbox1);

	label5 = gtk_label_new ("Command to execute");
	gtk_box_pack_start (GTK_BOX (hbox1), label5, TRUE, TRUE, 0);

	entry_cmd = gtk_entry_new ();
	gtk_box_pack_start (GTK_BOX (hbox1), entry_cmd, TRUE, TRUE, 0);

	label2 = gtk_label_new ("Command");
	gtk_frame_set_label_widget (GTK_FRAME (frame2), label2);

	dialog_action_area1 = GTK_DIALOG (new_job_dialog)->action_area;
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

	cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
	gtk_dialog_add_action_widget (GTK_DIALOG (new_job_dialog), cancelbutton1, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

	okbutton1 = gtk_button_new_from_stock ("gtk-ok");
	gtk_dialog_add_action_widget (GTK_DIALOG (new_job_dialog), okbutton1, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);

	g_signal_connect ((gpointer) chk_weekly, "toggled",
					  G_CALLBACK (on_chk_weekly_toggled),
					  NULL);
	g_signal_connect ((gpointer) chk_monthly, "toggled",
					  G_CALLBACK (on_chk_monthly_toggled),
					  NULL);

	return new_job_dialog;
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
