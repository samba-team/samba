/* 
   Unix SMB/CIFS implementation.
   SMB-related GTK+ functions
   
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
#include "gtk/common/select.h"
#include "gtk/common/gtk-smb.h"

/* GtkSelectDomainDialog */

const char *gtk_select_domain_dialog_get_domain(GtkSelectDomainDialog *d)
{
	return gtk_entry_get_text(GTK_ENTRY(d->entry_domain));
}

void gtk_select_domain_dialog_init (GtkSelectDomainDialog *select_domain_dialog)
{
	GtkWidget *dialog_vbox1;
	GtkWidget *hbox1;
	GtkWidget *label1;
	GtkWidget *scrolledwindow1;
	GtkWidget *dialog_action_area1;
	GtkWidget *cancelbutton1;
	GtkWidget *okbutton1;
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *curcol;

	gtk_window_set_title (GTK_WINDOW (select_domain_dialog), "Select Domain");

	dialog_vbox1 = GTK_DIALOG (select_domain_dialog)->vbox;

	hbox1 = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), hbox1, TRUE, TRUE, 0);

	label1 = gtk_label_new ("Domain:");
	gtk_box_pack_start (GTK_BOX (hbox1), label1, FALSE, FALSE, 0);

	select_domain_dialog->entry_domain = gtk_entry_new ();
	gtk_box_pack_start (GTK_BOX (hbox1), select_domain_dialog->entry_domain, TRUE, TRUE, 0);

	scrolledwindow1 = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (dialog_vbox1), scrolledwindow1, TRUE, TRUE, 0);

	select_domain_dialog->list_domains = gtk_tree_view_new ();
	gtk_container_add (GTK_CONTAINER (scrolledwindow1), select_domain_dialog->list_domains);

	curcol = gtk_tree_view_column_new ();
	gtk_tree_view_column_set_title(curcol, "Name");
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(curcol, renderer, True);
	gtk_tree_view_append_column(GTK_TREE_VIEW(select_domain_dialog->list_domains), curcol);
	gtk_tree_view_column_add_attribute(curcol, renderer, "text", 0);

	select_domain_dialog->store_domains = gtk_list_store_new(1, G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(select_domain_dialog->list_domains), GTK_TREE_MODEL(select_domain_dialog->store_domains));
	g_object_unref(select_domain_dialog->store_domains);

	dialog_action_area1 = GTK_DIALOG (select_domain_dialog)->action_area;
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area1), GTK_BUTTONBOX_END);

	cancelbutton1 = gtk_button_new_from_stock ("gtk-cancel");
	gtk_dialog_add_action_widget (GTK_DIALOG (select_domain_dialog), cancelbutton1, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancelbutton1, GTK_CAN_DEFAULT);

	okbutton1 = gtk_button_new_from_stock ("gtk-ok");
	gtk_dialog_add_action_widget (GTK_DIALOG (select_domain_dialog), okbutton1, GTK_RESPONSE_OK);
	gtk_widget_show_all(dialog_vbox1);
	GTK_WIDGET_SET_FLAGS (okbutton1, GTK_CAN_DEFAULT);
}

struct policy_handle gtk_select_domain_dialog_get_handle(GtkSelectDomainDialog *d)
{
	struct policy_handle h;
	
	
	/* FIXME */
	return h;
}

GType gtk_select_domain_dialog_get_type (void)
{
	static GType mytype = 0;

	if (!mytype)
	{
		static const GTypeInfo myinfo =
		{
			sizeof (GtkSelectDomainDialogClass),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			sizeof(GtkSelectDomainDialog),
			0,
			(GInstanceInitFunc) gtk_select_domain_dialog_init,
		};

		mytype = g_type_register_static (GTK_TYPE_DIALOG,
										 "GtkSelectDomainDialog", &myinfo, 0);
	}

	return mytype;
}
                                                                                                                             
GtkWidget *gtk_select_domain_dialog_new (struct dcerpc_pipe *sam_pipe)
{
	GtkSelectDomainDialog *d = gtk_type_new (gtk_select_domain_dialog_get_type ());
	NTSTATUS status;
	struct samr_EnumDomains r;
	struct samr_Connect cr;
	struct samr_Close dr;
	struct policy_handle handle;
	uint32_t resume_handle = 0;
	int i;
	TALLOC_CTX *mem_ctx = talloc_init("gtk_select_domain_dialog_new");

	d->sam_pipe = sam_pipe;

	cr.in.system_name = 0;
	cr.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	cr.out.connect_handle = &handle;

	status = dcerpc_samr_Connect(sam_pipe, mem_ctx, &cr);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(NULL, status);
		talloc_destroy(mem_ctx);
		return GTK_WIDGET(d);
	}

	r.in.connect_handle = &handle;
	r.in.resume_handle = &resume_handle;
	r.in.buf_size = (uint32_t)-1;
	r.out.resume_handle = &resume_handle;

	status = dcerpc_samr_EnumDomains(sam_pipe, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(NULL, status);
	} else if (r.out.sam) {
		for (i=0;i<r.out.sam->count;i++) {
			GtkTreeIter iter;
			gtk_list_store_append(d->store_domains, &iter);
			gtk_list_store_set (d->store_domains, &iter, 0, r.out.sam->entries[i].name.string, -1);
		}
	}

	dr.in.handle = &handle;
	dr.out.handle = &handle;

	status = dcerpc_samr_Close(sam_pipe, mem_ctx, &dr);
	if (!NT_STATUS_IS_OK(status)) {
		gtk_show_ntstatus(NULL, status);
		talloc_destroy(mem_ctx);
		return GTK_WIDGET ( d );
	}

	talloc_destroy(mem_ctx);

	return GTK_WIDGET ( d );
}


/* GtkSelectHostDialog */
const char *gtk_select_host_dialog_get_host (GtkSelectHostDialog *d)
{
	return gtk_entry_get_text(GTK_ENTRY(d->entry_host));
}

void gtk_select_host_dialog_init (GtkSelectHostDialog *select_host_dialog)
{
	GtkWidget *dialog_vbox2;
	GtkWidget *hbox2;
	GtkWidget *label2;
	GtkWidget *scrolledwindow2;
	GtkWidget *dialog_action_area2;
	GtkWidget *cancelbutton2;
	GtkWidget *okbutton2;

	gtk_window_set_title (GTK_WINDOW (select_host_dialog), "Select Host");

	dialog_vbox2 = GTK_DIALOG (select_host_dialog)->vbox;

	hbox2 = gtk_hbox_new (FALSE, 0);
	gtk_box_pack_start (GTK_BOX (dialog_vbox2), hbox2, TRUE, TRUE, 0);

	label2 = gtk_label_new ("Host");
	gtk_box_pack_start (GTK_BOX (hbox2), label2, FALSE, FALSE, 0);

	select_host_dialog->entry_host = gtk_entry_new ();
	gtk_box_pack_start (GTK_BOX (hbox2), select_host_dialog->entry_host, TRUE, TRUE, 0);

	scrolledwindow2 = gtk_scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (dialog_vbox2), scrolledwindow2, TRUE, TRUE, 0);

	select_host_dialog->tree_host = gtk_tree_view_new ();
	gtk_container_add (GTK_CONTAINER (scrolledwindow2), select_host_dialog->tree_host);

	select_host_dialog->store_host = gtk_tree_store_new(1, G_TYPE_STRING);
	gtk_tree_view_set_model(GTK_TREE_VIEW(select_host_dialog->tree_host), GTK_TREE_MODEL(select_host_dialog->store_host));
	g_object_unref(select_host_dialog->store_host); 

	dialog_action_area2 = GTK_DIALOG (select_host_dialog)->action_area;
	gtk_button_box_set_layout (GTK_BUTTON_BOX (dialog_action_area2), GTK_BUTTONBOX_END);

	cancelbutton2 = gtk_button_new_from_stock ("gtk-cancel");
	gtk_dialog_add_action_widget (GTK_DIALOG (select_host_dialog), cancelbutton2, GTK_RESPONSE_CANCEL);
	GTK_WIDGET_SET_FLAGS (cancelbutton2, GTK_CAN_DEFAULT);

	okbutton2 = gtk_button_new_from_stock ("gtk-ok");
	gtk_widget_show_all (dialog_vbox2);
	gtk_dialog_add_action_widget (GTK_DIALOG (select_host_dialog), okbutton2, GTK_RESPONSE_OK);
	GTK_WIDGET_SET_FLAGS (okbutton2, GTK_CAN_DEFAULT);
}

GType gtk_select_host_dialog_get_type (void)
{
	static GType mytype = 0;

	if (!mytype)
	{
		static const GTypeInfo myinfo =
		{
			sizeof (GtkSelectHostDialogClass),
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			sizeof(GtkSelectHostDialog),
			0,
			(GInstanceInitFunc) gtk_select_host_dialog_init,
		};

		mytype = g_type_register_static (GTK_TYPE_DIALOG,
										 "GtkSelectHostDialog", &myinfo, 0);
	}

	return mytype;
}
                                                                                                                             
GtkWidget *gtk_select_host_dialog_new (struct sam_pipe *sam_pipe, BOOL nocredentials)
{
        return GTK_WIDGET ( gtk_type_new (gtk_select_host_dialog_get_type ()));
}
