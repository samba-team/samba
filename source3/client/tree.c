/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB client GTK+ tree-based application
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2001
   Copyright (C) John Terpstra 2001
   
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

/* example-gtk+ application, ripped off from the gtk+ tree.c sample */

#include <stdio.h>
#include <errno.h>
#include <gtk/gtk.h>
#include "libsmbclient.h"

/* for all the GtkItem:: and GtkTreeItem:: signals */
static void cb_itemsignal( GtkWidget *item,
                           gchar     *signame )
{
  GtkWidget *real_tree, *aitem, *subtree;
  gchar *name;
  GtkLabel *label;
  gint dh, err, dirlen;
  char dirbuf[512];
  struct smbc_dirent *dirp;
  
  /* It's a Bin, so it has one child, which we know to be a
     label, so get that */
  label = GTK_LABEL (GTK_BIN (item)->child);
  /* Get the text of the label */
  gtk_label_get (label, &name);
  /* Get the level of the tree which the item is in */
  g_print ("%s called for item %s->%p, level %d\n", signame, name,
	   item, GTK_TREE (item->parent)->level);

  if (strncmp(signame, "expand", 6) == 0) { /* Expand called */

    char server[128];

    slprintf(server, 128, "smb://%s", name);

    if ((dh = smbc_opendir(server)) < 0) { /* Handle error */

      g_print("cb_wholenet: Could not open dir %s, %s\n", server, 
	      strerror(errno));

      gtk_main_quit();

      return;

    }

    real_tree = GTK_TREE_ITEM_SUBTREE(item);  /* Get the subtree */

    while ((err = smbc_getdents(dh, (struct smbc_dirent *)dirbuf, 
				sizeof(dirbuf))) != 0) {

      if (err < 0) { /* An error, report it */

	g_print("cb_wholenet: Could not read dir smbc://, %s\n",
		strerror(errno));

	gtk_main_quit();

	return;

      }

      dirp = (struct smbc_dirent *)dirbuf;

      while (err > 0) {

	dirlen = sizeof(struct smbc_dirent) + dirp->namelen +
	  dirp->commentlen + 1;

	aitem = gtk_tree_item_new_with_label(dirp->name);

	/* Connect all GtkItem:: and GtkTreeItem:: signals */
	gtk_signal_connect (GTK_OBJECT(aitem), "select",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "select");
	gtk_signal_connect (GTK_OBJECT(aitem), "deselect",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "deselect");
	gtk_signal_connect (GTK_OBJECT(aitem), "toggle",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "toggle");
	gtk_signal_connect (GTK_OBJECT(aitem), "expand",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "expand");
	gtk_signal_connect (GTK_OBJECT(aitem), "collapse",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "collapse");
	/* Add it to the parent tree */
	gtk_tree_append (GTK_TREE(real_tree), aitem);
	/* Show it - this can be done at any time */
	gtk_widget_show (aitem);

	fprintf(stdout, "Added: %s, len: %u\n", dirp->name, dirlen);

	subtree = gtk_tree_new();

	gtk_tree_item_set_subtree(GTK_TREE_ITEM(aitem), subtree);

	(char *)dirp += dirlen;
	err -= dirlen;

      }

    }

    smbc_closedir(dh);   

  }

}

/* Note that this is never called */
static void cb_unselect_child( GtkWidget *root_tree,
                               GtkWidget *child,
                               GtkWidget *subtree )
{
  g_print ("unselect_child called for root tree %p, subtree %p, child %p\n",
	   root_tree, subtree, child);
}

/* Note that this is called every time the user clicks on an item,
   whether it is already selected or not. */
static void cb_select_child (GtkWidget *root_tree, GtkWidget *child,
			     GtkWidget *subtree)
{
  g_print ("select_child called for root tree %p, subtree %p, child %p\n",
	   root_tree, subtree, child);
}

static void cb_selection_changed( GtkWidget *tree )
{
  GList *i;
  
  g_print ("selection_change called for tree %p\n", tree);
  g_print ("selected objects are:\n");

  i = GTK_TREE_SELECTION(tree);
  while (i){
    gchar *name;
    GtkLabel *label;
    GtkWidget *item;

    /* Get a GtkWidget pointer from the list node */
    item = GTK_WIDGET (i->data);
    label = GTK_LABEL (GTK_BIN (item)->child);
    gtk_label_get (label, &name);
    g_print ("\t%s on level %d\n", name, GTK_TREE
	     (item->parent)->level);
    i = i->next;
  }
}

/*
 * Expand or collapse the whole network ...
 */
static void cb_wholenet(GtkWidget *item, gchar *signame)
{
  GtkWidget *real_tree, *aitem, *subtree;
  gchar *name;
  GtkLabel *label;
  gint dh, err, dirlen;
  char dirbuf[512];
  struct smbc_dirent *dirp;
  
  label = GTK_LABEL (GTK_BIN (item)->child);
  gtk_label_get (label, &name);
  g_print ("%s called for item %s->%p, level %d\n", signame, name,
	   item, GTK_TREE (item->parent)->level);

  if (strncmp(signame, "expand", 6) == 0) { /* Expand called */

    if ((dh = smbc_opendir("smb://")) < 0) { /* Handle error */

      g_print("cb_wholenet: Could not open dir smbc://, %s\n",
	      strerror(errno));

      gtk_main_quit();

      return;

    }

    real_tree = GTK_TREE_ITEM_SUBTREE(item);  /* Get the subtree */

    while ((err = smbc_getdents(dh, (struct smbc_dirent *)dirbuf, 
				sizeof(dirbuf))) != 0) {

      if (err < 0) { /* An error, report it */

	g_print("cb_wholenet: Could not read dir smbc://, %s\n",
		strerror(errno));

	gtk_main_quit();

	return;

      }

      dirp = (struct smbc_dirent *)dirbuf;

      while (err > 0) {

	dirlen = sizeof(struct smbc_dirent) + dirp->namelen +
	  dirp->commentlen + 1;

	aitem = gtk_tree_item_new_with_label(dirp->name);

	/* Connect all GtkItem:: and GtkTreeItem:: signals */
	gtk_signal_connect (GTK_OBJECT(aitem), "select",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "select");
	gtk_signal_connect (GTK_OBJECT(aitem), "deselect",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "deselect");
	gtk_signal_connect (GTK_OBJECT(aitem), "toggle",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "toggle");
	gtk_signal_connect (GTK_OBJECT(aitem), "expand",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "expand");
	gtk_signal_connect (GTK_OBJECT(aitem), "collapse",
			    GTK_SIGNAL_FUNC(cb_itemsignal), "collapse");
	/* Add it to the parent tree */
	gtk_tree_append (GTK_TREE(real_tree), aitem);
	/* Show it - this can be done at any time */
	gtk_widget_show (aitem);

	fprintf(stdout, "Added: %s, len: %u\n", dirp->name, dirlen);

	subtree = gtk_tree_new();

	gtk_tree_item_set_subtree(GTK_TREE_ITEM(aitem), subtree);

	(char *)dirp += dirlen;
	err -= dirlen;

      }

    }

    smbc_closedir(dh);   

  }

  /* Create this item's subtree */
  /*  subtree = gtk_tree_new();
  g_print ("-> item %s->%p, subtree %p\n", "Whole Network", item,
	   subtree);

  /* This is still necessary if you want these signals to be called
     for the subtree's children.  Note that selection_change will be 
     signalled for the root tree regardless. */
  /*  gtk_signal_connect (GTK_OBJECT(subtree), "select_child",
		      GTK_SIGNAL_FUNC(cb_select_child), subtree);
    gtk_signal_connect (GTK_OBJECT(subtree), "unselect_child",
			GTK_SIGNAL_FUNC(cb_unselect_child), subtree);
    /* This has absolutely no effect, because it is completely ignored 
       in subtrees */
  /*    gtk_tree_set_selection_mode (GTK_TREE(subtree),
				 GTK_SELECTION_SINGLE);
    /* Neither does this, but for a rather different reason - the
       view_mode and view_line values of a tree are propagated to
       subtrees when they are mapped.  So, setting it later on would
       actually have a (somewhat unpredictable) effect */
  /*    gtk_tree_set_view_mode (GTK_TREE(subtree), GTK_TREE_VIEW_ITEM);
    /* Set this item's subtree - note that you cannot do this until
       AFTER the item has been added to its parent tree! */
  /*    gtk_tree_item_set_subtree (GTK_TREE_ITEM(item), subtree);

    for (j = 0; j < 5; j++){
      GtkWidget *subitem;

      /* Create a subtree item, in much the same way */
  /*      subitem = gtk_tree_item_new_with_label (itemnames[j]);
      /* Connect all GtkItem:: and GtkTreeItem:: signals */
  /*      gtk_signal_connect (GTK_OBJECT(subitem), "select",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "select");
      gtk_signal_connect (GTK_OBJECT(subitem), "deselect",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "deselect");
      gtk_signal_connect (GTK_OBJECT(subitem), "toggle",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "toggle");
      gtk_signal_connect (GTK_OBJECT(subitem), "expand",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "expand");
      gtk_signal_connect (GTK_OBJECT(subitem), "collapse",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "collapse");
      g_print ("-> -> item %s->%p\n", itemnames[j], subitem);
      /* Add it to its parent tree */
  /*      gtk_tree_append (GTK_TREE(subtree), subitem);
      /* Show it */
  /*      gtk_widget_show (subitem);
    }
  */
}

static void 
auth_fn(char *server, char *share,
	     char **workgroup, char **username, char **password)
{

  /* Do nothing for now ... */

}

int main( int   argc,
          char *argv[] )
{
  GtkWidget *window, *scrolled_win, *tree;
  GtkWidget *subtree, *item;
  gint err, dh;
  gint i;
  char dirbuf[512];
  struct smbc_dirent *dirp;

  gtk_init (&argc, &argv);

  /* Init the smbclient library */

  err = smbc_init(auth_fn, "", 10);

  /* a generic toplevel window */
  window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
  gtk_signal_connect (GTK_OBJECT(window), "delete_event",
		      GTK_SIGNAL_FUNC (gtk_main_quit), NULL);
  gtk_container_set_border_width (GTK_CONTAINER(window), 5);

  /* A generic scrolled window */
  scrolled_win = gtk_scrolled_window_new (NULL, NULL);
  gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (scrolled_win),
				  GTK_POLICY_AUTOMATIC,
				  GTK_POLICY_AUTOMATIC);
  gtk_widget_set_usize (scrolled_win, 150, 200);
  gtk_container_add (GTK_CONTAINER(window), scrolled_win);
  gtk_widget_show (scrolled_win);
  
  /* Create the root tree */
  tree = gtk_tree_new();
  g_print ("root tree is %p\n", tree);
  /* connect all GtkTree:: signals */
  gtk_signal_connect (GTK_OBJECT(tree), "select_child",
		      GTK_SIGNAL_FUNC(cb_select_child), tree);
  gtk_signal_connect (GTK_OBJECT(tree), "unselect_child",
		      GTK_SIGNAL_FUNC(cb_unselect_child), tree);
  gtk_signal_connect (GTK_OBJECT(tree), "selection_changed",
		      GTK_SIGNAL_FUNC(cb_selection_changed), tree);
  /* Add it to the scrolled window */
  gtk_scrolled_window_add_with_viewport (GTK_SCROLLED_WINDOW(scrolled_win),
                                         tree);
  /* Set the selection mode */
  gtk_tree_set_selection_mode (GTK_TREE(tree),
			       GTK_SELECTION_MULTIPLE);
  /* Show it */
  gtk_widget_show (tree);

  /* Now, build the top level display ... */

  if ((dh = smbc_opendir("smb:///")) < 0) {

    fprintf(stderr, "Could not list default workgroup: smb:///: %s\n",
	    strerror(errno));

    exit(1);

  }

  /* Create a tree item for Whole Network */

  item = gtk_tree_item_new_with_label ("Whole Network");
  /* Connect all GtkItem:: and GtkTreeItem:: signals */
  gtk_signal_connect (GTK_OBJECT(item), "select",
		      GTK_SIGNAL_FUNC(cb_itemsignal), "select");
  gtk_signal_connect (GTK_OBJECT(item), "deselect",
		      GTK_SIGNAL_FUNC(cb_itemsignal), "deselect");
  gtk_signal_connect (GTK_OBJECT(item), "toggle",
		      GTK_SIGNAL_FUNC(cb_itemsignal), "toggle");
  gtk_signal_connect (GTK_OBJECT(item), "expand",
		      GTK_SIGNAL_FUNC(cb_wholenet), "expand");
  gtk_signal_connect (GTK_OBJECT(item), "collapse",
		      GTK_SIGNAL_FUNC(cb_wholenet), "collapse");
  /* Add it to the parent tree */
  gtk_tree_append (GTK_TREE(tree), item);
  /* Show it - this can be done at any time */
  gtk_widget_show (item);

  subtree = gtk_tree_new();  /* A subtree for Whole Network */

  gtk_tree_item_set_subtree(GTK_TREE_ITEM(item), subtree);

  /* Now, get the items in smb:/// and add them to the tree */

  dirp = (struct smbc_dirent *)dirbuf;

  while ((err = smbc_getdents(dh, (struct smbc_dirent *)dirbuf, 
			      sizeof(dirbuf))) != 0) {

    if (err < 0) { /* Handle the error */

      fprintf(stderr, "Could not read directory for smbc:///: %s\n",
	      strerror(errno));

      exit(1);

    }

    fprintf(stdout, "Dir len: %u\n", err);

    while (err > 0) { /* Extract each entry and make a sub-tree */

      int dirlen = sizeof(struct smbc_dirent) + dirp->namelen + 
	dirp->commentlen + 1;

      item = gtk_tree_item_new_with_label(dirp->name);
      /* Connect all GtkItem:: and GtkTreeItem:: signals */
      gtk_signal_connect (GTK_OBJECT(item), "select",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "select");
      gtk_signal_connect (GTK_OBJECT(item), "deselect",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "deselect");
      gtk_signal_connect (GTK_OBJECT(item), "toggle",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "toggle");
      gtk_signal_connect (GTK_OBJECT(item), "expand",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "expand");
      gtk_signal_connect (GTK_OBJECT(item), "collapse",
			  GTK_SIGNAL_FUNC(cb_itemsignal), "collapse");
      /* Add it to the parent tree */
      gtk_tree_append (GTK_TREE(tree), item);
      /* Show it - this can be done at any time */
      gtk_widget_show (item);

      fprintf(stdout, "Added: %s, len: %u\n", dirp->name, dirlen);

      subtree = gtk_tree_new();

      gtk_tree_item_set_subtree(GTK_TREE_ITEM(item), subtree);

      (char *)dirp += dirlen;
      err -= dirlen;

    }

  }

  smbc_closedir(dh); /* FIXME, check for error :-) */

  /* Show the window and loop endlessly */
  gtk_widget_show (window);
  gtk_main();
  return 0;
}
/* example-end */
