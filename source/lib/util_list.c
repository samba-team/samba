/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell                   1992-1999
   Copyright (C) Gerald Carter <jerry@samba.org>   2000
   
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

/****************************************************************
 In order to make use of the GENERIC_LIST data structure, you
 should create wrapper functions around:
 
 	BOOL 	generic_list_append()
	void* 	generic_list_remove()
	void* 	generic_list_locate()
	
 The reason this is necessary is that the GENERIC_LIST uses a
 void pointer to store your data structure.  This means that
 you get no type checking and can create a hetergenous list.
 However, you will need to have some way to determine the type
 of your data.  If you are using a homogenous list, then
 wrapper functions are the easiest way.  If you are creating
 a hetergenous list, then you will need to use the type field
 for your arbitrary identifiers.
 
 TODO:
 If neccessary, you can add a few generic_list_*() to do things
 like grab from the front (to implement a FIFO queue) or from
 the tail (to implement a FILO stack)
 ****************************************************************/

#include "includes.h"


#if 0
/*
 * list variables
 */
static GENERIC_LIST hnds;
#endif

/****************************************************************
 Initialize the list.  This doesn't do much currently.  Just make
 sure that you call it so we can determine wether the list is 
 empty or not.
 ****************************************************************/
static void generic_list_init(GENERIC_LIST *l)
{

	l->head 	= NULL;
	l->tail 	= NULL;
	l->length 	= 0;
	l->initialized	= True;
	
	return;
}

/****************************************************************
 Create and return a new GENERIC_LIST
 ****************************************************************/
GENERIC_LIST *generic_list_new(void)
{
	GENERIC_LIST *l;

	l = g_new(GENERIC_LIST, 1);
	if (! l)
	{
		DEBUG(0, ("generic_list_new: No memory\n"));
		return l;
	}

	generic_list_init(l);

	return l;
}

/*****************************************************************
 Insert some data into the list (appended to the end of the list)
 *****************************************************************/
GENERIC_LIST *generic_list_append(GENERIC_LIST *l, 
				  void *item, uint8 type)
{
	if (! l)
	{
		DEBUG(1, ("generic_list_append: NULL list\n"));
		l = generic_list_new();
	}

	if (! l)
		return l;

	/* check for an emtpy list first */
	if (l->length == 0) 
	{
		if ((l->head = malloc(sizeof(struct _list_node))) == NULL)
		{
			DEBUG(0, ("ERROR: out of memory!  Cannot allocate a list node!\n"));
			return l;
		}
		l->head->data = item;
		l->head->type = type;
		l->head->next = NULL;
		l->length++;
		l->tail = l->head;
	}
	
	/* we already have an existing list */
	else
	{
		if ((l->tail->next = malloc(sizeof(struct _list_node))) == NULL)
		{
			DEBUG(0, ("ERROR: out of memory!  Cannot allocate a list node!\n"));
			return l;
		}
		l->tail = l->tail->next;
		l->tail->next = NULL;
		l->tail->data = item;
		l->tail->type = type;
		l->length++;
	}
	
	/* return the list pointer in case this was the first node */
	return l;
}

/****************************************************************
 Return the first element in the list and its type
 ****************************************************************/
void *generic_list_first(GENERIC_LIST *l, uint8 *type)
{
	struct _list_node *item;

	if (! l)
		return NULL;
	if (l->length == 0)
		return NULL;

	item = l->head;
	if (type)
		*type = item->type;
	return item->data;
}

/****************************************************************
 In order to locate an item in the list we need a pointer to 
 a compare function for the data items.
 
 We will return the actual pointer to the item in the list.  Not
 a copy of the item.
 ****************************************************************/
void *generic_list_locate (GENERIC_LIST *l, void *search,
				  BOOL(*cmp)(const void*,const void*))
{
	struct _list_node *item;

	if (!l || !cmp)
		return NULL;

	/* loop through the list in linear order */
	item = l->head;
	while (item != NULL)
	{
		if (cmp(search, item->data))
			return item->data;
		else
		{
			item = item->next;
		}
	}

	return NULL;
}

	
/***************************************************************
 In order to remove a node from the list, we will need a pointer
 to a compare function.  The function will return a pointer to
 data in the removed node.  
 
 **WARNING** It is the responsibility of the caller to save 
 the pointer and destroy the data.

 If you don't specify the cmp-function, the search-pointerr must
 be the data-pointer.
 ***************************************************************/
void *generic_list_remove(GENERIC_LIST *l, void *search,
			  BOOL(*cmp)(const void*,const void*))
{
	struct _list_node 	*item, *tag;
	void			*data_ptr;
	
	/* loop through the list in linear order */
	tag = NULL;
	item = l->head;
	while (item != NULL)
	{
		/* did we find it?  If so remove the node */
		if (cmp==NULL 
		    ? (search == item->data)
		    : cmp(search, item->data))
		{
			/* found, so remove the node */

			/* remove the first item in the list */
			if (item == l->head)
				l->head = item->next;
			/* remove from the middle or the end */
			else
				tag->next = item->next;
			
			/* check to see if we need to update the tail */
			if (l->tail == item)
				l->tail = tag;

			l->length--;
			data_ptr = item->data;
			free(item);
			return data_ptr;
		}
		/* increment to the nbext node in the list */
		else
		{
			tag = item;
			item = item->next;
		}
	}

	return NULL;
}

#if 0
/**************************************************************
 copy a POLICY_HND
 *************************************************************/
 BOOL copy_policy_hnd (POLICY_HND *dest, const POLICY_HND *src)
{
	int i;

	/* if we have no destination, return an error */
	if (dest == NULL)
		return False;

	/* if the src handle is NULL, then copy 0x00 to 
	   the dest handle  */
	if (src == NULL)
	{
		/* if POLICY_HND internals ever changes,
		   this will need to be fixed */
		memset (dest->data, 0, POLICY_HND_SIZE);
		return True;
	}	

	/* copy the src handle to the dest */
	for (i=0; i<POLICY_HND_SIZE; i++)
		dest->data[i] = src->data[i];

	return True;
}

/***************************************************************
 Return True if the to RPC_HND_NODEs are eqivalent in value.
 Return False if they are not.  Since a POLICY_HND is really 
 a UUID, two RPC_HND_NODES are considered to be the same if the
 POLICY_HND value matches.

 No ordering betweeen the two is attempted.
 **************************************************************/
 BOOL compare_rpc_hnd_node(const RPC_HND_NODE *x, 
			  const RPC_HND_NODE *y)
{
	/* only compare valid nodes */
	if (x==NULL || y==NULL)
		return FALSE;

	/* if the POLICY_HND field(s) are ever changed, this
	   will need to be updated.  Probably should be a set of
	  support function for dealing with POLICY_HND */
	return (memcmp(x->hnd.data, y->hnd.data, POLICY_HND_SIZE) == 0);
}

/***************************************************************
 associate a POLICY_HND with a cli_connection
 **************************************************************/
 BOOL RpcHndList_set_connection(const POLICY_HND *hnd, 
		  	       struct cli_connection *con)
{

	RPC_HND_NODE	*node = NULL;

	/* initialize the list if necessary */
	if (!hnds.initialized)
		generic_list_init(&hnds);

	/* allocate a node to insert */
	if ((node=(RPC_HND_NODE*)malloc(sizeof(RPC_HND_NODE))) == NULL)
	{
		DEBUG(0, ("ERROR: Unable to allocate memory for an RPC_HND_NODE!\n"));
		return False;
	}

	/* fill in the RPC_HND_NODE */
	copy_policy_hnd (&node->hnd, hnd);
	node->cli = con;

	/* insert the node into the list: 
 	   	The 3rd parameter is set to 0 since we don't care
	   	anything about the type field */
	return (generic_list_append(&hnds, (void*)node, 0));
}

/************************************************************************
 delete a POLICY_HND (and associated cli_connection) from the list
 ***********************************************************************/
 BOOL RpcHndList_del_connection(const POLICY_HND *hnd)
{
	RPC_HND_NODE	node, *located;

	/* return NULL if the list has not been initialized */
	if (!hnds.initialized)
		return False;

	/* fill in the RPC_HND_NODE */
	copy_policy_hnd (&node.hnd, hnd);
	node.cli = NULL;
	
	/* search for the POLICY_HND */
	located = (RPC_HND_NODE*)generic_list_remove(&hnds, &node,
		  (BOOL(*)(const void*, const void*))compare_rpc_hnd_node);
	if (located == NULL)
		return False;

	/* delete the information */
	cli_connection_free(located->cli);
	free(located);
	return True;
}

/************************************************************************
 search for a POLICY_HND and return a pointer to the associated
 cli_connection struct in the list
 **********************************************************************/
 struct cli_connection* RpcHndList_get_connection(const POLICY_HND *hnd)
{
	RPC_HND_NODE	node, *located;

	/* return NULL if the list has not been initialized */
	if (!hnds.initialized)
		return NULL;

	/* fill in the RPC_HND_NODE */
	copy_policy_hnd (&node.hnd, hnd);
	node.cli = NULL;
	
	/* search for the POLICY_HND */
	located = (RPC_HND_NODE*)generic_list_locate(&hnds, &node, 
		  (BOOL(*)(const void*, const void*))compare_rpc_hnd_node);
	if (located  == NULL)
		return NULL;
	else
		return located->cli;
}
#endif
