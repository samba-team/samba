/* ========================================================================== **
 *                              ubi_dLinkList.c
 *
 *  Copyright (C) 1997 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *  This module implements simple doubly-linked lists.
 * -------------------------------------------------------------------------- **
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this library; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * -------------------------------------------------------------------------- **
 *
 * Revision 0.3  1997/10/15 03:05:39  crh
 * Added some handy type casting to the macros.  Added AddHere and RemThis
 * macros.
 *
 * Revision 0.2  1997/10/08 03:07:21  crh
 * Fixed a few forgotten link-ups in Insert(), and fixed the AddHead()
 * macro, which was passing the wrong value for <After> to Insert().
 *
 * Revision 0.1  1997/10/07 04:34:07  crh
 * Initial Revision.
 *
 *
 * ========================================================================== **
 */

#include "../includes.h"
#include "ubi_dLinkList.h"

/* ========================================================================== **
 * Functions...
 */

ubi_dlListPtr ubi_dlInitList( ubi_dlListPtr ListPtr )
  /* ------------------------------------------------------------------------ **
   * Initialize a doubly-linked list header.
   *
   *  Input:  ListPtr - A pointer to the list structure that is to be
   *                    initialized for use.
   *
   *  Output: A pointer to the initialized list header (i.e., same as
   *          <ListPtr>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ListPtr->Head  = NULL;
  ListPtr->Tail  = NULL;
  ListPtr->count = 0;
  return( ListPtr );
  } /* ubi_dlInitList */

ubi_dlNodePtr ubi_dlInsert( ubi_dlListPtr ListPtr,
                            ubi_dlNodePtr New,
                            ubi_dlNodePtr After )
  /* ------------------------------------------------------------------------ **
   * Insert a new node into the list.
   *
   *  Input:  ListPtr - A pointer to the list into which the node is to
   *                    be inserted.
   *          New     - Pointer to the new node.
   *          After   - NULL, or a pointer to a node that is already in the
   *                    list.
   *                    If NULL, then <New> will be added at the head of the
   *                    list, else it will be added following <After>.
   * 
   *  Output: A pointer to the node that was inserted into the list (i.e.,
   *          the same as <New>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  if( NULL == After )
    {
    New->Next           = ListPtr->Head;
    New->Prev           = NULL;
    if( NULL != ListPtr->Head )
      ListPtr->Head->Prev = New;
    else
      ListPtr->Tail       = New;
    ListPtr->Head       = New;
    }
  else
    {
    New->Next         = After->Next;
    New->Prev         = After;
    if( NULL != After->Next )
      After->Next->Prev = New;
    else
      ListPtr->Tail       = New;
    After->Next       = New;
    }

  ++(ListPtr->count);

  return( New );
  } /* ubi_dlInsert */

ubi_dlNodePtr ubi_dlRemove( ubi_dlListPtr ListPtr, ubi_dlNodePtr Old )
  /* ------------------------------------------------------------------------ **
   * Remove a node from the list.
   *
   *  Input:  ListPtr - A pointer to the list from which <Old> is to be
   *                    removed.
   *          Old     - A pointer to the node that is to be removed from the
   *                    list.
   *
   *  Output: A pointer to the node that was removed (i.e., <Old>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  if( NULL != Old )
    {
    if( Old->Next )
      Old->Next->Prev = Old->Prev;
    else
      ListPtr->Tail = Old->Prev;

    if( Old->Prev )
      Old->Prev->Next = Old->Next;
    else
      ListPtr->Head = Old->Next;

    --(ListPtr->count);
    }

  return( Old );
  } /* ubi_dlRemove */


/* ================================ The End ================================= */
