/* ========================================================================== **
 *                              ubi_sLinkList.c
 *
 *  Copyright (C) 1997 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *  This module implements a really simple singly-linked list.
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
 * Revision 0.2  1997/10/21 03:35:18  crh
 * Added parameter <After> in function Insert().  Made necessary changes
 * to macro AddHead() and added macro AddHere().
 *
 * Revision 0.1  1997/10/16 02:53:45  crh
 * Initial Revision.
 *
 * ========================================================================== **
 */

#include "ubi_sLinkList.h"

/* ========================================================================== **
 * Functions...
 */

ubi_slListPtr ubi_slInitList( ubi_slListPtr ListPtr )
  /* ------------------------------------------------------------------------ **
   * Initialize a singly-linked list header.
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
  ListPtr->count = 0;
  return( ListPtr );
  } /* ubi_slInitList */

ubi_slNodePtr ubi_slInsert( ubi_slListPtr ListPtr,
                            ubi_slNodePtr New,
                            ubi_slNodePtr After )
  /* ------------------------------------------------------------------------ **
   * Insert a new node at the head of the list.
   *
   *  Input:  ListPtr - A pointer to the list into which the node is to
   *                    be inserted.
   *          New     - Pointer to the node that is to be added to the list.
   *          After   - Pointer to a list in a node after which the new node
   *                    will be inserted.  If NULL, then the new node will
   *                    be added at the head of the list.
   *
   *  Output: A pointer to the node that was inserted into the list (i.e.,
   *          the same as <New>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_slNodePtr *PredPtr;

  PredPtr = ( NULL == After ) ? &(ListPtr->Head) : &(After->Next);
  New->Next = *PredPtr;
  *PredPtr  = New;
  ++(ListPtr->count);
  return( New );
  } /* ubi_slInsert */

ubi_slNodePtr ubi_slRemove( ubi_slListPtr ListPtr )
  /* ------------------------------------------------------------------------ **
   * Remove a node from the head of the list.
   *
   *  Input:  ListPtr - A pointer to the list from which the node is to be
   *                    removed.
   *
   *  Output: A pointer to the node that was removed.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_slNodePtr Old = ListPtr->Head;

  if( NULL != Old )
    {
    ListPtr->Head = Old->Next;
    --(ListPtr->count);
    }
  return( Old );
  } /* ubi_slRemove */


/* ================================ The End ================================= */
