/* ========================================================================== **
 *                              ubi_StackQueue.c
 *
 *  Copyright (C) 1997 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *  This module implements simple queues and stacks using a singly linked
 *  list.
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
 *  This module uses a singly-linked list to implement both a queue and a
 *  stack.  For a queue, entries are added at the tail and removed from the
 *  head of the list.  For a stack, the entries are entered and removed from
 *  the head of the list. A traversal of the list will always start at the
 *  head of the list and proceed toward the tail.  This is all mind-numbingly
 *  simple, but I'm surprised by the number of programs out there which
 *  re-implement this a dozen or so times.
 *
 *  Note:  When the list header is initialized, the Tail pointer is set to
 *         point to the Head pointer.  This simplifies the InsTail function
 *         at little or no cost to InsHead or Remove.  The one problem is
 *         that you can't initialize a stack or queue headerby simply zeroing
 *         it out.  One sure way to initialize the header is to call
 *         ubi_sqInit().  Another option would be something like this:
 *
 *         static ubi_sqList MyList = { NULL, (ubi_sqNodePtr)&MyList, 0 };
 *
 *         See ubi_sqInit() and the ubi_sqList structure for more info.
 *
 * -------------------------------------------------------------------------- **
 *
 * Revision 0.1  1997/10/24 02:47:52  crh
 * Initial revision.
 *
 * ========================================================================== **
 */

#include "ubi_StackQueue.h"

/* ========================================================================== **
 * Functions...
 */

ubi_sqListPtr ubi_sqInit( ubi_sqListPtr ListPtr )
  /* ------------------------------------------------------------------------ **
   * Initialize a stack & queue header.
   *
   *  Input:  ListPtr - A pointer to the list header that is to be
   *                    initialized for use.
   *
   *  Output: A pointer to the initialized list header (i.e., same as
   *          <ListPtr>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ListPtr->Head  = NULL;
  ListPtr->Tail  = (ubi_sqNodePtr)ListPtr;
  ListPtr->count = 0;
  return( ListPtr );
  } /* ubi_sqInit */

ubi_sqNodePtr ubi_sqInsHead( ubi_sqListPtr ListPtr, ubi_sqNodePtr New )
  /* ------------------------------------------------------------------------ **
   * Insert a new node at the head of the list (push).
   *
   *  Input:  ListPtr - A pointer to the stack into which the node is to
   *                    be inserted.
   *          New     - Pointer to the node that is to be pushed onto the
   *                    stack.
   *
   *  Output: A pointer to the node that was added to the list (i.e., same
   *          same as <New>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  if( NULL == ListPtr->Head )   /* If list is empty, must change tail ptr. */
    ListPtr->Tail = New;
  New->Next     = ListPtr->Head;
  ListPtr->Head = New;
  ++(ListPtr->count);
  return( New );
  } /* ubi_sqInsHead */

ubi_sqNodePtr ubi_sqInsTail( ubi_sqListPtr ListPtr, ubi_sqNodePtr New )
  /* ------------------------------------------------------------------------ **
   * Add a new node to the tail of the list (enqueue).
   *
   *  Input:  ListPtr - A pointer to the queue into which the node is to
   *                    be inserted.
   *          New     - Pointer to the node that is to be enqueued.
   *
   *  Output: A pointer to the node that was inserted into the queue (i.e.,
   *          the same as <New>).
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ListPtr->Tail->Next = New;
  ListPtr->Tail       = New;
  New->Next           = NULL;
  ++(ListPtr->count);
  return( New );
  } /* ubi_sqInsTail */

ubi_sqNodePtr ubi_sqRemove( ubi_sqListPtr ListPtr )
  /* ------------------------------------------------------------------------ **
   * Remove the frontmost entry from the queue, or topmost entry from the
   * stack.
   *
   *  Input:  ListPtr - A pointer to the list from which the node is to be
   *                     removed.
   *
   *  Output: A pointer to the node that was removed.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_sqNodePtr Old = ListPtr->Head;

  if( NULL != Old )
    {
    if( NULL == Old->Next )
      ListPtr->Tail = (ubi_sqNodePtr)ListPtr;
    ListPtr->Head = Old->Next;
    --(ListPtr->count);
    }
  return( Old );
  } /* ubi_sqRemove */


/* ================================ The End ================================= */
