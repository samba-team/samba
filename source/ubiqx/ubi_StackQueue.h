#ifndef ubi_StackQueue_H
#define ubi_StackQueue_H
/* ========================================================================== **
 *                              ubi_StackQueue.h
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
 * Revision 0.1  1997/10/24 02:48:23  crh
 * Initial revision.
 *
 * ========================================================================== **
 */

#include <stdlib.h>


/* ========================================================================== **
 * Typedefs...
 *
 *  ubi_sqNode      - This is the basic node structure.
 *  ubi_sqNodePtr   - Pointer to a node.
 *  ubi_sqList      - This is the stack & queue header structure.
 *  ubi_sqListPtr   - Pointer to a stack & queue header.
 *
 */

typedef struct ubi_sqListNode
  {
  struct ubi_sqListNode *Next;
  } ubi_sqNode;

typedef ubi_sqNode *ubi_sqNodePtr;

typedef struct
  {
  ubi_sqNodePtr Head;
  ubi_sqNodePtr Tail;
  unsigned long count;
  } ubi_sqList;

typedef ubi_sqList *ubi_sqListPtr;

/* ========================================================================== **
 * Macros...
 * 
 *  ubi_sqEnqueue - Add a new node at the tail of a queue.
 *  ubi_sqDequeue - Remove a node from the head of the queue.
 *  ubi_sqPush    - Add a new node at the head of the queue.
 *  ubi_sqPop     - Remove a node from the head of the queue (same as Dequeue). 
 *  ubi_sqFirst   - Return a pointer to the frontmost node in the queue.
 *  ubi_sqNext    - Given a node, return a pointer to the next node.
 *  ubi_sqLast    - Return a pointer to the last (valid) node in the queue.
 *
 *  Note that all of these provide type casting of the parameters.  The
 *  Enqueue/Dequeue macros are nothing more than nice front-ends to the
 *  Insert and Remove operations.
 *
 */

#define ubi_sqEnqueue( L, N ) \
        ubi_sqInsTail( (ubi_sqListPtr)(L), (ubi_sqNodePtr)(N) )

#define ubi_sqDequeue( L ) ubi_sqRemove( (ubi_sqListPtr)(L) )

#define ubi_sqPush( L, N ) \
        ubi_sqInsHead( (ubi_sqListPtr)(L), (ubi_sqNodePtr)(N) )

#define ubi_sqPop ubi_sqDequeue

#define ubi_sqFirst( L ) (((ubi_sqListPtr)(L))->Head)

#define ubi_sqNext( N )  (((ubi_sqNodePtr)(N))->Next)

#define ubi_sqLast( L )  \
    ( (((ubi_sqListPtr)(L))->Head) ? (((ubi_sqListPtr)(L))->Tail) : NULL )


/* ========================================================================== **
 * Function prototypes...
 */

ubi_sqListPtr ubi_sqInit( ubi_sqListPtr ListPtr );
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

ubi_sqNodePtr ubi_sqInsHead( ubi_sqListPtr ListPtr, ubi_sqNodePtr New );
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

ubi_sqNodePtr ubi_sqInsTail( ubi_sqListPtr ListPtr, ubi_sqNodePtr New );
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

ubi_sqNodePtr ubi_sqRemove( ubi_sqListPtr ListPtr );
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

/* ================================ The End ================================= */
#endif /* ubi_StackQueue_H */
