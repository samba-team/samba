#ifndef ubi_sLinkList_H
#define ubi_sLinkList_H
/* ========================================================================== **
 *                              ubi_sLinkList.h
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
 * Revision 0.2  1997/10/21 03:36:14  crh
 * Added parameter <After> in function Insert().  Made necessary changes
 * to macro AddHead() and added macro AddHere().
 *
 * Revision 0.1  1997/10/16 02:54:08  crh
 * Initial Revision.
 *
 * ========================================================================== **
 */

#include <stdlib.h>


/* ========================================================================== **
 * Typedefs...
 *
 *  ubi_slNode    - This is the basic node structure.
 *  ubi_slNodePtr - Pointer to a node.
 *  ubi_slList    - This is the list header structure.
 *  ubi_slListPtr - Pointer to a List (i.e., a list header structure).
 *
 */

typedef struct ubi_slListNode
  {
  struct ubi_slListNode *Next;
  } ubi_slNode;

typedef ubi_slNode *ubi_slNodePtr;

typedef struct
  {
  ubi_slNodePtr Head;
  unsigned long count;
  } ubi_slList;

typedef ubi_slList *ubi_slListPtr;

/* ========================================================================== **
 * Macros...
 * 
 *  ubi_slAddHead - Add a new node at the head of the list.
 *  ubi_slRemHead - Remove the node at the head of the list, if any.
 *  ubi_slFirst   - Return a pointer to the first node in the list, if any.
 *  ubi_slNext    - Given a node, return a pointer to the next node.
 *
 *  Note that all of these provide type casting of the parameters.  The
 *  Add and Rem macros are nothing more than nice front-ends to the
 *  Insert and Remove operations.
 *
 */

#define ubi_slAddHead( L, N ) \
        ubi_slInsert( (ubi_slListPtr)(L), (ubi_slNodePtr)(N), NULL )

#define ubi_slAddHere( L, N, P ) \
        ubi_slInsert( (ubi_slListPtr)(L), \
                      (ubi_slNodePtr)(N), \
                      (ubi_slNodePtr)(P) )

#define ubi_slRemHead( L ) ubi_slRemove( (ubi_slListPtr)(L) )

#define ubi_slFirst( L ) (((ubi_slListPtr)(L))->Head)

#define ubi_slNext( N )  (((ubi_slNodePtr)(N))->Next)


/* ========================================================================== **
 * Function prototypes...
 */

ubi_slListPtr ubi_slInitList( ubi_slListPtr ListPtr );
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

ubi_slNodePtr ubi_slInsert( ubi_slListPtr ListPtr,
                            ubi_slNodePtr New,
                            ubi_slNodePtr After );
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

ubi_slNodePtr ubi_slRemove( ubi_slListPtr ListPtr );
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

/* ================================ The End ================================= */
#endif /* ubi_sLinkList_H */
