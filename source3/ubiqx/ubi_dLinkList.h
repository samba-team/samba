#ifndef ubi_dLinkList_H
#define ubi_dLinkList_H
/* ========================================================================== **
 *                              ubi_dLinkList.h
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
 * Revision 0.3  1997/10/15 03:04:31  crh
 * Added some handy type casting to the macros.  Added AddHere and RemThis
 * macros.
 *
 * Revision 0.2  1997/10/08 03:08:16  crh
 * Fixed a few forgotten link-ups in Insert(), and fixed the AddHead()
 * macro, which was passing the wrong value for <After> to Insert().
 *
 * Revision 0.1  1997/10/07 04:34:38  crh
 * Initial Revision.
 *
 *
 * ========================================================================== **
 */

#include <stdlib.h>


/* ========================================================================== **
 * Typedefs...
 *
 *  ubi_dlNode    - This is the basic node structure.
 *  ubi_dlNodePtr - Pointer to a node.
 *  ubi_dlList    - This is the list header structure.
 *  ubi_dlListPtr - Pointer to a List (i.e., a list header structure).
 *
 */

typedef struct ubi_dlListNode
  {
  struct ubi_dlListNode *Next;
  struct ubi_dlListNode *Prev;
  } ubi_dlNode;

typedef ubi_dlNode *ubi_dlNodePtr;

typedef struct
  {
  ubi_dlNodePtr Head;
  ubi_dlNodePtr Tail;
  unsigned long count;
  } ubi_dlList;

typedef ubi_dlList *ubi_dlListPtr;

/* ========================================================================== **
 * Macros...
 * 
 *  ubi_dlAddHead - Add a new node at the head of the list.
 *  ubi_dlAddTail - Add a new node at the tail of the list.
 *  ubi_dlAddHere - Add a node following the given node.
 *  ubi_dlRemHead - Remove the node at the head of the list, if any.
 *  ubi_dlRemTail - Remove the node at the tail of the list, if any.
 *  ubi_dlRemThis - Remove the indicated node.
 *  ubi_dlFirst   - Return a pointer to the first node in the list, if any.
 *  ubi_dlLast    - Return a pointer to the last node in the list, if any.
 *  ubi_dlNext    - Given a node, return a pointer to the next node.
 *  ubi_dlPrev    - Given a node, return a pointer to the previous node.
 *
 *  Note that all of these provide type casting of the parameters.  The
 *  Add and Rem macros are nothing more than nice front-ends to the
 *  Insert and Remove operations.
 *
 */

#define ubi_dlAddHead( L, N ) \
        ubi_dlInsert( (ubi_dlListPtr)(L), (ubi_dlNodePtr)(N), NULL )

#define ubi_dlAddTail( L, N ) \
        ubi_dlInsert( (ubi_dlListPtr)(L), \
                      (ubi_dlNodePtr)(N), \
                    (((ubi_dlListPtr)(L))->Tail) )

#define ubi_dlAddHere( L, N, P ) \
        ubi_dlInsert( (ubi_dlListPtr)(L), \
                      (ubi_dlNodePtr)(N), \
                      (ubi_dlNodePtr)(P) )

#define ubi_dlRemHead( L ) ubi_dlRemove( (ubi_dlListPtr)(L), \
                                         (((ubi_dlListPtr)(L))->Head) )

#define ubi_dlRemTail( L ) ubi_dlRemove( (ubi_dlListPtr)(L), \
                                         (((ubi_dlListPtr)(L))->Tail) )

#define ubi_dlRemThis( L, N ) ubi_dlRemove( (ubi_dlListPtr)(L), \
                                            (ubi_dlNodePtr)(N) )

#define ubi_dlFirst( L ) (((ubi_dlListPtr)(L))->Head)

#define ubi_dlLast( L )  (((ubi_dlListPtr)(L))->Tail)

#define ubi_dlNext( N )  (((ubi_dlNodePtr)(N))->Next)

#define ubi_dlPrev( N )  (((ubi_dlNodePtr)(N))->Prev)


/* ========================================================================== **
 * Function prototypes...
 */

ubi_dlListPtr ubi_dlInitList( ubi_dlListPtr ListPtr );
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

ubi_dlNodePtr ubi_dlInsert( ubi_dlListPtr ListPtr,
                            ubi_dlNodePtr New,
                            ubi_dlNodePtr After );
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

ubi_dlNodePtr ubi_dlRemove( ubi_dlListPtr ListPtr, ubi_dlNodePtr Old );
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


/* ================================ The End ================================= */
#endif /* ubi_dLinkList_H */
