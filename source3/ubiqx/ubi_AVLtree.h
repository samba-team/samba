#ifndef ubi_AVLtree_H
#define ubi_AVLtree_H
/* ========================================================================== **
 *                              ubi_AVLtree.h
 *
 *  Copyright (C) 1991-1997 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *
 *  This module provides an implementation of AVL height balanced binary
 *  trees.  (Adelson-Velskii, Landis 1962)
 *
 *  This header file contains the basic AVL structure and pointer typedefs
 *  as well as the prototypes needed to access the functions in the AVL
 *  module ubi_AVLtree.  The .c file implements the low-level height balancing
 *  routines that manage the AVL tree, plus all of the basic primops for
 *  adding, searching for, and deleting nodes.
 *
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
 * Log: ubi_AVLtree.h,v
 * Revision 3.1  1997/12/18 06:27:01  crh
 * Fixed some comment bugs.
 *
 * Revision 3.0  1997/12/08 05:39:01  crh
 * This is a new major revision level.  The handling of the pointers in the
 * ubi_trNode structure was redesigned.  The result is that there are fewer
 * macros floating about, and fewer cases in which values have to be
 * incremented or decremented.  See ubi_BinTree for more information.
 *
 * Revision 2; 1995/03/05 - 1997/12/07:
 * An overhaul to the node delete process.  I had gotten it wrong in a
 * couple of places, thought I'd fixed it, and then found that I'd missed
 * something more.  Thanks to Andrew Leppard for the bug report!
 * 
 * Revision 1;  93/10/15 - 95/03/05:
 * Added the ubi_tr defines.  See ubi_BinTree.h for more info.
 *
 *  V0.0 - May, 1990   -  Written by Christopher R. Hertel (CRH).
 *
 *  ========================================================================= **
 */

#include "ubi_BinTree.h"   /* Base erg binary tree support.       */

/*  ------------------------------------------------------------------------- **
 *  AVL Tree Node Structure:  This structure defines the basic elements of
 *       the AVL tree nodes.  In general you *SHOULD NOT PLAY WITH THESE
 *       FIELDS*!  But, of course, I have to put the structure into this
 *       header so that you can use the structure as a building block.
 *
 *  The fields are as follows:
 *    leftlink -  A space filler.  This field will be accessed as Link[-1].
 *    Link     -  An array of pointers.  These pointers are manipulated by the
 *                BT and AVL routines, and indicate the left and right child
 *                nodes, plus the parent node.  By keeping track of the parent
 *                pointer, we avoid the need for recursive routines or hand-
 *                tooled stacks to keep track of our path back to the root.
 *                The use of these pointers is subject to change without
 *                notice.
 *    gender   -  For tree rebalancing purposes, it is necessary that each node
 *                know whether it is the left or right child of its parent, or
 *                if it is the root.  This information is stored in this field.
 *    balance  -  This field is also needed for AVL balancing purposes.  It
 *                indicates which subtree of the current node is longer, or if
 *                the subtrees are, in fact, balanced with respect to each
 *                other.
 *
 */

typedef struct ubi_avlNodeStruct
  {
  struct ubi_avlNodeStruct *leftlink;
  struct ubi_avlNodeStruct *Link[2];
  signed char               gender; 
  signed char               balance;
  } ubi_avlNode;

typedef ubi_avlNode *ubi_avlNodePtr;    /* a Pointer to an AVL node. */

/* -------------------------------------------------------------------------- **
 *  Function prototypes...
 */

ubi_avlNodePtr ubi_avlInitNode( ubi_avlNodePtr NodePtr );
  /* ------------------------------------------------------------------------ **
   * Initialize a tree node.
   *
   *  Input:   NodePtr  - a pointer to a ubi_btNode structure to be
   *                      initialized.
   *  Output:  a pointer to the initialized ubi_avlNode structure (ie. the
   *           same as the input pointer).
   * ------------------------------------------------------------------------ **
   */

ubi_trBool ubi_avlInsert( ubi_btRootPtr   RootPtr,
                          ubi_avlNodePtr  NewNode,
                          ubi_btItemPtr   ItemPtr,
                          ubi_avlNodePtr *OldNode );
  /* ------------------------------------------------------------------------ **
   * This function uses a non-recursive algorithm to add a new element to
   * the tree.
   *
   *  Input:   RootPtr  -  a pointer to the ubi_btRoot structure that indicates
   *                       the root of the tree to which NewNode is to be added.
   *           NewNode  -  a pointer to an ubi_avlNode structure that is NOT
   *                       part of any tree.
   *           ItemPtr  -  A pointer to the sort key that is stored within
   *                       *NewNode.  ItemPtr MUST point to information stored
   *                       in *NewNode or an EXACT DUPLICATE.  The key data
   *                       indicated by ItemPtr is used to place the new node
   *                       into the tree.
   *           OldNode  -  a pointer to an ubi_btNodePtr.  When searching
   *                       the tree, a duplicate node may be found.  If
   *                       duplicates are allowed, then the new node will
   *                       be simply placed into the tree.  If duplicates
   *                       are not allowed, however, then one of two things
   *                       may happen.
   *                       1) if overwritting *is not* allowed, this
   *                          function will return FALSE (indicating that
   *                          the new node could not be inserted), and
   *                          *OldNode will point to the duplicate that is
   *                          still in the tree.
   *                       2) if overwritting *is* allowed, then this
   *                          function will swap **OldNode for *NewNode.
   *                          In this case, *OldNode will point to the node
   *                          that was removed (thus allowing you to free
   *                          the node).
   *                          **  If you are using overwrite mode, ALWAYS  **
   *                          ** check the return value of this parameter! **
   *                 Note: You may pass NULL in this parameter, the
   *                       function knows how to cope.  If you do this,
   *                       however, there will be no way to return a
   *                       pointer to an old (ie. replaced) node (which is
   *                       a problem if you are using overwrite mode).
   *
   *  Output:  a boolean value indicating success or failure.  The function
   *           will return FALSE if the node could not be added to the tree.
   *           Such failure will only occur if duplicates are not allowed,
   *           nodes cannot be overwritten, AND a duplicate key was found
   *           within the tree.
   * ------------------------------------------------------------------------ **
   */

ubi_avlNodePtr ubi_avlRemove( ubi_btRootPtr  RootPtr,
                              ubi_avlNodePtr DeadNode );
  /* ------------------------------------------------------------------------ **
   * This function removes the indicated node from the tree, after which the
   * tree is rebalanced.
   *
   *  Input:  RootPtr  -  A pointer to the header of the tree that contains
   *                      the node to be removed.
   *          DeadNode -  A pointer to the node that will be removed.
   *
   *  Output: This function returns a pointer to the node that was removed
   *          from the tree (ie. the same as DeadNode).
   *
   *  Note:   The node MUST be in the tree indicated by RootPtr.  If not,
   *          strange and evil things will happen to your trees.
   * ------------------------------------------------------------------------ **
   */

int ubi_avlModuleID( int size, char *list[] );
  /* ------------------------------------------------------------------------ **
   * Returns a set of strings that identify the module.
   *
   *  Input:  size  - The number of elements in the array <list>.
   *          list  - An array of pointers of type (char *).  This array
   *                  should, initially, be empty.  This function will fill
   *                  in the array with pointers to strings.
   *  Output: The number of elements of <list> that were used.  If this value
   *          is less than <size>, the values of the remaining elements are
   *          not guaranteed.
   *
   *  Notes:  Please keep in mind that the pointers returned indicate strings
   *          stored in static memory.  Don't free() them, don't write over
   *          them, etc.  Just read them.
   * ------------------------------------------------------------------------ **
   */

/* -------------------------------------------------------------------------- **
 * Masquarade...
 *
 * This set of defines allows you to write programs that will use any of the
 * implemented binary tree modules (currently BinTree, AVLtree, and SplayTree).
 * Instead of using ubi_avl... or ubi_bt, use ubi_tr... and select the tree
 * type by including the appropriate module header.
 */

#undef ubi_trNode
#undef ubi_trNodePtr
#define ubi_trNode    ubi_avlNode
#define ubi_trNodePtr ubi_avlNodePtr

#undef ubi_trInitNode
#define ubi_trInitNode( Np ) ubi_avlInitNode( (ubi_avlNodePtr)(Np) )

#undef ubi_trInsert
#define ubi_trInsert( Rp, Nn, Ip, On ) \
        ubi_avlInsert( (ubi_btRootPtr)(Rp), (ubi_avlNodePtr)(Nn), \
                       (ubi_btItemPtr)(Ip), (ubi_avlNodePtr *)(On) )

#undef ubi_trRemove
#define ubi_trRemove( Rp, Dn ) \
        ubi_avlRemove( (ubi_btRootPtr)(Rp), (ubi_avlNodePtr)(Dn) )

#undef ubi_trLocate
#define ubi_trLocate( Rp, Ip, Op ) \
        (ubi_avlNodePtr)ubi_btLocate( (ubi_btRootPtr)(Rp), \
                                      (ubi_btItemPtr)(Ip), \
                                      (ubi_trCompOps)(Op) )

#undef ubi_trFind
#define ubi_trFind( Rp, Ip ) \
        (ubi_avlNodePtr)ubi_btFind( (ubi_btRootPtr)(Rp), (ubi_btItemPtr)(Ip) )

#undef ubi_trNext
#define ubi_trNext( P ) (ubi_avlNodePtr)ubi_btNext( (ubi_btNodePtr)(P) )

#undef ubi_trPrev
#define ubi_trPrev( P ) (ubi_avlNodePtr)ubi_btPrev( (ubi_btNodePtr)(P) )

#undef ubi_trFirst
#define ubi_trFirst( P ) (ubi_avlNodePtr)ubi_btFirst( (ubi_btNodePtr)(P) )

#undef ubi_trLast
#define ubi_trLast( P ) (ubi_avlNodePtr)ubi_btLast( (ubi_btNodePtr)(P) )

#undef ubi_trFirstOf
#define ubi_trFirstOf( Rp, Ip, P ) \
        (ubi_avlNodePtr)ubi_btFirstOf( (ubi_btRootPtr)(Rp), \
                       (ubi_btItemPtr)(Ip), \
                       (ubi_btNodePtr)(P) )

#undef ubi_trLastOf
#define ubi_trLastOf( Rp, Ip, P ) \
        (ubi_avlNodePtr)ubi_btLastOf( (ubi_btRootPtr)(Rp), \
                                      (ubi_btItemPtr)(Ip), \
                                      (ubi_btNodePtr)(P) )

#undef ubi_trLeafNode
#define ubi_trLeafNode( Nd ) \
        (ubi_avlNodePtr)ubi_btLeafNode( (ubi_btNodePtr)(Nd) )

#undef ubi_trModuleID
#define ubi_trModuleID( s, l ) ubi_avlModuleID( s, l )


/* =========================== End  ubi_AVLtree.h =========================== */
#endif /* ubi_AVLtree_H */
