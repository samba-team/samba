/* ========================================================================== **
 *                              ubi_AVLtree.c
 *
 *  Copyright (C) 1991-1997 by Christopher R. Hertel
 *
 *  Email: crh@ubiqx.mn.org
 * -------------------------------------------------------------------------- **
 *
 *  This module provides an implementation of AVL height balanced binary
 *  trees.  (Adelson-Velskii, Landis 1962)
 *
 *  This file implements the core of the height-balanced (AVL) tree management
 *  routines.  The header file, ubi_AVLtree.h, contains function prototypes
 *  for all "exported" functions.
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
 *
 * Log: ubi_AVLtree.c,v
 * Revision 2.5  1997/12/23 04:00:42  crh
 * In this version, all constants & macros defined in the header file have
 * the ubi_tr prefix.  Also cleaned up anything that gcc complained about
 * when run with '-pedantic -fsyntax-only -Wall'.
 *
 * Revision 2.4  1997/07/26 04:36:20  crh
 * Andrew Leppard, aka "Grazgur", discovered that I still had my brains tied
 * on backwards with respect to node deletion.  I did some more digging and
 * discovered that I was not changing the balance values correctly in the
 * single rotation functions.  Double rotation was working correctly because
 * the formula for changing the balance values is the same for insertion or
 * deletion.  Not so for single rotation.
 *
 * I have tested the fix by loading the tree with over 44 thousand names,
 * deleting 2,629 of them (all those in which the second character is 'u')
 * and then walking the tree recursively to verify that the balance factor of
 * each node is correct.  Passed.
 *
 * Thanks Andrew!
 *
 * Also:
 * + Changed ubi_TRUE and ubi_FALSE to ubi_trTRUE and ubi_trFALSE.
 * + Rewrote the ubi_tr<func> macros because they weren't doing what I'd
 *   hoped they would do (see the bottom of the header file).  They work now.
 *
 * Revision 2.3  1997/06/03 04:41:35  crh
 * Changed TRUE and FALSE to ubi_TRUE and ubi_FALSE to avoid causing
 * problems.
 *
 * Revision 2.2  1995/10/03 22:16:01  CRH
 * Ubisized!
 *
 * Revision 2.1  95/03/09  23:45:59  CRH
 * Added the ModuleID static string and function.  These modules are now
 * self-identifying.
 * 
 * Revision 2.0  95/03/05  14:10:51  CRH
 * This revision of ubi_AVLtree coincides with revision 2.0 of ubi_BinTree,
 * and so includes all of the changes to that module.  In addition, a bug in
 * the node deletion process has been fixed.
 *
 * After rewriting the Locate() function in ubi_BinTree, I decided that it was
 * time to overhaul this module.  In the process, I discovered a bug related
 * to node deletion.  To fix the bug, I wrote function Debalance().  A quick
 * glance will show that it is very similar to the Rebalance() function.  In
 * previous versions of this module, I tried to include the functionality of
 * Debalance() within Rebalance(), with poor results.
 *
 * Revision 1.0  93/10/15  22:58:56  CRH
 * With this revision, I have added a set of #define's that provide a single,
 * standard API to all existing tree modules.  Until now, each of the three
 * existing modules had a different function and typedef prefix, as follows:
 *
 *       Module        Prefix
 *     ubi_BinTree     ubi_bt
 *     ubi_AVLtree     ubi_avl
 *     ubi_SplayTree   ubi_spt
 *
 * To further complicate matters, only those portions of the base module
 * (ubi_BinTree) that were superceeded in the new module had the new names.
 * For example, if you were using ubi_AVLtree, the AVL node structure was
 * named "ubi_avlNode", but the root structure was still "ubi_btRoot".  Using
 * SplayTree, the locate function was called "ubi_sptLocate", but the next
 * and previous functions remained "ubi_btNext" and "ubi_btPrev".
 *
 * This was not too terrible if you were familiar with the modules and knew
 * exactly which tree model you wanted to use.  If you wanted to be able to
 * change modules (for speed comparisons, etc), things could get messy very
 * quickly.
 *
 * So, I have added a set of defined names that get redefined in any of the
 * descendant modules.  To use this standardized interface in your code,
 * simply replace all occurances of "ubi_bt", "ubi_avl", and "ubi_spt" with
 * "ubi_tr".  The "ubi_tr" names will resolve to the correct function or
 * datatype names for the module that you are using.  Just remember to
 * include the header for that module in your program file.  Because these
 * names are handled by the preprocessor, there is no added run-time
 * overhead.
 *
 * Note that the original names do still exist, and can be used if you wish
 * to write code directly to a specific module.  This should probably only be
 * done if you are planning to implement a new descendant type, such as
 * red/black trees.  CRH
 *
 *  V0.0 - May, 1990   -  Written by Christopher R. Hertel (CRH).
 *
 *  ========================================================================= **
 */

#include "ubi_AVLtree.h"            /* Header for THIS module.             */
#include <stdlib.h>                 /* Standard C definitions, etc.        */

/* ========================================================================== **
 * Static data.
 */

static char ModuleID[] = "ubi_AVLtree\n\
\tRevision: 2.5\n\
\tDate: 1997/12/23 04:00:42\n\
\tAuthor: crh\n";

/* ========================================================================== **
 * The next set of functions are the AVL balancing routines.  There are left
 * and right, single and double rotations.  The rotation routines handle the
 * rotations and reconnect all tree pointers that might get confused by the
 * rotations.  A pointer to the new subtree root node is returned.
 *
 * Note that L1 and R1 are identical, except that all the RIGHTs and LEFTs
 * are reversed.  The same is true for L2 and R2.  I'm sure that there is
 * a clever way to reduce the amount of code by combining these functions,
 * but it might involve additional overhead, and it would probably be a pain
 * to read, debug, etc.
 * -------------------------------------------------------------------------- **
 */

static ubi_avlNodePtr L1( ubi_avlNodePtr p )
  /* ------------------------------------------------------------------------ **
   * Single rotate left.
   *
   *  Input:  p - Pointer to the root of a tree (possibly a subtree).
   *  Output: A pointer to the new root of the same subtree (now that node
   *          p has been moved).
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_avlNodePtr tmp;

  tmp                      = p->Link[ubi_trRIGHT];
  p->Link[ubi_trRIGHT]     = tmp->Link[ubi_trLEFT];
  tmp->Link[ubi_trLEFT]    = p;

  tmp->Link[ubi_trPARENT]  = p->Link[ubi_trPARENT];
  tmp->gender              = p->gender;
  if(tmp->Link[ubi_trPARENT])
    (tmp->Link[ubi_trPARENT])->Link[(int)(tmp->gender)] = tmp;
  p->Link[ubi_trPARENT]    = tmp;
  p->gender                = ubi_trLEFT;
  if( p->Link[ubi_trRIGHT] )
    {
    p->Link[ubi_trRIGHT]->Link[ubi_trPARENT] = p;
    (p->Link[ubi_trRIGHT])->gender           = ubi_trRIGHT;
    }
  p->balance -= ubi_trNormalize( tmp->balance );
  (tmp->balance)--;
  return( tmp );
  } /* L1 */

static ubi_avlNodePtr R1( ubi_avlNodePtr p )
  /* ------------------------------------------------------------------------ **
   * Single rotate right.
   *
   *  Input:  p - Pointer to the root of a tree (possibly a subtree).
   *  Output: A pointer to the new root of the same subtree (now that node
   *          p has been moved).
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_avlNodePtr tmp;

  tmp                      = p->Link[ubi_trLEFT];
  p->Link[ubi_trLEFT]      = tmp->Link[ubi_trRIGHT];
  tmp->Link[ubi_trRIGHT]   = p;

  tmp->Link[ubi_trPARENT]  = p->Link[ubi_trPARENT];
  tmp->gender              = p->gender;
  if(tmp->Link[ubi_trPARENT])
    (tmp->Link[ubi_trPARENT])->Link[(int)(tmp->gender)] = tmp;
  p->Link[ubi_trPARENT]    = tmp;
  p->gender                = ubi_trRIGHT;
  if(p->Link[ubi_trLEFT])
    {
    p->Link[ubi_trLEFT]->Link[ubi_trPARENT]  = p;
    p->Link[ubi_trLEFT]->gender              = ubi_trLEFT;
    }
  p->balance -= ubi_trNormalize( tmp->balance );
  (tmp->balance)++;
  return( tmp );
  } /* R1 */

static ubi_avlNodePtr L2( ubi_avlNodePtr tree )
  /* ------------------------------------------------------------------------ **
   * Double rotate left.
   *
   *  Input:  p - Pointer to the root of a tree (possibly a subtree).
   *  Output: A pointer to the new root of the same subtree (now that node
   *          p has been moved).
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_avlNodePtr tmp, newroot;

  tmp                         = tree->Link[ubi_trRIGHT];
  newroot                     = tmp->Link[ubi_trLEFT];
  tmp->Link[ubi_trLEFT]       = newroot->Link[ubi_trRIGHT];
  newroot->Link[ubi_trRIGHT]  = tmp;
  tree->Link[ubi_trRIGHT]     = newroot->Link[ubi_trLEFT];
  newroot->Link[ubi_trLEFT]   = tree;

  newroot->Link[ubi_trPARENT] = tree->Link[ubi_trPARENT];
  newroot->gender             = tree->gender;
  tree->Link[ubi_trPARENT]    = newroot;
  tree->gender                = ubi_trLEFT;
  tmp->Link[ubi_trPARENT]     = newroot;
  tmp->gender                 = ubi_trRIGHT;

  if( tree->Link[ubi_trRIGHT] )
    {
    tree->Link[ubi_trRIGHT]->Link[ubi_trPARENT] = tree;
    tree->Link[ubi_trRIGHT]->gender             = ubi_trRIGHT;
    }
  if( tmp->Link[ubi_trLEFT] )
    {
    tmp->Link[ubi_trLEFT]->Link[ubi_trPARENT]   = tmp;
    tmp->Link[ubi_trLEFT]->gender               = ubi_trLEFT;
    }
  if(newroot->Link[ubi_trPARENT])
    newroot->Link[ubi_trPARENT]->Link[(int)(newroot->gender)] = newroot;

  switch( newroot->balance )
    {
    case ubi_trLEFT :
      tree->balance = ubi_trEQUAL; tmp->balance = ubi_trRIGHT; break;
    case ubi_trEQUAL:
      tree->balance = ubi_trEQUAL; tmp->balance = ubi_trEQUAL; break;
    case ubi_trRIGHT:
      tree->balance = ubi_trLEFT;  tmp->balance = ubi_trEQUAL; break;
    }
  newroot->balance = ubi_trEQUAL;
  return( newroot );
  } /* L2 */

static ubi_avlNodePtr R2( ubi_avlNodePtr tree )
  /* ------------------------------------------------------------------------ **
   * Double rotate right.
   *
   *  Input:  p - Pointer to the root of a tree (possibly a subtree).
   *  Output: A pointer to the new root of the same subtree (now that node
   *          p has been moved).
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_avlNodePtr tmp, newroot;

  tmp                         = tree->Link[ubi_trLEFT];
  newroot                     = tmp->Link[ubi_trRIGHT];
  tmp->Link[ubi_trRIGHT]      = newroot->Link[ubi_trLEFT];
  newroot->Link[ubi_trLEFT]   = tmp;
  tree->Link[ubi_trLEFT]      = newroot->Link[ubi_trRIGHT];
  newroot->Link[ubi_trRIGHT]  = tree;

  newroot->Link[ubi_trPARENT] = tree->Link[ubi_trPARENT];
  newroot->gender             = tree->gender;
  tree->Link[ubi_trPARENT]    = newroot;
  tree->gender                = ubi_trRIGHT;
  tmp->Link[ubi_trPARENT]     = newroot;
  tmp->gender                 = ubi_trLEFT;

  if( tree->Link[ubi_trLEFT] )
    {
    tree->Link[ubi_trLEFT]->Link[ubi_trPARENT]  = tree;
    tree->Link[ubi_trLEFT]->gender              = ubi_trLEFT;
    }
  if( tmp->Link[ubi_trRIGHT] )
    {
    tmp->Link[ubi_trRIGHT]->Link[ubi_trPARENT]  = tmp;
    tmp->Link[ubi_trRIGHT]->gender              = ubi_trRIGHT;
    }
  if(newroot->Link[ubi_trPARENT])
    newroot->Link[ubi_trPARENT]->Link[(int)(newroot->gender)] = newroot;

  switch( newroot->balance )
    {
    case ubi_trLEFT  :
      tree->balance = ubi_trRIGHT; tmp->balance = ubi_trEQUAL; break;
    case ubi_trEQUAL :
      tree->balance = ubi_trEQUAL; tmp->balance = ubi_trEQUAL; break;
    case ubi_trRIGHT :
      tree->balance = ubi_trEQUAL; tmp->balance = ubi_trLEFT;  break;
    }
  newroot->balance = ubi_trEQUAL;
  return( newroot );
  } /* R2 */


static ubi_avlNodePtr Adjust( ubi_avlNodePtr p, char LorR )
  /* ------------------------------------------------------------------------ **
   * Adjust the balance value at node *p.  If necessary, rotate the subtree
   * rooted at p.
   *
   *  Input:  p    -  A pointer to the node to be adjusted.  One of the
   *                  subtrees of this node has changed height, so the
   *                  balance value at this node must be adjusted, possibly
   *                  by rotating the tree at this node.
   *          LorR -  Indicates the TALLER subtree.
   *
   *  Output: A pointer to the (possibly new) root node of the subtree.
   *
   *  Notes:  This function may be called after a node has been added *or*
   *          deleted, so LorR indicates the TALLER subtree.
   * ------------------------------------------------------------------------ **
   */
  {
  if( p->balance != LorR )
    p->balance += ubi_trNormalize(LorR);
  else
    {
    char tallerbal;  /* Balance value of the root of the taller subtree of p. */

    tallerbal = p->Link[(int)LorR]->balance;
    if( ( ubi_trEQUAL == tallerbal ) || ( p->balance == tallerbal ) )
      p = ( (ubi_trLEFT==LorR) ? R1(p) : L1(p) );   /* single rotation */
    else
      p = ( (ubi_trLEFT==LorR) ? R2(p) : L2(p) );   /* double rotation */
    }
  return( p );
  } /* Adjust */

static ubi_avlNodePtr Rebalance( ubi_avlNodePtr Root,
                                 ubi_avlNodePtr subtree,
                                 char           LorR )
  /* ------------------------------------------------------------------------ **
   * Rebalance the tree following an insertion.
   *
   *  Input:  Root    - A pointer to the root node of the whole tree.
   *          subtree - A pointer to the node that has just gained a new
   *                    child.
   *          LorR    - Gender of the child that has just been gained.
   *
   *  Output: A pointer to the (possibly new) root of the AVL tree.
   *          Rebalancing the tree moves nodes around a bit, so the node
   *          that *was* the root, may not be the root when we're finished.
   *
   *  Notes:  Rebalance() must walk up the tree from where we are (which is
   *          where the latest change occurred), rebalancing the subtrees
   *          along the way.  The rebalancing operation can stop if the
   *          change at the current subtree root won't affect the rest of
   *          the tree.  In the case of an addition, if a subtree root's
   *          balance becomes EQUAL, then we know that the height of that
   *          subtree has not changed, so we can exit.
   * ------------------------------------------------------------------------ **
   */
  {
  while( subtree )
    {
    subtree = Adjust( subtree, LorR );
    if( ubi_trPARENT == subtree->gender )
      return( subtree );
    if( ubi_trEQUAL == subtree->balance )
      return( Root );
    LorR = subtree->gender;
    subtree = subtree->Link[ubi_trPARENT];
    }
  return( Root );
  } /* Rebalance */

static ubi_avlNodePtr Debalance( ubi_avlNodePtr Root,
                                 ubi_avlNodePtr subtree,
                                 char           LorR )
  /* ------------------------------------------------------------------------ **
   * Rebalance the tree following a deletion.
   *
   *  Input:  Root    - A pointer to the root node of the whole tree.
   *          subtree - A pointer to the node who's child has just "left the
   *                    nest".
   *          LorR    - Gender of the child that left.
   *
   *  Output: A pointer to the (possibly new) root of the AVL tree.
   *          Rebalancing the tree moves nodes around a bit, so the node
   *          that *was* the root, may not be the root when we're finished.
   *
   *  Notes:  Debalance() is subtly different from Rebalance() (above) in
   *          two respects.
   *            * When it calls Adjust(), it passes the *opposite* of LorR.
   *              This is because LorR, as passed into Debalance() indicates
   *              the shorter subtree.  As we move up the tree, LorR is
   *              assigned the gender of the node that we are leaving (i.e.,
   *              the subtree that we just rebalanced).
   *            * We know that a subtree has not changed height if the
   *              balance becomes LEFT or RIGHT.  This is the *opposite* of
   *              what happens in Rebalance().
   * ------------------------------------------------------------------------ **
   */
  {
  while( subtree )
    {
    subtree = Adjust( subtree, ubi_trRevWay(LorR) );
    if( ubi_trPARENT == subtree->gender )
      return( subtree );
    if( ubi_trEQUAL != subtree->balance )
      return( Root );
    LorR = subtree->gender;
    subtree = subtree->Link[ubi_trPARENT];
    }
  return( Root );
  } /* Debalance */


/* -------------------------------------------------------------------------- **
 * The next two functions are used for general tree manipulation.  They are
 * each slightly different from their ubi_BinTree counterparts.
 * -------------------------------------------------------------------------- **
 */

static void ReplaceNode( ubi_avlNodePtr *parent,
                         ubi_avlNodePtr  oldnode,
                         ubi_avlNodePtr  newnode )
  /* ------------------------------------------------------------------------ **
   * Remove node oldnode from the tree, replacing it with node newnode.
   *
   * Input:
   *  parent   - A pointer to he parent pointer of the node to be
   *             replaced.  <parent> may point to the Link[] field of
   *             a parent node, or it may indicate the root pointer at
   *             the top of the tree.
   *  oldnode  - A pointer to the node that is to be replaced.
   *  newnode  - A pointer to the node that is to be installed in the
   *             place of <*oldnode>.
   *
   * Notes:    Don't forget to free oldnode.
   *           The only difference between this function and the ubi_bt
   *           version is that the node size is sizeof( ubi_avlNode ), not
   *           sizeof( ubi_btNode ).
   * ------------------------------------------------------------------------ **
   */
  {
  register int i;
  register int avlNodeSize = sizeof( ubi_avlNode );

  for( i = 0; i < avlNodeSize; i++ )
    ((unsigned char *)newnode)[i] = ((unsigned char *)oldnode)[i];
  (*parent) = newnode;

  if(oldnode->Link[ubi_trLEFT ] )
    (oldnode->Link[ubi_trLEFT ])->Link[ubi_trPARENT] = newnode;
  if(oldnode->Link[ubi_trRIGHT] )
    (oldnode->Link[ubi_trRIGHT])->Link[ubi_trPARENT] = newnode;
  } /* ReplaceNode */

static void SwapNodes( ubi_btRootPtr  RootPtr,
                       ubi_avlNodePtr Node1,
                       ubi_avlNodePtr Node2 )
  /* ------------------------------------------------------------------------ **
   * This function swaps two nodes in the tree.  Node1 will take the place of
   * Node2, and Node2 will fill in the space left vacant by Node 1.
   *
   * Input:
   *  RootPtr  - pointer to the tree header structure for this tree.
   *  Node1    - \
   *              > These are the two nodes which are to be swapped.
   *  Node2    - /
   *
   * Notes:
   *  This function does a three step swap, using a dummy node as a place
   *  holder.  This function is used by ubi_avlRemove().
   *  The only difference between this function and its ubi_bt counterpart
   *  is that the nodes are ubi_avlNodes, not ubi_btNodes.
   * ------------------------------------------------------------------------ **
   */
  {
  ubi_avlNodePtr *Parent;
  ubi_avlNode     dummy;
  ubi_avlNodePtr  dummy_p = &dummy;

  if( Node1->Link[ubi_trPARENT] )
    Parent = &((Node1->Link[ubi_trPARENT])->Link[(int)(Node1->gender)]);
  else
    Parent = (ubi_avlNodePtr *)&(RootPtr->root);
  ReplaceNode( Parent, Node1, dummy_p );

  if( Node2->Link[ubi_trPARENT] )
    Parent = &((Node2->Link[ubi_trPARENT])->Link[(int)(Node2->gender)]);
  else
    Parent = (ubi_avlNodePtr *)&(RootPtr->root);
  ReplaceNode( Parent, Node2, Node1 );

  if( dummy_p->Link[ubi_trPARENT] )
    Parent = &((dummy_p->Link[ubi_trPARENT])->Link[(int)(dummy_p->gender)]);
  else
    Parent = (ubi_avlNodePtr *)&(RootPtr->root);
  ReplaceNode( Parent, dummy_p, Node2 );
  } /* SwapNodes */


/* ========================================================================== **
 *         Public, exported (ie. not static-ly declared) functions...
 * -------------------------------------------------------------------------- **
 */

ubi_avlNodePtr ubi_avlInitNode( ubi_avlNodePtr NodePtr )
  /* ------------------------------------------------------------------------ **
   * Initialize a tree node.
   *
   *  Input:   NodePtr  - pointer to a ubi_btNode structure to be
   *                      initialized.
   *  Output:  a pointer to the initialized ubi_avlNode structure (ie. the
   *           same as the input pointer).
   * ------------------------------------------------------------------------ **
   */
  {
  (void)ubi_btInitNode( (ubi_btNodePtr)NodePtr );
  NodePtr->balance = ubi_trEQUAL;
  return( NodePtr );
  } /* ubi_avlInitNode */

ubi_trBool ubi_avlInsert( ubi_btRootPtr   RootPtr,
                          ubi_avlNodePtr  NewNode,
                          ubi_btItemPtr   ItemPtr,
                          ubi_avlNodePtr *OldNode )
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
  {
  ubi_avlNodePtr OtherP;

  if( !(OldNode) ) OldNode = &OtherP;
  if( ubi_btInsert( RootPtr,
                    (ubi_btNodePtr)NewNode,
                    ItemPtr,
                    (ubi_btNodePtr *)OldNode ) )
    {
    if( (*OldNode) )
      NewNode->balance = (*OldNode)->balance;
    else
      {
      NewNode->balance = ubi_trEQUAL;
      RootPtr->root = (ubi_btNodePtr)Rebalance( (ubi_avlNodePtr)RootPtr->root,
                                                NewNode->Link[ubi_trPARENT],
                                                NewNode->gender );
      }
    return( ubi_trTRUE );
    }
  return( ubi_trFALSE );      /* Failure: could not replace an existing node. */
  } /* ubi_avlInsert */

ubi_avlNodePtr ubi_avlRemove( ubi_btRootPtr  RootPtr,
                              ubi_avlNodePtr DeadNode )
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
  {
  ubi_btNodePtr p,
               *parentp;

  /* if the node has both left and right subtrees, then we have to swap
   * it with another node.
   */
  if( (DeadNode->Link[ubi_trLEFT]) && (DeadNode->Link[ubi_trRIGHT]) )
    SwapNodes( RootPtr, DeadNode, ubi_trPrev( DeadNode ) );

  /* The parent of the node to be deleted may be another node, or it may be
   * the root of the tree.  Since we're not sure, it's best just to have
   * a pointer to the parent pointer, whatever it is.
   */
  if( DeadNode->Link[ubi_trPARENT] )
    parentp = (ubi_btNodePtr *)
              &((DeadNode->Link[ubi_trPARENT])->Link[(int)(DeadNode->gender)]);
  else
    parentp = &( RootPtr->root );

  /* Now link the parent to the only grand-child.  Patch up the gender and
   * such, and rebalance.
   */
  if( ubi_trEQUAL == DeadNode->balance )
    (*parentp) = NULL;
  else
    {
    p = (ubi_btNodePtr)(DeadNode->Link[(int)(DeadNode->balance)]);
    p->Link[ubi_trPARENT] = (ubi_btNodePtr)DeadNode->Link[ubi_trPARENT];
    p->gender  = DeadNode->gender;
    (*parentp) = p;
    }
  RootPtr->root = (ubi_btNodePtr)Debalance( (ubi_avlNodePtr)RootPtr->root,
                                            DeadNode->Link[ubi_trPARENT],
                                            DeadNode->gender );

  (RootPtr->count)--;
  return( DeadNode );
  } /* ubi_avlRemove */

int ubi_avlModuleID( int size, char *list[] )
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
  {
  if( size > 0 )
    {
    list[0] = ModuleID;
    if( size > 1 )
      return( 1 + ubi_btModuleID( --size, &(list[1]) ) );
    return( 1 );
    }
  return( 0 );
  } /* ubi_avlModuleID */

/* ============================== The End ============================== */
