/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998

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

#include "includes.h"

/* -------------------------------------------------------------------------- **
 * Discussion...
 *
 * This module implements WINS failover.
 *
 * Microsoft's WINS servers provide a feature called WINS replication,
 * which synchronises the WINS name databases between two or more servers. 
 * This means that the two servers can be used interchangably (more or
 * less). WINS replication is particularly useful if you are trying to
 * synchronise the WINS namespace between servers in remote locations, or
 * if your WINS servers tend to crash a lot. 
 *
 * WINS failover allows the client to 'switch' to a different WINS server
 * if the current WINS server mysteriously disappears.  On Windows
 * systems, this is typically represented as 'primary' and 'secondary'
 * WINS servers. 
 *
 * Failover only works if the WINS servers are synced.  If they are not,
 * then
 *   a) if the primary WINS server never fails the client will never 'see'
 *      the secondary (or tertiary or...) WINS server name space.
 *   b) if the primary *does* fail, the client will be entering an
 *      unfamiliar namespace.  The client itself will not be registered in
 *      that namespace and any names which match names in the previous
 *      space will likely resolve to different host IP addresses.
 *
 * One key thing to remember regarding WINS failover is that Samba does
 * not (yet) implement WINS replication.  For those interested, sniff port
 * 42 (TCP? UDP? ...dunno off hand) and see what two MS WINS servers do. 
 *
 * At this stage, only failover is implemented.  The next thing is to add
 * support for multi-WINS server registration and query
 * (multi-membership).
 *
 * Multi-membership is a little wierd.  The idea is that the client can
 * register itself with multiple non-replicated WINS servers, and query
 * all of those servers (in a prescribed sequence) to resolve a name. 
 *
 * The implications of multi-membership are not quite clear.  Worth
 * trying, I suppose.  Changes will be needed in the name query and
 * registration code to accomodate this feature.  Also, there will need to
 * be some sort of syntax extension for the 'wins server' parameter in
 * smb.conf.  I'm thinking that a colon could be used as a separator. 
 *
 * Of course, for each WINS namespace there might be multiple, synced WINS
 * servers.  The change to this module would likely be the addition of a
 * linked list of linked lists.
 *
 * crh@samba.org
 */

/* -------------------------------------------------------------------------- **
 * Defines... 
 *
 *   NECROMANCYCLE - The dead server retry period, in seconds.  When a WINS
 *                   server is declared dead, wait this many seconds before
 *                   attempting to communicate with it.
 */

#define NECROMANCYCLE 600   /* 600 seconds == 10 minutes. */

/* -------------------------------------------------------------------------- **
 * Typedefs...
 */

typedef struct
  {
  ubi_slNode node;      /* Linked list node structure.                        */
  time_t     mourning;  /* If greater than current time server is dead, Jim.  */
  char      *server;    /* DNS name or IP of NBNS server to query.            */
  } list_entry;

/* -------------------------------------------------------------------------- **
 * Private, static variables.
 */

static ubi_slNewList( wins_srv_list );

/* -------------------------------------------------------------------------- **
 * Functions...
 */


BOOL wins_srv_load_list( char *src )
  /* ------------------------------------------------------------------------ **
   * Create or recreate the linked list of failover WINS servers.
   */
  {
  list_entry   *entry;
  char         *p = src;
  pstring       wins_id_bufr;
  unsigned long count;

  /* Empty the list. */
  while( NULL != (entry =(list_entry *)ubi_slRemHead( wins_srv_list )) )
    {
    if( entry->server )
      free( entry->server );
    free( entry );
    }
  (void)ubi_slInitList( wins_srv_list );  /* shouldn't be needed */

  /* Parse out the DNS names or IP addresses of the WINS servers. */
  DEBUG( 4, ("wins_srv: Building WINS server list:\n") );
  while( next_token( &p, wins_id_bufr, LIST_SEP, sizeof( wins_id_bufr ) ) )
    {
    entry = (list_entry *)malloc( sizeof( list_entry ) );
    if( NULL == entry )
      {
      DEBUG( 0, ("wins_srv_load_list(): malloc(list_entry) failed.\n") );
      }
    else
      {
      entry->mourning = 0;
      if( NULL == (entry->server = strdup( wins_id_bufr )) )
        {
        free( entry );
        DEBUG( 0, ("wins_srv_load_list(): strdup(\"%s\") failed.\n", wins_id_bufr) );
        }
      else
        {
        /* Add server to list. */
        (void)ubi_slAddTail( wins_srv_list, entry );
        DEBUGADD( 4, ("\t\t%s,\n", wins_id_bufr) );
        }
      }
    }

  count = ubi_slCount( wins_srv_list );
  DEBUGADD( 4, ( "\t\t%d WINS server%s listed.\n", count, (1==count)?"":"s" ) );

  return( (count > 0) ? True : False );
  } /* wins_srv_load_list */


char *wins_srv( void )
  /* ------------------------------------------------------------------------ **
   */
  {
  time_t      now     = time(NULL);
  list_entry *entry   = (list_entry *)ubi_slFirst( wins_srv_list );
  list_entry *coldest = entry;

  /* Go through the list.  Look for the first live entry. */
  while( (NULL != entry) && (now < entry->mourning) )
    {
    entry = (list_entry *)ubi_slNext( entry );
    if( entry->mourning < coldest->mourning )
      coldest = entry;
    }

  /* If they were all dead, then return the one that's been dead longest. */
  if( NULL == entry )
    {
    entry = coldest;
    DEBUG( 4, ("wins_srv: All WINS servers appear to have failed.\n") );
    }

  /* The list could be empty.  Check it. */
  if( NULL == entry )
    return( NULL );
  return( entry->server );
  } /* wins_srv */


void wins_srv_died( char *boothill )
  /* ------------------------------------------------------------------------ **
   * Called to indicate that a specific WINS server has died.
   */
  {
  list_entry *entry = (list_entry *)ubi_slFirst( wins_srv_list );

  while( NULL != entry )
    {
    /* Match based on server ID [DNS name or IP]. */
    if( 0 == strcmp( boothill, entry->server ) )
      {
      entry->mourning = time(NULL) + NECROMANCYCLE;
      DEBUG( 2, ("wins_srv: WINS server %s appears to be down.\n", boothill) );
      return;
      }
    entry = (list_entry *)ubi_slNext( entry );
    }
  } /* wins_srv_died */


unsigned long wins_srv_count( void )
  /* ------------------------------------------------------------------------ **
   * Return the total number of entries in the list, dead or alive.
   */
  {
  return( ubi_slCount( wins_srv_list ) );
  } /* wins_srv_count */

/* ========================================================================== */
