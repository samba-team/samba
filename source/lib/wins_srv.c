/*
   Unix SMB/Netbios implementation.
   Version 2.
   Samba utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Christopher R. Hertel 2000

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
 * support for multi-WINS server registration and query (multi-membership).
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
  ubi_slNode     node;      /* Linked list node structure.                  */
  time_t         mourning;  /* If > current time then  server is dead, Jim. */
  char          *server;    /* DNS name or IP of NBNS server to query.      */
  struct in_addr ip_addr;   /* Cache translated IP.                         */
  } list_entry;

/* -------------------------------------------------------------------------- **
 * Private, static variables.
 */

static ubi_slNewList( wins_srv_list );

/* -------------------------------------------------------------------------- **
 * Functions...
 */


BOOL wins_srv_load_list( const char *src )
  /* ------------------------------------------------------------------------ **
   * Create or recreate the linked list of failover WINS servers.
   *
   *  Input:  src - String of DNS names and/or IP addresses delimited by the
   *                characters listed in LIST_SEP (see include/local.h).
   *
   *  Output: True if at least one name or IP could be parsed out of the
   *          list, else False.
   *
   *  Notes:  There is no syntax checking done on the names or IPs.  We do
   *          check to see if the field is an IP, in which case we copy it
   *          to the ip_addr field of the entry.  Don't bother to to a host
   *          name lookup on all names now.  They're done as needed in
   *          wins_srv_ip().
   */
  {
  list_entry   *entry;
  const char         *p = src;
  pstring       wins_id_bufr;
  unsigned long count;

  /* Empty the list. */
  while( NULL != (entry =(list_entry *)ubi_slRemHead( wins_srv_list )) )
    {
    SAFE_FREE( entry->server );
    SAFE_FREE( entry );
    }
  (void)ubi_slInitList( wins_srv_list );  /* shouldn't be needed */

  /* Parse out the DNS names or IP addresses of the WINS servers. */
  DEBUG( 4, ("wins_srv_load_list(): Building WINS server list:\n") );
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
        SAFE_FREE( entry );
        DEBUG( 0, ("wins_srv_load_list(): strdup(\"%s\") failed.\n", wins_id_bufr) );
        }
      else
        {
        /* Add server to list. */
        if( is_ipaddress( wins_id_bufr ) )
          entry->ip_addr = *interpret_addr2( wins_id_bufr );
        else
          entry->ip_addr = *interpret_addr2( "0.0.0.0" );
        (void)ubi_slAddTail( wins_srv_list, entry );
        DEBUGADD( 4, ("%s,\n", wins_id_bufr) );
        }
      }
    }

  count = ubi_slCount( wins_srv_list );
  DEBUGADD( 4, ( "%d WINS server%s listed.\n", (int)count, (1==count)?"":"s" ) );

  return( (count > 0) ? True : False );
  } /* wins_srv_load_list */


struct in_addr wins_srv_ip( void )
  /* ------------------------------------------------------------------------ **
   */
  {
  time_t      now     = time(NULL);
  list_entry *entry   = (list_entry *)ubi_slFirst( wins_srv_list );

  while( NULL != entry )
    {
    if( now >= entry->mourning )        /* Found a live one. */
      {
      /* If we don't have the IP, look it up. */
      if( is_zero_ip( entry->ip_addr ) )
        entry->ip_addr = *interpret_addr2( entry->server );

      /* If we still don't have the IP then kill it, else return it. */
      if( is_zero_ip( entry->ip_addr ) )
        entry->mourning = now + NECROMANCYCLE;
      else
        return( entry->ip_addr );
      }
    entry = (list_entry *)ubi_slNext( entry );
    }

  /* If there are no live entries, return the zero IP. */
  return( *interpret_addr2( "0.0.0.0" ) );
  } /* wins_srv_ip */


void wins_srv_died( struct in_addr boothill_ip )
  /* ------------------------------------------------------------------------ **
   * Called to indicate that a specific WINS server has died.
   */
  {
  list_entry *entry;

  if( is_zero_ip( boothill_ip ) )
    {
    DEBUG( 4, ("wins_srv_died(): Got request to mark zero IP down.\n") );
    return;
    }

  entry = (list_entry *)ubi_slFirst( wins_srv_list );
  while( NULL != entry )
    {
    /* Match based on IP. */
    if( ip_equal( boothill_ip, entry->ip_addr ) )
      {
      entry->mourning = time(NULL) + NECROMANCYCLE;
      entry->ip_addr.s_addr = 0;  /* Force a re-lookup at re-birth. */
      DEBUG( 2, ( "wins_srv_died(): WINS server %s appears to be down.\n", 
                  entry->server ) );
      return;
      }
    entry = (list_entry *)ubi_slNext( entry );
    }

  if( DEBUGLVL( 1 ) )
    {
    dbgtext( "wins_srv_died(): Could not mark WINS server %s down.\n",
              inet_ntoa( boothill_ip ) );
    dbgtext( "Address not found in server list.\n" );
    }
  } /* wins_srv_died */


unsigned long wins_srv_count( void )
  /* ------------------------------------------------------------------------ **
   * Return the total number of entries in the list, dead or alive.
   */
  {
  unsigned long count = ubi_slCount( wins_srv_list );

  if( DEBUGLVL( 8 ) )
    {
    list_entry *entry = (list_entry *)ubi_slFirst( wins_srv_list );
    time_t      now   = time(NULL);

    dbgtext( "wins_srv_count: WINS status: %ld servers.\n", count );
    while( NULL != entry )
      {
      dbgtext( "  %s <%s>: ", entry->server, inet_ntoa( entry->ip_addr ) );
      if( now >= entry->mourning )
        dbgtext( "alive\n" );
      else
        dbgtext( "dead for %d more seconds\n", (int)(entry->mourning - now) );

      entry = (list_entry *)ubi_slNext( entry );
      }
    }

  return( count );
  } /* wins_srv_count */

/* ========================================================================== */
