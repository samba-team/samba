/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   stat cache code
   Copyright (C) Andrew Tridgell 1992-2000
   Copyright (C) Jeremy Allison 1999-2000
   
   
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

extern BOOL case_sensitive;


/****************************************************************************
 Stat cache code used in unix_convert.
*****************************************************************************/

typedef struct {
  int name_len;
  char names[2]; /* This is extended via malloc... */
} stat_cache_entry;

#define INIT_STAT_CACHE_SIZE 512
static hash_table stat_cache;

/****************************************************************************
 Add an entry into the stat cache.
*****************************************************************************/

void stat_cache_add( char *full_orig_name, char *orig_translated_path)
{
  stat_cache_entry *scp;
  stat_cache_entry *found_scp;
  pstring orig_name;
  pstring translated_path;
  int namelen;
  hash_element *hash_elem;

  if (!lp_stat_cache()) return;

  namelen = strlen(orig_translated_path);

  /*
   * Don't cache trivial valid directory entries.
   */
  if((*full_orig_name == '\0') || (strcmp(full_orig_name, ".") == 0) ||
     (strcmp(full_orig_name, "..") == 0))
    return;

  /*
   * If we are in case insentive mode, we need to
   * store names that need no translation - else, it
   * would be a waste.
   */

  if(case_sensitive && (strcmp(full_orig_name, orig_translated_path) == 0))
    return;

  /*
   * Remove any trailing '/' characters from the
   * translated path.
   */

  pstrcpy(translated_path, orig_translated_path);
  if(translated_path[namelen-1] == '/') {
    translated_path[namelen-1] = '\0';
    namelen--;
  }

  /*
   * We will only replace namelen characters 
   * of full_orig_name.
   * StrnCpy always null terminates.
   */

  StrnCpy(orig_name, full_orig_name, MIN(namelen, sizeof(orig_name)-1));
  if(!case_sensitive)
    strupper( orig_name );

  /*
   * Check this name doesn't exist in the cache before we 
   * add it.
   */

  if ((hash_elem = hash_lookup(&stat_cache, orig_name))) {
    found_scp = (stat_cache_entry *)(hash_elem->value);
    if (strcmp((found_scp->names+found_scp->name_len+1), translated_path) == 0) {
      return;
    } else {
      hash_remove(&stat_cache, hash_elem);
      if((scp = (stat_cache_entry *)malloc(sizeof(stat_cache_entry)+2*namelen)) == NULL) {
        DEBUG(0,("stat_cache_add: Out of memory !\n"));
        return;
      }
      pstrcpy(scp->names, orig_name);
      pstrcpy((scp->names+namelen+1), translated_path);
      scp->name_len = namelen;
      hash_insert(&stat_cache, (char *)scp, orig_name);
    }
    return;
  } else {

    /*
     * New entry.
     */

    if((scp = (stat_cache_entry *)malloc(sizeof(stat_cache_entry)+2*namelen)) == NULL) {
      DEBUG(0,("stat_cache_add: Out of memory !\n"));
      return;
    }
    pstrcpy(scp->names, orig_name);
    pstrcpy(scp->names+namelen+1, translated_path);
    scp->name_len = namelen;
    hash_insert(&stat_cache, (char *)scp, orig_name);
  }

  DEBUG(5,("stat_cache_add: Added entry %s -> %s\n", scp->names, (scp->names+scp->name_len+1)));
}

/****************************************************************************
 Look through the stat cache for an entry - promote it to the top if found.
 Return True if we translated (and did a scuccessful stat on) the entire name.
*****************************************************************************/

BOOL stat_cache_lookup(connection_struct *conn, char *name, char *dirpath, 
		       char **start, SMB_STRUCT_STAT *pst)
{
  stat_cache_entry *scp;
  char *trans_name;
  pstring chk_name;
  int namelen;
  hash_element *hash_elem;
  char *sp;

  if (!lp_stat_cache())
    return False;
 
  namelen = strlen(name);

  *start = name;

  DO_PROFILE_INC(statcache_lookups);

  /*
   * Don't lookup trivial valid directory entries.
   */
  if((*name == '\0') || (strcmp(name, ".") == 0) || (strcmp(name, "..") == 0)) {
    DO_PROFILE_INC(statcache_misses);
    return False;
  }

  pstrcpy(chk_name, name);
  if(!case_sensitive)
    strupper( chk_name );

  while (1) {
    hash_elem = hash_lookup(&stat_cache, chk_name);
    if(hash_elem == NULL) {
      /*
       * Didn't find it - remove last component for next try.
       */
      sp = strrchr(chk_name, '/');
      if (sp) {
        *sp = '\0';
      } else {
        /*
         * We reached the end of the name - no match.
         */
	DO_PROFILE_INC(statcache_misses);
        return False;
      }
      if((*chk_name == '\0') || (strcmp(chk_name, ".") == 0)
                          || (strcmp(chk_name, "..") == 0)) {
	DO_PROFILE_INC(statcache_misses);
        return False;
      }
    } else {
      scp = (stat_cache_entry *)(hash_elem->value);
      DO_PROFILE_INC(statcache_hits);
      trans_name = scp->names+scp->name_len+1;
      if(vfs_stat(conn,trans_name, pst) != 0) {
        /* Discard this entry - it doesn't exist in the filesystem.  */
        hash_remove(&stat_cache, hash_elem);
        return False;
      }
      memcpy(name, trans_name, scp->name_len);
      *start = &name[scp->name_len];
      if(**start == '/')
        ++*start;
      StrnCpy( dirpath, trans_name, name - (*start));
      return (namelen == scp->name_len);
    }
  }
}

/*************************************************************************** **
 * Initializes or clears the stat cache.
 *
 *  Input:  none.
 *  Output: none.
 *
 * ************************************************************************** **
 */
BOOL reset_stat_cache( void )
{
	static BOOL initialised;
	if (!lp_stat_cache()) return True;

	if (initialised) {
		hash_clear(&stat_cache);
	}

	initialised = hash_table_init( &stat_cache, INIT_STAT_CACHE_SIZE, 
				       (compare_function)(strcmp));
	return initialised;
} /* reset_stat_cache  */
