/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Name mangling
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

/* -------------------------------------------------------------------------- **
 * Notable problems...
 *
 *  March/April 1998  CRH
 *  - Many of the functions in this module overwrite string buffers passed to
 *    them.  This causes a variety of problems and is, generally speaking,
 *    dangerous and scarry.  See the kludge notes in name_map_mangle()
 *    below.
 *  - It seems that something is calling name_map_mangle() twice.  The
 *    first call is probably some sort of test.  Names which contain
 *    illegal characters are being doubly mangled.  I'm not sure, but
 *    I'm guessing the problem is in server.c.
 *
 * -------------------------------------------------------------------------- **
 */

/* -------------------------------------------------------------------------- **
 * History...
 *
 *  March/April 1998  CRH
 *  Updated a bit.  Rewrote is_mangled() to be a bit more selective.
 *  Rewrote the mangled name cache.  Added comments here and there.
 *  &c.
 * -------------------------------------------------------------------------- **
 */

#include "includes.h"


/* -------------------------------------------------------------------------- **
 * External Variables...
 */

extern int case_default;    /* Are conforming 8.3 names all upper or lower?   */
extern BOOL case_mangle;    /* If true, all chars in 8.3 should be same case. */

/* -------------------------------------------------------------------------- **
 * Other stuff...
 *
 * magic_char     - This is the magic char used for mangling.  It's
 *                  global.  There is a call to lp_magicchar() in server.c
 *                  that is used to override the initial value.
 *
 * MANGLE_BASE    - This is the number of characters we use for name mangling.
 *
 * basechars      - The set characters used for name mangling.  This
 *                  is static (scope is this file only).
 *
 * mangle()       - Macro used to select a character from basechars (i.e.,
 *                  mangle(n) will return the nth digit, modulo MANGLE_BASE).
 *
 * chartest       - array 0..255.  The index range is the set of all possible
 *                  values of a byte.  For each byte value, the content is a
 *                  two nibble pair.  See BASECHAR_MASK and ILLEGAL_MASK,
 *                  below.
 *
 * ct_initialized - False until the chartest array has been initialized via
 *                  a call to init_chartest().
 *
 * BASECHAR_MASK  - Masks the upper nibble of a one-byte value.
 *
 * ILLEGAL_MASK   - Masks the lower nibble of a one-byte value.
 *
 * isbasecahr()   - Given a character, check the chartest array to see
 *                  if that character is in the basechars set.  This is
 *                  faster than using strchr_m().
 *
 * isillegal()    - Given a character, check the chartest array to see
 *                  if that character is in the illegal characters set.
 *                  This is faster than using strchr_m().
 *
 * mangled_cache  - Cache header used for storing mangled -> original
 *                  reverse maps.
 *
 * mc_initialized - False until the mangled_cache structure has been
 *                  initialized via a call to reset_mangled_cache().
 *
 * MANGLED_CACHE_MAX_ENTRIES - Default maximum number of entries for the
 *                  cache.  A value of 0 indicates "infinite".
 *
 * MANGLED_CACHE_MAX_MEMORY  - Default maximum amount of memory for the
 *                  cache.  When the cache was kept as an array of 256
 *                  byte strings, the default cache size was 50 entries.
 *                  This required a fixed 12.5Kbytes of memory.  The
 *                  mangled stack parameter is no longer used (though
 *                  this might change).  We're now using a fixed 16Kbyte
 *                  maximum cache size.  This will probably be much more
 *                  than 50 entries.
 */

char magic_char = '~';

static char basechars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-!@#$%";
#define MANGLE_BASE       ( (sizeof(basechars)/sizeof(char)) - 1 )

static unsigned char chartest[256]  = { 0 };
static BOOL          ct_initialized = False;

#define mangle(V) ((char)(basechars[(V) % MANGLE_BASE]))
#define BASECHAR_MASK 0xf0
#define ILLEGAL_MASK  0x0f
#define isbasechar(C) ( (chartest[ ((C) & 0xff) ]) & BASECHAR_MASK )
#define isillegal(C) ( (chartest[ ((C) & 0xff) ]) & ILLEGAL_MASK )

static ubi_cacheRoot mangled_cache[1] = {{ { 0, 0, 0, 0 }, 0, 0, 0, 0, 0, 0 }};
static BOOL          mc_initialized   = False;
#define MANGLED_CACHE_MAX_ENTRIES 0
#define MANGLED_CACHE_MAX_MEMORY  16384


/* -------------------------------------------------------------------------- **
 * Functions...
 */

/* ************************************************************************** **
 * Initialize the static character test array.
 *
 *  Input:  none
 *
 *  Output: none
 *
 *  Notes:  This function changes (loads) the contents of the <chartest>
 *          array.  The scope of <chartest> is this file.
 *
 * ************************************************************************** **
 */
static void init_chartest( void )
  {
  char          *illegalchars = "*\\/?<>|\":";
  unsigned char *s;
  
  memset( (char *)chartest, '\0', 256 );

  for( s = (unsigned char *)illegalchars; *s; s++ )
    chartest[*s] = ILLEGAL_MASK;

  for( s = (unsigned char *)basechars; *s; s++ )
    chartest[*s] |= BASECHAR_MASK;

  ct_initialized = True;
  } /* init_chartest */

/* ************************************************************************** **
 * Return True if a name is a special msdos reserved name.
 *
 *  Input:  fname - String containing the name to be tested.
 *
 *  Output: True, if the name matches one of the list of reserved names.
 *
 *  Notes:  This is a static function called by is_8_3(), below.
 *
 * ************************************************************************** **
 */
static BOOL is_reserved_msdos( char *fname )
  {
  char upperFname[13];
  char *p;

  StrnCpy (upperFname, fname, 12);

  /* lpt1.txt and con.txt etc are also illegal */
  p = strchr_m(upperFname,'.');
  if( p )
    *p = '\0';

  strupper( upperFname );
  p = upperFname + 1;
  switch( upperFname[0] )
    {
    case 'A':
      if( 0 == strcmp( p, "UX" ) )
        return( True );
      break;
    case 'C':
      if( (0 == strcmp( p, "LOCK$" ))
       || (0 == strcmp( p, "ON" ))
       || (0 == strcmp( p, "OM1" ))
       || (0 == strcmp( p, "OM2" ))
       || (0 == strcmp( p, "OM3" ))
       || (0 == strcmp( p, "OM4" ))
        )
        return( True );
      break;
    case 'L':
      if( (0 == strcmp( p, "PT1" ))
       || (0 == strcmp( p, "PT2" ))
       || (0 == strcmp( p, "PT3" ))
        )
        return( True );
      break;
    case 'N':
      if( 0 == strcmp( p, "UL" ) )
        return( True );
      break;
    case 'P':
      if( 0 == strcmp( p, "RN" ) )
        return( True );
      break;
    }

  return( False );
  } /* is_reserved_msdos */

/* ************************************************************************** **
 * Determine whether or not a given name contains illegal characters, even
 * long names.
 *
 *  Input:  name  - The name to be tested.
 *
 *  Output: True if an illegal character was found in <name>, else False.
 *
 *  Notes:  This is used to test a name on the host system, long or short,
 *          for characters that would be illegal on most client systems,
 *          particularly DOS and Windows systems.  Unix and AmigaOS, for
 *          example, allow a filenames which contain such oddities as
 *          quotes (").  If a name is found which does contain an illegal
 *          character, it is mangled even if it conforms to the 8.3
 *          format.
 *
 * ************************************************************************** **
 */
static BOOL is_illegal_name( char *name )
  {
  unsigned char *s;

  if( !name )
    return( True );

  if( !ct_initialized )
    init_chartest();

  s = (unsigned char *)name;
  while( *s )
    {
      if( *s>0x7F && isillegal( *s ) )
        return( True );
      else
        s++;
    }

  return( False );
  } /* is_illegal_name */

/* ************************************************************************** **
 * Return True if the name *could be* a mangled name.
 *
 *  Input:  s - A path name - in UNIX pathname format.
 *
 *  Output: True if the name matches the pattern described below in the
 *          notes, else False.
 *
 *  Notes:  The input name is *not* tested for 8.3 compliance.  This must be
 *          done separately.  This function returns true if the name contains
 *          a magic character followed by excactly two characters from the
 *          basechars list (above), which in turn are followed either by the
 *          nul (end of string) byte or a dot (extension) or by a '/' (end of
 *          a directory name).
 *
 * ************************************************************************** **
 */
BOOL is_mangled( char *s )
  {
  char *magic;

  if( !ct_initialized )
    init_chartest();

  magic = strchr_m( s, magic_char );
  while( magic && magic[1] && magic[2] )          /* 3 chars, 1st is magic. */
    {
    if( ('.' == magic[3] || '/' == magic[3] || !(magic[3]))          /* Ends with '.' or nul or '/' ?  */
     && isbasechar( toupper(magic[1]) )           /* is 2nd char basechar?  */
     && isbasechar( toupper(magic[2]) ) )         /* is 3rd char basechar?  */
      return( True );                           /* If all above, then true, */
    magic = strchr_m( magic+1, magic_char );      /*    else seek next magic. */
    }
  return( False );
  } /* is_mangled */

/* ************************************************************************** **
 * Return True if the name is a valid DOS name in 8.3 DOS format.
 *
 *  Input:  fname       - File name to be checked.
 *          check_case  - If True, and if case_mangle is True, then the
 *                        name will be checked to see if all characters
 *                        are the correct case.  See case_mangle and
 *                        case_default above.
 *
 *  Output: True if the name is a valid DOS name, else FALSE.
 *
 * ************************************************************************** **
 */
BOOL is_8_3( char *fname, BOOL check_case )
  {
  int   len;
  int   l;
  char *p;
  char *dot_pos;
  char *slash_pos = strrchr_m( fname, '/' );

  /* If there is a directory path, skip it. */
  if( slash_pos )
    fname = slash_pos + 1;
  len = strlen( fname );

  DEBUG( 5, ( "Checking %s for 8.3\n", fname ) );

  /* Can't be 0 chars or longer than 12 chars */
  if( (len == 0) || (len > 12) )
    return( False );

  /* Mustn't be an MS-DOS Special file such as lpt1 or even lpt1.txt */
  if( is_reserved_msdos( fname ) )
    return( False );

  /* Check that all characters are the correct case, if asked to do so. */
  if( check_case && case_mangle )
    {
    switch( case_default )
      {
      case CASE_LOWER:
        if( strhasupper( fname ) )
          return(False);
        break;
      case CASE_UPPER:
        if( strhaslower( fname ) )
          return(False);
        break;
      }
    }

  /* Can't contain invalid dos chars */
  /* Windows use the ANSI charset.
     But filenames are translated in the PC charset.
     This Translation may be more or less relaxed depending
     the Windows application. */

  /* %%% A nice improvment to name mangling would be to translate
     filename to ANSI charset on the smb server host */

  p       = fname;
  dot_pos = NULL;
  while( *p )
    {
      if( *p == '.' && !dot_pos )
        dot_pos = (char *)p;
      /*else
        if( !isdoschar( *p ) )
          return( False );*/
      p++;
    }

  /* no dot and less than 9 means OK */
  if( !dot_pos )
    return( len <= 8 );
        
  l = PTR_DIFF( dot_pos, fname );

  /* base must be at least 1 char except special cases . and .. */
  if( l == 0 )
    return( 0 == strcmp( fname, "." ) || 0 == strcmp( fname, ".." ) );

  /* base can't be greater than 8 */
  if( l > 8 )
    return( False );

  /* see smb.conf(5) for a description of the 'strip dot' parameter. */
  if( lp_strip_dot()
   && len - l == 1
   && !strchr_m( dot_pos + 1, '.' ) )
    {
    *dot_pos = 0;
    return( True );
    }

  /* extension must be between 1 and 3 */
  if( (len - l < 2 ) || (len - l > 4) )
    return( False );

  /* extensions may not have a dot */
  if( strchr_m( dot_pos+1, '.' ) )
    return( False );

  /* must be in 8.3 format */
  return( True );
  } /* is_8_3 */


/* ************************************************************************** **
 * Compare two cache keys and return a value indicating their ordinal
 * relationship.
 *
 *  Input:  ItemPtr - Pointer to a comparison key.  In this case, this will
 *                    be a mangled name string.
 *          NodePtr - Pointer to a node in the cache.  The node structure
 *                    will be followed in memory by a mangled name string.
 *
 *  Output: A signed integer, as follows:
 *            (x < 0)  <==> Key1 less than Key2
 *            (x == 0) <==> Key1 equals Key2
 *            (x > 0)  <==> Key1 greater than Key2
 *
 *  Notes:  This is a ubiqx-style comparison routine.  See ubi_BinTree for
 *          more info.
 *
 * ************************************************************************** **
 */
static signed int cache_compare( ubi_btItemPtr ItemPtr, ubi_btNodePtr NodePtr )
  {
  char *Key1 = (char *)ItemPtr;
  char *Key2 = (char *)(((ubi_cacheEntryPtr)NodePtr) + 1);

  return( StrCaseCmp( Key1, Key2 ) );
  } /* cache_compare */

/* ************************************************************************** **
 * Free a cache entry.
 *
 *  Input:  WarrenZevon - Pointer to the entry that is to be returned to
 *                        Nirvana.
 *  Output: none.
 *
 *  Notes:  This function gets around the possibility that the standard
 *          free() function may be implemented as a macro, or other evil
 *          subversions (oh, so much fun).
 *
 * ************************************************************************** **
 */
static void cache_free_entry( ubi_trNodePtr WarrenZevon )
  {
	  ZERO_STRUCTP(WarrenZevon);
	  SAFE_FREE( WarrenZevon );
  } /* cache_free_entry */

/* ************************************************************************** **
 * Initializes or clears the mangled cache.
 *
 *  Input:  none.
 *  Output: none.
 *
 *  Notes:  There is a section below that is commented out.  It shows how
 *          one might use lp_ calls to set the maximum memory and entry size
 *          of the cache.  You might also want to remove the constants used
 *          in ubi_cacheInit() and replace them with lp_ calls.  If so, then
 *          the calls to ubi_cacheSetMax*() would be moved into the else
 *          clause.  Another option would be to pass in the max_entries and
 *          max_memory values as parameters.  crh 09-Apr-1998.
 *
 * ************************************************************************** **
 */
void reset_mangled_cache( void )
  {
  if( !mc_initialized )
    {
    (void)ubi_cacheInit( mangled_cache,
                         cache_compare,
                         cache_free_entry,
                         MANGLED_CACHE_MAX_ENTRIES,
                         MANGLED_CACHE_MAX_MEMORY );
    mc_initialized = True;
    }
  else
    {
    (void)ubi_cacheClear( mangled_cache );
    }

  /*
  (void)ubi_cacheSetMaxEntries( mangled_cache, lp_mangled_cache_entries() );
  (void)ubi_cacheSetMaxMemory(  mangled_cache, lp_mangled_cache_memory() );
  */
  } /* reset_mangled_cache  */


/* ************************************************************************** **
 * Add a mangled name into the cache.
 *
 *  Notes:  If the mangled cache has not been initialized, then the
 *          function will simply fail.  It could initialize the cache,
 *          but that's not the way it was done before I changed the
 *          cache mechanism, so I'm sticking with the old method.
 *
 *          If the extension of the raw name maps directly to the
 *          extension of the mangled name, then we'll store both names
 *          *without* extensions.  That way, we can provide consistent
 *          reverse mangling for all names that match.  The test here is
 *          a bit more careful than the one done in earlier versions of
 *          mangle.c:
 *
 *            - the extension must exist on the raw name,
 *            - it must be all lower case
 *            - it must match the mangled extension (to prove that no
 *              mangling occurred).
 *
 *  crh 07-Apr-1998
 *
 * ************************************************************************** **
 */
static void cache_mangled_name( char *mangled_name, char *raw_name )
  {
  ubi_cacheEntryPtr new_entry;
  char             *s1;
  char             *s2;
  size_t               mangled_len;
  size_t               raw_len;
  size_t               i;

  /* If the cache isn't initialized, give up. */
  if( !mc_initialized )
    return;

  /* Init the string lengths. */
  mangled_len = strlen( mangled_name );
  raw_len     = strlen( raw_name );

  /* See if the extensions are unmangled.  If so, store the entry
   * without the extension, thus creating a "group" reverse map.
   */
  s1 = strrchr_m( mangled_name, '.' );
  if( s1 && (s2 = strrchr_m( raw_name, '.' )) )
    {
    i = 1;
    while( s1[i] && (tolower( s1[1] ) == s2[i]) )
      i++;
    if( !s1[i] && !s2[i] )
      {
      mangled_len -= i;
      raw_len     -= i;
      }
    }

  /* Allocate a new cache entry.  If the allocation fails, just return. */
  i = sizeof( ubi_cacheEntry ) + mangled_len + raw_len + 2;
  new_entry = malloc( i );
  if( !new_entry )
    return;

  /* Fill the new cache entry, and add it to the cache. */
  s1 = (char *)(new_entry + 1);
  s2 = (char *)&(s1[mangled_len + 1]);
  (void)StrnCpy( s1, mangled_name, mangled_len );
  (void)StrnCpy( s2, raw_name,     raw_len );
  ubi_cachePut( mangled_cache, i, new_entry, s1 );
  } /* cache_mangled_name */

/* ************************************************************************** **
 * Check for a name on the mangled name stack
 *
 *  Input:  s - Input *and* output string buffer.
 *
 *  Output: True if the name was found in the cache, else False.
 *
 *  Notes:  If a reverse map is found, the function will overwrite the string
 *          space indicated by the input pointer <s>.  This is frightening.
 *          It should be rewritten to return NULL if the long name was not
 *          found, and a pointer to the long name if it was found.
 *
 * ************************************************************************** **
 */

BOOL check_mangled_cache( char *s )
{
  ubi_cacheEntryPtr FoundPtr;
  char             *ext_start = NULL;
  char             *found_name;
  char             *saved_ext = NULL;

  /* If the cache isn't initialized, give up. */
  if( !mc_initialized )
    return( False );

  FoundPtr = ubi_cacheGet( mangled_cache, (ubi_trItemPtr)s );

  /* If we didn't find the name *with* the extension, try without. */
  if( !FoundPtr )
  {
    ext_start = strrchr_m( s, '.' );
    if( ext_start )
    {
      if((saved_ext = strdup(ext_start)) == NULL)
        return False;

      *ext_start = '\0';
      FoundPtr = ubi_cacheGet( mangled_cache, (ubi_trItemPtr)s );
      /* 
       * At this point s is the name without the
       * extension. We re-add the extension if saved_ext
       * is not null, before freeing saved_ext.
       */
    }
  }

  /* Okay, if we haven't found it we're done. */
  if( !FoundPtr )
  {
    if(saved_ext)
    {
      /* Replace the saved_ext as it was truncated. */
      (void)pstrcat( s, saved_ext );
      SAFE_FREE(saved_ext);
    }
    return( False );
  }

  /* If we *did* find it, we need to copy it into the string buffer. */
  found_name = (char *)(FoundPtr + 1);
  found_name += (strlen( found_name ) + 1);

  DEBUG( 3, ("Found %s on mangled stack ", s) );

  (void)pstrcpy( s, found_name );
  if( saved_ext )
  {
    /* Replace the saved_ext as it was truncated. */
    (void)pstrcat( s, saved_ext );
    SAFE_FREE(saved_ext);
  }

  DEBUG( 3, ("as %s\n", s) );

  return( True );
} /* check_mangled_cache */


/* ************************************************************************** **
 * Used only in do_fwd_mangled_map(), below.
 * ************************************************************************** **
 */
static char *map_filename( char *s,         /* This is null terminated */
                           char *pattern,   /* This isn't. */
                           int len )        /* This is the length of pattern. */
  {
  static pstring matching_bit;  /* The bit of the string which matches */
                                /* a * in pattern if indeed there is a * */
  char *sp;                     /* Pointer into s. */
  char *pp;                     /* Pointer into p. */
  char *match_start;            /* Where the matching bit starts. */
  pstring pat;

  StrnCpy( pat, pattern, len ); /* Get pattern into a proper string! */
  pstrcpy( matching_bit, "" );  /* Match but no star gets this. */
  pp = pat;                     /* Initialize the pointers. */
  sp = s;

  if( strequal(s, ".") || strequal(s, ".."))
    {
    return NULL;                /* Do not map '.' and '..' */
    }

  if( (len == 1) && (*pattern == '*') )
    {
    return NULL;                /* Impossible, too ambiguous for */
    }                           /* words! */

  while( (*sp)                  /* Not the end of the string. */
      && (*pp)                  /* Not the end of the pattern. */
      && (*sp == *pp)           /* The two match. */
      && (*pp != '*') )         /* No wildcard. */
    {
    sp++;                       /* Keep looking. */
    pp++;
    }

  if( !*sp && !*pp )            /* End of pattern. */
    return( matching_bit );     /* Simple match.  Return empty string. */

  if( *pp == '*' )
    {
    pp++;                       /* Always interrested in the chacter */
                                /* after the '*' */
    if( !*pp )                  /* It is at the end of the pattern. */
      {
      StrnCpy( matching_bit, s, sp-s );
      return( matching_bit );
      }
    else
      {
      /* The next character in pattern must match a character further */
      /* along s than sp so look for that character. */
      match_start = sp;
      while( (*sp)              /* Not the end of s. */
          && (*sp != *pp) )     /* Not the same  */
        sp++;                   /* Keep looking. */
      if( !*sp )                /* Got to the end without a match. */
        {
        return( NULL );
        }                       /* Still hope for a match. */
      else
        {
        /* Now sp should point to a matching character. */
        StrnCpy(matching_bit, match_start, sp-match_start);
        /* Back to needing a stright match again. */
        while( (*sp)            /* Not the end of the string. */
            && (*pp)            /* Not the end of the pattern. */
            && (*sp == *pp) )   /* The two match. */
          {
          sp++;                 /* Keep looking. */
          pp++;
          }
        if( !*sp && !*pp )      /* Both at end so it matched */
          return( matching_bit );
        else
          return( NULL );
        }
      }
    }
  return( NULL );               /* No match. */
  } /* map_filename */


/* ************************************************************************** **
 * MangledMap is a series of name pairs in () separated by spaces.
 * If s matches the first of the pair then the name given is the
 * second of the pair.  A * means any number of any character and if
 * present in the second of the pair as well as the first the
 * matching part of the first string takes the place of the * in the
 * second.
 *
 * I wanted this so that we could have RCS files which can be used
 * by UNIX and DOS programs.  My mapping string is (RCS rcs) which
 * converts the UNIX RCS file subdirectory to lowercase thus
 * preventing mangling.
 *
 * (I think Andrew wrote the above, but I'm not sure. -- CRH)
 *
 * See 'mangled map' in smb.conf(5).
 *
 * ************************************************************************** **
 */
static void do_fwd_mangled_map(char *s, char *MangledMap)
  {
  char *start=MangledMap;       /* Use this to search for mappings. */
  char *end;                    /* Used to find the end of strings. */
  char *match_string;
  pstring new_string;           /* Make up the result here. */
  char *np;                     /* Points into new_string. */

  DEBUG( 5, ("Mangled Mapping '%s' map '%s'\n", s, MangledMap) );
  while( *start )
    {
    while( (*start) && (*start != '(') )
      start++;
    if( !*start )
      continue;                 /* Always check for the end. */
    start++;                    /* Skip the ( */
    end = start;                /* Search for the ' ' or a ')' */
    DEBUG( 5, ("Start of first in pair '%s'\n", start) );
    while( (*end) && !((*end == ' ') || (*end == ')')) )
      end++;
    if( !*end )
      {
      start = end;
      continue;                 /* Always check for the end. */
      }
    DEBUG( 5, ("End of first in pair '%s'\n", end) );
    if( (match_string = map_filename( s, start, end-start )) )
      {
      DEBUG( 5, ("Found a match\n") );
      /* Found a match. */
      start = end + 1;          /* Point to start of what it is to become. */
      DEBUG( 5, ("Start of second in pair '%s'\n", start) );
      end = start;
      np = new_string;
      while( (*end)             /* Not the end of string. */
          && (*end != ')')      /* Not the end of the pattern. */
          && (*end != '*') )    /* Not a wildcard. */
        *np++ = *end++;
      if( !*end )
        {
        start = end;
        continue;               /* Always check for the end. */
        }
      if( *end == '*' )
        {
        pstrcpy( np, match_string );
        np += strlen( match_string );
        end++;                  /* Skip the '*' */
        while( (*end)             /* Not the end of string. */
            && (*end != ')')      /* Not the end of the pattern. */
            && (*end != '*') )    /* Not a wildcard. */
          *np++ = *end++;
        }
      if( !*end )
        {
        start = end;
        continue;               /* Always check for the end. */
        }
      *np++ = '\0';             /* NULL terminate it. */
      DEBUG(5,("End of second in pair '%s'\n", end));
      pstrcpy( s, new_string );  /* Substitute with the new name. */
      DEBUG( 5, ("s is now '%s'\n", s) );
      }
    start = end;              /* Skip a bit which cannot be wanted anymore. */
    start++;
    }
  } /* do_fwd_mangled_map */

/*****************************************************************************
 * do the actual mangling to 8.3 format
 * the buffer must be able to hold 13 characters (including the null)
 *****************************************************************************
 */
void mangle_name_83( char *s)
  {
  int csum;
  char *p;
  char extension[4];
  char base[9];
  int baselen = 0;
  int extlen = 0;

  extension[0] = 0;
  base[0] = 0;

  p = strrchr_m(s,'.');  
  if( p && (strlen(p+1) < (size_t)4) )
    {
    BOOL all_normal = ( strisnormal(p+1) ); /* XXXXXXXXX */

    if( all_normal && p[1] != 0 )
      {
      *p = 0;
      csum = str_checksum( s );
      *p = '.';
      }
    else
      csum = str_checksum(s);
    }
  else
    csum = str_checksum(s);

  strupper( s );

  DEBUG( 5, ("Mangling name %s to ",s) );

  if( p )
    {
    if( p == s )
      safe_strcpy( extension, "___", 3 );
    else
      {
      *p++ = 0;
      while( *p && extlen < 3 )
        {
            if( /*isdoschar (*p) &&*/ *p != '.' )
              extension[extlen++] = p[0];
            p++;
        }
      extension[extlen] = 0;
      }
    }

  p = s;

  while( *p && baselen < 5 )
    {
        if( /*isdoschar( *p ) &&*/ *p != '.' )
          base[baselen++] = p[0];
        p++;
    }
  base[baselen] = 0;

  csum = csum % (MANGLE_BASE*MANGLE_BASE);

  (void)slprintf(s, 12, "%s%c%c%c",
                 base, magic_char, mangle( csum/MANGLE_BASE ), mangle( csum ) );

  if( *extension )
    {
    (void)pstrcat( s, "." );
    (void)pstrcat( s, extension );
    }

  DEBUG( 5, ( "%s\n", s ) );

  } /* mangle_name_83 */

/*****************************************************************************
 * Convert a filename to DOS format.  Return True if successful.
 *
 *  Input:  OutName - Source *and* destination buffer. 
 *
 *                    NOTE that OutName must point to a memory space that
 *                    is at least 13 bytes in size!
 *
 *          need83  - If False, name mangling will be skipped unless the
 *                    name contains illegal characters.  Mapping will still
 *                    be done, if appropriate.  This is probably used to
 *                    signal that a client does not require name mangling,
 *                    thus skipping the name mangling even on shares which
 *                    have name-mangling turned on.
 *          cache83 - If False, the mangled name cache will not be updated.
 *                    This is usually used to prevent that we overwrite
 *                    a conflicting cache entry prematurely, i.e. before
 *                    we know whether the client is really interested in the
 *                    current name.  (See PR#13758).  UKD.
 *          snum    - Share number.  This identifies the share in which the
 *                    name exists.
 *
 *  Output: Returns False only if the name wanted mangling but the share does
 *          not have name mangling turned on.
 *
 * ****************************************************************************
 */
BOOL name_map_mangle(char *OutName, BOOL need83, BOOL cache83, int snum)
{
	char *map;
	DEBUG(5,("name_map_mangle( %s, need83 = %s, cache83 = %s, %d )\n", OutName,
		need83 ? "TRUE" : "FALSE", cache83 ? "TRUE" : "FALSE", snum));

#ifdef MANGLE_LONG_FILENAMES
	if( !need83 && is_illegal_name(OutName) )
		need83 = True;
#endif  

	/* apply any name mappings */
	map = lp_mangled_map(snum);

	if (map && *map) {
		do_fwd_mangled_map( OutName, map );
	}

	/* check if it's already in 8.3 format */
	if (need83 && !is_8_3(OutName, True)) {
		char *tmp = NULL; 

		if (!lp_manglednames(snum)) {
			return(False);
		}

		/* mangle it into 8.3 */
		if (cache83)
			tmp = strdup(OutName);

		mangle_name_83(OutName);

		if(tmp != NULL) {
			cache_mangled_name(OutName, tmp);
			SAFE_FREE(tmp);
		}
	}

	DEBUG(5,("name_map_mangle() ==> [%s]\n", OutName));
	return(True);
} /* name_map_mangle */





#if 1
#define MANGLE_TDB_VERSION		"20010927"
#define MANGLE_TDB_FILE_NAME		"mangle.tdb"
#define MANGLED_PREFIX			"MANGLED_"
#define LONG_PREFIX			"LONG_"
#define COUNTER_PREFIX			"COUNTER_"
#define	MANGLE_COUNTER_MAX		99
#define MANGLE_SUFFIX_SIZE		2


static TDB_CONTEXT	*mangle_tdb;

static int POW10(unsigned int exp)
{
	int result = 1;
	
	while (exp) {
		result *= 10;
		exp--;
	}
  
	return result;
}

BOOL init_mangle_tdb(void)
{
	char *tdbfile;
	
	tdbfile = lock_path(MANGLE_TDB_FILE_NAME); /* this return a static pstring do not try to free it */

	/* Open tdb */
	if (!(mangle_tdb = tdb_open_log(tdbfile, 0, TDB_DEFAULT, O_RDWR | O_CREAT, 0600)))
	{
		DEBUG(0, ("Unable to open Mangle TDB\n"));
		return False;
	}

	return True;
}

/* trasform a dos charset string in a terminated unicode string */
static int dos_to_ucs2(void *dest, const char *src, int dest_len)
{
	int len=0;
	int src_len = strlen(src) + 1;
	pstring tmpbuf;

	/* treat a pstring as "unlimited" length */
	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	/* ucs2 is always a multiple of 2 bytes */
	dest_len &= ~1;

	len = convert_string(CH_DOS, CH_UCS2, src, src_len, dest, dest_len);
	return len;
}

/* trasform a unicode string into a dos charset string */
static int ucs2_to_dos(char *dest, const smb_ucs2_t *src, int dest_len)
{
	int src_len, ret;

	if (dest_len == -1) {
		dest_len = sizeof(pstring);
	}

	src_len = strlen_w(src) * sizeof(smb_ucs2_t);
	
	ret = convert_string(CH_UCS2, CH_DOS, src, src_len, dest, dest_len);
	if (dest_len) dest[MIN(ret, dest_len-1)] = 0;

	return ret;
}

/* trasform a ucs2 string in a dos charset string that contain only valid chars for 8.3 filenames */
static int ucs2_to_dos83(char *dest, const smb_ucs2_t *src, int dest_len)
{
	int src_len, u2s_len, ret;
	smb_ucs2_t *u2s;

	u2s = (smb_ucs2_t *)malloc((strlen_w(src) + 1) * sizeof(smb_ucs2_t));
	if (!u2s) {
		DEBUG(0, ("ucs2_to_dos83: out of memory!\n"));
		return 0;
	}
	
	src_len = strlen_w(src);
	
	u2s[src_len] = 0;
	while (src_len--)
	{
		smb_ucs2_t c;
		
		c = src[src_len];
		if (isvalid83_w(c)) u2s[src_len] = c;
		else u2s[src_len] = UCS2_CHAR('_');
	}
	
	ret = ucs2_to_dos(dest, u2s, dest_len);
	
	SAFE_FREE(u2s);

	return ret;
}


/* return False if something fail and
 * return 2 alloced unicode strings that contain prefix and extension
 */
static BOOL mangle_get_prefix(const smb_ucs2_t *ucs2_string, smb_ucs2_t **prefix, smb_ucs2_t **extension)
{
	size_t str_len;
	smb_ucs2_t *p;
	fstring ext;

	*extension = 0;
	*prefix = strdup_w(ucs2_string);
	if (!*prefix)
	{
		DEBUG(0,("mangle_get_prefix: out of memory!\n"));
		return False;
	}
	if (p = strrchr_wa(*prefix, '.'))
	{
		p++;
		str_len = ucs2_to_dos83(ext, p, sizeof(ext));
		if (str_len > 0 && str_len < 4) /* check extension */
		{
			*(p - 1) = 0;
			*extension = strdup_w(p);
			if (!*extension)
			{
				DEBUG(0,("mangle_get_prefix: out of memory!\n"));
				SAFE_FREE(*prefix);
				return False;
			}
		}
	}

	return True;
}


/* mangled must contain only the file name, not a path.
   and MUST be ZERO terminated */
smb_ucs2_t *unmangle(const smb_ucs2_t *mangled)
{
	TDB_DATA data, key;
	fstring keystr;
	fstring mufname;
	smb_ucs2_t *pref, *ext, *retstr;
	size_t long_len, ext_len, muf_len;
	BOOL ret;

	if (strlen_w(mangled) > 12) return NULL;
	if (!strchr_wa(mangled, '~')) return NULL;
	
	ret = mangle_get_prefix(mangled, &pref, &ext);
	if (!ret) return NULL;
	
	/* TODO: get out extension */
	strlower_w(pref);
	/* set search key */
	muf_len = ucs2_to_dos(mufname, pref, sizeof(mufname));
	SAFE_FREE(pref);
	if (!muf_len) return NULL;
	
	slprintf(keystr, sizeof(keystr) - 1, "%s%s", MANGLED_PREFIX, mufname);
	key.dptr = keystr;
	key.dsize = strlen (keystr) + 1;
	
	/* get the record */
	data = tdb_fetch(mangle_tdb, key);
	
	if (!data.dptr) /* not found */
	{
		DEBUG(5,("unmangle: failed retrieve from db %s\n", tdb_errorstr(mangle_tdb)));
		retstr = NULL;
		goto done;
	}

	if (ext)
	{
		long_len = (data.dsize / 2) - 1;
		ext_len = strlen_w(ext);
		retstr = (smb_ucs2_t *)malloc((long_len + ext_len + 2)*sizeof(smb_ucs2_t));
		if (!retstr)
		{
			DEBUG(0, ("unamngle: out of memory!\n"));
			goto done;
		}
		strncpy_w(retstr, (smb_ucs2_t *)data.dptr, long_len);
		retstr[long_len] = UCS2_CHAR('.');
		retstr[long_len + 1] = 0;
		strncat_w(retstr, ext, ext_len);
	}
	else
	{
		retstr = strdup_w((smb_ucs2_t *)data.dptr);
		if (!retstr)
		{
			DEBUG(0, ("unamngle: out of memory!\n"));
			goto done;
		}

	}

done:
	SAFE_FREE(data.dptr);
	SAFE_FREE(pref);
	SAFE_FREE(ext);

	return retstr;
}

/* unmangled must contain only the file name, not a path.
   and MUST be ZERO terminated */
smb_ucs2_t *_mangle(const smb_ucs2_t *unmangled)
{
	TDB_DATA data, key, klock;
	pstring keystr;
	pstring longname;
	fstring keylock;
	fstring mufname;
	fstring prefix;
	BOOL tclock = False;
	char suffix[7];
	smb_ucs2_t *mangled = NULL;
	smb_ucs2_t *um, *ext, *p = NULL;
	smb_ucs2_t temp[9];
	size_t pref_len, ext_len, ud83_len;
	size_t um_len;
	uint32 n, c, pos;

	/* TODO: if it is a path return a failure ?? */
	if (!mangle_get_prefix(unmangled, &um, &ext)) return NULL;

	/* test if the same is yet mangled */

	/* set search key */
	pull_ucs2(NULL, longname, um, sizeof(longname), 0, STR_TERMINATE);
	slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
	key.dptr = keystr;
	key.dsize = strlen(keystr) + 1;

	/* get the record */
	data = tdb_fetch (mangle_tdb, key);
	if (!data.dptr) /* not found */
	{
		if (tdb_error(mangle_tdb) != TDB_ERR_NOEXIST)
		{
			DEBUG(0, ("mangle: database retrieval error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}

		/* if not find the first free possibile mangled name */

		n = 0;
		do
		{
			n++;
			pos = 8 - n - MANGLE_SUFFIX_SIZE;
			if (pos == 0)
			{
				DEBUG(0, ("mangle: unable to mangle file name!\n"));
				goto done;
			}
			strncpy_w(temp, um, pos);
			temp[pos] = 0;
			strlower_w(temp);

			ud83_len = ucs2_to_dos83(prefix, temp, sizeof(prefix));
			if (!ud83_len) goto done;
		}
		while (ud83_len > 8 - (MANGLE_SUFFIX_SIZE + 1));

		slprintf(keylock, sizeof(keylock)-1, "%s%s", COUNTER_PREFIX, prefix);
		klock.dptr = keylock;
		klock.dsize = strlen(keylock) + 1;

		c = 0;
		data.dptr = (char *)&c;
		data.dsize = sizeof(uint32);
		/* try to insert a new counter prefix, if it exist the call will
		   fail (correct) otherwise it will create a new entry with counter set
		   to 0
		 */
		if(tdb_store(mangle_tdb, klock, data, TDB_INSERT) != TDB_SUCCESS)
		{
			if (tdb_error(mangle_tdb) != TDB_ERR_EXISTS)
			{
				DEBUG(0, ("mangle: database store error: %s\n",
					tdb_errorstr(mangle_tdb)));
				goto done;
			}
		}

		/* lock the mangle counter for this prefix */		
		if (tdb_chainlock(mangle_tdb, klock))
		{
			DEBUG(0,("mangle: failed to lock database\n!"));
			goto done;
		}
		tclock = True;

		data = tdb_fetch(mangle_tdb, klock);
		if (!data.dptr)
		{
			DEBUG(0, ("mangle: database retrieval error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}
		c = *((uint32 *)data.dptr);
		c++;
		
		if (c > MANGLE_COUNTER_MAX)
		{
			DEBUG(0, ("mangle: error, counter overflow!\n"));
			goto done;
		}
			
		temp[pos] = UCS2_CHAR('~');
		temp[pos+1] = 0;
		snprintf(suffix, 7, "%.6d", c);
		strncat_wa(temp, &suffix[6 - MANGLE_SUFFIX_SIZE], MANGLE_SUFFIX_SIZE + 1);

		ud83_len = ucs2_to_dos(mufname, temp, sizeof(mufname));
		if (!ud83_len) goto done;
		if (ud83_len > 8)
		{
			DEBUG(0, ("mangle: darn, logic error aborting!\n"));
			goto done;
		}
			
		/* store the long entry with mangled key */
		slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
		key.dptr = keystr;
		key.dsize = strlen (keystr) + 1;
		data.dsize = (strlen_w(um) + 1) * sizeof (smb_ucs2_t);
		data.dptr = (void *)um;

		if (tdb_store(mangle_tdb, key, data, TDB_INSERT) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store error: %s\n",
					tdb_errorstr(mangle_tdb)));
			goto done;
		}

		/* store the mangled entry with long key*/
		pull_ucs2(NULL, longname, um, sizeof(longname), 0, STR_TERMINATE);
		slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
		key.dptr = keystr;
		key.dsize = strlen (keystr) + 1;
		data.dsize = strlen(mufname) + 1;
		data.dptr = mufname;
		if (tdb_store(mangle_tdb, key, data, TDB_INSERT) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store failed: %s\n",
					tdb_errorstr(mangle_tdb)));

			/* try to delete the mangled key entry to avoid later inconsistency */
			slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			goto done;
		}

		p = strdup_w(temp);
		if (!p)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
		
		data.dptr = (char *)&c;
		data.dsize = sizeof(uint32);
		/* store the counter */
		if(tdb_store(mangle_tdb, klock, data, TDB_REPLACE) != TDB_SUCCESS)
		{
			DEBUG(0, ("mangle: database store failed: %s\n",
					tdb_errorstr(mangle_tdb)));
			/* try to delete the mangled and long key entry to avoid later inconsistency */
			slprintf(keystr, sizeof(keystr)-1, "%s%s", MANGLED_PREFIX, mufname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			slprintf(keystr, sizeof(keystr)-1, "%s%s", LONG_PREFIX, longname);
			key.dptr = keystr;
			key.dsize = strlen (keystr) + 1;
			if (!tdb_delete(mangle_tdb, key))
			{
				DEBUG(0, ("mangle: severe error, mangled tdb may be inconsistent!\n"));
			}
			goto done;
		}

		tclock = False;
		tdb_chainunlock(mangle_tdb, klock);
	}
	else /* FOUND */
	{
		p = (smb_ucs2_t *)malloc(data.dsize*sizeof(smb_ucs2_t));
		if (!p)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
		dos_to_ucs2(p, data.dptr, data.dsize*sizeof(smb_ucs2_t));
	}
		
	if (ext)
	{
		pref_len = strlen_w(p);
		ext_len = strlen_w(ext);
		mangled = (smb_ucs2_t *)malloc((pref_len + ext_len + 2)*sizeof(smb_ucs2_t));
		if (!mangled)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
		strncpy_w (mangled, p, pref_len);
		mangled[pref_len] = UCS2_CHAR('.');
		mangled[pref_len + 1] = 0;
		strncat_w (mangled, ext, ext_len);
	}
	else
	{
		mangled = strdup_w(p);
		if (!mangled)
		{
			DEBUG(0,("mangle: out of memory!\n"));
			goto done;
		}
	}

done:
	if (tclock) tdb_chainunlock(mangle_tdb, klock);
	SAFE_FREE(p);
	SAFE_FREE(um);
	SAFE_FREE(ext);

	return mangled;
}

#endif /* 0 */

#if 1 /* TEST_MANGLE_CODE */

#define LONG		"this_is_a_long_file_name"
#define	LONGM		"this_~01"
#define SHORT		"short"
#define	SHORTM		"short~01"
#define EXT1		"ex1"
#define EXT2		"e2"
#define EXT3		"3"
#define EXTFAIL		"longext"
#define EXTNULL		""

static void unmangle_test (char *name, char *ext)
{
	smb_ucs2_t ucs2_name[2048];
	smb_ucs2_t *retstr;
	pstring unix_name;	

	push_ucs2(NULL, ucs2_name, name, sizeof(ucs2_name), STR_TERMINATE);
	if (ext)
	{
		strncat_wa(ucs2_name, ".", 1);
		strncat_wa(ucs2_name, ext, strlen(ext) + 1);
	}
	retstr = unmangle(ucs2_name);
	if(retstr) pull_ucs2(NULL, unix_name, retstr, sizeof(unix_name), 0, STR_TERMINATE);
	else unix_name[0] = 0;
	if (ext) printf ("[%s.%s] ---> [%s]\n", name, ext, unix_name);
	else printf ("[%s] ---> [%s]\n", name, unix_name);
	SAFE_FREE(retstr);
}

static void mangle_test (char *name, char *ext)
{
	smb_ucs2_t ucs2_name[2048];
	smb_ucs2_t *retstr;
	pstring unix_name;	

	push_ucs2(NULL, ucs2_name, name, sizeof(ucs2_name), STR_TERMINATE);
	if (ext)
	{
		strncat_wa(ucs2_name, ".", 1);
		strncat_wa(ucs2_name, ext, strlen(ext) + 1);
	}
	retstr = _mangle(ucs2_name);
	if(retstr) pull_ucs2(NULL, unix_name, retstr, sizeof(unix_name), 0, STR_TERMINATE);
	else unix_name[0] = 0;
	if (ext) printf ("[%s.%s] ---> [%s]\n", name, ext, unix_name);
	else printf ("[%s] ---> [%s]\n", name, unix_name);
	SAFE_FREE(retstr);
}

void mangle_test_code(void)
{
	init_mangle_tdb();

	/* unmangle every */
	printf("Unmangle test 1:\n");
	
	unmangle_test (LONG, NULL);
	unmangle_test (LONG, EXT1);
	unmangle_test (LONG, EXT2);
	unmangle_test (LONG, EXT3);
	unmangle_test (LONG, EXTFAIL);
	unmangle_test (LONG, EXTNULL);

	unmangle_test (LONGM, NULL);
	unmangle_test (LONGM, EXT1);
	unmangle_test (LONGM, EXT2);
	unmangle_test (LONGM, EXT3);
	unmangle_test (LONGM, EXTFAIL);
	unmangle_test (LONGM, EXTNULL);

	unmangle_test (SHORT, NULL);
	unmangle_test (SHORT, EXT1);
	unmangle_test (SHORT, EXT2);
	unmangle_test (SHORT, EXT3);
	unmangle_test (SHORT, EXTFAIL);
	unmangle_test (SHORT, EXTNULL);

	unmangle_test (SHORTM, NULL);
	unmangle_test (SHORTM, EXT1);
	unmangle_test (SHORTM, EXT2);
	unmangle_test (SHORTM, EXT3);
	unmangle_test (SHORTM, EXTFAIL);
	unmangle_test (SHORTM, EXTNULL);

	/* mangle every */
	printf("Mangle test\n");
	
	mangle_test (LONG, NULL);
	mangle_test (LONG, EXT1);
	mangle_test (LONG, EXT2);
	mangle_test (LONG, EXT3);
	mangle_test (LONG, EXTFAIL);
	mangle_test (LONG, EXTNULL);

	mangle_test (LONGM, NULL);
	mangle_test (LONGM, EXT1);
	mangle_test (LONGM, EXT2);
	mangle_test (LONGM, EXT3);
	mangle_test (LONGM, EXTFAIL);
	mangle_test (LONGM, EXTNULL);

	mangle_test (SHORT, NULL);
	mangle_test (SHORT, EXT1);
	mangle_test (SHORT, EXT2);
	mangle_test (SHORT, EXT3);
	mangle_test (SHORT, EXTFAIL);
	mangle_test (SHORT, EXTNULL);

	mangle_test (SHORTM, NULL);
	mangle_test (SHORTM, EXT1);
	mangle_test (SHORTM, EXT2);
	mangle_test (SHORTM, EXT3);
	mangle_test (SHORTM, EXTFAIL);
	mangle_test (SHORTM, EXTNULL);

	/* unmangle again every */
	printf("Unmangle test 2:\n");
	
	unmangle_test (LONG, NULL);
	unmangle_test (LONG, EXT1);
	unmangle_test (LONG, EXT2);
	unmangle_test (LONG, EXT3);
	unmangle_test (LONG, EXTFAIL);
	unmangle_test (LONG, EXTNULL);

	unmangle_test (LONGM, NULL);
	unmangle_test (LONGM, EXT1);
	unmangle_test (LONGM, EXT2);
	unmangle_test (LONGM, EXT3);
	unmangle_test (LONGM, EXTFAIL);
	unmangle_test (LONGM, EXTNULL);

	unmangle_test (SHORT, NULL);
	unmangle_test (SHORT, EXT1);
	unmangle_test (SHORT, EXT2);
	unmangle_test (SHORT, EXT3);
	unmangle_test (SHORT, EXTFAIL);
	unmangle_test (SHORT, EXTNULL);

	unmangle_test (SHORTM, NULL);
	unmangle_test (SHORTM, EXT1);
	unmangle_test (SHORTM, EXT2);
	unmangle_test (SHORTM, EXT3);
	unmangle_test (SHORTM, EXTFAIL);
	unmangle_test (SHORTM, EXTNULL);
}

#endif /* TEST_MANGLE_CODE */
