/* 
   Unix SMB/CIFS implementation.
   Name mangling
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Simo Sorce 2001
   Copyright (C) Andrew Bartlett 2002
   
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
#define MANGLE_BASE       (sizeof(basechars)/sizeof(char)-1)

static unsigned char chartest[256]  = { 0 };
static BOOL          ct_initialized = False;

#define mangle(V) ((char)(basechars[(V) % MANGLE_BASE]))
#define BASECHAR_MASK 0xf0
#define ILLEGAL_MASK  0x0f
#define isbasechar(C) ( (chartest[ ((C) & 0xff) ]) & BASECHAR_MASK )
#define isillegal(C) ( (chartest[ ((C) & 0xff) ]) & ILLEGAL_MASK )

static ubi_cacheRoot mangled_cache[1] =  { { { 0, 0, 0, 0 }, 0, 0, 0, 0, 0, 0 } };
static BOOL          mc_initialized   = False;
#define MANGLED_CACHE_MAX_ENTRIES 0
#define MANGLED_CACHE_MAX_MEMORY  16384


/* -------------------------------------------------------------------------- **
 * External Variables...
 */

extern int case_default;    /* Are conforming 8.3 names all upper or lower?   */
extern BOOL case_mangle;    /* If true, all chars in 8.3 should be same case. */

/* -------------------------------------------------------------------- */

NTSTATUS has_valid_chars(const smb_ucs2_t *s)
{
	if (!s || !*s) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("has_valid_chars: testing\n")); /* [%s]\n", s)); */
	
	/* CHECK: this should not be necessary if the ms wild chars
	   are not valid in valid.dat  --- simo */
	if (ms_has_wild_w(s)) return NT_STATUS_UNSUCCESSFUL;

	while (*s) {
		if(!isvalid83_w(*s)) return NT_STATUS_UNSUCCESSFUL;
		s++;
	}

	return NT_STATUS_OK;
}

/* return False if something fail and
 * return 2 alloced unicode strings that contain prefix and extension
 */
static NTSTATUS mangle_get_prefix(const smb_ucs2_t *ucs2_string, smb_ucs2_t **prefix, smb_ucs2_t **extension)
{
	size_t ext_len;
	smb_ucs2_t *p;

	*extension = 0;
	*prefix = strdup_w(ucs2_string);
	if (!*prefix)
	{
		DEBUG(0,("mangle_get_prefix: out of memory!\n"));
		return NT_STATUS_NO_MEMORY;
	}
	if ((p = strrchr_w(*prefix, UCS2_CHAR('.'))))
	{
		ext_len = strlen_w(p+1);
		if ((ext_len > 0) && (ext_len < 4) && (p != *prefix) &&
		    (NT_STATUS_IS_OK(has_valid_chars(p+1)))) /* check extension */
		{
			*p = 0;
			*extension = strdup_w(p+1);
			if (!*extension)
			{
				DEBUG(0,("mangle_get_prefix: out of memory!\n"));
				SAFE_FREE(*prefix);
				return NT_STATUS_NO_MEMORY;
			}
		}
	}
	return NT_STATUS_OK;
}

/* ************************************************************************** **
 * Return NT_STATUS_UNSUCCESSFUL if a name is a special msdos reserved name.
 *
 *  Input:  fname - String containing the name to be tested.
 *
 *  Output: NT_STATUS_UNSUCCESSFUL, if the name matches one of the list of reserved names.
 *
 *  Notes:  This is a static function called by is_8_3(), below.
 *
 * ************************************************************************** **
 */
static NTSTATUS is_valid_name(const smb_ucs2_t *fname)
{
	smb_ucs2_t *str, *p;
	NTSTATUS ret = NT_STATUS_OK;

	if (!fname || !*fname) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("is_valid_name: testing\n")); /* [%s]\n", s)); */

	if (*fname == UCS2_CHAR('.')) return NT_STATUS_UNSUCCESSFUL;
	
	ret = has_valid_chars(fname);
	if (NT_STATUS_IS_ERR(ret)) return ret;

	str = strdup_w(fname);
	p = strchr_w(str, UCS2_CHAR('.'));
	if (p) *p = 0;
	strupper_w(str);
	p = &(str[1]);

	switch(str[0])
	{
	case UCS2_CHAR('A'):
		if(strcmp_wa(p, "UX") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('C'):
		if((strcmp_wa(p, "LOCK$") == 0)
		|| (strcmp_wa(p, "ON") == 0)
		|| (strcmp_wa(p, "OM1") == 0)
		|| (strcmp_wa(p, "OM2") == 0)
		|| (strcmp_wa(p, "OM3") == 0)
		|| (strcmp_wa(p, "OM4") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('L'):
		if((strcmp_wa(p, "PT1") == 0)
		|| (strcmp_wa(p, "PT2") == 0)
		|| (strcmp_wa(p, "PT3") == 0)
		)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('N'):
		if(strcmp_wa(p, "UL") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	case UCS2_CHAR('P'):
		if(strcmp_wa(p, "RN") == 0)
			ret = NT_STATUS_UNSUCCESSFUL;
		break;
	default:
		break;
	}

	SAFE_FREE(str);
	return ret;
}

static NTSTATUS is_8_3_w(const smb_ucs2_t *fname)
{
	smb_ucs2_t *pref = 0, *ext = 0;
	size_t plen;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!fname || !*fname) return NT_STATUS_INVALID_PARAMETER;

	DEBUG(10,("is_8_3_w: testing\n")); /* [%s]\n", fname)); */

	if (strlen_w(fname) > 12) return NT_STATUS_UNSUCCESSFUL;
	
	if (strcmp_wa(fname, ".") == 0 || strcmp_wa(fname, "..") == 0)
		return NT_STATUS_OK;

	if (NT_STATUS_IS_ERR(is_valid_name(fname))) goto done;

	if (NT_STATUS_IS_ERR(mangle_get_prefix(fname, &pref, &ext))) goto done;
	plen = strlen_w(pref);

	if (strchr_wa(pref, '.')) goto done;
	if (plen < 1 || plen > 8) goto done;
	if (ext) if (strlen_w(ext) > 3) goto done;

	ret = NT_STATUS_OK;

done:
	SAFE_FREE(pref);
	SAFE_FREE(ext);
	return ret;
}

BOOL is_8_3(const char *fname, BOOL check_case)
{
	const char *f;
	smb_ucs2_t *ucs2name;
	NTSTATUS ret = NT_STATUS_UNSUCCESSFUL;

	if (!fname || !*fname) return False;
	if ((f = strrchr(fname, '/')) == NULL) f = fname;
	else f++;

	DEBUG(10,("is_8_3: testing [%s]\n", f));

	if (strlen(f) > 12) return False;
	
	ucs2name = acnv_uxu2(f);
	if (!ucs2name)
	{
		DEBUG(0,("is_8_3: internal error acnv_uxu2() failed!\n"));
		goto done;
	}

	ret = is_8_3_w(ucs2name);

done:
	SAFE_FREE(ucs2name);

	DEBUG(10,("is_8_3: returning -> %s\n", NT_STATUS_IS_OK(ret)?"True":"False"));

	if (!NT_STATUS_IS_OK(ret)) { 
		return False;
	}
	
	return True;
}



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
  s1 = strrchr( mangled_name, '.' );
  if( s1 && (s2 = strrchr( raw_name, '.' )) )
    {
    i = 1;
    while( s1[i] && (tolower( s1[i] ) == s2[i]) )
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
    ext_start = strrchr( s, '.' );
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

  p = strrchr(s,'.');  
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
			  if ( *p != '.') {
				  extension[extlen++] = p[0];
			  }
			  p++;
		  }
		  extension[extlen] = 0;
      }
  }
  
  p = s;

  while( *p && baselen < 5 )
  {
	  if (*p != '.') {
		  base[baselen++] = p[0];
	  }
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
	smb_ucs2_t *OutName_ucs2;
	DEBUG(5,("name_map_mangle( %s, need83 = %s, cache83 = %s, %d )\n", OutName,
		 need83 ? "True" : "False", cache83 ? "True" : "False", snum));
	
	if (push_ucs2_allocate((void **)&OutName_ucs2, OutName) < 0) {
		DEBUG(0, ("push_ucs2_allocate failed!\n"));
		return False;
	}

	/* apply any name mappings */
	map = lp_mangled_map(snum);

	if (map && *map) {
		do_fwd_mangled_map( OutName, map );
	}

	/* check if it's already in 8.3 format */
	if (need83 && !NT_STATUS_IS_OK(is_8_3_w(OutName_ucs2))) {
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
	SAFE_FREE(OutName_ucs2);
	return(True);
} /* name_map_mangle */

