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

static const char *last_ptr=NULL;

void set_first_token(char *ptr)
{
	last_ptr = ptr;
}

/****************************************************************************
  Get the next token from a string, return False if none found
  handles double-quotes. 
Based on a routine by GJC@VILLAGE.COM. 
Extensively modified by Andrew.Tridgell@anu.edu.au
****************************************************************************/

BOOL next_token(const char **ptr,char *buff,const char *sep, size_t bufsize)
{
	const char *s;
	BOOL quoted;
	size_t len=1;

	if (!ptr)
		ptr = &last_ptr;
	if (!ptr)
		return(False);

	s = *ptr;

	/* default to simple separators */
	if (!sep)
		sep = " \t\n\r";

	/* find the first non sep char */
	while(*s && strchr(sep,*s))
		s++;

	/* nothing left? */
	if (! *s)
		return(False);

	/* copy over the token */
	for (quoted = False; len < bufsize && *s && (quoted || !strchr(sep,*s)); s++) {
		if (*s == '\"') {
			quoted = !quoted;
		} else {
			len++;
			*buff++ = *s;
		}
	}

	*ptr = (*s) ? s+1 : s;  
	*buff = 0;
	last_ptr = *ptr;

	return(True);
}

/****************************************************************************
Convert list of tokens to array; dependent on above routine.
Uses last_ptr from above - bit of a hack.
****************************************************************************/
char **toktocliplist(int *ctok, const char *sep)
{
  char *s= (char *)last_ptr;
  int ictok=0;
  char **ret, **iret;

  if (!sep) sep = " \t\n\r";

  while(*s && strchr(sep,*s)) s++;

  /* nothing left? */
  if (!*s) return(NULL);

  do {
    ictok++;
    while(*s && (!strchr(sep,*s))) s++;
    while(*s && strchr(sep,*s)) *s++=0;
  } while(*s);

  *ctok=ictok;
  s=last_ptr;

  if (!(ret=iret=malloc(ictok*sizeof(char *)))) return NULL;
  
  while(ictok--) {    
    *iret++=s;
    while(*s++);
    while(!*s) s++;
  }

  return ret;
}


/*******************************************************************
  case insensitive string compararison
********************************************************************/
int StrCaseCmp(const char *s, const char *t)
{
  /* compare until we run out of string, either t or s, or find a difference */
  /* We *must* use toupper rather than tolower here due to the
     asynchronous upper to lower mapping.
   */
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA.
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    int diff;
    for (;;)
    {
      if (!*s || !*t)
	    return toupper (*s) - toupper (*t);
      else if (is_sj_alph (*s) && is_sj_alph (*t))
      {
        diff = sj_toupper2 (*(s+1)) - sj_toupper2 (*(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
      }
      else if (is_shift_jis (*s) && is_shift_jis (*t))
      {
        diff = ((int) (unsigned char) *s) - ((int) (unsigned char) *t);
        if (diff)
          return diff;
        diff = ((int) (unsigned char) *(s+1)) - ((int) (unsigned char) *(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
      }
      else if (is_shift_jis (*s))
        return 1;
      else if (is_shift_jis (*t))
        return -1;
      else 
      {
        diff = toupper (*s) - toupper (*t);
        if (diff)
          return diff;
        s++;
        t++;
      }
    }
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (*s && *t && toupper(*s) == toupper(*t))
    {
      s++;
      t++;
    }

    return(toupper(*s) - toupper(*t));
  }
}

/*******************************************************************
  case insensitive string compararison, length limited
********************************************************************/
int StrnCaseCmp(const char *s, const char *t, size_t n)
{
  /* compare until we run out of string, either t or s, or chars */
  /* We *must* use toupper rather than tolower here due to the
     asynchronous upper to lower mapping.
   */
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    int diff;
    for (;n > 0;)
    {
      if (!*s || !*t)
        return toupper (*s) - toupper (*t);
      else if (is_sj_alph (*s) && is_sj_alph (*t))
      {
        diff = sj_toupper2 (*(s+1)) - sj_toupper2 (*(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
        n -= 2;
      }
      else if (is_shift_jis (*s) && is_shift_jis (*t))
      {
        diff = ((int) (unsigned char) *s) - ((int) (unsigned char) *t);
        if (diff)
          return diff;
        diff = ((int) (unsigned char) *(s+1)) - ((int) (unsigned char) *(t+1));
        if (diff)
          return diff;
        s += 2;
        t += 2;
        n -= 2;
      }
      else if (is_shift_jis (*s))
        return 1;
      else if (is_shift_jis (*t))
        return -1;
      else 
      {
        diff = toupper (*s) - toupper (*t);
        if (diff)
          return diff;
        s++;
        t++;
        n--;
      }
    }
    return 0;
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (n && *s && *t && toupper(*s) == toupper(*t))
    {
      s++;
      t++;
      n--;
    }

    /* not run out of chars - strings are different lengths */
    if (n) 
      return(toupper(*s) - toupper(*t));

    /* identical up to where we run out of chars, 
       and strings are same length */
    return(0);
  }
}

/*******************************************************************
  compare 2 strings - DOS codepage.
********************************************************************/
BOOL strequal(const char *s1, const char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(StrCaseCmp(s1,s2)==0);
}

/*******************************************************************
  compare 2 strings - UNIX codepage.
********************************************************************/
BOOL strequal_unix(const char *s1, const char *s2)
{
  pstring dos_s1, dos_s2;
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  pstrcpy(dos_s1, unix_to_dos_static(s1));
  pstrcpy(dos_s2, unix_to_dos_static(s2));
  return(StrCaseCmp(dos_s1,dos_s2)==0);
}

/*******************************************************************
  compare 2 strings up to and including the nth char.
  ******************************************************************/
BOOL strnequal(const char *s1,const char *s2,size_t n)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2 || !n) return(False);
  
  return(StrnCaseCmp(s1,s2,n)==0);
}

/*******************************************************************
  compare 2 strings (case sensitive)
********************************************************************/
BOOL strcsequal(const char *s1,const char *s2)
{
  if (s1 == s2) return(True);
  if (!s1 || !s2) return(False);
  
  return(strcmp(s1,s2)==0);
}

/***************************************************************************
Do a case-insensitive, whitespace-ignoring string compare.
***************************************************************************/
int strwicmp(const char *psz1, const char *psz2)
{
	/* if BOTH strings are NULL, return TRUE, if ONE is NULL return */
	/* appropriate value. */
	if (psz1 == psz2)
		return (0);
	else if (psz1 == NULL)
		return (-1);
	else if (psz2 == NULL)
		return (1);

	/* sync the strings on first non-whitespace */
	while (1)
	{
		while (isspace((int)*psz1))
			psz1++;
		while (isspace((int)*psz2))
			psz2++;
		if (toupper(*psz1) != toupper(*psz2) || *psz1 == '\0'
		    || *psz2 == '\0')
			break;
		psz1++;
		psz2++;
	}
	return (*psz1 - *psz2);
}


/*******************************************************************
  convert a string to lower case
********************************************************************/
void strlower(char *s)
{
  while (*s)
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_upper (s[0], s[1]))
          s[1] = sj_tolower2 (s[1]);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (isupper(*s))
          *s = tolower(*s);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else
      {
        if (isupper(*s))
          *s = tolower(*s);
        s++;
      }
    }
  }
}

/*******************************************************************
  convert a string to upper case
********************************************************************/
void strupper(char *s)
{
  while (*s)
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_lower (s[0], s[1]))
          s[1] = sj_toupper2 (s[1]);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (islower(*s))
          *s = toupper(*s);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else
      {
        if (islower(*s))
          *s = toupper(*s);
        s++;
      }
    }
  }
}

/* Convert a string to upper case, but don't modify it */

char *strupper_static(const char *s)
{
	static pstring str;

	pstrcpy(str, s);
	strupper(str);

	return str;
}

/*******************************************************************
  convert a string to "normal" form
********************************************************************/
void strnorm(char *s)
{
  extern int case_default;
  if (case_default == CASE_UPPER)
    strupper(s);
  else
    strlower(s);
}

/*******************************************************************
check if a string is in "normal" case
********************************************************************/
BOOL strisnormal(char *s)
{
  extern int case_default;
  if (case_default == CASE_UPPER)
    return(!strhaslower(s));

  return(!strhasupper(s));
}


/****************************************************************************
  string replace
****************************************************************************/
void string_replace(char *s,char oldc,char newc)
{
  size_t skip;

  /*
   * sbcs optimization.
   */
  if(!global_is_multibyte_codepage) {
    while (*s) {
      if (oldc == *s)
        *s = newc;
      s++;
    }
  } else {
    while (*s)
    {
      skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else
      {
        if (oldc == *s)
          *s = newc;
        s++;
      }
    }
  }
}


/*******************************************************************
skip past some strings in a buffer
********************************************************************/
char *skip_string(char *buf,size_t n)
{
  while (n--)
    buf += strlen(buf) + 1;
  return(buf);
}

/*******************************************************************
 Count the number of characters in a string. Normally this will
 be the same as the number of bytes in a string for single byte strings,
 but will be different for multibyte.
 16.oct.98, jdblair@cobaltnet.com.
********************************************************************/

size_t str_charnum(const char *s)
{
  size_t len = 0;
  
  /*
   * sbcs optimization.
   */
  if(!global_is_multibyte_codepage) {
    return strlen(s);
  } else {
    while (*s != '\0') {
      int skip = get_character_len(*s);
      s += (skip ? skip : 1);
      len++;
    }
  }
  return len;
}

/*******************************************************************
trim the specified elements off the front and back of a string
********************************************************************/

BOOL trim_string(char *s,const char *front,const char *back)
{
    BOOL ret = False;
    size_t s_len;
    size_t front_len;
    size_t back_len;
    char	*sP;

	/* Ignore null or empty strings. */

    if ( !s || (s[0] == '\0'))
        return False;

    sP	= s;
    s_len	= strlen( s ) + 1;
    front_len	= (front) ? strlen( front ) + 1 : 0;
    back_len	= (back) ? strlen( back ) + 1 : 0;

    /*
     * remove "front" string from given "s", if it matches front part,
     * repeatedly.
     */
    if ( front && front_len > 1 ) {
        while (( s_len >= front_len )&&
               ( memcmp( sP, front, front_len - 1 )) == 0 ) {
            ret		= True;
            sP		+= ( front_len - 1 );
            s_len	-= ( front_len - 1 );
        }
    }

    /*
     * we'll memmove sP to s later, after we're done with
     * back part removal, for minimizing copy.
     */


    /*
     * We split out the multibyte code page
     * case here for speed purposes. Under a
     * multibyte code page we need to walk the
     * string forwards only and multiple times.
     * Thanks to John Blair for finding this
     * one. JRA.
     */
    /*
     * This JRA's comment is partly correct, but partly wrong.
     * You can always check from "end" part, and if it did not match,
     * it means there is no possibility of finding one.
     * If you found matching point, mark them, then look from front
     * if marking point suits multi-byte string rule.
     * Kenichi Okuyama.
     */

    if ( back && back_len > 1 && s_len >= back_len) {
        char	*bP	= sP + s_len - back_len;
        long	b_len	= s_len;

        while (( b_len >= back_len )&&
               ( memcmp( bP, back, back_len - 1 ) == 0 )) {
            bP		-= ( back_len - 1 );
            b_len	-= ( back_len - 1 );
        }

        /*
         * You're here, means you ether have found match multiple times,
         * or you found none. If you've found match, then bP should be
         * moving.
         */
        if ( bP != sP + s_len - back_len ) {
            bP	+= ( back_len - 1 ); /* slide bP to first matching point. */

            if( !global_is_multibyte_codepage ) {
                /* simply terminate */
                (*bP)	= '\0';
                s_len	= b_len;
                ret	= True;
            } else {
                /* trace string from start. */
                char	*cP	= sP;
                while ( cP < sP + s_len - back_len ) {
                    size_t	skip;
                    skip	= skip_multibyte_char( *cP );
                    cP	+= ( skip ? skip : 1 );
                    if ( cP == bP ) {
                        /* you found the match */
                        (*bP)	= '\0';
                        ret	= True;
                        s_len	= b_len;
                        break;
                    }
                    while (( cP > bP )&&( bP < sP + s_len - back_len )) {
                        bP	+= ( back_len - 1 );
                        b_len	+= ( back_len - 1 );
                    }
                }
            }
        }
    }

    /* if front found matching point */
    if ( sP != s ) {
        /* slide string to buffer top */
        memmove( s, sP, s_len );
    }
    return ret;
}


/****************************************************************************
does a string have any uppercase chars in it?
****************************************************************************/
BOOL strhasupper(const char *s)
{
  while (*s) 
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
        s += 2;
      else if (is_kana (*s))
        s++;
      else
      {
        if (isupper(*s))
          return(True);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (isupper(*s))
          return(True);
        s++;
      }
    }
  }
  return(False);
}

/****************************************************************************
does a string have any lowercase chars in it?
****************************************************************************/
BOOL strhaslower(const char *s)
{
  while (*s) 
  {
#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

    if(lp_client_code_page() == KANJI_CODEPAGE)
    {
      /* Win95 treats full width ascii characters as case sensitive. */
      if (is_shift_jis (*s))
      {
        if (is_sj_upper (s[0], s[1]))
          return(True);
        if (is_sj_lower (s[0], s[1]))
          return (True);
        s += 2;
      }
      else if (is_kana (*s))
      {
        s++;
      }
      else
      {
        if (islower(*s))
          return(True);
        s++;
      }
    }
    else
#endif /* KANJI_WIN95_COMPATIBILITY */
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (islower(*s))
          return(True);
        s++;
      }
    }
  }
  return(False);
}

/****************************************************************************
find the number of chars in a string
****************************************************************************/
size_t count_chars(const char *s,char c)
{
  size_t count=0;

#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA. 
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    while (*s) 
    {
      if (is_shift_jis (*s))
        s += 2;
      else 
      {
        if (*s == c)
          count++;
        s++;
      }
    }
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (*s) 
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (*s == c)
          count++;
        s++;
      }
    }
  }
  return(count);
}

/*******************************************************************
Return True if a string consists only of one particular character.
********************************************************************/

BOOL str_is_all(const char *s,char c)
{
  if(s == NULL)
    return False;
  if(!*s)
    return False;

#if !defined(KANJI_WIN95_COMPATIBILITY)
  /*
   * For completeness we should put in equivalent code for code pages
   * 949 (Korean hangul) and 950 (Big5 Traditional Chinese) here - but
   * doubt anyone wants Samba to behave differently from Win95 and WinNT
   * here. They both treat full width ascii characters as case senstive
   * filenames (ie. they don't do the work we do here).
   * JRA.
   */

  if(lp_client_code_page() == KANJI_CODEPAGE)
  {
    /* Win95 treats full width ascii characters as case sensitive. */
    while (*s)
    {
      if (is_shift_jis (*s))
        s += 2;
      else
      {
        if (*s != c)
          return False;
        s++;
      }
    }
  }
  else
#endif /* KANJI_WIN95_COMPATIBILITY */
  {
    while (*s)
    {
      size_t skip = get_character_len( *s );
      if( skip != 0 )
        s += skip;
      else {
        if (*s != c)
          return False;
        s++;
      }
    }
  }
  return True;
}

/*******************************************************************
safe string copy into a known length string. maxlength does not
include the terminating zero.
********************************************************************/

char *safe_strcpy(char *dest,const char *src, size_t maxlength)
{
	size_t len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcpy\n"));
		return NULL;
	}

	if (!src) {
		*dest = 0;
		return dest;
	}  

	len = strlen(src);

	if (len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %d in safe_strcpy [%.50s]\n",
			(int)(len-maxlength), src));
		len = maxlength;
	}
      
	memcpy(dest, src, len);
	dest[len] = 0;
	return dest;
}  

/*******************************************************************
safe string cat into a string. maxlength does not
include the terminating zero.
********************************************************************/

char *safe_strcat(char *dest, const char *src, size_t maxlength)
{
	size_t src_len, dest_len;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in safe_strcat\n"));
		return NULL;
	}

	if (!src)
		return dest;
	
	src_len = strlen(src);
	dest_len = strlen(dest);

	if (src_len + dest_len > maxlength) {
		DEBUG(0,("ERROR: string overflow by %d in safe_strcat [%.50s]\n",
			 (int)(src_len + dest_len - maxlength), src));
		if (maxlength > dest_len) {
			memcpy(&dest[dest_len], src, maxlength - dest_len);
		}
		dest[maxlength] = 0;
		return NULL;
	}
	
	memcpy(&dest[dest_len], src, src_len);
	dest[dest_len + src_len] = 0;
	return dest;
}

/*******************************************************************
 Paranoid strcpy into a buffer of given length (includes terminating
 zero. Strips out all but 'a-Z0-9' and the character in other_safe_chars
 and replaces with '_'. Deliberately does *NOT* check for multibyte
 characters. Don't change it !
********************************************************************/

char *alpha_strcpy(char *dest, const char *src, const char *other_safe_chars, size_t maxlength)
{
	size_t len, i;
	size_t buflen;
	smb_ucs2_t *str_ucs, *other_ucs;

	if (!dest) {
		DEBUG(0,("ERROR: NULL dest in alpha_strcpy\n"));
		return NULL;
	}

	if (!src) {
		*dest = 0;
		return dest;
	}  

	/* Get UCS2 version of src string*/

	buflen=2*strlen(src)+2;
	if (buflen >= (2*maxlength))
		buflen = 2*(maxlength - 1);

	str_ucs = (smb_ucs2_t*)malloc(buflen);
	if(!str_ucs) {
		*dest=0;
		return dest;
	}
	unix_to_unicode(str_ucs, src, buflen);
	len = strlen_w(str_ucs);

	if (!other_safe_chars)
		other_safe_chars = "";

	/* Get UCS2 version of other_safe_chars string*/
	buflen=2*strlen(other_safe_chars)+2;
	other_ucs = (smb_ucs2_t*)malloc(buflen);
	if(!other_ucs) {
		*dest=0;
		SAFE_FREE(str_ucs);
		return dest;
	}
	unix_to_unicode(other_ucs, other_safe_chars, buflen);

	for(i = 0; i < len; i++) {
		if(isupper_w(str_ucs[i]) || islower_w(str_ucs[i]) || isdigit_w(str_ucs[i]) || strchr_w(other_ucs, str_ucs[i]))
			;
		else
			str_ucs[i] = (smb_ucs2_t)'_'; /*This will work*/

	}
	unicode_to_unix(dest, str_ucs, maxlength);

	SAFE_FREE(other_ucs);
	SAFE_FREE(str_ucs);

	return dest;
}

/****************************************************************************
 Like strncpy but always null terminates. Make sure there is room!
 The variable n should always be one less than the available size.
****************************************************************************/

char *StrnCpy(char *dest,const char *src,size_t n)
{
  char *d = dest;
  if (!dest) return(NULL);
  if (!src) {
    *dest = 0;
    return(dest);
  }
  while (n-- && (*d++ = *src++)) ;
  *d = 0;
  return(dest);
}

/****************************************************************************
like strncpy but copies up to the character marker.  always null terminates.
returns a pointer to the character marker in the source string (src).
****************************************************************************/
char *strncpyn(char *dest, const char *src,size_t n, char c)
{
	char *p;
	size_t str_len;

	p = strchr(src, c);
	if (p == NULL)
	{
		DEBUG(5, ("strncpyn: separator character (%c) not found\n", c));
		return NULL;
	}

	str_len = PTR_DIFF(p, src);
	strncpy(dest, src, MIN(n, str_len));
	dest[str_len] = '\0';

	return p;
}


/*************************************************************
 Routine to get hex characters and turn them into a 16 byte array.
 the array can be variable length, and any non-hex-numeric
 characters are skipped.  "0xnn" or "0Xnn" is specially catered
 for.

 valid examples: "0A5D15"; "0x15, 0x49, 0xa2"; "59\ta9\te3\n"

**************************************************************/
size_t strhex_to_str(char *p, size_t len, const char *strhex)
{
	size_t i;
	size_t num_chars = 0;
	unsigned char   lonybble, hinybble;
	const char           *hexchars = "0123456789ABCDEF";
	char           *p1 = NULL, *p2 = NULL;

	for (i = 0; i < len && strhex[i] != 0; i++)
	{
		if (strnequal(hexchars, "0x", 2))
		{
			i++; /* skip two chars */
			continue;
		}

		if (!(p1 = strchr(hexchars, toupper(strhex[i]))))
		{
			break;
		}

		i++; /* next hex digit */

		if (!(p2 = strchr(hexchars, toupper(strhex[i]))))
		{
			break;
		}

		/* get the two nybbles */
		hinybble = PTR_DIFF(p1, hexchars);
		lonybble = PTR_DIFF(p2, hexchars);

		p[num_chars] = (hinybble << 4) | lonybble;
		num_chars++;

		p1 = NULL;
		p2 = NULL;
	}
	return num_chars;
}

/****************************************************************************
check if a string is part of a list
****************************************************************************/
BOOL in_list(char *s,char *list,BOOL casesensitive)
{
  pstring tok;
  const char *p=list;

  if (!list) return(False);

  while (next_token(&p,tok,LIST_SEP,sizeof(tok))) {
    if (casesensitive) {
      if (strcmp(tok,s) == 0)
        return(True);
    } else {
      if (StrCaseCmp(tok,s) == 0)
        return(True);
    }
  }
  return(False);
}

/* this is used to prevent lots of mallocs of size 1 */
static char *null_string = NULL;

/****************************************************************************
set a string value, allocing the space for the string
****************************************************************************/
static BOOL string_init(char **dest,const char *src)
{
  size_t l;
  if (!src)     
    src = "";

  l = strlen(src);

  if (l == 0)
    {
      if (!null_string) {
        if((null_string = (char *)malloc(1)) == NULL) {
          DEBUG(0,("string_init: malloc fail for null_string.\n"));
          return False;
        }
        *null_string = 0;
      }
      *dest = null_string;
    }
  else
    {
      (*dest) = (char *)malloc(l+1);
      if ((*dest) == NULL) {
	      DEBUG(0,("Out of memory in string_init\n"));
	      return False;
      }

      pstrcpy(*dest,src);
    }
  return(True);
}

/****************************************************************************
free a string value
****************************************************************************/
void string_free(char **s)
{
  if (!s || !(*s)) return;
  if (*s == null_string)
    *s = NULL;
  SAFE_FREE(*s);
}

/****************************************************************************
set a string value, allocing the space for the string, and deallocating any 
existing space
****************************************************************************/
BOOL string_set(char **dest,const char *src)
{
  string_free(dest);

  return(string_init(dest,src));
}


/****************************************************************************
substitute a string for a pattern in another string. Make sure there is 
enough room!

This routine looks for pattern in s and replaces it with 
insert. It may do multiple replacements.

any of " ; ' $ or ` in the insert string are replaced with _
if len==0 then no expansion is permitted.
****************************************************************************/
void string_sub(char *s,const char *pattern,const char *insert, size_t len)
{
	char *p;
	ssize_t ls,lp,li, i;

	if (!insert || !pattern || !s) return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (!*pattern) return;

	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */
	
	while (lp <= ls && (p = strstr(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by %d in string_sub(%.50s, %d)\n", 
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		for (i=0;i<li;i++) {
			switch (insert[i]) {
			case '`':
			case '"':
			case '\'':
			case ';':
			case '$':
			case '%':
			case '\r':
			case '\n':
				p[i] = '_';
				break;
			default:
				p[i] = insert[i];
			}
		}
		s = p + li;
		ls += (li-lp);
	}
}

void fstring_sub(char *s,const char *pattern,const char *insert)
{
	string_sub(s, pattern, insert, sizeof(fstring));
}

void pstring_sub(char *s,const char *pattern,const char *insert)
{
	string_sub(s, pattern, insert, sizeof(pstring));
}

/****************************************************************************
similar to string_sub() but allows for any character to be substituted. 
Use with caution!
if len==0 then no expansion is permitted.
****************************************************************************/
void all_string_sub(char *s,const char *pattern,const char *insert, size_t len)
{
	char *p;
	ssize_t ls,lp,li;

	if (!insert || !pattern || !s) return;

	ls = (ssize_t)strlen(s);
	lp = (ssize_t)strlen(pattern);
	li = (ssize_t)strlen(insert);

	if (!*pattern) return;
	
	if (len == 0)
		len = ls + 1; /* len is number of *bytes* */
	
	while (lp <= ls && (p = strstr(s,pattern))) {
		if (ls + (li-lp) >= len) {
			DEBUG(0,("ERROR: string overflow by %d in all_string_sub(%.50s, %d)\n", 
				 (int)(ls + (li-lp) - len),
				 pattern, (int)len));
			break;
		}
		if (li != lp) {
			memmove(p+li,p+lp,strlen(p+lp)+1);
		}
		memcpy(p, insert, li);
		s = p + li;
		ls += (li-lp);
	}
}

/****************************************************************************
 splits out the front and back at a separator.
****************************************************************************/
void split_at_last_component(char *path, char *front, char sep, char *back)
{
	char *p = strrchr(path, sep);

	if (p != NULL)
	{
		*p = 0;
	}
	if (front != NULL)
	{
		pstrcpy(front, path);
	}
	if (p != NULL)
	{
		if (back != NULL)
		{
			pstrcpy(back, p+1);
		}
		*p = '\\';
	}
	else
	{
		if (back != NULL)
		{
			back[0] = 0;
		}
	}
}


/****************************************************************************
write an octal as a string
****************************************************************************/
const char *octal_string(int i)
{
	static char ret[64];
	if (i == -1) {
		return "-1";
	}
	slprintf(ret, sizeof(ret)-1, "0%o", i);
	return ret;
}


/****************************************************************************
truncate a string at a specified length
****************************************************************************/
char *string_truncate(char *s, int length)
{
	if (s && strlen(s) > length) {
		s[length] = 0;
	}
	return s;
}

/*
  return a RFC2254 binary string representation of a buffer
  used in LDAP filters
  caller must free
*/
char *binary_string(char *buf, int len)
{
	char *s;
	int i, j;
	const char *hex = "0123456789ABCDEF";
	s = malloc(len * 3 + 1);
	if (!s) return NULL;
	for (j=i=0;i<len;i++) {
		s[j] = '\\';
		s[j+1] = hex[((unsigned char)buf[i]) >> 4];
		s[j+2] = hex[((unsigned char)buf[i]) & 0xF];
		j += 3;
	}
	s[j] = 0;
	return s;
}

#ifndef HAVE_STRNLEN
/*******************************************************************
 Some platforms don't have strnlen
********************************************************************/

 size_t strnlen(const char *s, size_t n)
{
	int i;
	for (i=0; s[i] && i<n; i++)
		/* noop */ ;
	return i;
}
#endif

#ifndef HAVE_STRNDUP
/*******************************************************************
 Some platforms don't have strndup.
********************************************************************/

 char *strndup(const char *s, size_t n)
{
	char *ret;

	n = strnlen(s, n);
	ret = malloc(n+1);
	if (!ret)
		return NULL;
	memcpy(ret, s, n);
	ret[n] = 0;

	return ret;
}
#endif
