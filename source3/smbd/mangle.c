/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Name mangling
   Copyright (C) Andrew Tridgell 1992-1995
   
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

extern int DEBUGLEVEL;
extern int case_default;
extern BOOL case_mangle;

/****************************************************************************
provide a checksum on a string
****************************************************************************/
int str_checksum(char *s)
{
  int res = 0;
  int c;
  int i=0;
  while (*s)
    {
      c = *s;
      res ^= (c << (i % 15)) ^ (c >> (15-(i%15)));
      s++; i++;
    }
  return(res);
}

/****************************************************************************
return True if a name is a special msdos reserved name
****************************************************************************/
static BOOL is_reserved_msdos(char *fname)
{
  char upperFname[13];
  char *p;

  StrnCpy (upperFname, fname, 12);

  /* lpt1.txt and con.txt etc are also illegal */
  p=strchr(upperFname,'.');
  if (p)
   *p='\0';
  strupper (upperFname);
  if ((strcmp(upperFname,"CLOCK$") == 0) ||
    (strcmp(upperFname,"CON") == 0) ||
    (strcmp(upperFname,"AUX") == 0) ||
    (strcmp(upperFname,"COM1") == 0) ||
    (strcmp(upperFname,"COM2") == 0) ||
    (strcmp(upperFname,"COM3") == 0) ||
    (strcmp(upperFname,"COM4") == 0) ||
    (strcmp(upperFname,"LPT1") == 0) ||
    (strcmp(upperFname,"LPT2") == 0) ||
    (strcmp(upperFname,"LPT3") == 0) ||
    (strcmp(upperFname,"NUL") == 0) ||
    (strcmp(upperFname,"PRN") == 0))
      return (True) ;

  return (False);
}



/****************************************************************************
return True if a name is in 8.3 dos format
****************************************************************************/
BOOL is_8_3(char *fname)
{
  int len;
  char *dot_pos;
  char *slash_pos = strrchr(fname,'/');
  int l;

  if (slash_pos) fname = slash_pos+1;
  len = strlen(fname);

  DEBUG(5,("checking %s for 8.3\n",fname));

  if (case_mangle)
    switch (case_default)
      {
      case CASE_LOWER:
	if (strhasupper(fname)) return(False);
	break;
      case CASE_UPPER:
	if (strhaslower(fname)) return(False);
	break;
      }

  /* can't be longer than 12 chars */
  if (len == 0 || len > 12)
    return(False);

  /* can't be an MS-DOS Special file such as lpt1 or even lpt1.txt */
  if (is_reserved_msdos(fname))
    return(False);

  /* can't contain invalid dos chars */
  /* Windows use the ANSI charset.
     But filenames are translated in the PC charset.
     This Translation may be more or less relaxed depending
     the Windows application. */

  /* %%% A nice improvment to name mangling would be to translate
     filename to ANSI charset on the smb server host */

  dot_pos = strchr(fname,'.');

  {
    char *p = fname;
#ifdef KANJI
    dot_pos = 0;
    while (*p)
      {
	  if (is_shift_jis (*p)) {
	      p += 2;
	  } else if (is_kana (*p)) {
	      p ++;
	  } else {
	      if (*p == '.' && !dot_pos)
		  dot_pos = (char *) p;
	      if (!isdoschar(*p))
		  return(False);
	      p++;
	  }
      }      
#else
    while (*p)
      {
	if (!isdoschar(*p))
	  return(False);
	p++;
      }      
#endif /* KANJI */
  }

  /* no dot and less than 9 means OK */
  if (!dot_pos)
    return(len <= 8);
	
  l = PTR_DIFF(dot_pos,fname);

  /* base must be at least 1 char except special cases . and .. */
  if (l == 0)
    return(strcmp(fname,".") == 0 || strcmp(fname,"..") == 0);

  /* base can't be greater than 8 */
  if (l > 8)
    return(False);

  if (lp_strip_dot() && 
      len - l == 1 &&
      !strchr(dot_pos+1,'.'))
    {
      *dot_pos = 0;
      return(True);
    }

  /* extension must be between 1 and 3 */
  if ( (len - l < 2 ) || (len - l > 4) )
    return(False);

  /* extension can't have a dot */
  if (strchr(dot_pos+1,'.'))
    return(False);

  /* must be in 8.3 format */
  return(True);
}



/*
keep a stack of name mangling results - just
so file moves and copies have a chance of working
*/
fstring *mangled_stack = NULL;
int mangled_stack_size = 0;
int mangled_stack_len = 0;

/****************************************************************************
create the mangled stack
****************************************************************************/
void create_mangled_stack(int size)
{
  if (mangled_stack)
    {
      free(mangled_stack);
      mangled_stack_size = 0;
      mangled_stack_len = 0;
    }
  if (size > 0)
    mangled_stack = (fstring *)malloc(sizeof(fstring)*size);
  if (mangled_stack) mangled_stack_size = size;
}

/****************************************************************************
push a mangled name onto the stack
****************************************************************************/
static void push_mangled_name(char *s)
{
  int i;
  char *p;

  if (!mangled_stack)
    return;

  for (i=0;i<mangled_stack_len;i++)
    if (strcmp(s,mangled_stack[i]) == 0)
      {
	array_promote(mangled_stack[0],sizeof(fstring),i);	
	return;
      }

  memmove(mangled_stack[1],mangled_stack[0],
	  sizeof(fstring)*MIN(mangled_stack_len,mangled_stack_size-1));
  strcpy(mangled_stack[0],s);
  p = strrchr(mangled_stack[0],'.');
  if (p && (!strhasupper(p+1)) && (strlen(p+1) < 4))
    *p = 0;
  mangled_stack_len = MIN(mangled_stack_size,mangled_stack_len+1);
}

/****************************************************************************
check for a name on the mangled name stack
****************************************************************************/
BOOL check_mangled_stack(char *s)
{
  int i;
  pstring tmpname;
  char extension[5];
  char *p = strrchr(s,'.');
  BOOL check_extension = False;

  extension[0] = 0;

  if (!mangled_stack) return(False);

  if (p)
    {
      check_extension = True;
      StrnCpy(extension,p,4);
      strlower(extension); /* XXXXXXX */
    }

  for (i=0;i<mangled_stack_len;i++)
    {
      strcpy(tmpname,mangled_stack[i]);
      mangle_name_83(tmpname);
      if (strequal(tmpname,s))
	{
	  strcpy(s,mangled_stack[i]);
	  break;
	}
      if (check_extension && !strchr(mangled_stack[i],'.'))
	{
	  strcpy(tmpname,mangled_stack[i]);
	  strcat(tmpname,extension);
	  mangle_name_83(tmpname);
	  if (strequal(tmpname,s))
	    {
	      strcpy(s,mangled_stack[i]);
	      strcat(s,extension);
	      break;
	    }	  
	}
    }

  if (i < mangled_stack_len)
    {
      DEBUG(3,("Found %s on mangled stack as %s\n",s,mangled_stack[i]));
      array_promote(mangled_stack[0],sizeof(fstring),i);
      return(True);      
    }

  return(False);
}	

static char *map_filename(char *s, /* This is null terminated */
			  char *pattern, /* This isn't. */
			  int len) /* This is the length of pattern. */
{
  static pstring matching_bit;  /* The bit of the string which matches */
                                /* a * in pattern if indeed there is a * */
  char *sp;                     /* Pointer into s. */
  char *pp;                     /* Pointer into p. */
  char *match_start;            /* Where the matching bit starts. */
  pstring pat;

  StrnCpy(pat, pattern, len);   /* Get pattern into a proper string! */
  strcpy(matching_bit,"");      /* Match but no star gets this. */
  pp = pat;                     /* Initialise the pointers. */
  sp = s;
  if ((len == 1) && (*pattern == '*')) {
    return NULL;                /* Impossible, too ambiguous for */
                                /* words! */
  }

  while ((*sp)                  /* Not the end of the string. */
         && (*pp)               /* Not the end of the pattern. */
         && (*sp == *pp)        /* The two match. */
         && (*pp != '*')) {     /* No wildcard. */
    sp++;                       /* Keep looking. */
    pp++;
  }
  if (!*sp && !*pp)             /* End of pattern. */
    return matching_bit;        /* Simple match.  Return empty string. */
  if (*pp == '*') {
    pp++;                       /* Always interrested in the chacter */
                                /* after the '*' */
    if (!*pp) {                 /* It is at the end of the pattern. */
      StrnCpy(matching_bit, s, sp-s);
      return matching_bit;
    } else {
      /* The next character in pattern must match a character further */
      /* along s than sp so look for that character. */
      match_start = sp;
      while ((*sp)              /* Not the end of s. */
             && (*sp != *pp))   /* Not the same  */
        sp++;                   /* Keep looking. */
      if (!*sp) {               /* Got to the end without a match. */
        return NULL;
      } else {                  /* Still hope for a match. */
        /* Now sp should point to a matching character. */
        StrnCpy(matching_bit, match_start, sp-match_start);
        /* Back to needing a stright match again. */
        while ((*sp)            /* Not the end of the string. */
               && (*pp)         /* Not the end of the pattern. */
               && (*sp == *pp)) { /* The two match. */
          sp++;                 /* Keep looking. */
          pp++;
        }
        if (!*sp && !*pp)       /* Both at end so it matched */
          return matching_bit;
        else
          return NULL;
      }
    }
  }
  return NULL;                  /* No match. */
}


/* this is the magic char used for mangling */
char magic_char = '~';


/****************************************************************************
determine whther is name could be a mangled name
****************************************************************************/
BOOL is_mangled(char *s)
{
  char *m = strchr(s,magic_char);
  if (!m) return(False);

  /* we use two base 36 chars efore the extension */
  if (m[1] == '.' || m[1] == 0 ||
      m[2] == '.' || m[2] == 0 ||
      (m[3] != '.' && m[3] != 0))
    return(is_mangled(m+1));

  /* it could be */
  return(True);
}



/****************************************************************************
return a base 36 character. v must be from 0 to 35.
****************************************************************************/
static char base36(int v)
{
  v = v % 36;
  if (v < 10)
    return('0'+v);
  else /* needed to work around a DEC C compiler bug */
    return('A' + (v-10));
}


static void do_fwd_mangled_map(char *s, char *MangledMap)
{
  /* MangledMap is a series of name pairs in () separated by spaces.
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
   */
  char *start=MangledMap;       /* Use this to search for mappings. */
  char *end;                    /* Used to find the end of strings. */
  char *match_string;
  pstring new_string;           /* Make up the result here. */
  char *np;                     /* Points into new_string. */

  DEBUG(5,("Mangled Mapping '%s' map '%s'\n", s, MangledMap));
  while (*start) {
    while ((*start) && (*start != '('))
      start++;
    start++;                    /* Skip the ( */
    if (!*start)
      continue;                 /* Always check for the end. */
    end = start;                /* Search for the ' ' or a ')' */
    DEBUG(5,("Start of first in pair '%s'\n", start));
    while ((*end) && !((*end == ' ') || (*end == ')')))
      end++;
    if (!*end) {
      start = end;
      continue;                 /* Always check for the end. */
    }
    DEBUG(5,("End of first in pair '%s'\n", end));
    if ((match_string = map_filename(s, start, end-start))) {
      DEBUG(5,("Found a match\n"));
      /* Found a match. */
      start = end+1;            /* Point to start of what it is to become. */
      DEBUG(5,("Start of second in pair '%s'\n", start));
      end = start;
      np = new_string;
      while ((*end)             /* Not the end of string. */
             && (*end != ')')   /* Not the end of the pattern. */
             && (*end != '*'))  /* Not a wildcard. */
        *np++ = *end++;
      if (!*end) {
        start = end;
        continue;               /* Always check for the end. */
      }
      if (*end == '*') {
        strcpy(np, match_string);
        np += strlen(match_string);
        end++;                  /* Skip the '*' */
        while ((*end)             /* Not the end of string. */
               && (*end != ')')   /* Not the end of the pattern. */
               && (*end != '*'))  /* Not a wildcard. */
          *np++ = *end++;
      }
      if (!*end) {
        start = end;
        continue;               /* Always check for the end. */
      }
      *np++ = '\0';             /* NULL terminate it. */
      DEBUG(5,("End of second in pair '%s'\n", end));
      strcpy(s, new_string);    /* Substitute with the new name. */
      DEBUG(5,("s is now '%s'\n", s));
    }
    start = end;              /* Skip a bit which cannot be wanted */
    /* anymore. */
    start++;
  }
}

/****************************************************************************
do the actual mangling to 8.3 format
****************************************************************************/
void mangle_name_83(char *s)
{
  int csum = str_checksum(s);
  char *p;
  char extension[4];
  char base[9];
  int baselen = 0;
  int extlen = 0;

  extension[0]=0;
  base[0]=0;

  p = strrchr(s,'.');  
  if (p && (strlen(p+1)<4) )
    {
      BOOL all_normal = (strisnormal(p+1)); /* XXXXXXXXX */
      if (all_normal && p[1] != 0)
	{
	  *p = 0;
	  csum = str_checksum(s);
	  *p = '.';
	}
    }
      

  strupper(s);

  DEBUG(5,("Mangling name %s to ",s));

  if (p)
    {
      if (p == s)
	strcpy(extension,"___");
      else
	{
	  *p++ = 0;
	  while (*p && extlen < 3)
	    {
#ifdef KANJI
	      if (is_shift_jis (*p))
		{
		  if (extlen < 2)
		    {
		      extension[extlen++] = p[0];
		      extension[extlen++] = p[1];
		    }
		  else 
		    {
		      extension[extlen++] = base36 (((unsigned char) *p) % 36);
		    }
		  p += 2;
		}
	      else if (is_kana (*p))
		{
		  extension[extlen++] = p[0];
		  p++;
		}
	      else 
		{
		  if (isdoschar (*p) && *p != '.')
		    extension[extlen++] = p[0];
		  p++;
		}
#else
	      if (isdoschar(*p) && *p != '.')
		extension[extlen++] = *p;
	      p++;
#endif /* KANJI */
	    }
	  extension[extlen] = 0;
	}
    }

  p = s;

  while (*p && baselen < 5)
    {
#ifdef KANJI
      if (is_shift_jis (*p))
	{
	  if (baselen < 4)
	    {
	      base[baselen++] = p[0];
	      base[baselen++] = p[1];
	    }
	  else 
	    {
	      base[baselen++] = base36 (((unsigned char) *p) % 36);
	    }
	  p += 2;
	}
      else if (is_kana (*p))
	{
	  base[baselen++] = p[0];
	  p++;
	}
      else 
	{
	  if (isdoschar (*p) && *p != '.')
	    base[baselen++] = p[0];
	  p++;
	}
#else
      if (isdoschar(*p) && *p != '.')
	base[baselen++] = *p;
      p++;
#endif /* KANJI */
    }
  base[baselen] = 0;

  csum = csum % (36*36);

    sprintf(s,"%s%c%c%c",base,magic_char,base36(csum/36),base36(csum%36));

  if (*extension)
    {
      strcat(s,".");
      strcat(s,extension);
    }
  DEBUG(5,("%s\n",s));
}



/*******************************************************************
  work out if a name is illegal, even for long names
  ******************************************************************/
static BOOL illegal_name(char *name)
{
  static unsigned char illegal[256];
  static BOOL initialised=False;
  unsigned char *s;

  if (!initialised) {
    char *ill = "*\\/?<>|\":{}";
    initialised = True;
  
    bzero((char *)illegal,256);
    for (s = (unsigned char *)ill; *s; s++)
      illegal[*s] = True;
  }

#ifdef KANJI
  for (s = (unsigned char *)name; *s;) {
    if (is_shift_jis (*s)) {
      s += 2;
    } else if (illegal[*s]) {
      return(True);
    } else {
      s++;
    }
  }
#else
  for (s = (unsigned char *)name;*s;s++)
    if (illegal[*s]) return(True);
#endif


  return(False);
}


/****************************************************************************
convert a filename to DOS format. return True if successful.
****************************************************************************/
BOOL name_map_mangle(char *OutName,BOOL need83,int snum)
{
#ifdef MANGLE_LONG_FILENAMES
  if (!need83 && illegal_name(OutName)) need83 = True;
#endif  

  /* apply any name mappings */
  {
    char *map = lp_mangled_map(snum);
    if (map && *map)
      do_fwd_mangled_map(OutName,map);
  }

  /* check if it's already in 8.3 format */
  if (need83 && !is_8_3(OutName)) {
    if (!lp_manglednames(snum)) return(False);

    /* mangle it into 8.3 */
    push_mangled_name(OutName);  
    mangle_name_83(OutName);
  }
  
  return(True);
}

