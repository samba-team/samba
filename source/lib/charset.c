/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set handling
   Copyright (C) Andrew Tridgell 1992-1997
   
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

#define CHARSET_C
#include "includes.h"

extern int DEBUGLEVEL;

/*
 * Codepage definitions.
 */

/* lower->upper mapping for IBM Code Page 850 - MS-DOS Latin 1 */
unsigned char cp_850[][4] = {
/* dec col/row oct hex  description */
/* 133  08/05  205  85  a grave */
/* 183  11/07  267  B7  A grave */ 	{0x85,0xB7,1,1},
/* 160  10/00  240  A0  a acute */
/* 181  11/05  265  B5  A acute */	{0xA0,0xB5,1,1},
/* 131  08/03  203  83  a circumflex */
/* 182  11/06  266  B6  A circumflex */	{0x83,0xB6,1,1},
/* 198  12/06  306  C6  a tilde */
/* 199  12/07  307  C7  A tilde */	{0xC6,0xC7,1,1},
/* 132  08/04  204  84  a diaeresis */
/* 142  08/14  216  8E  A diaeresis */	{0x84,0x8E,1,1},
/* 134  08/06  206  86  a ring */
/* 143  08/15  217  8F  A ring */	{0x86,0x8F,1,1},
/* 145  09/01  221  91  ae diphthong */
/* 146  09/02  222  92  AE diphthong */	{0x91,0x92,1,1},
/* 135  08/07  207  87  c cedilla */
/* 128  08/00  200  80  C cedilla */	{0x87,0x80,1,1},
/* 138  08/10  212  8A  e grave */
/* 212  13/04  324  D4  E grave */	{0x8A,0xD4,1,1},
/* 130  08/02  202  82  e acute */
/* 144  09/00  220  90  E acute */	{0x82,0x90,1,1},
/* 136  08/08  210  88  e circumflex */
/* 210  13/02  322  D2  E circumflex */	{0x88,0xD2,1,1},
/* 137  08/09  211  89  e diaeresis */
/* 211  13/03  323  D3  E diaeresis */	{0x89,0xD3,1,1},
/* 141  08/13  215  8D  i grave */
/* 222  13/14  336  DE  I grave */	{0x8D,0xDE,1,1},
/* 161  10/01  241  A1  i acute */
/* 214  13/06  326  D6  I acute */	{0xA1,0xD6,1,1},
/* 140  08/12  214  8C  i circumflex */
/* 215  13/07  327  D7  I circumflex */	{0x8C,0xD7,1,1},
/* 139  08/11  213  8B  i diaeresis */
/* 216  13/08  330  D8  I diaeresis */	{0x8B,0xD8,1,1},
/* 208  13/00  320  D0  Icelandic eth */
/* 209  13/01  321  D1  Icelandic Eth */ {0xD0,0xD1,1,1},
/* 164  10/04  244  A4  n tilde */
/* 165  10/05  245  A5  N tilde */	{0xA4,0xA5,1,1},
/* 149  09/05  225  95  o grave */
/* 227  14/03  343  E3  O grave */	{0x95,0xE3,1,1},
/* 162  10/02  242  A2  o acute */
/* 224  14/00  340  E0  O acute */	{0xA2,0xE0,1,1},
/* 147  09/03  223  93  o circumflex */
/* 226  14/02  342  E2  O circumflex */	{0x93,0xE2,1,1},
/* 228  14/04  344  E4  o tilde */
/* 229  14/05  345  E5  O tilde */	{0xE4,0xE5,1,1},
/* 148  09/04  224  94  o diaeresis */
/* 153  09/09  231  99  O diaeresis */	{0x94,0x99,1,1},
/* 155  09/11  233  9B  o slash */
/* 157  09/13  235  9D  O slash */	{0x9B,0x9D,1,1},
/* 151  09/07  227  97  u grave */
/* 235  14/11  353  EB  U grave */ 	{0x97,0xEB,1,1},
/* 163  10/03  243  A3  u acute */
/* 233  14/09  351  E9  U acute */	{0xA3,0xE9,1,1},
/* 150  09/06  226  96  u circumflex */
/* 234  14/10  352  EA  U circumflex */ {0x96,0xEA,1,1},
/* 129  08/01  201  81  u diaeresis */
/* 154  09/10  232  9A  U diaeresis */	{0x81,0x9A,1,1},
/* 236  14/12  354  EC  y acute */
/* 237  14/13  355  ED  Y acute */	{0xEC,0xED,1,1},
/* 231  14/07  347  E7  Icelandic thorn */
/* 232  14/08  350  E8  Icelandic Thorn */ {0xE7,0xE8,1,1},
   
  {0x9C,0,0,0},     /* Pound        */
  {0,0,0,0}
};
 
/* lower->upper mapping for IBM Code Page 437 - MS-DOS Latin US */
unsigned char cp_437[][4] = {
/* 135  08/07  207  87  c cedilla */
/* 128  08/00  200  80  C cedilla */	{0x87,0x80,1,1},
/* 129  08/01  201  81  u diaeresis */
/* 154  09/10  232  9A  U diaeresis */	{0x81,0x9A,1,1},
/* 130  08/02  202  82  e acute */
/* 144  09/00  220  90  E acute */	{0x82,0x90,1,1},
/* 131  08/03  203  83  a circumflex */ {0x83,0x41,1,0},
/* 132  08/04  204  84  a diaeresis */
/* 142  08/14  216  8E  A diaeresis */	{0x84,0x8E,1,1},
/* 133  08/05  205  85  a grave */      {0x85,0x41,1,0},
/* 134  08/06  206  86  a ring */       {0x86,0x8F,1,1},
/* 136  08/08  210  88  e circumflex */ {0x88,0x45,1,0},
/* 137  08/09  211  89  e diaeresis */  {0x89,0x45,1,0},
/* 138  08/10  212  8A  e grave */      {0x8A,0x45,1,0},
/* 139  08/11  213  8B  i diaeresis */  {0x8B,0x49,1,0},
/* 140  08/12  214  8C  i circumflex */ {0x8C,0x49,1,0},
/* 141  08/13  215  8D  i grave */      {0x8D,0x49,1,0},
/* 145  09/01  221  91  ae diphthong */
/* 146  09/02  222  92  AE diphthong */	{0x91,0x92,1,1},
/* 147  09/03  223  93  o circumflex */ {0x93,0x4F,1,0},
/* 148  09/04  224  94  o diaeresis */
/* 153  09/09  231  99  O diaeresis */	{0x94,0x99,1,1},
/* 149  09/05  225  95  o grave */      {0x95,0x4F,1,0},
/* 150  09/06  226  96  u circumflex */ {0x96,0x55,1,0},
/* 151  09/07  227  97  u grave */      {0x97,0x55,1,0},
/* 152  ??/??  201  98  u diaeresis */
  {0x9B,0,0,0},     /* Cent         */
  {0x9C,0,0,0},     /* Pound        */
  {0x9D,0,0,0},     /* Yen          */
/* 160  10/00  240  A0  a acute */      {0xA0,0x41,1,0},
/* 161  10/01  241  A1  i acute */      {0xA1,0x49,1,0},
/* 162  10/02  242  A2  o acute */      {0xA2,0x4F,1,0},
/* 163  10/03  243  A3  u acute */      {0xA3,0x55,1,0},
/* 164  10/04  244  A4  n tilde */
/* 165  10/05  245  A5  N tilde */	{0xA4,0xA5,1,1},
/* Punctuation... */
  {0xA8,0,0,0}, 
  {0xAD,0,0,0},
  {0xAE,0,0,0},
  {0xAF,0,0,0},
/* Greek character set */
  {0xE0,0,0,0},
  {0xE1,0,0,0},
  {0xE2,0,0,0},
  {0xE3,0,0,0},
  {0xE4,0,0,0},
  {0xE5,0,0,0},
  {0xE6,0,0,0},
  {0xE7,0,0,0},
  {0xE8,0,0,0},
  {0xE9,0,0,0},
  {0xEA,0,0,0},
  {0xEB,0,0,0},
  {0xEC,0,0,0},
  {0xED,0,0,0},
  {0xEE,0,0,0},
  {0xEF,0,0,0},
  {0,0,0,0}
};

/* lower->upper mapping for IBM Code Page 932 - MS-DOS Japanese SJIS */
unsigned char cp_932[][4] = {
  {0,0,0,0}
};
 
char xx_dos_char_map[256];
char xx_upper_char_map[256];
char xx_lower_char_map[256];

char *dos_char_map = xx_dos_char_map;
char *upper_char_map = xx_upper_char_map;
char *lower_char_map = xx_lower_char_map;

/*
 * This code has been extended to deal with ascynchronous mappings
 * like MS-DOS Latin US (Code page 437) where things like :
 * a acute are capitalized to 'A', but the reverse mapping
 * must not hold true. This allows the filename case insensitive
 * matching in do_match() to work, as the DOS/Win95/NT client 
 * uses 'A' as a mask to match against characters like a acute.
 * This is the meaning behind the parameters that allow a
 * mapping from lower to upper, but not upper to lower.
 */

static void add_dos_char(int lower, BOOL map_lower_to_upper, 
                         int upper, BOOL map_upper_to_lower)
{
  lower &= 0xff;
  upper &= 0xff;
  DEBUG(6,("Adding chars 0x%x 0x%x (l->u = %s) (u->l = %s)\n",lower,upper,
         map_lower_to_upper ? "True" : "False",
         map_upper_to_lower ? "True" : "False"));
  if (lower) dos_char_map[lower] = 1;
  if (upper) dos_char_map[upper] = 1;
  if (lower && upper) {
    if(map_upper_to_lower)
      lower_char_map[upper] = (char)lower;
    if(map_lower_to_upper)
      upper_char_map[lower] = (char)upper;
  }
}

/****************************************************************************
initialise the charset arrays
****************************************************************************/
void charset_initialise()
{
  int i;

#ifdef LC_ALL
  /* include <locale.h> in includes.h if available for OS                  */
  /* we take only standard 7-bit ASCII definitions from ctype              */
  setlocale(LC_ALL,"C");
#endif

  for (i= 0;i<=255;i++) {
    dos_char_map[i] = 0;
  }

  for (i=0;i<=127;i++) {
    if (isalnum((char)i) || strchr("._^$~!#%&-{}()@'`",(char)i))
      add_dos_char(i,False,0,False);
  }

  for (i=0; i<=255; i++) {
    char c = (char)i;
    upper_char_map[i] = lower_char_map[i] = c;
    if (isupper(c)) lower_char_map[i] = tolower(c);
    if (islower(c)) upper_char_map[i] = toupper(c);
  }
}

/****************************************************************************
initialise the client codepage.
****************************************************************************/
void codepage_initialise(int client_codepage)
{
  int i;
  unsigned char (*cp)[4] = NULL;
  static BOOL done = False;

  if(done == True) 
  {
    DEBUG(6,
      ("codepage_initialise: called twice - ignoring second client code page = %d\n",
      client_codepage));
    return;
  }

  DEBUG(6,("codepage_initialise: client code page = %d\n", client_codepage));

  /*
   * Known client codepages - these can be added to.
   */
  switch(client_codepage)
  {
    case 850:
      cp = cp_850;
      break;
    case 437:
      cp = cp_437;
      break;
    case 932:
      cp = cp_932;
      break;
    default:
#ifdef KANJI
      /* Use default codepage - currently 932 */
      DEBUG(6,("codepage_initialise: Using default client codepage %d\n", 
               932));
      cp = cp_932;
#else /* KANJI */
      /* Use default codepage - currently 850 */
      DEBUG(6,("codepage_initialise: Using default client codepage %d\n", 
               850));
      cp = cp_850;
#endif /* KANJI */
      break;
  }

  if(cp)
  {
    for(i = 0; !((cp[i][0] == '\0') && (cp[i][1] == '\0')); i++)
      add_dos_char(cp[i][0], (BOOL)cp[i][2], cp[i][1], (BOOL)cp[i][3]);
  }

  done = True;
}

/*******************************************************************
add characters depending on a string passed by the user
********************************************************************/
void add_char_string(char *s)
{
  char *extra_chars = (char *)strdup(s);
  char *t;
  if (!extra_chars) return;

  for (t=strtok(extra_chars," \t\r\n"); t; t=strtok(NULL," \t\r\n")) {
    char c1=0,c2=0;
    int i1=0,i2=0;
    if (isdigit((unsigned char)*t) || (*t)=='-') {
      sscanf(t,"%i:%i",&i1,&i2);
      add_dos_char(i1,True,i2,True);
    } else {
      sscanf(t,"%c:%c",&c1,&c2);
      add_dos_char((unsigned char)c1,True,(unsigned char)c2, True);
    }
  }

  free(extra_chars);
}
