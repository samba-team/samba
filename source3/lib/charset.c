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

char xx_dos_char_map[256];
char xx_upper_char_map[256];
char xx_lower_char_map[256];

char *dos_char_map = xx_dos_char_map;
char *upper_char_map = xx_upper_char_map;
char *lower_char_map = xx_lower_char_map;

static void add_dos_char(int lower, int upper)
{
  lower &= 0xff;
  upper &= 0xff;
  DEBUG(6,("Adding chars 0%o 0%o\n",lower,upper));
  if (lower) dos_char_map[lower] = 1;
  if (upper) dos_char_map[upper] = 1;
  if (lower && upper) {
    lower_char_map[upper] = (char)lower;
    upper_char_map[lower] = (char)upper;
  }
}

/****************************************************************************
initialise the charset arrays
****************************************************************************/
void charset_initialise(void)
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
      add_dos_char(i,0);
  }

  for (i=0; i<=255; i++) {
    char c = (char)i;
    upper_char_map[i] = lower_char_map[i] = c;
    if (isupper(c)) lower_char_map[i] = tolower(c);
    if (islower(c)) upper_char_map[i] = toupper(c);
  }

#define CP850
#ifdef CP850
/* lower->upper mapping for IBM Code Page 850 */

/* dec col/row oct hex  description */
/* 133  08/05  205  85  a grave */
/* 183  11/07  267  B7  A grave */ 	add_dos_char(0205,0267);
/* 160  10/00  240  A0  a acute */
/* 181  11/05  265  B5  A acute */	add_dos_char(0240,0265);
/* 131  08/03  203  83  a circumflex */
/* 182  11/06  266  B6  A circumflex */	add_dos_char(0203,0266);
/* 198  12/06  306  C6  a tilde */
/* 199  12/07  307  C7  A tilde */	add_dos_char(0306,0307);
/* 132  08/04  204  84  a diaeresis */
/* 142  08/14  216  8E  A diaeresis */	add_dos_char(0204,0216);
/* 134  08/06  206  86  a ring */
/* 143  08/15  217  8F  A ring */	add_dos_char(0206,0217);
/* 145  09/01  221  91  ae diphthong */
/* 146  09/02  222  92  AE diphthong */	add_dos_char(0221,0222);
/* 128  08/00  200  80  C cedilla */
/* 135  08/07  207  87  c cedilla */	add_dos_char(0207,0200);
/* 138  08/10  212  8A  e grave */
/* 212  13/04  324  D4  E grave */	add_dos_char(0212,0324);
/* 130  08/02  202  82  e acute */
/* 144  09/00  220  90  E acute */	add_dos_char(0202,0220);
/* 136  08/08  210  88  e circumflex */
/* 210  13/02  322  D2  E circumflex */	add_dos_char(0210,0322);
/* 137  08/09  211  89  e diaeresis */
/* 211  13/03  323  D3  E diaeresis */	add_dos_char(0211,0323);
/* 141  08/13  215  8D  i grave */
/* 222  13/14  336  DE  I grave */	add_dos_char(0215,0336);
/* 161  10/01  241  A1  i acute */
/* 214  13/06  326  D6  I acute */	add_dos_char(0241,0326);
/* 140  08/12  214  8C  i circumflex */
/* 215  13/07  327  D7  I circumflex */	add_dos_char(0214,0327);
/* 139  08/11  213  8B  i diaeresis */
/* 216  13/08  330  D8  I diaeresis */	add_dos_char(0213,0330);
/* 208  13/00  320  D0  Icelandic eth */
/* 209  13/01  321  D1  Icelandic Eth */ add_dos_char(0320,0321);
/* 164  10/04  244  A4  n tilde */
/* 165  10/05  245  A5  N tilde */	add_dos_char(0244,0245);
/* 149  09/05  225  95  o grave */
/* 227  14/03  343  E3  O grave */	add_dos_char(0225,0343);
/* 162  10/02  242  A2  o acute */
/* 224  14/00  340  E0  O acute */	add_dos_char(0242,0340);
/* 147  09/03  223  93  o circumflex */
/* 226  14/02  342  E2  O circumflex */	add_dos_char(0223,0342);
/* 228  14/04  344  E4  o tilde */
/* 229  14/05  345  E5  O tilde */	add_dos_char(0344,0345);
/* 148  09/04  224  94  o diaeresis */
/* 153  09/09  231  99  O diaeresis */	add_dos_char(0224,0231);
/* 155  09/11  233  9B  o slash */
/* 157  09/13  235  9D  O slash */	add_dos_char(0233,0235);
/* 151  09/07  227  97  u grave */
/* 235  14/11  353  EB  U grave */ 	add_dos_char(0227,0353);
/* 163  10/03  243  A3  u acute */
/* 233  14/09  351  E9  U acute */	add_dos_char(0243,0351);
/* 150  09/06  226  96  u circumflex */
/* 234  14/10  352  EA  U circumflex */ add_dos_char(0226,0352);
/* 129  08/01  201  81  u diaeresis */
/* 154  09/10  232  9A  U diaeresis */	add_dos_char(0201,0232);
/* 236  14/12  354  EC  y acute */
/* 237  14/13  355  ED  Y acute */	add_dos_char(0354,0355);
/* 231  14/07  347  E7  Icelandic thorn */
/* 232  14/08  350  E8  Icelandic Thorn */ add_dos_char(0347,0350);
   
  add_dos_char(156,0);     /* Pound        */
#endif
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
    if (isdigit(*t) || (*t)=='-') {
      sscanf(t,"%i:%i",&i1,&i2);
      add_dos_char(i1,i2);
    } else {
      sscanf(t,"%c:%c",&c1,&c2);
      add_dos_char(c1,c2);
    }
  }

  free(extra_chars);
}
