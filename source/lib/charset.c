/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set handling
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

#define CHARSET_C
#include "includes.h"

extern int DEBUGLEVEL;

char xx_dos_char_map[256];
char xx_upper_char_map[256];
char xx_lower_char_map[256];

char *dos_char_map = NULL;
char *upper_char_map = NULL;
char *lower_char_map = NULL;

static void add_dos_char(int lower, int upper)
{
  DEBUG(6,("Adding chars 0%o 0%o\n",lower,upper));
  if (lower) dos_char_map[(char)lower] = 1;
  if (upper) dos_char_map[(char)upper] = 1;
  if (lower && upper) {
    lower_char_map[(char)upper] = (char)lower;
    upper_char_map[(char)lower] = (char)upper;
  }
}

/****************************************************************************
initialise the charset arrays
****************************************************************************/
void charset_initialise(void)
{
  int i;

  dos_char_map = &xx_dos_char_map[128];
  upper_char_map = &xx_upper_char_map[128];
  lower_char_map = &xx_lower_char_map[128];

  for (i= -128;i<=127;i++) {
    dos_char_map[(char)i] = 0;
  }

  for (i=0;i<=127;i++) {
    if (isalnum((char)i) || strchr("._^$~!#%&-{}()@'`",(char)i))
      add_dos_char(i,0);
  }

  for (i= -128;i<=127;i++) {
    char c = (char)i;
    upper_char_map[i] = lower_char_map[i] = c;
    if (isupper(c)) lower_char_map[c] = tolower(c);
    if (islower(c)) upper_char_map[c] = toupper(c);
  }

  /* valid for all DOS PC */
  add_dos_char(142,0);     /* A trema      */
  add_dos_char(143,0);     /* A o          */
  add_dos_char(144,0);     /* E '          */
  add_dos_char(146,0);     /* AE           */
  add_dos_char(153,0);     /* O trema      */
  add_dos_char(154,0);     /* U trema      */
  add_dos_char(165,0);     /* N tilda      */
  add_dos_char(128,0);     /* C cedille    */
  add_dos_char(156,0);     /* Pound        */
  add_dos_char(183,0);     /* A `     (WIN)*/
  add_dos_char(157,0);     /* Phi     (WIN)*/
  add_dos_char(212,0);     /* E`      (WIN)*/
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
