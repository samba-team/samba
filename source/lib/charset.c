/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set handling
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

#define CHARSET_C
#include "includes.h"

extern int DEBUGLEVEL;

/*
 * Codepage definitions.
 */

#if !defined(KANJI)
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
#else /* KANJI */ 
/* lower->upper mapping for IBM Code Page 932 - MS-DOS Japanese SJIS */
unsigned char cp_932[][4] = {
  {0,0,0,0}
};
#endif /* KANJI */

char xx_dos_char_map[256];
char xx_upper_char_map[256];
char xx_lower_char_map[256];

char *dos_char_map = xx_dos_char_map;
char *upper_char_map = xx_upper_char_map;
char *lower_char_map = xx_lower_char_map;

