/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set conversion Extensions
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
#include "includes.h"
#define CTRLZ 26
extern int DEBUGLEVEL;

static char cvtbuf[1024];

static BOOL mapsinited = 0;

static char unix2dos[256];
static char dos2unix[256];

static void initmaps() {
    int k;

    for (k = 0; k < 256; k++) unix2dos[k] = k;
    for (k = 0; k < 256; k++) dos2unix[k] = k;

    mapsinited = True;
}

static void update_map(char * str) {
    char *p;

    for (p = str; *p; p++) {
        if (p[1]) {
            unix2dos[(unsigned char)*p] = p[1];
            dos2unix[(unsigned char)p[1]] = *p;
            p++;
        }
    }
}

static void init_iso8859_1() {

    int i;
    if (!mapsinited) initmaps();

    /* Do not map undefined characters to some accidental code */
    for (i = 128; i < 256; i++) 
    {
       unix2dos[i] = CTRLZ;
       dos2unix[i] = CTRLZ;
    }

/* MSDOS Code Page 850 -> ISO-8859 */
update_map("\240\377\241\255\242\275\243\234\244\317\245\276\246\335\247\365");
update_map("\250\371\251\270\252\246\253\256\254\252\255\360\256\251\257\356");
update_map("\260\370\261\361\262\375\263\374\264\357\265\346\266\364\267\372");
update_map("\270\367\271\373\272\247\273\257\274\254\275\253\276\363\277\250");
update_map("\300\267\301\265\302\266\303\307\304\216\305\217\306\222\307\200");
update_map("\310\324\311\220\312\322\313\323\314\336\315\326\316\327\317\330");
update_map("\320\321\321\245\322\343\323\340\324\342\325\345\326\231\327\236");
update_map("\330\235\331\353\332\351\333\352\334\232\335\355\336\350\337\341");
update_map("\340\205\341\240\342\203\343\306\344\204\345\206\346\221\347\207");
update_map("\350\212\351\202\352\210\353\211\354\215\355\241\356\214\357\213");
update_map("\360\320\361\244\362\225\363\242\364\223\365\344\366\224\367\366");
update_map("\370\233\371\227\372\243\373\226\374\201\375\354\376\347\377\230");

}

/* Init for eastern european languages. May need more work ? */

static void init_iso8859_2() {

    int i;
    if (!mapsinited) initmaps();

    /* Do not map undefined characters to some accidental code */
    for (i = 128; i < 256; i++) 
    {
       unix2dos[i] = CTRLZ;
       dos2unix[i] = CTRLZ;
    }

update_map("\241\244\306\217\312\250\243\235\321\343\323\340\246\227\254\215");
update_map("\257\275\261\245\346\206\352\251\263\210\361\344\363\242\266\230");
update_map("\274\253\277\276");
}

/*
 * Convert unix to dos
 */
char *unix2dos_format(char *str,BOOL overwrite)
{
    char *p;
    char *dp;

    if (!mapsinited) initmaps();

    if(lp_client_code_page() == KANJI_CODEPAGE)
      return (*_unix_to_dos)(str, overwrite);
    else {
      if (overwrite) {
          for (p = str; *p; p++) *p = unix2dos[(unsigned char)*p];
          return str;
      } else {
          for (p = str, dp = cvtbuf; *p; p++,dp++) *dp = unix2dos[(unsigned char)*p];
          *dp = 0;
          return cvtbuf;
      }
    }
}

/*
 * Convert dos to unix
 */
char *dos2unix_format(char *str, BOOL overwrite)
{
    char *p;
    char *dp;

    if (!mapsinited) initmaps();

    if(lp_client_code_page() == KANJI_CODEPAGE)
      return (*_dos_to_unix)(str, overwrite);
    else {
      if (overwrite) {
          for (p = str; *p; p++) *p = dos2unix[(unsigned char)*p];
          return str;
      } else {
          for (p = str, dp = cvtbuf; *p; p++,dp++) *dp = dos2unix[(unsigned char)*p];
          *dp = 0;
          return cvtbuf;
      }
    }
}


/*
 * Interpret character set.
 */
void interpret_character_set(char *str)
{
    if (strequal (str, "iso8859-1")) {
        init_iso8859_1();
    } else if (strequal (str, "iso8859-2")) {
        init_iso8859_2();
    } else {
        DEBUG(0,("unrecognized character set\n"));
    }
}
