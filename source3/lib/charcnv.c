/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set conversion Extensions
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
#define CTRLZ 26
extern int DEBUGLEVEL;

static char cvtbuf[1024];

static BOOL mapsinited = 0;

static char unix2dos[256];
static char dos2unix[256];

static void initmaps(void) {
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

static void init_iso8859_1(void) {

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

/* Init for eastern european languages. */

static void init_iso8859_2(void) {

    int i;
    if (!mapsinited) initmaps();

    /* Do not map undefined characters to some accidental code */
    for (i = 128; i < 256; i++) 
    {
       unix2dos[i] = CTRLZ;
       dos2unix[i] = CTRLZ;
    }

/*
 * Tranlation table created by Petr Hubeny <psh@capitol.cz>
 * Requires client code page = 852
 * and character set = ISO8859-2 in smb.conf
 */

/* MSDOS Code Page 852 -> ISO-8859-2 */
update_map("\241\244\242\364\243\235\244\317\245\225\246\227\247\365");
update_map("\250\371\251\346\252\270\253\233\254\215\256\246\257\275");
update_map("\261\245\262\362\263\210\264\357\265\226\266\230\267\363");
update_map("\270\367\271\347\272\255\273\234\274\253\275\361\276\247\277\276");
update_map("\300\350\301\265\302\266\303\306\304\216\305\221\306\217\307\200");
update_map("\310\254\311\220\312\250\313\323\314\267\315\326\316\327\317\322");
update_map("\320\321\321\343\322\325\323\340\324\342\325\212\326\231\327\236");
update_map("\330\374\331\336\332\351\333\353\334\232\335\355\336\335\337\341");
update_map("\340\352\341\240\342\203\343\307\344\204\345\222\346\206\347\207");
update_map("\350\237\351\202\352\251\353\211\354\330\355\241\356\214\357\324");
update_map("\360\320\361\344\362\345\363\242\364\223\365\213\366\224\367\366");
update_map("\370\375\371\205\372\243\373\373\374\201\375\354\376\356\377\372");
}

/* Init for russian language (iso8859-5) */

/* Added by Max Khon <max@iclub.nsu.ru> */

static void init_iso8859_5(void)
{
  int i;
  if (!mapsinited) initmaps();

  /* Do not map undefined characters to some accidental code */
  for (i = 128; i < 256; i++) 
  {
     unix2dos[i] = CTRLZ;
     dos2unix[i] = CTRLZ;
  }

/* MSDOS Code Page 866 -> ISO8859-5 */
update_map("\200\260\201\261\202\262\203\263\204\264\205\265\206\266\207\267");
update_map("\210\270\211\271\212\272\213\273\214\274\215\275\216\276\217\277");
update_map("\220\300\221\301\222\302\223\303\224\304\225\305\226\306\227\307");
update_map("\230\310\231\311\232\312\233\313\234\314\235\315\236\316\237\317");
update_map("\240\320\241\321\242\322\243\323\244\324\245\325\246\326\247\327");
update_map("\250\330\251\331\252\332\253\333\254\334\255\335\256\336\257\337");
update_map("\340\340\341\341\342\342\343\343\344\344\345\345\346\346\347\347");
update_map("\350\350\351\351\352\352\353\353\354\354\355\355\356\356\357\357");
update_map("\360\241\361\361\362\244\363\364\364\247\365\367\366\256\367\376");
update_map("\374\360\377\240");
}

/* Init for russian language (koi8) */

static void init_koi8_r(void)
{
  if (!mapsinited) initmaps();

  /* There aren't undefined characters between 128 and 255 */

/* MSDOS Code Page 866 -> KOI8-R */
update_map("\200\304\201\263\202\332\203\277\204\300\205\331\206\303\207\264");
update_map("\210\302\211\301\212\305\213\337\214\334\215\333\216\335\217\336");
update_map("\220\260\221\261\222\262\223\364\224\376\225\371\226\373\227\367");
update_map("\230\363\231\362\232\377\233\365\234\370\235\375\236\372\237\366");
update_map("\240\315\241\272\242\325\243\361\244\326\245\311\246\270\247\267");
update_map("\250\273\251\324\252\323\253\310\254\276\255\275\256\274\257\306");
update_map("\260\307\261\314\262\265\263\360\264\266\265\271\266\321\267\322");
update_map("\270\313\271\317\272\320\273\312\274\330\275\327\276\316\277\374");
update_map("\300\356\301\240\302\241\303\346\304\244\305\245\306\344\307\243");
update_map("\310\345\311\250\312\251\313\252\314\253\315\254\316\255\317\256");
update_map("\320\257\321\357\322\340\323\341\324\342\325\343\326\246\327\242");
update_map("\330\354\331\353\332\247\333\350\334\355\335\351\336\347\337\352");
update_map("\340\236\341\200\342\201\343\226\344\204\345\205\346\224\347\203");
update_map("\350\225\351\210\352\211\353\212\354\213\355\214\356\215\357\216");
update_map("\360\217\361\237\362\220\363\221\364\222\365\223\366\206\367\202");
update_map("\370\234\371\233\372\207\373\230\374\235\375\231\376\227\377\232");
}

/*
 * Convert unix to dos
 */
char *unix2dos_format(char *str,BOOL overwrite)
{
    char *p;
    char *dp;

    if (!mapsinited) initmaps();

      if (overwrite) {
          for (p = str; *p; p++) *p = unix2dos[(unsigned char)*p];
          return str;
      } else {
          for (p = str, dp = cvtbuf; *p; p++,dp++) *dp = unix2dos[(unsigned char)*p];
          *dp = 0;
          return cvtbuf;
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

      if (overwrite) {
          for (p = str; *p; p++) *p = dos2unix[(unsigned char)*p];
          return str;
      } else {
          for (p = str, dp = cvtbuf; *p; p++,dp++) *dp = dos2unix[(unsigned char)*p];
          *dp = 0;
          return cvtbuf;
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
    } else if (strequal (str, "iso8859-5")) {
        init_iso8859_5();
    } else if (strequal (str, "koi8-r")) {
        init_koi8_r();
    } else {
        DEBUG(0,("unrecognized character set\n"));
    }
}
