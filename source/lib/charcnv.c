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
#define CTRLZ 	26
#define SPC 	32

static char cvtbuf[sizeof(pstring)];

static BOOL mapsinited = 0;

static char unix2dos[256];
static char dos2unix[256];

static void initmaps(void) {
    int k;

    for (k = 0; k < 256; k++) unix2dos[k] = k;
    for (k = 0; k < 256; k++) dos2unix[k] = k;

    mapsinited = True;
}

static void update_map(const char *str) {
    const char *p;

    for (p = str; *p; p++) {
        if (p[1]) {
            unix2dos[(unsigned char)*p] = p[1];
            dos2unix[(unsigned char)p[1]] = *p;
            p++;
        }
    }
}

static void setupmaps(void)
{
    int i;
    if (!mapsinited) initmaps();

    /* Do not map undefined characters to some accidental code */
    for (i = 128; i < 256; i++)
    {
#if 0 	/* JERRY */
	/* Win2k & XP don't like the Ctrl-Z apparently */
	/* patch from Toomas.Soome@microlink.ee */
       unix2dos[i] = CTRLZ;
       dos2unix[i] = CTRLZ;
#else
       unix2dos[i] = SPC;
       dos2unix[i] = SPC;
#endif
    }
}

static void init_iso8859_1(int codepage) {

	setupmaps();

    if (codepage == 437) {
        /* MSDOS Code Page 437 -> ISO-8859-1 */
        update_map("\xA1\xAD\xA2\x98\xA3\x9C\xA4\xED\xA5\x9D\xA6\xB3\xA7\xEE");
        update_map("\xAA\xA6\xAB\xAE\xAC\xAA\xAE\xE9\xAF\xC4");
        update_map("\xB0\xF8\xB1\xF1\xB2\xFD\xB5\xE6\xB7\xFA\xBA\xA7\xBC\xAC\xBD\xAB\xBF\xA8");
        update_map("\xC0\x85\xC1\xA0\xC2\x83\xC4\x8E\xC5\x8F\xC6\x92\xC7\x80\xC8\x8A");
        update_map("\xC9\x90\xCA\x88\xCB\x89\xCC\x8D\xCD\xA1\xCE\x8C\xCF\x8B");
        update_map("\xD1\xA5\xD2\x96\xD3\xA2\xD4\x93\xD6\x99\xD9\x97\xDA\xA3\xDB\x96\xDC\x9A\xDF\xE1");
        update_map("\xE0\x85\xE1\xA0\xE2\x83\xE4\x84\xE5\x86\xE6\x91\xE7\x87\xE8\x8A\xE9\x82\xEA\x88\xEB\x89\xEC\x8D\xED\xA1\xEE\x8C\xEF\x8B");
        update_map("\xF0\xEB\xF1\xA4\xF2\x95\xF3\xA2\xF4\x93\xF6\x94\xF7\xF6\xF8\xED\xF9\x97\xFA\xA3\xFB\x96\xFC\x81\xFF\x98");
    } else {
        /* MSDOS Code Page 850 -> ISO-8859-1 */
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
}

static void init_iso8859_15(int codepage) {

	setupmaps();


    if (codepage == 775) {
        /* MSDOS Code Page 775 -> ISO-8859-15  this is for estonian */
update_map("\240\377\242\226\243\234\246\276\247\365");
update_map("\250\325\251\250\253\256\254\252\255\360\256\251");
update_map("\260\370\261\361\262\375\263\374\264\317\265\346\266\364\267\372");
update_map("\270\330\271\373\273\257");
update_map("\304\216\305\217\306\222");
update_map("\311\220");
update_map("\323\340\325\345\326\231\327\236");
update_map("\330\235\334\232\337\341");
update_map("\344\204\345\206\346\221");
update_map("\351\202");
update_map("\363\242\365\344\366\224\367\366");
update_map("\370\233\374\201");
    } else {
        /* MSDOS Code Page 850 -> ISO-8859-15 */
update_map("\240\377\241\255\242\275\243\234\244\317\245\276\246\321\247\365");
update_map("\250\320\251\270\252\246\253\256\254\252\255\360\256\251\257\356");
update_map("\260\370\261\361\262\375\263\374\264\350\265\346\266\364\267\372");
update_map("\270\347\271\373\272\247\273\257\274\254\275\253\276\363\277\250");
update_map("\300\267\301\265\302\266\303\307\304\216\305\217\306\222\307\200");
update_map("\310\324\311\220\312\322\313\323\314\336\315\326\316\327\317\330");
update_map("\320\321\321\245\322\343\323\340\324\342\325\345\326\231\327\236");
update_map("\330\235\331\353\332\351\333\352\334\232\335\355\336\350\337\341");
update_map("\340\205\341\240\342\203\343\306\344\204\345\206\346\221\347\207");
update_map("\350\212\351\202\352\210\353\211\354\215\355\241\356\214\357\213");
update_map("\360\320\361\244\362\225\363\242\364\223\365\344\366\224\367\366");
update_map("\370\233\371\227\372\243\373\226\374\201\375\354\376\347\377\230");
}
}

/* Init for eastern european languages. */

static void init_iso8859_2(void) {

	setupmaps();

/*
 * Tranlation table created by Petr Hubeny <psh@capitol.cz>
 * Requires client code page = 852
 * and character set = ISO8859-2 in smb.conf
 */

/* MSDOS Code Page 852 -> ISO-8859-2 */
update_map("\240\377"); /* Fix for non-breaking space */
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
/* 1125 mapping added by Alexander Bokovoy <a.bokovoy@sam-solutions.net> */
static void init_iso8859_5(int codepage)
{
	setupmaps();

	if (codepage == 1125) {
/* MSDOS Code Page 1125 -> ISO8859-5 */
update_map ("\360\374\361\361\340\340\341\341\320\240\342\342\321\241\300\220");
update_map ("\364\365\343\343\322\242\301\221\260\200\344\344\323\243\302\222");
update_map ("\261\201\366\367\241\360\345\345\324\244\303\223\262\202\367\371");
update_map ("\346\346\325\245\304\224\263\203\347\347\326\246\305\225\264\204");
update_map ("\244\364\350\350\327\247\306\226\265\205\351\351\330\250\307\227");
update_map ("\266\206\246\366\331\251\310\230\267\207\247\370\311\231\270\210");
update_map ("\271\211");
        } else {
/* MSDOS Code Page 866 -> ISO8859-5 */
update_map("\260\200\261\201\262\202\263\203\264\204\265\205\266\206\267\207");
update_map("\270\210\271\211\272\212\273\213\274\214\275\215\276\216\277\217");
update_map("\300\220\301\221\302\222\303\223\304\224\305\225\306\226\307\227");
update_map("\310\230\311\231\312\232\313\233\314\234\315\235\316\236\317\237");
update_map("\320\240\321\241\322\242\323\243\324\244\325\245\326\246\327\247");
update_map("\330\250\331\251\332\252\333\253\334\254\335\255\336\256\337\257");
update_map("\340\340\341\341\342\342\343\343\344\344\345\345\346\346\347\347");
update_map("\350\350\351\351\352\352\353\353\354\354\355\355\356\356\357\357");
update_map("\241\360\361\361\244\362\364\363\247\364\367\365\256\366\376\367");
update_map("\360\374\240\377");
	}
}

/* Added by Antonios Kavarnos (Antonios.Kavarnos@softlab.ece.ntua.gr */

static void init_iso8859_7(void)
{
	setupmaps();

/* MSDOS Code Page 737 -> ISO-8859-7 (Greek-Hellenic) */

update_map("\301\200\302\201\303\202\304\203\305\204\306\205\307\206");
update_map("\310\207\311\210\312\211\313\212\314\213\315\214\316\215\317\216");
update_map("\320\217\321\220\323\221\324\222\325\223\326\224\327\225");
update_map("\330\226\331\227");
update_map("\341\230\342\231\343\232\344\233\345\234\346\235\347\236");
update_map("\350\237\351\240\352\241\353\242\354\243\355\244\356\245\357\246");
update_map("\360\247\361\250\362\252\363\251\364\253\365\254\366\255\367\256");
update_map("\370\257\371\340");
update_map("\332\364\333\365\334\341\335\342\336\343\337\345");
update_map("\372\344\373\350\374\346\375\347\376\351");
update_map("\266\352");
update_map("\270\353\271\354\272\355\274\356\276\357\277\360");
}

/* Added by Yedidyah Bar-David (didi@tau.ac.il) */

static void init_iso8859_8(void)
{
       setupmaps();

/* MSDOS Code Page 862 -> ISO-8859-8 (Hebrew) */

update_map("\340\200\341\201\342\202\343\203\344\204\345\205\346\206\347\207");
update_map("\350\210\351\211\352\212\353\213\354\214\355\215\356\216\357\217");
update_map("\360\220\361\221\362\222\363\223\364\224\365\225\366\226\367\227");
update_map("\370\230\371\231\372\232");
}

/* Added by Deniz Akkus (akkus@alum.mit.edu) */

static void init_iso8859_9(void)
{
  setupmaps();

  /* MSDOS Code Page 857 -> ISO-8859-9 (Turkish) */

  update_map("\xa0\xff\xa1\xad\xa2\xbd\xa3\x9c\xa4\xcf\xA5\xbe\xa6\xdd\xa7\xf5");
  update_map("\xa8\xf9\xa9\xb8\xaa\xd1\xab\xae\xac\xaa\xad\xf0\xae\xa9\xaf\xee");
  update_map("\xb0\xf8\xb1\xf1\xb2\xfd\xb3\xfc\xb4\xef\xb5\xe6\xb6\xf4\xb7\xfa");
  update_map("\xb8\xf7\xb9\xfb\xba\xd0\xbb\xaf\xbc\xac\xbd\xab\xbe\xf3\xbf\xa8");
  update_map("\xc0\xb7\xc1\xb5\xc2\xb6\xc3\xc7\xc4\x8e\xc5\x8f\xc6\x92\xc7\x80");
  update_map("\xc8\xd4\xc9\x90\xca\xd2\xcb\xd3\xcc\xde\xcd\xd6\xce\xd7\xcf\xd8");
  update_map("\xd0\xa6\xd1\xa5\xd2\xe3\xd3\xe0\xd4\xe2\xd5\xe5\xd6\x99\xd7\xe8");
  update_map("\xd8\x9d\xd9\xeb\xda\xe9\xdb\xea\xdc\x9a\xdd\x98\xde\x9e\xdf\xe1");
  update_map("\xe0\x85\xe1\xa0\xe2\x83\xe3\xc6\xe4\x84\xe5\x86\xe6\x91\xe7\x87");
  update_map("\xe8\x8a\xe9\x82\xea\x88\xeb\x89\xec\xec\xed\xa1\xee\x8c\xef\x8b");
  update_map("\xf0\xa7\xf1\xa4\xf2\x95\xf3\xa2\xf4\x93\xf5\xe4\xf6\x94\xf7\xf6");
  update_map("\xf8\x9b\xf9\x97\xfa\xa3\xfb\x96\xfc\x81\xfd\x8d\xfe\x9f\xff\xed");
}

/* init for Baltic Rim */

static void init_iso8859_13(void) {

	setupmaps();

        /* MSDOS Code Page 775 -> ISO-8859-13 */
update_map("\240\377\241\246\242\226\243\234\244\237\245\367\246\247\247\365");
update_map("\250\235\251\250\252\212\253\256\254\252\255\360\256\251\257\222");
update_map("\260\370\261\361\262\375\263\374\264\362\265\346\266\364\267\372");
update_map("\270\233\271\373\272\213\273\257\274\254\275\253\276\363\277\221");
update_map("\300\265\301\275\302\240\303\200\304\216\305\217\306\267\307\355");
update_map("\310\266\311\220\312\215\313\270\314\225\315\350\316\241\317\352");
update_map("\320\276\321\343\322\356\323\340\324\342\325\345\326\231\327\236");
update_map("\330\306\331\255\332\227\333\307\334\232\335\243\336\317\337\341");
update_map("\340\320\341\324\342\203\343\207\344\204\345\206\346\322\347\211");
update_map("\350\321\351\202\352\245\353\323\354\205\355\351\356\214\357\353");
update_map("\360\325\361\347\362\354\363\242\364\223\365\344\366\224\367\366");
update_map("\370\326\371\210\372\230\373\327\374\201\375\244\376\330\377\357");
}

/* Init for russian language (koi8) */

static void init_koi8_r(void)
{
	setupmaps();

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

/* Init for Bulgarian, Belarussian, and variants of Russian and Ukrainian locales */
/* Patch from Alexander Bokovoy. */

static void init_1251(int codepage)
{
	setupmaps();

	if (codepage == 866) {
/* MSDOS Code Page 866 -> 1251 */
update_map ("\240\377\241\366\242\367\244\375");
update_map ("\250\360\252\362\257\364");
update_map ("\260\370\267\372");
update_map ("\270\361\271\374\272\363\277\365");
update_map ("\300\200\301\201\302\202\303\203\304\204\305\205\306\206\307\207");
update_map ("\310\210\311\211\312\212\313\213\314\214\315\215\316\216\317\217");
update_map ("\320\220\321\221\322\222\323\223\324\224\325\225\326\226\327\227");
update_map ("\330\230\331\231\332\232\333\233\334\234\335\235\336\236\337\237");
update_map ("\340\240\341\241\342\242\343\243\344\244\345\245\346\246\347\247");
update_map ("\350\250\351\251\352\252\353\253\354\254\355\255\356\256\357\257");
update_map ("\360\340\361\341\362\342\363\343\364\344\365\345\366\346\367\347");
update_map ("\370\350\371\351\372\352\373\353\374\354\375\355\376\356\377\357");
	} else {
/* MSDOS Code Page 1125 (Ukranian) -> 1251 */
update_map ("\271\374\270\361\360\340\361\341\340\240\362\342\341\241\320\220");
update_map ("\272\365\363\343\342\242\321\221\300\200\364\344\343\243\322\222");
update_map ("\301\201\263\367\250\360\365\345\344\244\323\223\302\202\277\371");
update_map ("\366\346\345\245\324\224\303\203\367\347\346\246\325\225\304\204");
update_map ("\252\364\370\350\347\247\326\226\305\205\371\351\350\250\327\227");
update_map ("\306\206\262\366\351\251\330\230\307\207\257\370\331\231\310\210");
update_map ("\311\211\245\362\264\363");
	}
}


/* Init for ukrainian language (koi8-u)    */
/* Added by Oleg Deribas <older@iname.com> */

static void init_koi8_u(int codepage)
{
	setupmaps();

    if (codepage == 866) {
        /* MSDOS Code Page 866 -> KOI8-U */
        update_map("\x80\xC4\x81\xB3\x82\xDA\x83\xBF\x84\xC0\x85\xD9\x86\xC3\x87\xB4\x88\xC2");
        update_map("\x89\xC1\x8A\xC5\x8B\xDF\x8C\xDC\x8D\xDB\x8E\xDD\x8F\xDE\x90\xB0\x91\xB1");
        update_map("\x92\xB2\x94\xFE\x95\xF9\x96\xFB\x9A\xFF\x9C\xF8\x9E\xFA\xA0\xCD\xA1\xBA");
        update_map("\xA2\xD5\xA3\xF1\xA4\xF3\xA5\xC9\xA7\xF5\xA8\xBB\xA9\xD4\xAA\xD3\xAB\xC8");
        update_map("\xAC\xBE\xAE\xBC\xAF\xC6\xB0\xC7\xB1\xCC\xB2\xB5\xB3\xF0\xB4\xF2\xB5\xB9");
        update_map("\xB7\xF4\xB8\xCB\xB9\xCF\xBA\xD0\xBB\xCA\xBC\xD8\xBE\xCE\xC0\xEE\xC1\xA0");
        update_map("\xC2\xA1\xC3\xE6\xC4\xA4\xC5\xA5\xC6\xE4\xC7\xA3\xC8\xE5\xC9\xA8\xCA\xA9");
        update_map("\xCB\xAA\xCC\xAB\xCD\xAC\xCE\xAD\xCF\xAE\xD0\xAF\xD1\xEF\xD2\xE0\xD3\xE1");
        update_map("\xD4\xE2\xD5\xE3\xD6\xA6\xD7\xA2\xD8\xEC\xD9\xEB\xDA\xA7\xDB\xE8\xDC\xED");
        update_map("\xDD\xE9\xDE\xE7\xDF\xEA\xE0\x9E\xE1\x80\xE2\x81\xE3\x96\xE4\x84\xE5\x85");
        update_map("\xE6\x94\xE7\x83\xE8\x95\xE9\x88\xEA\x89\xEB\x8A\xEC\x8B\xED\x8C\xEE\x8D");
        update_map("\xEF\x8E\xF0\x8F\xF1\x9F\xF2\x90\xF3\x91\xF4\x92\xF5\x93\xF6\x86\xF7\x82");
        update_map("\xF8\x9C\xF9\x9B\xFA\x87\xFB\x98\xFC\x9D\xFD\x99\xFE\x97\xFF\x9A");
    } else {
        /* MSDOS Code Page 1125 -> KOI8-U */
        update_map("\x80\xC4\x81\xB3\x82\xDA\x83\xBF\x84\xC0\x85\xD9\x86\xC3\x87\xB4\x88\xC2\x89\xC1");
        update_map("\x8A\xC5\x8B\xDF\x8C\xDC\x8D\xDB\x8E\xDD\x8F\xDE\x90\xB0\x91\xB1\x92\xB2\x94\xFE");
        update_map("\x96\xFB\x9A\xFF\x9E\xFA\xA0\xCD\xA1\xBA\xA2\xD5\xA3\xF1\xA4\xF5\xA5\xC9\xA6\xF7");
        update_map("\xA7\xF9\xA8\xBB\xA9\xD4\xAA\xD3\xAB\xC8\xAC\xBE\xAD\xF3\xAE\xBC\xAF\xC6\xB0\xC7");
        update_map("\xB1\xCC\xB2\xB5\xB3\xF0\xB4\xF4\xB5\xB9\xB6\xF6\xB7\xF8\xB8\xCB\xB9\xCF\xBA\xD0");
        update_map("\xBB\xCA\xBC\xD8\xBD\xF2\xBE\xCE\xC0\xEE\xC1\xA0\xC2\xA1\xC3\xE6\xC4\xA4\xC5\xA5");
        update_map("\xC6\xE4\xC7\xA3\xC8\xE5\xC9\xA8\xCA\xA9\xCB\xAA\xCC\xAB\xCD\xAC\xCE\xAD\xCF\xAE");
        update_map("\xD0\xAF\xD1\xEF\xD2\xE0\xD3\xE1\xD4\xE2\xD5\xE3\xD6\xA6\xD7\xA2\xD8\xEC\xD9\xEB");
        update_map("\xDA\xA7\xDB\xE8\xDC\xED\xDD\xE9\xDE\xE7\xDF\xEA\xE0\x9E\xE1\x80\xE2\x81\xE3\x96");
        update_map("\xE4\x84\xE5\x85\xE6\x94\xE7\x83\xE8\x95\xE9\x88\xEA\x89\xEB\x8A\xEC\x8B\xED\x8C");
        update_map("\xEE\x8D\xEF\x8E\xF0\x8F\xF1\x9F\xF2\x90\xF3\x91\xF4\x92\xF5\x93\xF6\x86\xF7\x82");
        update_map("\xF8\x9C\xF9\x9B\xFA\x87\xFB\x98\xFC\x9D\xFD\x99\xFE\x97\xFF\x9A");
    }
}

/* Init for ROMAN-8 (HP-UX) */

static void init_roman8(void) {

	setupmaps();

/* MSDOS Code Page 850 -> ROMAN8 */
update_map("\240\377\241\267\242\266\243\324\244\322\245\323\246\327\247\330");
update_map("\250\357\253\371\255\353\256\352\257\234");
update_map("\260\356\261\355\262\354\263\370\264\200\265\207\266\245\267\244");
update_map("\270\255\271\250\272\317\273\234\274\276\275\365\276\237\277\275");
update_map("\300\203\301\210\302\223\303\226\304\240\305\202\306\242\307\243");
update_map("\310\205\311\212\312\225\313\227\314\204\315\211\316\224\317\201");
update_map("\320\217\321\214\322\235\323\222\324\206\325\241\326\233\327\221");
update_map("\330\216\331\215\332\231\333\232\334\220\335\213\336\341\337\342");
update_map("\340\265\341\307\342\306\343\321\344\320\345\326\346\336\347\340");
update_map("\350\343\351\345\352\344\355\351\357\230");
update_map("\360\350\361\347\362\372\363\346\364\364\365\363\366\360\367\254");
update_map("\370\253\371\246\372\247\373\256\374\376\375\257\376\361");
}

/*
 * Convert unix to dos
 */

char *unix2dos_format_static(const char *str)
{
	const char *p;
	char *dp;

	if (!mapsinited)
		initmaps();

	if (!str)
		return NULL;
	for (p = str, dp = cvtbuf;*p && (dp - cvtbuf < sizeof(cvtbuf) - 1); p++,dp++)
		*dp = unix2dos[(unsigned char)*p];
	*dp = 0;
	return cvtbuf;
}

char *unix2dos_format(char *str)
{
	char *p;

	if (!mapsinited)
		initmaps();

	if (!str)
		return NULL;
	for (p = str; *p; p++)
		*p = unix2dos[(unsigned char)*p];
	return str;
}

/*
 * Convert dos to unix
 */

char *dos2unix_format_static(const char *str)
{
	const char *p;
	char *dp;

	if (!mapsinited)
		initmaps();

	if (!str)
		return NULL;
	for (p = str, dp = cvtbuf;*p && (dp - cvtbuf < sizeof(cvtbuf) - 1); p++,dp++)
		*dp = dos2unix[(unsigned char)*p];
	*dp = 0;
	return cvtbuf;
}

char *dos2unix_format(char *str)
{
	char *p;

	if (!mapsinited)
		initmaps();

	if (!str)
		return NULL;

	for (p = str; *p; p++)
		*p = dos2unix[(unsigned char)*p];
	return str;
}


/*
 * Interpret character set.
 */
void interpret_character_set(char *str, int codepage)
{
    if (strequal (str, "iso8859-1")) {
        init_iso8859_1(codepage);
    } else if (strequal (str, "iso8859-2")) {
        init_iso8859_2();
    } else if (strequal (str, "iso8859-5")) {
        init_iso8859_5(codepage);
    } else if (strequal (str, "iso8859-8")) {
        init_iso8859_8();
    } else if (strequal (str, "iso8859-7")) {
        init_iso8859_7();
    } else if (strequal (str, "iso8859-9")) {
        init_iso8859_9();
    } else if (strequal (str, "iso8859-13")) {
        init_iso8859_13();
    } else if (strequal (str, "iso8859-15")) {
        init_iso8859_15(codepage);
    } else if (strequal (str, "koi8-r")) {
        init_koi8_r();
    } else if (strequal (str, "koi8-u")) {
        init_koi8_u(codepage);
    } else if (strequal (str, "1251u")) {
        init_1251(1125);
    } else if (strequal (str, "1251")) {
        init_1251(866);
    } else if (strequal (str, "roman8")) {
        init_roman8();
    } else {
        DEBUG(0,("unrecognized character set %s\n", str));
    }

    load_unix_unicode_map(str, True);
}
