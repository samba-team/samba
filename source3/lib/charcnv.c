/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Character set conversion Extensions
   Copyright (C) Andrew Tridgell 1992-1994
   
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

static char cvtbuf[1024];

static mapsinited = 0;

static char unix2dos[256];
static char dos2unix[256];

static void initmaps() {
    int k;

    for (k = 0; k < 256; k++) unix2dos[k] = k;
    for (k = 0; k < 256; k++) dos2unix[k] = k;

    mapsinited = 1;
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

static void initiso() {

    if (!mapsinited) initmaps();

    update_map("\241\255\242\233\243\234\244\236\245\235\246\272\247\025\250\251");
    update_map("\251\273\252\246\253\256\254\252\255\274\256\310\257\257\260\370");
    update_map("\261\361\262\375\263\264\264\265\265\266\266\024\267\371\270\267");
    update_map("\271\270\272\247\273\275\274\254\275\253\276\276\277\250\200\277");
    update_map("\301\300\302\301\303\302\304\216\305\217\306\222\307\200\310\303");
    update_map("\311\220\312\305\313\306\314\307\315\315\316\317\317\320\320\311");
    update_map("\321\245\322\321\323\322\324\323\325\324\326\231\327\312\330\325");
    update_map("\331\326\332\327\333\330\334\232\335\313\336\314\337\341\340\205");
    update_map("\341\240\342\203\343\331\344\204\345\206\346\221\347\207\350\212");
    update_map("\351\202\352\210\353\211\354\215\355\241\356\214\357\213\360\316");
    update_map("\361\244\362\225\363\242\364\223\365\332\366\224\367\366\370\362");
    update_map("\371\227\372\243\373\226\374\201\375\304\376\263\377\230");
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
int interpret_character_set(char *str, int def)
{

    if (strequal (str, "iso8859-1")) {
        initiso();
        return def;
    } else {
        DEBUG(0,("unrecognized character set\n"));
    }
    return def;
}
