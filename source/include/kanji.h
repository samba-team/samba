/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Kanji Extensions
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

   Adding for Japanese language by <fujita@ainix.isac.co.jp> 1994.9.5
     and extend coding system to EUC/SJIS/JIS/HEX at 1994.10.11
     and add all jis codes sequence at 1995.8.16
     Notes: Hexadecimal code by <ohki@gssm.otuka.tsukuba.ac.jp>
*/
#ifndef _KANJI_H_
#define _KANJI_H_

#ifdef KANJI

/* FOR SHIFT JIS CODE */
#define is_shift_jis(c) \
    ((0x81 <= ((unsigned char) (c)) && ((unsigned char) (c)) <= 0x9f) \
     || (0xe0 <= ((unsigned char) (c)) && ((unsigned char) (c)) <= 0xef))
#define is_shift_jis2(c) \
    (0x40 <= ((unsigned char) (c)) && ((unsigned char) (c)) <= 0xfc \
    && ((unsigned char) (c)) != 0x7f)
#define is_kana(c) ((0xa0 <= ((unsigned char) (c)) && ((unsigned char) (c)) <= 0xdf))

#ifdef _KANJI_C_
/* FOR EUC CODE */
#define euc_kana (0x8e)
#define is_euc_kana(c) (((unsigned char) (c)) == euc_kana)
#define is_euc(c)  (0xa0 < ((unsigned char) (c)) && ((unsigned char) (c)) < 0xff)

/* FOR JIS CODE */
/* default jis third shift code, use for output */
#ifndef JIS_KSO
#define JIS_KSO 'B'
#endif
#ifndef JIS_KSI
#define JIS_KSI 'J'
#endif
/* in: \E$B or \E$@ */
/* out: \E(J or \E(B or \E(H */
#define jis_esc (0x1b)
#define jis_so (0x0e)
#define jis_so1 ('$')
#define jis_so2 ('B')
#define jis_si (0x0f)
#define jis_si1 ('(')
#define jis_si2 ('J')
#define is_esc(c) (((unsigned char) (c)) == jis_esc)
#define is_so1(c) (((unsigned char) (c)) == jis_so1)
#define is_so2(c) (((unsigned char) (c)) == jis_so2 || ((unsigned char) (c)) == '@')
#define is_si1(c) (((unsigned char) (c)) == jis_si1)
#define is_si2(c) (((unsigned char) (c)) == jis_si2 || ((unsigned char) (c)) == 'B' \
    || ((unsigned char) (c)) == 'H')
#define is_so(c) (((unsigned char) (c)) == jis_so)
#define is_si(c) (((unsigned char) (c)) == jis_si)
#define junet_kana1 ('(')
#define junet_kana2 ('I')
#define is_juk1(c) (((unsigned char) (c)) == junet_kana1)
#define is_juk2(c) (((unsigned char) (c)) == junet_kana2)

#define _KJ_ROMAN (0)
#define _KJ_KANJI (1)
#define _KJ_KANA (2)

/* FOR HEX */
#define HEXTAG ':'
#define hex2bin(x)						      \
    ( ((int) '0' <= ((int) (x)) && ((int) (x)) <= (int)'9')?	      \
        (((int) (x))-(int)'0'):					      \
      ((int) 'a'<= ((int) (x)) && ((int) (x))<= (int) 'f')?	      \
        (((int) (x)) - (int)'a'+10):				      \
      (((int) (x)) - (int)'A'+10) )
#define bin2hex(x)						      \
    ( (((int) (x)) >= 10)? (((int) (x))-10 + (int) 'a'): (((int) (x)) + (int) '0') )

#else /* not _KANJI_C_ */

extern char* (*_dos_to_unix) (const char *str, BOOL overwrite);
extern char* (*_unix_to_dos) (const char *str, BOOL overwrite);

#define unix_to_dos (*_unix_to_dos)
#define dos_to_unix (*_dos_to_unix)

extern char *sj_strtok (char *s1, const char *s2);
extern char *sj_strchr (const char *s, int c);
extern char *sj_strrchr (const char *s, int c);
extern char *sj_strstr (const char *s1, const char *s2);

#define strchr sj_strchr
#define strrchr sj_strrchr
#define strstr sj_strstr
#define strtok sj_strtok

#endif /* _KANJI_C_ */

#define UNKNOWN_CODE (-1)
#define SJIS_CODE (0)
#define EUC_CODE (1)
#define JIS7_CODE (2)
#define JIS8_CODE (3)
#define JUNET_CODE (4)
#define HEX_CODE (5)
#define CAP_CODE (6)
#define DOSV_CODE SJIS_CODE

int interpret_coding_system (char *str, int def);

#else 

#define unix_to_dos(x,y) (x)
#define dos_to_unix(x,y) (x)

#endif /* not KANJI */

#endif /* _KANJI_H_ */
