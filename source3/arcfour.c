/* 
   Unix SMB/Netbios implementation.
   Version 1.9.

   a implementation of arcfour designed for use in the 
   SMB password change protocol based on the description
   in 'Applied Cryptography', 2nd Edition.

   Copyright (C) Jeremy Allison 1997
   
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

#include "arcfour.h"

void set_arc4_key(unsigned char *data, int key_length, arc4_key *arckey)
{
  unsigned int i; 
  unsigned char j;
  unsigned char tc;
  unsigned char *s_box = &arckey->s_box[0];

  arckey->index_i = 0;
  arckey->index_j = 0;
  for(i = 0; i < 256; i++)
    s_box[i] = (unsigned char)i;

  j = 0;
  for( i = 0; i < 256; i++)
  {
     j += (s_box[i] + data[i%key_length]);
     tc = s_box[i];
     s_box[i] = s_box[j];
     s_box[j] = tc;
  }
}

void arc4(arc4_key *arckey, unsigned char *data_in, unsigned char *data_out, 
          int length)
{
  unsigned char tc;
  int ind;
  unsigned char i, j;
  unsigned char t;
  unsigned char *s_box = &arckey->s_box[0];

  for( ind = 0; ind < length; ind++)
  {
    i = ++arckey->index_i;
    j = arckey->index_j += s_box[i];
    tc = s_box[i];
    s_box[i] = s_box[j];
    s_box[j] = tc;
    t = s_box[i] + s_box[j];
    *data_out++ = *data_in++ ^ s_box[t];
  }
}

#if 0
/* Test vector */
unsigned char key_data[] = { 0x61, 0x8a, 0x63, 0xd2, 0xfb };
unsigned char plaintext[] = { 0xdc, 0xee, 0x4c, 0xf9, 0x2c };
unsigned char ciphertext[] = { 0xf1, 0x38, 0x29, 0xc9, 0xde };

int main(int argc, char *argv[])
{
  unsigned char out[5];
  arc4_key key;

  set_arc4_key(key_data, 5, &key);
  arc4(&key, plaintext, out, 5);

  if(memcmp(out, ciphertext, 5) ==0)
    printf("Test ok !\n");
  else
    printf("Test fail !\n");
  return 0;
}
#endif
